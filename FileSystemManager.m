#import "FileSystemManager.h"
#import "MCPProcessUtil.h"
#import "MCPLogger.h"
#import "IOSMCPPreferences.h"
#import <CommonCrypto/CommonDigest.h>
#import <sys/stat.h>

#define FS_LOG(fmt, ...) [MCPLogger log:@"[FileSystem] " fmt, ##__VA_ARGS__]

// Default read cap for the JSON tool path. Larger files should use GET /download_file.
static const NSUInteger kFSDefaultMaxReadBytes = 512 * 1024;
static const NSUInteger kFSHardMaxReadBytes = 4 * 1024 * 1024;

@implementation FileSystemManager {
    NSMutableDictionary<NSString *, NSString *> *_pendingApprovals;
}

+ (instancetype)sharedInstance {
    static FileSystemManager *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[FileSystemManager alloc] init];
    });
    return instance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _pendingApprovals = [NSMutableDictionary dictionary];
    }
    return self;
}

#pragma mark - Path helpers & safety guard

static NSString *FSResolvePath(NSString *path) {
    if (path.length == 0) return @"";
    NSString *resolved = MCPResolvedJailbreakPath(path);
    return resolved.length ? resolved : path;
}

static NSString *FSFileTypeString(mode_t mode) {
    if (S_ISDIR(mode)) return @"directory";
    if (S_ISLNK(mode)) return @"symlink";
    if (S_ISREG(mode)) return @"file";
    if (S_ISFIFO(mode)) return @"fifo";
    if (S_ISSOCK(mode)) return @"socket";
    if (S_ISCHR(mode)) return @"char_device";
    if (S_ISBLK(mode)) return @"block_device";
    return @"unknown";
}

static NSString *FSModeOctal(mode_t mode) {
    return [NSString stringWithFormat:@"%03o", (unsigned)(mode & 07777)];
}

- (BOOL)validateWritePath:(NSString *)path
                  options:(NSDictionary *)options
              approvalOut:(NSDictionary **)approvalOut
                    error:(NSString **)error {
    if (approvalOut) *approvalOut = nil;
    if (error) *error = nil;
    if (![path isKindOfClass:[NSString class]] || !path.length) {
        if (error) *error = @"path is required";
        return NO;
    }

    BOOL allowUnsafe = [options[@"allow_unsafe_path"] boolValue];
    BOOL safetyEnabled = options[@"path_safety"] ? [options[@"path_safety"] boolValue] : IOSMCPPathSafetyEnabled();

    if (safetyEnabled && !allowUnsafe) {
        NSArray<NSString *> *components = [path pathComponents];
        if ([components containsObject:@".."]) {
            if (error) *error = @"Path traversal ('..') is blocked by path safety guard (pass allow_unsafe_path=true to override)";
            return NO;
        }
        NSString *stdPath = [path stringByStandardizingPath];
        NSArray<NSString *> *forbiddenPrefixes = @[@"/System", @"/bin", @"/sbin", @"/dev", @"/etc/master.passwd"];
        for (NSString *prefix in forbiddenPrefixes) {
            if ([stdPath isEqualToString:prefix] || [stdPath hasPrefix:[prefix stringByAppendingString:@"/"]]) {
                if (error) *error = [NSString stringWithFormat:@"Writing to protected system path '%@' is blocked by path safety guard", prefix];
                return NO;
            }
        }
        NSArray<NSString *> *allowedRoots = @[
            @"/var/mobile",
            @"/private/var/mobile",
            @"/var/containers",
            @"/private/var/containers",
            @"/var/jb",
            @"/private/preboot",
            @"/tmp",
            @"/private/tmp",
            @"/var/tmp",
            @"/private/var/tmp",
            @"/Library/MobileSubstrate",
            @"/usr/lib/ios-mcp"
        ];
        NSString *jbRoot = MCPJailbreakRoot();
        BOOL matchedRoot = NO;
        if (jbRoot.length > 1 && [stdPath hasPrefix:jbRoot]) {
            matchedRoot = YES;
        }
        for (NSString *root in allowedRoots) {
            if ([stdPath isEqualToString:root] || [stdPath hasPrefix:[root stringByAppendingString:@"/"]]) {
                matchedRoot = YES;
                break;
            }
        }
        if (!matchedRoot) {
            if (error) *error = [NSString stringWithFormat:@"Target path '%@' is outside allowed writable roots (/var/mobile, /var/containers, jbroot, /tmp). Pass allow_unsafe_path=true to override.", path];
            return NO;
        }
    }

    BOOL requireApproval = options[@"require_approval"] ? [options[@"require_approval"] boolValue] : IOSMCPRequireWriteApproval();
    if (requireApproval) {
        NSString *suppliedId = [options[@"approval_id"] isKindOfClass:[NSString class]] ? options[@"approval_id"] : nil;
        BOOL approved = NO;
        @synchronized (_pendingApprovals) {
            if (suppliedId.length && [_pendingApprovals[suppliedId] isEqualToString:path]) {
                [_pendingApprovals removeObjectForKey:suppliedId];
                approved = YES;
            } else {
                NSString *newId = [[NSUUID UUID] UUIDString];
                _pendingApprovals[newId] = path;
                if (approvalOut) {
                    *approvalOut = @{
                        @"status": @"write_approval_required",
                        @"approved": @NO,
                        @"approval_id": newId,
                        @"path": path,
                        @"instructions": @"Re-invoke the write tool with this approval_id to confirm the file modification."
                    };
                }
            }
        }
        if (!approved) {
            if (error) *error = @"Write approval required; see approval_id";
            return NO;
        }
    }

    return YES;
}

#pragma mark - List directory

- (NSDictionary *)listDirectoryAtPath:(NSString *)path error:(NSString **)error {
    if (error) *error = nil;
    if (path.length == 0) {
        if (error) *error = @"path is required";
        return nil;
    }

    NSString *resolved = FSResolvePath(path);
    NSFileManager *fm = [NSFileManager defaultManager];

    BOOL isDir = NO;
    if (![fm fileExistsAtPath:resolved isDirectory:&isDir]) {
        if (error) *error = [NSString stringWithFormat:@"No such file or directory: %@", path];
        return nil;
    }
    if (!isDir) {
        if (error) *error = @"path is not a directory; use read_file";
        return nil;
    }

    NSError *listError = nil;
    NSArray<NSString *> *names = [fm contentsOfDirectoryAtPath:resolved error:&listError];
    if (!names) {
        if (error) *error = [NSString stringWithFormat:@"Cannot list directory: %@",
                             listError.localizedDescription ?: @"permission denied"];
        FS_LOG(@"list failed path=%@ err=%@", path, listError.localizedDescription ?: @"-");
        return nil;
    }

    NSMutableArray<NSDictionary *> *entries = [NSMutableArray array];
    for (NSString *name in [names sortedArrayUsingSelector:@selector(localizedStandardCompare:)]) {
        NSString *child = [resolved stringByAppendingPathComponent:name];
        struct stat st;
        NSMutableDictionary *entry = [@{@"name": name} mutableCopy];
        if (lstat(child.fileSystemRepresentation, &st) == 0) {
            entry[@"type"] = FSFileTypeString(st.st_mode);
            entry[@"size"] = @(st.st_size);
            entry[@"mode"] = FSModeOctal(st.st_mode);
            entry[@"mtime"] = @((long long)st.st_mtimespec.tv_sec);
            if (S_ISLNK(st.st_mode)) {
                char buf[1024];
                ssize_t n = readlink(child.fileSystemRepresentation, buf, sizeof(buf) - 1);
                if (n > 0) {
                    buf[n] = '\0';
                    entry[@"symlink_target"] = [NSString stringWithUTF8String:buf] ?: @"";
                }
            }
        } else {
            entry[@"type"] = @"unknown";
        }
        [entries addObject:entry];
    }

    FS_LOG(@"list ok path=%@ count=%lu", path, (unsigned long)entries.count);
    return @{@"path": path, @"resolved_path": resolved, @"entries": entries};
}

#pragma mark - Read file

- (NSDictionary *)readFileAtPath:(NSString *)path
                        maxBytes:(NSUInteger)maxBytes
                     forceBinary:(BOOL)forceBinary
                           error:(NSString **)error {
    if (error) *error = nil;
    if (path.length == 0) {
        if (error) *error = @"path is required";
        return nil;
    }
    if (maxBytes == 0) maxBytes = kFSDefaultMaxReadBytes;
    if (maxBytes > kFSHardMaxReadBytes) maxBytes = kFSHardMaxReadBytes;

    NSString *resolved = FSResolvePath(path);
    NSFileManager *fm = [NSFileManager defaultManager];

    BOOL isDir = NO;
    if (![fm fileExistsAtPath:resolved isDirectory:&isDir]) {
        if (error) *error = [NSString stringWithFormat:@"No such file or directory: %@", path];
        return nil;
    }
    if (isDir) {
        if (error) *error = @"path is a directory; use list_dir";
        return nil;
    }

    // Read up to maxBytes+1 so we can detect truncation.
    NSFileHandle *handle = [NSFileHandle fileHandleForReadingAtPath:resolved];
    if (!handle) {
        if (error) *error = [NSString stringWithFormat:@"Cannot open file: %@ (permission denied or unreadable)", path];
        FS_LOG(@"read failed path=%@ (open)", path);
        return nil;
    }

    NSData *data = nil;
    @try {
        data = [handle readDataOfLength:maxBytes + 1];
    } @catch (NSException *e) {
        data = nil;
    }
    [handle closeFile];

    if (!data) {
        if (error) *error = [NSString stringWithFormat:@"Cannot read file: %@", path];
        return nil;
    }

    BOOL truncated = NO;
    if (data.length > maxBytes) {
        truncated = YES;
        data = [data subdataWithRange:NSMakeRange(0, maxBytes)];
    }

    NSString *encoding = @"utf8";
    NSString *content = nil;
    if (!forceBinary) {
        content = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    }
    if (!content) {
        encoding = @"base64";
        content = [data base64EncodedStringWithOptions:0];
    }

    FS_LOG(@"read ok path=%@ bytes=%lu enc=%@ trunc=%@",
           path, (unsigned long)data.length, encoding, truncated ? @"yes" : @"no");

    return @{
        @"path": path,
        @"resolved_path": resolved,
        @"size": @(data.length),
        @"encoding": encoding,
        @"content": content ?: @"",
        @"truncated": @(truncated),
        @"hint": truncated ? @"Output truncated; use read_file_chunk or GET /download_file?path=... for the full file." : @""
    };
}

#pragma mark - Write file

- (NSDictionary *)writeFileWithArgs:(NSDictionary *)args
                              error:(NSString **)error {
    NSString *path = [args[@"path"] isKindOfClass:[NSString class]] ? args[@"path"] : nil;
    NSDictionary *approval = nil;
    if (![self validateWritePath:path options:args approvalOut:&approval error:error]) {
        if (approval) {
            if (error) *error = nil;
            return approval;
        }
        return nil;
    }
    NSString *content = [args[@"content"] isKindOfClass:[NSString class]] ? args[@"content"] : @"";
    NSString *encoding = [args[@"encoding"] isKindOfClass:[NSString class]] ? args[@"encoding"] : @"utf8";
    return [self writeFileAtPath:path content:content encoding:encoding error:error];
}

- (NSDictionary *)writeFileAtPath:(NSString *)path
                          content:(NSString *)content
                         encoding:(NSString *)encoding
                            error:(NSString **)error {
    if (error) *error = nil;
    if (path.length == 0) {
        if (error) *error = @"path is required";
        return nil;
    }
    NSDictionary *approval = nil;
    if (![self validateWritePath:path options:@{} approvalOut:&approval error:error]) {
        if (approval) {
            if (error) *error = nil;
            return approval;
        }
        return nil;
    }
    if (content == nil) content = @"";

    NSData *data = nil;
    if ([encoding isEqualToString:@"base64"]) {
        data = [[NSData alloc] initWithBase64EncodedString:content options:NSDataBase64DecodingIgnoreUnknownCharacters];
        if (!data) {
            if (error) *error = @"content is not valid base64";
            return nil;
        }
    } else {
        data = [content dataUsingEncoding:NSUTF8StringEncoding] ?: [NSData data];
    }

    NSString *resolved = FSResolvePath(path);
    NSError *writeError = nil;
    if (![data writeToFile:resolved options:NSDataWritingAtomic error:&writeError]) {
        if (error) *error = [NSString stringWithFormat:@"Cannot write file: %@",
                             writeError.localizedDescription ?: @"permission denied"];
        FS_LOG(@"write failed path=%@ err=%@", path, writeError.localizedDescription ?: @"-");
        return nil;
    }

    FS_LOG(@"write ok path=%@ bytes=%lu", path, (unsigned long)data.length);
    return @{
        @"path": path,
        @"resolved_path": resolved,
        @"bytes_written": @(data.length)
    };
}

#pragma mark - Chunked read, tail, hash, zip, search (Step 4)

- (NSDictionary *)readFileChunkAtPath:(NSString *)path
                               offset:(uint64_t)offset
                               length:(NSUInteger)length
                          forceBinary:(BOOL)forceBinary
                                error:(NSString **)error {
    if (error) *error = nil;
    if (!path.length) {
        if (error) *error = @"path is required";
        return nil;
    }
    if (length == 0) length = 64 * 1024;
    if (length > kFSHardMaxReadBytes) length = kFSHardMaxReadBytes;

    NSString *resolved = FSResolvePath(path);
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL isDir = NO;
    if (![fm fileExistsAtPath:resolved isDirectory:&isDir] || isDir) {
        if (error) *error = isDir ? @"path is a directory" : [NSString stringWithFormat:@"File not found: %@", path];
        return nil;
    }

    NSDictionary *attrs = [fm attributesOfItemAtPath:resolved error:NULL];
    uint64_t totalSize = [attrs[NSFileSize] unsignedLongLongValue];
    NSFileHandle *fh = [NSFileHandle fileHandleForReadingAtPath:resolved];
    if (!fh) {
        if (error) *error = @"Cannot open file for reading";
        return nil;
    }
    NSData *chunk = nil;
    @try {
        if (offset < totalSize) {
            [fh seekToFileOffset:offset];
            chunk = [fh readDataOfLength:length];
        } else {
            chunk = [NSData data];
        }
    } @catch (NSException *e) {
        chunk = nil;
    }
    [fh closeFile];

    if (!chunk) {
        if (error) *error = @"Failed to read chunk at offset";
        return nil;
    }

    NSString *encoding = @"utf8";
    NSString *content = !forceBinary ? [[NSString alloc] initWithData:chunk encoding:NSUTF8StringEncoding] : nil;
    if (!content) {
        encoding = @"base64";
        content = [chunk base64EncodedStringWithOptions:0] ?: @"";
    }
    uint64_t nextOffset = offset + chunk.length;
    return @{
        @"path": path,
        @"resolved_path": resolved,
        @"total_size": @(totalSize),
        @"offset": @(offset),
        @"bytes_read": @(chunk.length),
        @"next_offset": @(nextOffset),
        @"eof": @(nextOffset >= totalSize),
        @"encoding": encoding,
        @"content": content
    };
}

- (NSDictionary *)tailFileAtPath:(NSString *)path
                           lines:(NSUInteger)lines
                        maxBytes:(NSUInteger)maxBytes
                           error:(NSString **)error {
    if (error) *error = nil;
    if (!path.length) {
        if (error) *error = @"path is required";
        return nil;
    }
    if (lines == 0) lines = 100;
    if (lines > 5000) lines = 5000;
    if (maxBytes == 0) maxBytes = 256 * 1024;
    if (maxBytes > kFSHardMaxReadBytes) maxBytes = kFSHardMaxReadBytes;

    NSString *resolved = FSResolvePath(path);
    NSFileManager *fm = [NSFileManager defaultManager];
    NSDictionary *attrs = [fm attributesOfItemAtPath:resolved error:NULL];
    if (!attrs) {
        if (error) *error = [NSString stringWithFormat:@"File not found: %@", path];
        return nil;
    }
    uint64_t totalSize = [attrs[NSFileSize] unsignedLongLongValue];
    uint64_t startOffset = totalSize > maxBytes ? (totalSize - maxBytes) : 0;

    NSFileHandle *fh = [NSFileHandle fileHandleForReadingAtPath:resolved];
    if (!fh) {
        if (error) *error = @"Cannot open file";
        return nil;
    }
    NSData *tailData = nil;
    @try {
        [fh seekToFileOffset:startOffset];
        tailData = [fh readDataToEndOfFile];
    } @catch (NSException *e) {}
    [fh closeFile];

    NSString *text = [[NSString alloc] initWithData:tailData ?: [NSData data] encoding:NSUTF8StringEncoding];
    if (!text) {
        text = [[NSString alloc] initWithData:tailData ?: [NSData data] encoding:NSISOLatin1StringEncoding] ?: @"";
    }
    NSArray<NSString *> *allLines = [text componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
    NSUInteger count = allLines.count;
    NSArray<NSString *> *sliced = count > lines ? [allLines subarrayWithRange:NSMakeRange(count - lines, lines)] : allLines;

    return @{
        @"path": path,
        @"resolved_path": resolved,
        @"total_size": @(totalSize),
        @"line_count": @(sliced.count),
        @"content": [sliced componentsJoinedByString:@"\n"]
    };
}

- (NSDictionary *)hashFileAtPath:(NSString *)path
                      algorithms:(NSArray<NSString *> *)algorithms
                           error:(NSString **)error {
    if (error) *error = nil;
    if (!path.length) {
        if (error) *error = @"path is required";
        return nil;
    }
    NSString *resolved = FSResolvePath(path);
    NSFileHandle *fh = [NSFileHandle fileHandleForReadingAtPath:resolved];
    if (!fh) {
        if (error) *error = [NSString stringWithFormat:@"Cannot open file: %@", path];
        return nil;
    }

    CC_SHA256_CTX sha256Ctx;
    CC_SHA256_Init(&sha256Ctx);
    CC_SHA1_CTX sha1Ctx;
    CC_SHA1_Init(&sha1Ctx);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    CC_MD5_CTX md5Ctx;
    CC_MD5_Init(&md5Ctx);
#pragma clang diagnostic pop

    uint64_t totalBytes = 0;
    while (YES) {
        @autoreleasepool {
            NSData *chunk = [fh readDataOfLength:64 * 1024];
            if (!chunk.length) break;
            totalBytes += chunk.length;
            CC_SHA256_Update(&sha256Ctx, chunk.bytes, (CC_LONG)chunk.length);
            CC_SHA1_Update(&sha1Ctx, chunk.bytes, (CC_LONG)chunk.length);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
            CC_MD5_Update(&md5Ctx, chunk.bytes, (CC_LONG)chunk.length);
#pragma clang diagnostic pop
        }
    }
    [fh closeFile];

    unsigned char sha256Digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(sha256Digest, &sha256Ctx);
    NSMutableString *sha256Hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) [sha256Hex appendFormat:@"%02x", sha256Digest[i]];

    unsigned char sha1Digest[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1_Final(sha1Digest, &sha1Ctx);
    NSMutableString *sha1Hex = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) [sha1Hex appendFormat:@"%02x", sha1Digest[i]];

    unsigned char md5Digest[CC_MD5_DIGEST_LENGTH];
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    CC_MD5_Final(md5Digest, &md5Ctx);
#pragma clang diagnostic pop
    NSMutableString *md5Hex = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_MD5_DIGEST_LENGTH; i++) [md5Hex appendFormat:@"%02x", md5Digest[i]];

    return @{
        @"path": path,
        @"resolved_path": resolved,
        @"size": @(totalBytes),
        @"sha256": sha256Hex,
        @"sha1": sha1Hex,
        @"md5": md5Hex
    };
}

- (NSDictionary *)zipDirectoryAtPath:(NSString *)path
                          outputPath:(NSString *)outputPath
                               error:(NSString **)error {
    if (error) *error = nil;
    if (!path.length) {
        if (error) *error = @"path is required";
        return nil;
    }
    NSString *resolved = FSResolvePath(path);
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:resolved]) {
        if (error) *error = [NSString stringWithFormat:@"Path not found: %@", path];
        return nil;
    }

    NSString *archivePath = outputPath.length ? FSResolvePath(outputPath) : nil;
    if (!archivePath.length) {
        NSString *workDir = MCPResolvedJailbreakPath(@"/var/mobile/Library/Caches/ios-mcp-work");
        [fm createDirectoryAtPath:workDir withIntermediateDirectories:YES attributes:nil error:NULL];
        NSString *baseName = [[resolved lastPathComponent] stringByReplacingOccurrencesOfString:@" " withString:@"_"];
        if (!baseName.length) baseName = @"archive";
        archivePath = [workDir stringByAppendingPathComponent:[NSString stringWithFormat:@"%@_%lld.tar.gz", baseName, (long long)[[NSDate date] timeIntervalSince1970]]];
    }
    [fm removeItemAtPath:archivePath error:NULL];

    NSString *parentDir = [resolved stringByDeletingLastPathComponent];
    NSString *targetName = [resolved lastPathComponent];
    int status = -1;
    NSString *out = nil;
    if ([archivePath hasSuffix:@".zip"]) {
        out = MCPReadCommandOutput(@[@"zip", @"-r", @"-q", archivePath, resolved], 60.0, &status);
    }
    if (status != 0 || ![fm fileExistsAtPath:archivePath]) {
        if (![archivePath hasSuffix:@".tar.gz"] && ![archivePath hasSuffix:@".tgz"]) {
            archivePath = [archivePath stringByAppendingString:@".tar.gz"];
        }
        out = MCPReadCommandOutput(@[@"tar", @"-czf", archivePath, @"-C", parentDir, targetName], 60.0, &status);
    }
    if (![fm fileExistsAtPath:archivePath]) {
        if (error) *error = [NSString stringWithFormat:@"Failed to create archive: %@", out ?: @"zip/tar unavailable"];
        return nil;
    }

    NSDictionary *attrs = [fm attributesOfItemAtPath:archivePath error:NULL];
    NSString *encodedPath = [archivePath stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLQueryAllowedCharacterSet]] ?: archivePath;
    return @{
        @"ok": @YES,
        @"source_path": path,
        @"archive_path": archivePath,
        @"size": attrs[NSFileSize] ?: @0,
        @"download_endpoint": [NSString stringWithFormat:@"/download_file?path=%@", encodedPath]
    };
}

- (NSDictionary *)searchFilesAtPath:(NSString *)path
                            pattern:(NSString *)pattern
                     contentPattern:(NSString *)contentPattern
                           maxDepth:(NSUInteger)maxDepth
                         maxResults:(NSUInteger)maxResults
                              error:(NSString **)error {
    if (error) *error = nil;
    if (!path.length) {
        if (error) *error = @"path is required";
        return nil;
    }
    if (maxDepth == 0) maxDepth = 6;
    if (maxResults == 0) maxResults = 100;
    if (maxResults > 1000) maxResults = 1000;

    NSString *resolved = FSResolvePath(path);
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL isDir = NO;
    if (![fm fileExistsAtPath:resolved isDirectory:&isDir] || !isDir) {
        if (error) *error = [NSString stringWithFormat:@"Directory not found: %@", path];
        return nil;
    }

    NSRegularExpression *nameRegex = nil;
    if (pattern.length) {
        nameRegex = [NSRegularExpression regularExpressionWithPattern:pattern options:NSRegularExpressionCaseInsensitive error:NULL];
    }
    NSRegularExpression *contentRegex = nil;
    if (contentPattern.length) {
        contentRegex = [NSRegularExpression regularExpressionWithPattern:contentPattern options:NSRegularExpressionCaseInsensitive error:NULL];
    }

    NSMutableArray<NSDictionary *> *matches = [NSMutableArray array];
    NSDirectoryEnumerator *enumerator = [fm enumeratorAtPath:resolved];
    NSString *rel = nil;
    while ((rel = [enumerator nextObject]) && matches.count < maxResults) {
        @autoreleasepool {
            NSUInteger depth = [[rel pathComponents] count];
            if (depth > maxDepth) {
                [enumerator skipDescendants];
                continue;
            }
            NSString *fileName = [rel lastPathComponent];
            if (pattern.length) {
                BOOL nameMatch = nameRegex
                    ? ([nameRegex firstMatchInString:fileName options:0 range:NSMakeRange(0, fileName.length)] != nil)
                    : ([fileName rangeOfString:pattern options:NSCaseInsensitiveSearch].location != NSNotFound);
                if (!nameMatch) continue;
            }

            NSString *fullPath = [resolved stringByAppendingPathComponent:rel];
            NSDictionary *attrs = [enumerator fileAttributes];
            NSString *fileType = attrs[NSFileType];
            BOOL isRegular = [fileType isEqualToString:NSFileTypeRegular];

            if (contentPattern.length) {
                if (!isRegular || [attrs[NSFileSize] unsignedLongLongValue] > 2 * 1024 * 1024) continue;
                NSData *d = [NSData dataWithContentsOfFile:fullPath options:NSDataReadingMappedIfSafe error:NULL];
                if (!d.length) continue;
                NSString *txt = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
                if (!txt) continue;
                BOOL textMatch = contentRegex
                    ? ([contentRegex firstMatchInString:txt options:0 range:NSMakeRange(0, txt.length)] != nil)
                    : ([txt rangeOfString:contentPattern options:NSCaseInsensitiveSearch].location != NSNotFound);
                if (!textMatch) continue;
            }

            [matches addObject:@{
                @"relative_path": rel,
                @"path": fullPath,
                @"type": [fileType isEqualToString:NSFileTypeDirectory] ? @"directory" : (isRegular ? @"file" : @"other"),
                @"size": attrs[NSFileSize] ?: @0,
                @"mtime": @([attrs[NSFileModificationDate] timeIntervalSince1970])
            }];
        }
    }

    return @{
        @"root_path": path,
        @"resolved_root": resolved,
        @"pattern": pattern ?: @"",
        @"content_pattern": contentPattern ?: @"",
        @"count": @(matches.count),
        @"matches": matches
    };
}

#pragma mark - Download resolution

- (NSString *)resolveDownloadPath:(NSString *)path
                      isTemporary:(BOOL *)isTemporary
                            error:(NSString **)error {
    if (isTemporary) *isTemporary = NO;
    if (error) *error = nil;
    if (path.length == 0) {
        if (error) *error = @"path is required";
        return nil;
    }

    NSString *resolved = FSResolvePath(path);
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL isDir = NO;

    if (![fm fileExistsAtPath:resolved isDirectory:&isDir]) {
        if (error) *error = @"File not found";
        return nil;
    }
    if (isDir) {
        if (error) *error = @"path is a directory";
        return nil;
    }
    if (![fm isReadableFileAtPath:resolved]) {
        if (error) *error = @"File is not readable";
        return nil;
    }
    return resolved;
}

@end
