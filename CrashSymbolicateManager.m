#import "CrashSymbolicateManager.h"
#import "MCPMachOUtil.h"
#import "MCPProcessUtil.h"
#import <dlfcn.h>
#import <mach-o/dyld.h>

static NSDictionary *MCPSymbolicateInLocalSharedCache(NSString *imagePath, uint64_t imageOffset) {
    if (!imagePath.length) return nil;
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *cname = _dyld_get_image_name(i);
        if (!cname) continue;
        NSString *loadedPath = [NSString stringWithUTF8String:cname];
        if (!loadedPath) continue;
        if ([loadedPath isEqualToString:imagePath] ||
            [loadedPath.lastPathComponent isEqualToString:imagePath.lastPathComponent]) {
            const struct mach_header *hdr = _dyld_get_image_header(i);
            if (!hdr) continue;
            uintptr_t targetAddr = (uintptr_t)hdr + (uintptr_t)imageOffset;
            Dl_info info;
            if (dladdr((const void *)targetAddr, &info) != 0 && info.dli_sname && info.dli_fbase == hdr) {
                uint64_t symOffset = (uintptr_t)info.dli_saddr <= targetAddr
                    ? (uint64_t)(targetAddr - (uintptr_t)info.dli_saddr)
                    : 0;
                NSString *symName = [NSString stringWithUTF8String:info.dli_sname] ?: @"";
                if (symName.length > 0 && ![symName isEqualToString:@"<redacted>"]) {
                    return @{
                        @"symbol": symName,
                        @"symbol_offset": @(symOffset),
                        @"source": @"dyld_shared_cache"
                    };
                }
            }
            break;
        }
    }
    return nil;
}

@implementation CrashSymbolicateManager

+ (instancetype)sharedInstance {
    static CrashSymbolicateManager *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[CrashSymbolicateManager alloc] init];
    });
    return instance;
}

- (NSData *)readCrashDataAtPath:(NSString *)path resolvedPath:(NSString **)outResolved error:(NSString **)error {
    NSString *resolved = MCPResolvedJailbreakPath(path);
    if (!resolved.length) resolved = path;
    if (outResolved) *outResolved = resolved;

    NSData *data = [NSData dataWithContentsOfFile:resolved];
    if (data.length > 0) return data;

    NSData *rootData = nil;
    BOOL truncated = NO;
    int code = -1;
    NSString *runErr = nil;
    if (MCPRunRootProcessData(@"/usr/libexec/ios-mcp/mcp-appmod",
                              @[@"read-file", resolved, @"16777216"],
                              15.0,
                              16 * 1024 * 1024,
                              &rootData,
                              &truncated,
                              &code,
                              &runErr) && code == 0 && rootData.length > 0) {
        return rootData;
    }

    if (error) *error = [NSString stringWithFormat:@"Cannot read crash log at %@", path];
    return nil;
}

- (NSDictionary<NSNumber *, NSDictionary *> *)symbolicateImagePath:(NSString *)imagePath
                                                              arch:(NSString *)arch
                                                           offsets:(NSArray<NSNumber *> *)offsets {
    if (!imagePath.length || !offsets.count) return @{};
    NSMutableDictionary<NSNumber *, NSDictionary *> *combined = [NSMutableDictionary dictionary];

    NSString *resolved = MCPResolvedJailbreakPath(imagePath);
    if (!resolved.length) resolved = imagePath;

    if ([[NSFileManager defaultManager] fileExistsAtPath:resolved]) {
        NSString *err = nil;
        NSDictionary<NSNumber *, NSDictionary *> *direct = MCPSymbolicateOffsetsInMachO(resolved, arch, offsets, &err);
        if (direct.count > 0) {
            [combined addEntriesFromDictionary:direct];
        } else {
            NSMutableArray<NSString *> *parts = [NSMutableArray arrayWithCapacity:offsets.count];
            for (NSNumber *n in offsets) {
                [parts addObject:[NSString stringWithFormat:@"%llu", n.unsignedLongLongValue]];
            }
            NSString *outStr = nil, *runErr = nil;
            int code = -1;
            if (MCPRunRootProcess(@"/usr/libexec/ios-mcp/mcp-appmod",
                                  @[@"symbolicate-macho", resolved, (arch.length ? arch : @"-"), [parts componentsJoinedByString:@","]],
                                  20.0,
                                  1024 * 1024,
                                  &outStr,
                                  &code,
                                  &runErr) && code == 0 && outStr.length > 0) {
                NSData *d = [outStr dataUsingEncoding:NSUTF8StringEncoding];
                NSDictionary *resp = d ? [NSJSONSerialization JSONObjectWithData:d options:0 error:NULL] : nil;
                NSDictionary *resMap = [resp[@"result"] isKindOfClass:[NSDictionary class]] ? resp[@"result"] : nil;
                for (NSString *k in resMap) {
                    uint64_t offVal = strtoull(k.UTF8String, NULL, 10);
                    if ([resMap[k] isKindOfClass:[NSDictionary class]]) {
                        combined[@(offVal)] = resMap[k];
                    }
                }
            }
        }
    }

    // Fallback to live dyld_shared_cache dladdr for system frameworks without standalone Mach-O files on disk
    for (NSNumber *off in offsets) {
        if (!combined[off]) {
            NSDictionary *cacheHit = MCPSymbolicateInLocalSharedCache(imagePath, off.unsignedLongLongValue);
            if (cacheHit) {
                combined[off] = cacheHit;
            }
        }
    }

    return combined;
}

- (NSDictionary *)symbolicateIPSHeader:(NSDictionary *)meta
                                  body:(NSDictionary *)body
                               logPath:(NSString *)logPath
                          resolvedPath:(NSString *)resolvedPath
                            allThreads:(BOOL)allThreads
                             maxFrames:(NSUInteger)maxFrames {
    NSArray *usedImages = [body[@"usedImages"] isKindOfClass:[NSArray class]] ? body[@"usedImages"] : @[];
    NSArray *rawThreads = [body[@"threads"] isKindOfClass:[NSArray class]] ? body[@"threads"] : @[];
    NSInteger faultingThread = [body[@"faultingThread"] respondsToSelector:@selector(integerValue)]
        ? [body[@"faultingThread"] integerValue]
        : -1;
    NSString *cpuType = [body[@"cpuType"] isKindOfClass:[NSString class]] ? body[@"cpuType"] : @"";
    NSString *defaultArch = ([cpuType rangeOfString:@"ARM-64E" options:NSCaseInsensitiveSearch].location != NSNotFound) ? @"arm64e" : nil;

    // Collect image offsets needing symbolication
    NSMutableDictionary<NSNumber *, NSMutableSet<NSNumber *> *> *offsetsByImg = [NSMutableDictionary dictionary];
    for (NSUInteger tIdx = 0; tIdx < rawThreads.count; tIdx++) {
        NSDictionary *th = [rawThreads[tIdx] isKindOfClass:[NSDictionary class]] ? rawThreads[tIdx] : nil;
        if (!th) continue;
        BOOL isTriggered = [th[@"triggered"] boolValue] || ((NSInteger)tIdx == faultingThread);
        if (!allThreads && !isTriggered && faultingThread >= 0) continue;

        NSArray *frames = [th[@"frames"] isKindOfClass:[NSArray class]] ? th[@"frames"] : @[];
        NSUInteger limit = MIN(frames.count, maxFrames);
        for (NSUInteger fIdx = 0; fIdx < limit; fIdx++) {
            NSDictionary *fr = [frames[fIdx] isKindOfClass:[NSDictionary class]] ? frames[fIdx] : nil;
            if (!fr) continue;
            NSString *existingSym = [fr[@"symbol"] isKindOfClass:[NSString class]] ? fr[@"symbol"] : nil;
            if (existingSym.length > 0 && ![existingSym isEqualToString:@"<redacted>"]) continue;

            if (![fr[@"imageIndex"] respondsToSelector:@selector(unsignedIntegerValue)] ||
                ![fr[@"imageOffset"] respondsToSelector:@selector(unsignedLongLongValue)]) continue;
            NSUInteger imgIdx = [fr[@"imageIndex"] unsignedIntegerValue];
            uint64_t imgOff = [fr[@"imageOffset"] unsignedLongLongValue];
            if (imgIdx >= usedImages.count) continue;
            NSMutableSet<NSNumber *> *set = offsetsByImg[@(imgIdx)];
            if (!set) {
                set = [NSMutableSet set];
                offsetsByImg[@(imgIdx)] = set;
            }
            [set addObject:@(imgOff)];
        }
    }

    NSMutableDictionary<NSNumber *, NSDictionary<NSNumber *, NSDictionary *> *> *resolvedByImg = [NSMutableDictionary dictionary];
    for (NSNumber *imgIdxNum in offsetsByImg) {
        NSDictionary *img = [usedImages[imgIdxNum.unsignedIntegerValue] isKindOfClass:[NSDictionary class]]
            ? usedImages[imgIdxNum.unsignedIntegerValue]
            : nil;
        NSString *imgPath = [img[@"path"] isKindOfClass:[NSString class]] ? img[@"path"] : nil;
        NSString *imgArch = [img[@"arch"] isKindOfClass:[NSString class]] ? img[@"arch"] : defaultArch;
        if (!imgPath.length) continue;
        resolvedByImg[imgIdxNum] = [self symbolicateImagePath:imgPath
                                                         arch:imgArch
                                                      offsets:offsetsByImg[imgIdxNum].allObjects];
    }

    NSUInteger totalFrames = 0;
    NSUInteger symbolicatedFrames = 0;
    NSMutableArray<NSDictionary *> *outThreads = [NSMutableArray array];

    for (NSUInteger tIdx = 0; tIdx < rawThreads.count; tIdx++) {
        NSDictionary *th = [rawThreads[tIdx] isKindOfClass:[NSDictionary class]] ? rawThreads[tIdx] : nil;
        if (!th) continue;
        BOOL isTriggered = [th[@"triggered"] boolValue] || ((NSInteger)tIdx == faultingThread);
        if (!allThreads && !isTriggered && faultingThread >= 0) continue;

        NSArray *frames = [th[@"frames"] isKindOfClass:[NSArray class]] ? th[@"frames"] : @[];
        NSUInteger limit = MIN(frames.count, maxFrames);
        NSMutableArray<NSDictionary *> *outFrames = [NSMutableArray arrayWithCapacity:limit];

        for (NSUInteger fIdx = 0; fIdx < limit; fIdx++) {
            NSDictionary *fr = [frames[fIdx] isKindOfClass:[NSDictionary class]] ? frames[fIdx] : nil;
            if (!fr) continue;
            totalFrames++;

            NSUInteger imgIdx = [fr[@"imageIndex"] respondsToSelector:@selector(unsignedIntegerValue)]
                ? [fr[@"imageIndex"] unsignedIntegerValue]
                : NSNotFound;
            uint64_t imgOff = [fr[@"imageOffset"] respondsToSelector:@selector(unsignedLongLongValue)]
                ? [fr[@"imageOffset"] unsignedLongLongValue]
                : 0;
            NSDictionary *img = (imgIdx < usedImages.count && [usedImages[imgIdx] isKindOfClass:[NSDictionary class]])
                ? usedImages[imgIdx]
                : nil;
            NSString *imgName = [img[@"name"] isKindOfClass:[NSString class]]
                ? img[@"name"]
                : (([img[@"path"] isKindOfClass:[NSString class]]) ? [img[@"path"] lastPathComponent] : @"???");
            NSString *imgPath = [img[@"path"] isKindOfClass:[NSString class]] ? img[@"path"] : @"";
            uint64_t imgBase = [img[@"base"] respondsToSelector:@selector(unsignedLongLongValue)]
                ? [img[@"base"] unsignedLongLongValue]
                : 0;
            uint64_t pc = imgBase + imgOff;

            NSString *sym = [fr[@"symbol"] isKindOfClass:[NSString class]] ? fr[@"symbol"] : nil;
            uint64_t symOff = [fr[@"symbolLocation"] respondsToSelector:@selector(unsignedLongLongValue)]
                ? [fr[@"symbolLocation"] unsignedLongLongValue]
                : 0;
            NSString *symSource = (sym.length > 0 && ![sym isEqualToString:@"<redacted>"]) ? @"ips_inline" : @"unsymbolicated";

            if ([symSource isEqualToString:@"unsymbolicated"] && imgIdx != NSNotFound) {
                NSDictionary *hit = resolvedByImg[@(imgIdx)][@(imgOff)];
                if (hit && [hit[@"symbol"] isKindOfClass:[NSString class]]) {
                    sym = hit[@"symbol"];
                    symOff = [hit[@"symbol_offset"] unsignedLongLongValue];
                    symSource = hit[@"source"] ?: @"macho";
                }
            }

            if (![symSource isEqualToString:@"unsymbolicated"]) {
                symbolicatedFrames++;
            }

            NSString *formatted = (sym.length > 0 && ![symSource isEqualToString:@"unsymbolicated"])
                ? [NSString stringWithFormat:@"%lu  %@  0x%llx %@ + %llu",
                   (unsigned long)fIdx, imgName, (unsigned long long)pc, sym, (unsigned long long)symOff]
                : [NSString stringWithFormat:@"%lu  %@  0x%llx 0x%llx + %llu",
                   (unsigned long)fIdx, imgName, (unsigned long long)pc, (unsigned long long)imgBase, (unsigned long long)imgOff];

            [outFrames addObject:@{
                @"index": @(fIdx),
                @"image_name": imgName ?: @"",
                @"image_path": imgPath ?: @"",
                @"image_base": [NSString stringWithFormat:@"0x%llx", (unsigned long long)imgBase],
                @"image_offset": @(imgOff),
                @"address": [NSString stringWithFormat:@"0x%llx", (unsigned long long)pc],
                @"symbol": sym ?: @"",
                @"symbol_offset": @(symOff),
                @"source": symSource,
                @"formatted": formatted
            }];
        }

        [outThreads addObject:@{
            @"thread_index": @(tIdx),
            @"triggered": @(isTriggered),
            @"name": [th[@"name"] isKindOfClass:[NSString class]] ? th[@"name"] : ([th[@"queue"] isKindOfClass:[NSString class]] ? th[@"queue"] : @""),
            @"frame_count": @(outFrames.count),
            @"frames": outFrames
        }];
    }

    NSDictionary *bundleInfo = [body[@"bundleInfo"] isKindOfClass:[NSDictionary class]] ? body[@"bundleInfo"] : @{};
    return @{
        @"log_path": logPath,
        @"resolved_path": resolvedPath,
        @"format": @"ips_json",
        @"process_name": body[@"procName"] ?: meta[@"app_name"] ?: @"",
        @"process_path": body[@"procPath"] ?: @"",
        @"bundle_id": bundleInfo[@"CFBundleIdentifier"] ?: meta[@"bundleID"] ?: @"",
        @"bundle_version": bundleInfo[@"CFBundleShortVersionString"] ?: meta[@"app_version"] ?: @"",
        @"os_version": meta[@"os_version"] ?: @"",
        @"incident_id": body[@"incident"] ?: meta[@"incident_id"] ?: @"",
        @"faulting_thread": @(faultingThread),
        @"exception": body[@"exception"] ?: @{},
        @"termination": body[@"termination"] ?: @{},
        @"total_frames_processed": @(totalFrames),
        @"symbolicated_frame_count": @(symbolicatedFrames),
        @"used_image_count": @(usedImages.count),
        @"threads": outThreads
    };
}

- (NSDictionary *)symbolicateLegacyText:(NSString *)text
                                logPath:(NSString *)logPath
                           resolvedPath:(NSString *)resolvedPath
                              maxFrames:(NSUInteger)maxFrames
                                  error:(NSString **)error {
    NSArray<NSString *> *lines = [text componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
    NSMutableDictionary<NSString *, NSDictionary *> *imagesByName = [NSMutableDictionary dictionary];
    NSMutableArray<NSDictionary *> *rawFrames = [NSMutableArray array];

    NSRegularExpression *imgRe = [NSRegularExpression regularExpressionWithPattern:
        @"^\\s*(0x[0-9a-fA-F]+)\\s*-\\s*(0x[0-9a-fA-F]+)\\s+\\+?([^\\s]+)\\s+([a-zA-Z0-9_]+)\\s+(?:<[^>]+>\\s+)?(/.*)$"
        options:0 error:NULL];
    NSRegularExpression *frameRe = [NSRegularExpression regularExpressionWithPattern:
        @"^\\s*(\\d+)\\s+([^\\s]+)\\s+(0x[0-9a-fA-F]+)\\s+(0x[0-9a-fA-F]+)\\s*\\+\\s*(\\d+)"
        options:0 error:NULL];

    BOOL inBinaryImages = NO;
    for (NSString *line in lines) {
        if ([line hasPrefix:@"Binary Images:"]) {
            inBinaryImages = YES;
            continue;
        }
        if (inBinaryImages) {
            NSTextCheckingResult *m = [imgRe firstMatchInString:line options:0 range:NSMakeRange(0, line.length)];
            if (m && m.numberOfRanges >= 6) {
                NSString *baseHex = [line substringWithRange:[m rangeAtIndex:1]];
                NSString *name = [line substringWithRange:[m rangeAtIndex:3]];
                NSString *arch = [line substringWithRange:[m rangeAtIndex:4]];
                NSString *path = [[line substringWithRange:[m rangeAtIndex:5]] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
                uint64_t base = strtoull(baseHex.UTF8String, NULL, 16);
                imagesByName[name] = @{@"base": @(base), @"arch": arch, @"path": path, @"name": name};
            }
        } else if (rawFrames.count < maxFrames) {
            NSTextCheckingResult *fm = [frameRe firstMatchInString:line options:0 range:NSMakeRange(0, line.length)];
            if (fm && fm.numberOfRanges >= 6) {
                NSUInteger idx = (NSUInteger)[[line substringWithRange:[fm rangeAtIndex:1]] integerValue];
                NSString *imgName = [line substringWithRange:[fm rangeAtIndex:2]];
                uint64_t pc = strtoull([line substringWithRange:[fm rangeAtIndex:3]].UTF8String, NULL, 16);
                uint64_t base = strtoull([line substringWithRange:[fm rangeAtIndex:4]].UTF8String, NULL, 16);
                uint64_t off = strtoull([line substringWithRange:[fm rangeAtIndex:5]].UTF8String, NULL, 10);
                [rawFrames addObject:@{
                    @"index": @(idx),
                    @"image_name": imgName,
                    @"pc": @(pc),
                    @"base": @(base),
                    @"offset": @(off)
                }];
            }
        }
    }

    if (!rawFrames.count && !imagesByName.count) {
        if (error) *error = @"Unrecognized crash report format (expected .ips JSON or Apple .crash text)";
        return nil;
    }

    NSMutableDictionary<NSString *, NSMutableSet<NSNumber *> *> *offsByImg = [NSMutableDictionary dictionary];
    for (NSDictionary *rf in rawFrames) {
        NSString *name = rf[@"image_name"];
        if (!imagesByName[name]) continue;
        NSMutableSet *s = offsByImg[name];
        if (!s) { s = [NSMutableSet set]; offsByImg[name] = s; }
        [s addObject:rf[@"offset"]];
    }

    NSMutableDictionary<NSString *, NSDictionary<NSNumber *, NSDictionary *> *> *symByImg = [NSMutableDictionary dictionary];
    for (NSString *name in offsByImg) {
        NSDictionary *img = imagesByName[name];
        symByImg[name] = [self symbolicateImagePath:img[@"path"] arch:img[@"arch"] offsets:offsByImg[name].allObjects];
    }

    NSUInteger symCount = 0;
    NSMutableArray<NSDictionary *> *outFrames = [NSMutableArray arrayWithCapacity:rawFrames.count];
    for (NSDictionary *rf in rawFrames) {
        NSString *name = rf[@"image_name"];
        uint64_t pc = [rf[@"pc"] unsignedLongLongValue];
        uint64_t base = [rf[@"base"] unsignedLongLongValue];
        uint64_t off = [rf[@"offset"] unsignedLongLongValue];
        NSDictionary *hit = symByImg[name][@(off)];
        NSString *sym = hit[@"symbol"] ?: @"";
        uint64_t symOff = [hit[@"symbol_offset"] unsignedLongLongValue];
        NSString *src = hit[@"source"] ?: @"unsymbolicated";
        if (sym.length > 0) symCount++;
        NSString *formatted = sym.length > 0
            ? [NSString stringWithFormat:@"%@  %@  0x%llx %@ + %llu", rf[@"index"], name, (unsigned long long)pc, sym, (unsigned long long)symOff]
            : [NSString stringWithFormat:@"%@  %@  0x%llx 0x%llx + %llu", rf[@"index"], name, (unsigned long long)pc, (unsigned long long)base, (unsigned long long)off];
        [outFrames addObject:@{
            @"index": rf[@"index"],
            @"image_name": name,
            @"image_path": imagesByName[name][@"path"] ?: @"",
            @"image_base": [NSString stringWithFormat:@"0x%llx", (unsigned long long)base],
            @"image_offset": @(off),
            @"address": [NSString stringWithFormat:@"0x%llx", (unsigned long long)pc],
            @"symbol": sym,
            @"symbol_offset": @(symOff),
            @"source": src,
            @"formatted": formatted
        }];
    }

    return @{
        @"log_path": logPath,
        @"resolved_path": resolvedPath,
        @"format": @"legacy_crash_text",
        @"total_frames_processed": @(outFrames.count),
        @"symbolicated_frame_count": @(symCount),
        @"used_image_count": @(imagesByName.count),
        @"threads": @[@{
            @"thread_index": @0,
            @"triggered": @YES,
            @"frame_count": @(outFrames.count),
            @"frames": outFrames
        }]
    };
}

- (NSDictionary *)symbolicateCrashAtPath:(NSString *)logPath
                              allThreads:(BOOL)allThreads
                               maxFrames:(NSUInteger)maxFrames
                                   error:(NSString **)error {
    if (error) *error = nil;
    if (![logPath isKindOfClass:[NSString class]] || !logPath.length) {
        if (error) *error = @"log_path is required";
        return nil;
    }
    if (maxFrames == 0) maxFrames = 64;
    if (maxFrames > 256) maxFrames = 256;

    NSString *resolvedPath = nil;
    NSData *data = [self readCrashDataAtPath:logPath resolvedPath:&resolvedPath error:error];
    if (!data) return nil;

    NSString *text = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (!text.length) {
        if (error) *error = @"Crash report is empty or not valid UTF-8";
        return nil;
    }

    // Try single JSON object first
    id singleObj = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
    if ([singleObj isKindOfClass:[NSDictionary class]] && singleObj[@"threads"]) {
        return [self symbolicateIPSHeader:@{}
                                     body:singleObj
                                  logPath:logPath
                             resolvedPath:resolvedPath
                               allThreads:allThreads
                                maxFrames:maxFrames];
    }

    // Try iOS 15-18 .ips v2 two-JSON-object format (line 1 header JSON + remaining payload JSON)
    NSRange nl = [text rangeOfString:@"\n"];
    if (nl.location != NSNotFound && nl.location + 1 < text.length) {
        NSString *firstLine = [text substringToIndex:nl.location];
        NSString *rest = [text substringFromIndex:nl.location + 1];
        NSData *d1 = [firstLine dataUsingEncoding:NSUTF8StringEncoding];
        NSData *d2 = [rest dataUsingEncoding:NSUTF8StringEncoding];
        NSDictionary *meta = d1 ? [NSJSONSerialization JSONObjectWithData:d1 options:0 error:NULL] : nil;
        NSDictionary *body = d2 ? [NSJSONSerialization JSONObjectWithData:d2 options:0 error:NULL] : nil;
        if ([meta isKindOfClass:[NSDictionary class]] && [body isKindOfClass:[NSDictionary class]] && body[@"threads"]) {
            return [self symbolicateIPSHeader:meta
                                         body:body
                                      logPath:logPath
                                 resolvedPath:resolvedPath
                                   allThreads:allThreads
                                    maxFrames:maxFrames];
        }
    }

    return [self symbolicateLegacyText:text
                               logPath:logPath
                          resolvedPath:resolvedPath
                             maxFrames:maxFrames
                                 error:error];
}

@end
