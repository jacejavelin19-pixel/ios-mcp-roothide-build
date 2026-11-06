#import <Foundation/Foundation.h>
#import "../MCPMachOUtil.h"
#ifdef MCP_ROOTHIDE
#include <roothide.h>
#endif
#import <errno.h>
#import <fcntl.h>
#import <poll.h>
#import <spawn.h>
#import <string.h>
#import <sys/socket.h>
#import <sys/stat.h>
#import <sys/un.h>
#import <sys/wait.h>
#import <unistd.h>

extern char **environ;

static void MCPAMEmitJSON(NSDictionary *payload) {
    NSData *data = [NSJSONSerialization dataWithJSONObject:payload options:0 error:NULL];
    if (data.length > 0) {
        fwrite(data.bytes, 1, data.length, stdout);
        fputc('\n', stdout);
        fflush(stdout);
    }
}

static int MCPAMFail(NSString *message) {
    MCPAMEmitJSON(@{@"ok": @NO, @"error": message ?: @"appmod operation failed"});
    return 1;
}

static BOOL MCPAMPathExists(NSString *path) {
    if (!path.length) return NO;
    struct stat st;
    return lstat(path.fileSystemRepresentation, &st) == 0;
}

static BOOL MCPAMIsExecutable(NSString *path) {
    if (!path.length) return NO;
    struct stat st;
    if (stat(path.fileSystemRepresentation, &st) != 0) return NO;
    return S_ISREG(st.st_mode) && ((st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0);
}

static NSString *MCPAMResolveJBTool(NSString *logicalPath) {
    if (!logicalPath.length) return @"";
#ifdef MCP_ROOTHIDE
    if ([logicalPath rangeOfString:@"/.jbroot-"].location != NSNotFound) {
        if (MCPAMIsExecutable(logicalPath)) return logicalPath;
    }
    NSString *jb = jbroot(logicalPath);
    if (MCPAMIsExecutable(jb)) return jb;
#endif
    if (MCPAMIsExecutable(logicalPath)) return logicalPath;
    NSString *rootless = [@"/var/jb" stringByAppendingString:logicalPath];
    if (MCPAMIsExecutable(rootless)) return rootless;
    return logicalPath;
}

static NSString *MCPAMResolveExistingPath(NSString *path) {
    if (!path.length) return @"";
    if (MCPAMPathExists(path)) return path;
#ifdef MCP_ROOTHIDE
    if ([path rangeOfString:@"/.jbroot-"].location == NSNotFound) {
        NSString *jb = jbroot(path);
        if (MCPAMPathExists(jb)) return jb;
    }
    NSString *rf = rootfs(path);
    if (MCPAMPathExists(rf)) return rf;
#endif
    return path;
}

static NSString *MCPAMResolveOutputPath(NSString *path) {
    if (!path.length) return @"";
    if (MCPAMPathExists(path)) return path;
    NSString *parent = [path stringByDeletingLastPathComponent];
    if (parent.length > 0 && MCPAMPathExists(parent)) return path;
#ifdef MCP_ROOTHIDE
    if ([path rangeOfString:@"/.jbroot-"].location == NSNotFound &&
        ![path hasPrefix:@"/var/mobile/"] && ![path hasPrefix:@"/private/var/mobile/"] &&
        ![path hasPrefix:@"/var/containers/"] && ![path hasPrefix:@"/private/var/containers/"]) {
        NSString *jb = jbroot(path);
        NSString *jbParent = [jb stringByDeletingLastPathComponent];
        if (jbParent.length > 0 && MCPAMPathExists(jbParent)) return jb;
    }
#endif
    return path;
}

static BOOL MCPAMIsProtectedTarget(NSString *path, NSString **error) {
    if (!path.length) {
        if (error) *error = @"empty target path";
        return YES;
    }
    NSString *norm = [path stringByStandardizingPath] ?: path;
    if ([norm containsString:@"/SpringBoard.app/"] ||
        [norm hasSuffix:@"/SpringBoard"] ||
        [norm hasPrefix:@"/System/"] ||
        [norm hasPrefix:@"/usr/sbin/"] ||
        [norm isEqualToString:@"/var/mobile/Library/ios-mcp/frida/gadget.dylib"] ||
        [norm isEqualToString:@"/private/var/mobile/Library/ios-mcp/frida/gadget.dylib"] ||
        [norm isEqualToString:@"/var/mobile/Library/ios-mcp/frida/gadget.dylib.xz"] ||
        [norm isEqualToString:@"/private/var/mobile/Library/ios-mcp/frida/gadget.dylib.xz"]) {
        if (error) *error = [NSString stringWithFormat:@"refusing to modify protected target: %@", path];
        return YES;
    }
    return NO;
}

static NSString *MCPAMCreateWorkDir(NSString **error) {
    NSString *base = @"/var/mobile/Library/Caches/ios-mcp-appmod";
    NSFileManager *fm = [NSFileManager defaultManager];
    NSError *err = nil;
    if (![fm createDirectoryAtPath:base withIntermediateDirectories:YES attributes:nil error:&err]) {
        base = @"/var/tmp/ios-mcp-appmod";
        [fm createDirectoryAtPath:base withIntermediateDirectories:YES attributes:nil error:nil];
    }
    chmod(base.fileSystemRepresentation, 0755);
    NSString *work = [base stringByAppendingPathComponent:
                      [NSString stringWithFormat:@"work-%d-%@", getpid(), [NSUUID UUID].UUIDString]];
    if (![fm createDirectoryAtPath:work withIntermediateDirectories:YES attributes:nil error:&err]) {
        if (error) *error = err.localizedDescription ?: @"failed to create work directory";
        return nil;
    }
    chmod(work.fileSystemRepresentation, 0755);
    return work;
}

static BOOL MCPAMRunCommandInDir(NSString *exePath,
                                 NSArray<NSString *> *args,
                                 NSString *workingDir,
                                 int *outExitCode,
                                 NSData **outStdout,
                                 NSString **outStderr,
                                 NSString **error) {
    if (!MCPAMIsExecutable(exePath)) {
        if (error) *error = [NSString stringWithFormat:@"helper not executable: %@", exePath];
        return NO;
    }

    int outPipe[2] = {-1, -1};
    int errPipe[2] = {-1, -1};
    if (pipe(outPipe) != 0 || pipe(errPipe) != 0) {
        if (outPipe[0] >= 0) { close(outPipe[0]); close(outPipe[1]); }
        if (errPipe[0] >= 0) { close(errPipe[0]); close(errPipe[1]); }
        if (error) *error = @"pipe() failed";
        return NO;
    }

    NSString *prevCwd = [[NSFileManager defaultManager] currentDirectoryPath];
    if (workingDir.length > 0) {
        chdir(workingDir.fileSystemRepresentation);
    }

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, outPipe[1], STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions, errPipe[1], STDERR_FILENO);
    posix_spawn_file_actions_addclose(&actions, outPipe[0]);
    posix_spawn_file_actions_addclose(&actions, outPipe[1]);
    posix_spawn_file_actions_addclose(&actions, errPipe[0]);
    posix_spawn_file_actions_addclose(&actions, errPipe[1]);

    NSMutableArray<NSString *> *argvObj = [NSMutableArray arrayWithObject:exePath];
    if (args.count > 0) [argvObj addObjectsFromArray:args];
    char **argv = calloc(argvObj.count + 1, sizeof(char *));
    for (NSUInteger i = 0; i < argvObj.count; i++) {
        argv[i] = strdup(argvObj[i].UTF8String ?: "");
    }
    argv[argvObj.count] = NULL;

    pid_t pid = 0;
    int rc = posix_spawn(&pid, exePath.fileSystemRepresentation, &actions, NULL, argv, environ);

    if (prevCwd.length > 0 && workingDir.length > 0) {
        chdir(prevCwd.fileSystemRepresentation);
    }

    posix_spawn_file_actions_destroy(&actions);
    for (NSUInteger i = 0; i < argvObj.count; i++) free(argv[i]);
    free(argv);

    close(outPipe[1]);
    close(errPipe[1]);

    if (rc != 0) {
        close(outPipe[0]);
        close(errPipe[0]);
        if (error) *error = [NSString stringWithFormat:@"posix_spawn(%@) failed: %s", exePath, strerror(rc)];
        return NO;
    }

    NSMutableData *stdoutBuf = [NSMutableData data];
    NSMutableData *stderrBuf = [NSMutableData data];
    uint8_t chunk[8192];
    ssize_t n = 0;
    while ((n = read(outPipe[0], chunk, sizeof(chunk))) > 0) {
        [stdoutBuf appendBytes:chunk length:(NSUInteger)n];
    }
    while ((n = read(errPipe[0], chunk, sizeof(chunk))) > 0) {
        [stderrBuf appendBytes:chunk length:(NSUInteger)n];
    }
    close(outPipe[0]);
    close(errPipe[0]);

    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    int code = WIFEXITED(status) ? WEXITSTATUS(status) : (WIFSIGNALED(status) ? (128 + WTERMSIG(status)) : -1);
    if (outExitCode) *outExitCode = code;
    if (outStdout) *outStdout = stdoutBuf;
    if (outStderr) *outStderr = [[NSString alloc] initWithData:stderrBuf encoding:NSUTF8StringEncoding] ?: @"";
    return YES;
}

static BOOL MCPAMWriteFreshVnode(NSData *data,
                                 NSString *destPath,
                                 mode_t mode,
                                 uid_t uid,
                                 gid_t gid,
                                 BOOL applyOwner,
                                 NSString **error) {
    if (!data || !destPath.length) {
        if (error) *error = @"invalid data or destination path";
        return NO;
    }
    NSString *dir = [destPath stringByDeletingLastPathComponent];
    if (dir.length > 0) {
        [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    }
    NSString *tmpPath = [dir stringByAppendingPathComponent:
                         [NSString stringWithFormat:@".mcp_vnode_%d_%@", getpid(), [NSUUID UUID].UUIDString]];
    const char *tmpFS = tmpPath.fileSystemRepresentation;
    const char *dstFS = destPath.fileSystemRepresentation;
    int fd = open(tmpFS, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0) {
        if (error) *error = [NSString stringWithFormat:@"open(%@) failed: %s", tmpPath, strerror(errno)];
        return NO;
    }
    const uint8_t *ptr = data.bytes;
    size_t rem = data.length;
    while (rem > 0) {
        ssize_t w = write(fd, ptr, rem);
        if (w < 0) {
            if (errno == EINTR) continue;
            int e = errno;
            close(fd);
            unlink(tmpFS);
            if (error) *error = [NSString stringWithFormat:@"write(%@) failed: %s", tmpPath, strerror(e)];
            return NO;
        }
        ptr += (size_t)w;
        rem -= (size_t)w;
    }
    fchmod(fd, mode);
    if (applyOwner) {
        fchown(fd, uid, gid);
    }
    fsync(fd);
    close(fd);

    unlink(dstFS);
    if (rename(tmpFS, dstFS) != 0) {
        int e = errno;
        unlink(tmpFS);
        if (error) *error = [NSString stringWithFormat:@"rename(%@ -> %@) failed: %s", tmpPath, destPath, strerror(e)];
        return NO;
    }
    chmod(dstFS, mode);
    if (applyOwner) {
        chown(dstFS, uid, gid);
    }
    return YES;
}

// After (re)signing, the binary's cdhash changed, so the kernel (RootHide pmap_cs)
// no longer trusts it and will SIGKILL it at launch. Register the new cdhash in the
// jailbreak trust cache via jbctl. The cdhash is content-derived, so registering the
// staged copy here covers the identical bytes once they are moved into place.
// mcp-appmod runs as root (via mcp-root), which jbctl trustcache add requires.
static void MCPAMRegisterTrust(NSString *workDir, NSString *stageFileName) {
    NSString *jbctlPath = MCPAMResolveJBTool(@"/usr/bin/jbctl");
    if (!MCPAMIsExecutable(jbctlPath)) {
        jbctlPath = MCPAMResolveJBTool(@"/basebin/jbctl");
    }
    if (!MCPAMIsExecutable(jbctlPath)) {
        fprintf(stderr, "mcp-appmod: jbctl not found; cannot register trust for %s\n", stageFileName.UTF8String ?: "");
        return;
    }
    NSString *stagePath = [workDir stringByAppendingPathComponent:stageFileName];
    int code = -1;
    NSData *out = nil;
    NSString *errText = nil;
    NSString *runErr = nil;
    if (!MCPAMRunCommandInDir(jbctlPath, @[@"trustcache", @"add", stagePath], nil, &code, &out, &errText, &runErr) || code != 0) {
        fprintf(stderr, "mcp-appmod: jbctl trustcache add failed (code=%d) for %s: %s %s\n",
                code, stagePath.UTF8String ?: "", (errText ?: @"").UTF8String, (runErr ?: @"").UTF8String);
    }
}

static BOOL MCPAMSignStageBinary(NSString *workDir,
                                 NSString *stageFileName,
                                 NSDictionary * _Nullable entitlements,
                                 NSString **error) {
    NSString *ldidPath = MCPAMResolveJBTool(@"/usr/bin/mcp-ldid");
    if (!MCPAMIsExecutable(ldidPath)) {
        ldidPath = MCPAMResolveJBTool(@"/usr/bin/ldid");
    }
    if (!MCPAMIsExecutable(ldidPath)) {
        if (error) *error = @"neither mcp-ldid nor ldid is executable";
        return NO;
    }

    NSString *signFlag = @"-S";
    if (entitlements && entitlements.count > 0) {
        NSError *plistErr = nil;
        NSData *entData = [NSPropertyListSerialization dataWithPropertyList:entitlements
                                                                     format:NSPropertyListXMLFormat_v1_0
                                                                    options:0
                                                                      error:&plistErr];
        if (!entData) {
            if (error) *error = plistErr.localizedDescription ?: @"failed to serialize entitlements XML";
            return NO;
        }
        NSString *entFile = [workDir stringByAppendingPathComponent:@"ent.plist"];
        if (![entData writeToFile:entFile options:NSDataWritingAtomic error:&plistErr]) {
            if (error) *error = plistErr.localizedDescription ?: @"failed to write ent.plist";
            return NO;
        }
        signFlag = @"-Sent.plist";
    }

    int exitCode = -1;
    NSData *outData = nil;
    NSString *errText = nil;
    if (!MCPAMRunCommandInDir(ldidPath, @[signFlag, stageFileName], workDir, &exitCode, &outData, &errText, error)) {
        return NO;
    }
    if (exitCode != 0) {
        NSString *fallbackLdid = MCPAMResolveJBTool(@"/usr/bin/ldid");
        if (MCPAMIsExecutable(fallbackLdid) && ![fallbackLdid isEqualToString:ldidPath]) {
            if (MCPAMRunCommandInDir(fallbackLdid, @[signFlag, stageFileName], workDir, &exitCode, &outData, &errText, error) && exitCode == 0) {
                MCPAMRegisterTrust(workDir, stageFileName);
                return YES;
            }
        }
        if (error) *error = [NSString stringWithFormat:@"ldid exited %d: %@", exitCode, errText ?: @""];
        return NO;
    }
    MCPAMRegisterTrust(workDir, stageFileName);
    return YES;
}

static NSDictionary *MCPAMExtractExistingEntitlements(NSString *binaryPath) {
    NSString *err = nil;
    NSDictionary *extracted = MCPExtractEntitlementsFromMachO(binaryPath, &err);
    if ([extracted[@"entitlements"] isKindOfClass:[NSDictionary class]]) {
        return extracted[@"entitlements"];
    }
    NSString *ldidPath = MCPAMResolveJBTool(@"/usr/bin/mcp-ldid");
    if (MCPAMIsExecutable(ldidPath)) {
        int code = -1;
        NSData *xmlData = nil;
        NSString *stderrText = nil;
        if (MCPAMRunCommandInDir(ldidPath, @[@"-e", binaryPath], nil, &code, &xmlData, &stderrText, nil) &&
            code == 0 && xmlData.length > 0) {
            id plist = [NSPropertyListSerialization propertyListWithData:xmlData options:0 format:NULL error:NULL];
            if ([plist isKindOfClass:[NSDictionary class]]) {
                return plist;
            }
        }
    }
    return @{};
}

static BOOL MCPAMEnsureOrigBackup(NSString *binaryPath, mode_t mode, uid_t uid, gid_t gid, BOOL hasStat, NSString **error) {
    NSString *origPath = [binaryPath stringByAppendingString:@".mcp_orig"];
    if (MCPAMPathExists(origPath)) return YES;
    NSData *origBytes = [NSData dataWithContentsOfFile:binaryPath];
    if (!origBytes.length) {
        if (error) *error = [NSString stringWithFormat:@"cannot read binary for backup: %@", binaryPath];
        return NO;
    }
    return MCPAMWriteFreshVnode(origBytes, origPath, mode, uid, gid, hasStat, error);
}

static NSString *MCPAMNormalizeUnixSocketPath(NSString *socketPath) {
    if ([socketPath hasPrefix:@"/private/var/"]) {
        return [socketPath substringFromIndex:8]; // "/var/..."
    }
    return socketPath;
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc < 2) {
            return MCPAMFail(@"usage: mcp-appmod <subcommand> ...");
        }
        NSString *cmd = [NSString stringWithUTF8String:argv[1]];

        if ([cmd isEqualToString:@"read-plist"] || [cmd isEqualToString:@"read-file"]) {
            if (argc < 3) return 2;
            NSString *path = MCPAMResolveExistingPath([NSString stringWithUTF8String:argv[2]]);
            NSUInteger maxBytes = 0;
            if (argc >= 4) {
                unsigned long long parsed = strtoull(argv[3], NULL, 10);
                if (parsed > 0) maxBytes = (NSUInteger)parsed;
            }
            int fd = open(path.fileSystemRepresentation, O_RDONLY | O_CLOEXEC);
            if (fd < 0) {
                fprintf(stderr, "open(%s) failed: %s\n", path.UTF8String ?: "", strerror(errno));
                return 1;
            }
            uint8_t buf[32768];
            NSUInteger total = 0;
            while (1) {
                size_t want = sizeof(buf);
                if (maxBytes > 0 && total + want > maxBytes) {
                    want = maxBytes - total;
                    if (want == 0) break;
                }
                ssize_t n = read(fd, buf, want);
                if (n < 0 && errno == EINTR) continue;
                if (n <= 0) break;
                fwrite(buf, 1, (size_t)n, stdout);
                total += (NSUInteger)n;
            }
            fflush(stdout);
            close(fd);
            return 0;
        }

        if ([cmd isEqualToString:@"write-plist"]) {
            if (argc < 4) return MCPAMFail(@"usage: mcp-appmod write-plist <dest> <src_tmp>");
            NSString *dest = MCPAMResolveOutputPath([NSString stringWithUTF8String:argv[2]]);
            NSString *src = MCPAMResolveExistingPath([NSString stringWithUTF8String:argv[3]]);
            NSData *data = [NSData dataWithContentsOfFile:src];
            if (!data) return MCPAMFail(@"cannot read temporary plist data");
            struct stat st;
            BOOL hasStat = (stat(dest.fileSystemRepresentation, &st) == 0);
            mode_t mode = hasStat ? (st.st_mode & 07777) : 0644;
            uid_t uid = 0; gid_t gid = 0;
            if (hasStat) {
                uid = st.st_uid; gid = st.st_gid;
            } else {
                struct stat pst;
                if (stat([dest stringByDeletingLastPathComponent].fileSystemRepresentation, &pst) == 0) {
                    uid = pst.st_uid; gid = pst.st_gid; hasStat = YES;
                }
            }
            NSString *err = nil;
            if (!MCPAMWriteFreshVnode(data, dest, mode, uid, gid, hasStat, &err)) {
                return MCPAMFail(err);
            }
            MCPAMEmitJSON(@{@"ok": @YES, @"result": @{@"path": dest, @"bytes_written": @(data.length)}});
            return 0;
        }

        if ([cmd isEqualToString:@"write-file"]) {
            if (argc < 4) return MCPAMFail(@"usage: mcp-appmod write-file <dest> <src_tmp> [mode_octal]");
            NSString *dest = MCPAMResolveOutputPath([NSString stringWithUTF8String:argv[2]]);
            NSString *protErr = nil;
            if (MCPAMIsProtectedTarget(dest, &protErr)) return MCPAMFail(protErr);
            NSString *src = MCPAMResolveExistingPath([NSString stringWithUTF8String:argv[3]]);
            NSData *data = [NSData dataWithContentsOfFile:src];
            if (!data) return MCPAMFail(@"cannot read source file");
            struct stat st;
            BOOL hasStat = (stat(dest.fileSystemRepresentation, &st) == 0);
            mode_t mode = hasStat ? (st.st_mode & 07777) : 0644;
            if (argc >= 5) {
                unsigned long parsed = strtoul(argv[4], NULL, 8);
                if (parsed > 0 && parsed <= 07777) mode = (mode_t)parsed;
            }
            uid_t uid = 0; gid_t gid = 0;
            if (hasStat) {
                uid = st.st_uid; gid = st.st_gid;
            } else {
                struct stat pst;
                if (stat([dest stringByDeletingLastPathComponent].fileSystemRepresentation, &pst) == 0) {
                    uid = pst.st_uid; gid = pst.st_gid; hasStat = YES;
                }
            }
            NSString *err = nil;
            if (!MCPAMWriteFreshVnode(data, dest, mode, uid, gid, hasStat, &err)) {
                return MCPAMFail(err);
            }
            MCPAMEmitJSON(@{@"ok": @YES, @"result": @{@"path": dest, @"bytes_written": @(data.length)}});
            return 0;
        }

        if ([cmd isEqualToString:@"delete-file"]) {
            if (argc < 3) return MCPAMFail(@"usage: mcp-appmod delete-file <path>");
            NSString *target = MCPAMResolveExistingPath([NSString stringWithUTF8String:argv[2]]);
            NSString *protErr = nil;
            if (MCPAMIsProtectedTarget(target, &protErr)) return MCPAMFail(protErr);
            BOOL existed = MCPAMPathExists(target);
            if (existed && unlink(target.fileSystemRepresentation) != 0 && errno != ENOENT) {
                return MCPAMFail([NSString stringWithFormat:@"unlink(%@) failed: %s", target, strerror(errno)]);
            }
            MCPAMEmitJSON(@{@"ok": @YES, @"result": @{@"path": target, @"deleted": @(existed)}});
            return 0;
        }

        if ([cmd isEqualToString:@"inspect-macho"]) {
            if (argc < 3) return MCPAMFail(@"usage: mcp-appmod inspect-macho <path>");
            NSString *path = MCPAMResolveExistingPath([NSString stringWithUTF8String:argv[2]]);
            NSString *err = nil;
            NSDictionary *info = MCPInspectMachOAtPath(path, &err);
            if (!info) return MCPAMFail(err);
            MCPAMEmitJSON(@{@"ok": @YES, @"result": info});
            return 0;
        }

        if ([cmd isEqualToString:@"symbolicate-macho"]) {
            if (argc < 5) return MCPAMFail(@"usage: mcp-appmod symbolicate-macho <path> <arch> <offsets_csv>");
            NSString *path = MCPAMResolveExistingPath([NSString stringWithUTF8String:argv[2]]);
            NSString *arch = [NSString stringWithUTF8String:argv[3]];
            if ([arch isEqualToString:@"-"]) arch = nil;
            NSString *csv = [NSString stringWithUTF8String:argv[4]];
            NSMutableArray<NSNumber *> *offsets = [NSMutableArray array];
            for (NSString *part in [csv componentsSeparatedByString:@","]) {
                if (!part.length) continue;
                unsigned long long val = strtoull(part.UTF8String, NULL, 0);
                [offsets addObject:@(val)];
            }
            NSString *err = nil;
            NSDictionary<NSNumber *, NSDictionary *> *symMap = MCPSymbolicateOffsetsInMachO(path, arch, offsets, &err);
            if (!symMap) return MCPAMFail(err);
            NSMutableDictionary *jsonMap = [NSMutableDictionary dictionaryWithCapacity:symMap.count];
            for (NSNumber *num in symMap) {
                jsonMap[[NSString stringWithFormat:@"%llu", num.unsignedLongLongValue]] = symMap[num];
            }
            MCPAMEmitJSON(@{@"ok": @YES, @"result": jsonMap});
            return 0;
        }

        if ([cmd isEqualToString:@"dump-entitlements"]) {
            if (argc < 3) return MCPAMFail(@"usage: mcp-appmod dump-entitlements <binary_path>");
            NSString *path = MCPAMResolveExistingPath([NSString stringWithUTF8String:argv[2]]);
            NSString *err = nil;
            NSDictionary *res = MCPExtractEntitlementsFromMachO(path, &err);
            if (!res) {
                NSDictionary *fallback = MCPAMExtractExistingEntitlements(path);
                if (fallback) {
                    NSData *xmlData = [NSPropertyListSerialization dataWithPropertyList:fallback
                                                                                 format:NSPropertyListXMLFormat_v1_0
                                                                                options:0
                                                                                  error:NULL];
                    NSString *xml = xmlData ? ([[NSString alloc] initWithData:xmlData encoding:NSUTF8StringEncoding] ?: @"") : @"";
                    MCPAMEmitJSON(@{
                        @"ok": @YES,
                        @"result": @{
                            @"binary_path": path,
                            @"has_entitlements": @(fallback.count > 0),
                            @"entitlements": fallback,
                            @"xml": xml
                        }
                    });
                    return 0;
                }
                return MCPAMFail(err);
            }
            MCPAMEmitJSON(@{
                @"ok": @YES,
                @"result": @{
                    @"binary_path": path,
                    @"has_entitlements": res[@"has_entitlements"] ?: @NO,
                    @"entitlements": res[@"entitlements"] ?: @{},
                    @"xml": res[@"xml"] ?: @""
                }
            });
            return 0;
        }

        if ([cmd isEqualToString:@"patch-entitlements"]) {
            if (argc < 4) return MCPAMFail(@"usage: mcp-appmod patch-entitlements <binary_path> <patch_file>");
            NSString *binaryPath = MCPAMResolveExistingPath([NSString stringWithUTF8String:argv[2]]);
            NSString *protErr = nil;
            if (MCPAMIsProtectedTarget(binaryPath, &protErr)) return MCPAMFail(protErr);
            NSString *patchFile = MCPAMResolveExistingPath([NSString stringWithUTF8String:argv[3]]);
            NSData *patchData = [NSData dataWithContentsOfFile:patchFile];
            if (!patchData.length) return MCPAMFail(@"cannot read patch file");

            NSDictionary *patchDict = [NSJSONSerialization JSONObjectWithData:patchData options:0 error:NULL];
            if (![patchDict isKindOfClass:[NSDictionary class]]) {
                id plist = [NSPropertyListSerialization propertyListWithData:patchData options:0 format:NULL error:NULL];
                if ([plist isKindOfClass:[NSDictionary class]]) patchDict = plist;
            }
            if (![patchDict isKindOfClass:[NSDictionary class]]) {
                return MCPAMFail(@"entitlements patch must be a dictionary");
            }

            struct stat st;
            BOOL hasStat = (stat(binaryPath.fileSystemRepresentation, &st) == 0);
            if (!hasStat || !S_ISREG(st.st_mode)) return MCPAMFail(@"target binary does not exist");
            mode_t origMode = (st.st_mode & 07777) ?: 0755;

            NSDictionary *existing = MCPAMExtractExistingEntitlements(binaryPath) ?: @{};
            NSMutableDictionary *merged = [existing mutableCopy];
            NSMutableArray<NSString *> *updatedKeys = [NSMutableArray array];
            NSMutableArray<NSString *> *removedKeys = [NSMutableArray array];

            for (NSString *k in patchDict) {
                id v = patchDict[k];
                if (!v || v == [NSNull null]) {
                    [merged removeObjectForKey:k];
                    [removedKeys addObject:k];
                } else {
                    merged[k] = v;
                    [updatedKeys addObject:k];
                }
            }
            if (existing[@"jb.pmap_cs.custom_trust"] && !patchDict[@"jb.pmap_cs.custom_trust"]) {
                merged[@"jb.pmap_cs.custom_trust"] = existing[@"jb.pmap_cs.custom_trust"];
            }

            NSString *err = nil;
            if (!MCPAMEnsureOrigBackup(binaryPath, origMode, st.st_uid, st.st_gid, YES, &err)) {
                return MCPAMFail(err);
            }

            NSString *workDir = MCPAMCreateWorkDir(&err);
            if (!workDir) return MCPAMFail(err);
            @try {
                NSString *stageBin = [workDir stringByAppendingPathComponent:@"stage.bin"];
                NSData *origBytes = [NSData dataWithContentsOfFile:binaryPath];
                if (![origBytes writeToFile:stageBin options:NSDataWritingAtomic error:nil]) {
                    return MCPAMFail(@"failed to stage binary in workDir");
                }
                chmod(stageBin.fileSystemRepresentation, 0755);

                if (!MCPAMSignStageBinary(workDir, @"stage.bin", merged, &err)) {
                    return MCPAMFail(err);
                }

                NSData *signedBytes = [NSData dataWithContentsOfFile:stageBin];
                if (!signedBytes.length) return MCPAMFail(@"signed binary is empty");
                if (!MCPAMWriteFreshVnode(signedBytes, binaryPath, origMode, st.st_uid, st.st_gid, YES, &err)) {
                    return MCPAMFail(err);
                }

                NSDictionary *verified = MCPAMExtractExistingEntitlements(binaryPath);
                MCPAMEmitJSON(@{
                    @"ok": @YES,
                    @"result": @{
                        @"binary_path": binaryPath,
                        @"updated_keys": updatedKeys,
                        @"removed_keys": removedKeys,
                        @"entitlements": verified ?: merged,
                        @"signed": @YES,
                        @"backup_path": [binaryPath stringByAppendingString:@".mcp_orig"]
                    }
                });
                return 0;
            } @finally {
                [[NSFileManager defaultManager] removeItemAtPath:workDir error:nil];
            }
        }

        if ([cmd isEqualToString:@"inject-dylib"]) {
            if (argc < 5) return MCPAMFail(@"usage: mcp-appmod inject-dylib <binary_path> <dylib_src> <frameworks_dest_name>");
            NSString *binaryPath = MCPAMResolveExistingPath([NSString stringWithUTF8String:argv[2]]);
            NSString *protErr = nil;
            if (MCPAMIsProtectedTarget(binaryPath, &protErr)) return MCPAMFail(protErr);
            NSString *dylibSrc = MCPAMResolveExistingPath([NSString stringWithUTF8String:argv[3]]);
            NSString *destName = [[NSString stringWithUTF8String:argv[4]] lastPathComponent];
            if (!destName.length) return MCPAMFail(@"invalid destination dylib name");
            if (!MCPAMPathExists(dylibSrc)) return MCPAMFail([NSString stringWithFormat:@"source dylib not found: %@", dylibSrc]);

            struct stat st;
            if (stat(binaryPath.fileSystemRepresentation, &st) != 0 || !S_ISREG(st.st_mode)) {
                return MCPAMFail(@"target binary does not exist");
            }
            mode_t origMode = (st.st_mode & 07777) ?: 0755;

            NSString *appDir = [binaryPath stringByDeletingLastPathComponent];
            NSString *frameworksDir = [appDir stringByAppendingPathComponent:@"Frameworks"];
            [[NSFileManager defaultManager] createDirectoryAtPath:frameworksDir withIntermediateDirectories:YES attributes:nil error:nil];
            chmod(frameworksDir.fileSystemRepresentation, 0755);
            chown(frameworksDir.fileSystemRepresentation, st.st_uid, st.st_gid);

            NSString *err = nil;
            if (!MCPAMEnsureOrigBackup(binaryPath, origMode, st.st_uid, st.st_gid, YES, &err)) {
                return MCPAMFail(err);
            }

            NSDictionary *origEnt = MCPAMExtractExistingEntitlements(binaryPath);
            NSString *workDir = MCPAMCreateWorkDir(&err);
            if (!workDir) return MCPAMFail(err);

            @try {
                // 1. Stage & sign dylib
                NSString *stageDylib = [workDir stringByAppendingPathComponent:destName];
                NSData *dylibData = [NSData dataWithContentsOfFile:dylibSrc];
                if (!dylibData.length || ![dylibData writeToFile:stageDylib options:NSDataWritingAtomic error:nil]) {
                    return MCPAMFail(@"failed to stage source dylib");
                }
                chmod(stageDylib.fileSystemRepresentation, 0755);
                if (!MCPAMSignStageBinary(workDir, destName, nil, &err)) {
                    return MCPAMFail(err);
                }
                NSData *signedDylib = [NSData dataWithContentsOfFile:stageDylib];
                NSString *finalDylibPath = [frameworksDir stringByAppendingPathComponent:destName];
                if (!MCPAMWriteFreshVnode(signedDylib, finalDylibPath, 0755, st.st_uid, st.st_gid, YES, &err)) {
                    return MCPAMFail(err);
                }

                // 2. Stage main binary, inject LC_LOAD_DYLIB, and re-sign preserving entitlements
                NSString *stageMain = [workDir stringByAppendingPathComponent:@"main.bin"];
                NSData *mainData = [NSData dataWithContentsOfFile:binaryPath];
                if (!mainData.length || ![mainData writeToFile:stageMain options:NSDataWritingAtomic error:nil]) {
                    return MCPAMFail(@"failed to stage main binary");
                }
                NSString *installPath = [NSString stringWithFormat:@"@executable_path/Frameworks/%@", destName];
                NSDictionary *injRes = MCPInjectLoadDylibInMachO(stageMain, installPath, &err);
                if (!injRes) {
                    return MCPAMFail(err);
                }
                if (!MCPAMSignStageBinary(workDir, @"main.bin", origEnt, &err)) {
                    return MCPAMFail(err);
                }
                NSData *signedMain = [NSData dataWithContentsOfFile:stageMain];
                if (!MCPAMWriteFreshVnode(signedMain, binaryPath, origMode, st.st_uid, st.st_gid, YES, &err)) {
                    return MCPAMFail(err);
                }

                MCPAMEmitJSON(@{
                    @"ok": @YES,
                    @"result": @{
                        @"binary_path": binaryPath,
                        @"staged_dylib_path": finalDylibPath,
                        @"load_command_path": installPath,
                        @"macho": injRes,
                        @"signed": @YES,
                        @"backup_path": [binaryPath stringByAppendingString:@".mcp_orig"]
                    }
                });
                return 0;
            } @finally {
                [[NSFileManager defaultManager] removeItemAtPath:workDir error:nil];
            }
        }

        if ([cmd isEqualToString:@"remove-dylib"]) {
            if (argc < 3) return MCPAMFail(@"usage: mcp-appmod remove-dylib <binary_path> [dylib_match] [--restore-orig] [--delete-staged]");
            NSString *binaryPath = MCPAMResolveExistingPath([NSString stringWithUTF8String:argv[2]]);
            NSString *protErr = nil;
            if (MCPAMIsProtectedTarget(binaryPath, &protErr)) return MCPAMFail(protErr);

            NSString *dylibMatch = nil;
            BOOL restoreOrig = NO;
            BOOL deleteStaged = NO;
            for (int i = 3; i < argc; i++) {
                NSString *arg = [NSString stringWithUTF8String:argv[i]];
                if ([arg isEqualToString:@"--restore-orig"]) restoreOrig = YES;
                else if ([arg isEqualToString:@"--delete-staged"]) deleteStaged = YES;
                else if ([arg isEqualToString:@"-"]) continue;
                else if (!dylibMatch) dylibMatch = arg;
            }

            struct stat st;
            if (stat(binaryPath.fileSystemRepresentation, &st) != 0 || !S_ISREG(st.st_mode)) {
                return MCPAMFail(@"target binary does not exist");
            }
            mode_t origMode = (st.st_mode & 07777) ?: 0755;
            NSString *appDir = [binaryPath stringByDeletingLastPathComponent];
            NSString *frameworksDir = [appDir stringByAppendingPathComponent:@"Frameworks"];

            NSString *err = nil;
            NSMutableArray<NSString *> *deletedFiles = [NSMutableArray array];

            if (restoreOrig) {
                NSString *origPath = [binaryPath stringByAppendingString:@".mcp_orig"];
                if (!MCPAMPathExists(origPath)) {
                    return MCPAMFail(@"no .mcp_orig backup found to restore");
                }
                NSData *origData = [NSData dataWithContentsOfFile:origPath];
                if (!MCPAMWriteFreshVnode(origData, binaryPath, origMode, st.st_uid, st.st_gid, YES, &err)) {
                    return MCPAMFail(err);
                }
                unlink(origPath.fileSystemRepresentation);
                if (deleteStaged && dylibMatch.length > 0) {
                    NSString *cand = [frameworksDir stringByAppendingPathComponent:dylibMatch.lastPathComponent];
                    if (MCPAMPathExists(cand) && unlink(cand.fileSystemRepresentation) == 0) {
                        [deletedFiles addObject:cand];
                    }
                }
                MCPAMEmitJSON(@{
                    @"ok": @YES,
                    @"result": @{
                        @"binary_path": binaryPath,
                        @"restored_from_backup": @YES,
                        @"deleted_staged_files": deletedFiles
                    }
                });
                return 0;
            }

            NSDictionary *origEnt = MCPAMExtractExistingEntitlements(binaryPath);
            NSString *workDir = MCPAMCreateWorkDir(&err);
            if (!workDir) return MCPAMFail(err);
            @try {
                NSString *stageMain = [workDir stringByAppendingPathComponent:@"main.bin"];
                NSData *mainData = [NSData dataWithContentsOfFile:binaryPath];
                if (!mainData.length || ![mainData writeToFile:stageMain options:NSDataWritingAtomic error:nil]) {
                    return MCPAMFail(@"failed to stage main binary");
                }
                NSDictionary *remRes = MCPRemoveLoadDylibFromMachO(stageMain, dylibMatch, NO, &err);
                if (!remRes) return MCPAMFail(err);

                if (!MCPAMSignStageBinary(workDir, @"main.bin", origEnt, &err)) {
                    return MCPAMFail(err);
                }
                NSData *signedMain = [NSData dataWithContentsOfFile:stageMain];
                if (!MCPAMWriteFreshVnode(signedMain, binaryPath, origMode, st.st_uid, st.st_gid, YES, &err)) {
                    return MCPAMFail(err);
                }

                if (deleteStaged && dylibMatch.length > 0) {
                    NSString *cand = [frameworksDir stringByAppendingPathComponent:dylibMatch.lastPathComponent];
                    if (MCPAMPathExists(cand) && unlink(cand.fileSystemRepresentation) == 0) {
                        [deletedFiles addObject:cand];
                    }
                }

                MCPAMEmitJSON(@{
                    @"ok": @YES,
                    @"result": @{
                        @"binary_path": binaryPath,
                        @"macho": remRes,
                        @"deleted_staged_files": deletedFiles,
                        @"signed": @YES
                    }
                });
                return 0;
            } @finally {
                [[NSFileManager defaultManager] removeItemAtPath:workDir error:nil];
            }
        }

        if ([cmd isEqualToString:@"scrub-dylib"]) {
            if (argc < 5) return MCPAMFail(@"usage: mcp-appmod scrub-dylib <input_path> <output_path> <seed_uint64>");
            NSString *inputPath = MCPAMResolveExistingPath([NSString stringWithUTF8String:argv[2]]);
            NSString *outputPath = MCPAMResolveOutputPath([NSString stringWithUTF8String:argv[3]]);
            NSString *protErr = nil;
            if (MCPAMIsProtectedTarget(outputPath, &protErr)) return MCPAMFail(protErr);
            uint64_t seed = strtoull(argv[4], NULL, 0);

            NSString *err = nil;
            NSString *workDir = MCPAMCreateWorkDir(&err);
            if (!workDir) return MCPAMFail(err);
            @try {
                NSString *stageName = [outputPath.lastPathComponent length] ? outputPath.lastPathComponent : @"scrubbed.dylib";
                NSString *stageOut = [workDir stringByAppendingPathComponent:stageName];
                NSDictionary *scrubRes = MCPScrubMachOBinaryAtPath(inputPath, stageOut, seed, &err);
                if (!scrubRes) return MCPAMFail(err);

                if (!MCPAMSignStageBinary(workDir, stageName, nil, &err)) {
                    return MCPAMFail(err);
                }
                NSData *signedBytes = [NSData dataWithContentsOfFile:stageOut];
                uid_t uid = 501; gid_t gid = 501;
                struct stat pst;
                if (stat([outputPath stringByDeletingLastPathComponent].fileSystemRepresentation, &pst) == 0) {
                    uid = pst.st_uid; gid = pst.st_gid;
                }
                if (!MCPAMWriteFreshVnode(signedBytes, outputPath, 0755, uid, gid, YES, &err)) {
                    return MCPAMFail(err);
                }

                NSMutableDictionary *full = [scrubRes mutableCopy];
                full[@"output_path"] = outputPath;
                full[@"signed"] = @YES;
                full[@"output_size"] = @(signedBytes.length);
                MCPAMEmitJSON(@{@"ok": @YES, @"result": full});
                return 0;
            } @finally {
                [[NSFileManager defaultManager] removeItemAtPath:workDir error:nil];
            }
        }

        if ([cmd isEqualToString:@"stage-frida"]) {
            if (argc < 11) {
                return MCPAMFail(@"usage: mcp-appmod stage-frida <app_bundle> <main_exec> <stealth_src> <gadget_src> <cfg_src> <js_src> <stealth_name> <gadget_name> <seed>");
            }
            NSString *appBundle = MCPAMResolveExistingPath([NSString stringWithUTF8String:argv[2]]);
            NSString *mainExec = MCPAMResolveExistingPath([NSString stringWithUTF8String:argv[3]]);
            NSString *protErr = nil;
            if (MCPAMIsProtectedTarget(mainExec, &protErr)) return MCPAMFail(protErr);
            NSString *stealthSrc = MCPAMResolveExistingPath([NSString stringWithUTF8String:argv[4]]);
            NSString *gadgetSrc = MCPAMResolveExistingPath([NSString stringWithUTF8String:argv[5]]);
            NSString *cfgSrc = MCPAMResolveExistingPath([NSString stringWithUTF8String:argv[6]]);
            NSString *jsSrc = MCPAMResolveExistingPath([NSString stringWithUTF8String:argv[7]]);
            NSString *stealthName = [[NSString stringWithUTF8String:argv[8]] lastPathComponent];
            NSString *gadgetName = [[NSString stringWithUTF8String:argv[9]] lastPathComponent];
            uint64_t seed = strtoull(argv[10], NULL, 0);

            struct stat st;
            if (stat(mainExec.fileSystemRepresentation, &st) != 0 || !S_ISREG(st.st_mode)) {
                return MCPAMFail(@"main executable not found");
            }
            mode_t origMode = (st.st_mode & 07777) ?: 0755;

            NSString *frameworksDir = [appBundle stringByAppendingPathComponent:@"Frameworks"];
            [[NSFileManager defaultManager] createDirectoryAtPath:frameworksDir withIntermediateDirectories:YES attributes:nil error:nil];
            chmod(frameworksDir.fileSystemRepresentation, 0755);
            chown(frameworksDir.fileSystemRepresentation, st.st_uid, st.st_gid);

            NSString *err = nil;
            if (!MCPAMEnsureOrigBackup(mainExec, origMode, st.st_uid, st.st_gid, YES, &err)) {
                return MCPAMFail(err);
            }
            NSDictionary *origEnt = MCPAMExtractExistingEntitlements(mainExec);
            NSString *workDir = MCPAMCreateWorkDir(&err);
            if (!workDir) return MCPAMFail(err);

            @try {
                // 1. Stage + sign stealth companion dylib (loaded FIRST)
                NSString *stageStealth = [workDir stringByAppendingPathComponent:stealthName];
                NSData *stealthData = [NSData dataWithContentsOfFile:stealthSrc];
                if (!stealthData.length || ![stealthData writeToFile:stageStealth options:NSDataWritingAtomic error:nil]) {
                    return MCPAMFail(@"failed to read stealth dylib");
                }
                if (!MCPAMSignStageBinary(workDir, stealthName, nil, &err)) {
                    return MCPAMFail(err);
                }
                NSData *signedStealth = [NSData dataWithContentsOfFile:stageStealth];
                NSString *destStealth = [frameworksDir stringByAppendingPathComponent:stealthName];
                if (!MCPAMWriteFreshVnode(signedStealth, destStealth, 0755, st.st_uid, st.st_gid, YES, &err)) {
                    return MCPAMFail(err);
                }

                // 2. Scrub + sign Frida Gadget dylib (loaded SECOND)
                NSString *stageGadget = [workDir stringByAppendingPathComponent:gadgetName];
                NSDictionary *scrubInfo = MCPScrubMachOBinaryAtPath(gadgetSrc, stageGadget, seed, &err);
                if (!scrubInfo) return MCPAMFail(err);
                if (!MCPAMSignStageBinary(workDir, gadgetName, nil, &err)) {
                    return MCPAMFail(err);
                }
                NSData *signedGadget = [NSData dataWithContentsOfFile:stageGadget];
                NSString *destGadget = [frameworksDir stringByAppendingPathComponent:gadgetName];
                if (!MCPAMWriteFreshVnode(signedGadget, destGadget, 0755, st.st_uid, st.st_gid, YES, &err)) {
                    return MCPAMFail(err);
                }

                // 3. Stage <gadgetStem>.config and <gadgetStem>.js
                NSString *gadgetStem = [gadgetName stringByDeletingPathExtension];
                NSString *destCfg = [frameworksDir stringByAppendingPathComponent:[gadgetStem stringByAppendingString:@".config"]];
                NSString *destJS = [frameworksDir stringByAppendingPathComponent:[gadgetStem stringByAppendingString:@".js"]];
                NSData *cfgData = [NSData dataWithContentsOfFile:cfgSrc];
                NSData *jsData = [NSData dataWithContentsOfFile:jsSrc];
                if (!cfgData.length || !jsData.length) return MCPAMFail(@"missing config or boot script data");
                if (!MCPAMWriteFreshVnode(cfgData, destCfg, 0644, st.st_uid, st.st_gid, YES, &err) ||
                    !MCPAMWriteFreshVnode(jsData, destJS, 0644, st.st_uid, st.st_gid, YES, &err)) {
                    return MCPAMFail(err);
                }

                // 4. Inject LC_LOAD_DYLIB (stealth FIRST, gadget SECOND) & re-sign main executable
                NSString *stageMain = [workDir stringByAppendingPathComponent:@"main.bin"];
                NSData *mainData = [NSData dataWithContentsOfFile:mainExec];
                if (!mainData.length || ![mainData writeToFile:stageMain options:NSDataWritingAtomic error:nil]) {
                    return MCPAMFail(@"failed to stage main executable");
                }
                NSString *stealthLC = [NSString stringWithFormat:@"@executable_path/Frameworks/%@", stealthName];
                NSString *gadgetLC = [NSString stringWithFormat:@"@executable_path/Frameworks/%@", gadgetName];
                NSDictionary *inj1 = MCPInjectLoadDylibInMachO(stageMain, stealthLC, &err);
                if (!inj1) return MCPAMFail(err);
                NSDictionary *inj2 = MCPInjectLoadDylibInMachO(stageMain, gadgetLC, &err);
                if (!inj2) return MCPAMFail(err);

                if (!MCPAMSignStageBinary(workDir, @"main.bin", origEnt, &err)) {
                    return MCPAMFail(err);
                }
                NSData *signedMain = [NSData dataWithContentsOfFile:stageMain];
                if (!MCPAMWriteFreshVnode(signedMain, mainExec, origMode, st.st_uid, st.st_gid, YES, &err)) {
                    return MCPAMFail(err);
                }

                MCPAMEmitJSON(@{
                    @"ok": @YES,
                    @"result": @{
                        @"main_executable": mainExec,
                        @"stealth_dylib": destStealth,
                        @"gadget_dylib": destGadget,
                        @"gadget_config": destCfg,
                        @"gadget_script": destJS,
                        @"stealth_load_command": stealthLC,
                        @"gadget_load_command": gadgetLC,
                        @"load_order": @[stealthLC, gadgetLC],
                        @"scrub": scrubInfo,
                        @"signed": @YES
                    }
                });
                return 0;
            } @finally {
                [[NSFileManager defaultManager] removeItemAtPath:workDir error:nil];
            }
        }

        if ([cmd isEqualToString:@"unstage-frida"]) {
            if (argc < 6) {
                return MCPAMFail(@"usage: mcp-appmod unstage-frida <app_bundle> <main_exec> <stealth_name> <gadget_name>");
            }
            NSString *appBundle = MCPAMResolveExistingPath([NSString stringWithUTF8String:argv[2]]);
            NSString *mainExec = MCPAMResolveExistingPath([NSString stringWithUTF8String:argv[3]]);
            NSString *protErr = nil;
            if (MCPAMIsProtectedTarget(mainExec, &protErr)) return MCPAMFail(protErr);
            NSString *stealthName = [[NSString stringWithUTF8String:argv[4]] lastPathComponent];
            NSString *gadgetName = [[NSString stringWithUTF8String:argv[5]] lastPathComponent];

            struct stat st;
            if (stat(mainExec.fileSystemRepresentation, &st) != 0 || !S_ISREG(st.st_mode)) {
                return MCPAMFail(@"main executable not found");
            }
            mode_t origMode = (st.st_mode & 07777) ?: 0755;
            NSDictionary *origEnt = MCPAMExtractExistingEntitlements(mainExec);

            NSString *err = nil;
            NSString *workDir = MCPAMCreateWorkDir(&err);
            if (!workDir) return MCPAMFail(err);
            @try {
                NSString *stageMain = [workDir stringByAppendingPathComponent:@"main.bin"];
                NSData *mainData = [NSData dataWithContentsOfFile:mainExec];
                if (!mainData.length || ![mainData writeToFile:stageMain options:NSDataWritingAtomic error:nil]) {
                    return MCPAMFail(@"failed to stage main executable");
                }
                if (gadgetName.length > 0 && ![gadgetName isEqualToString:@"-"]) {
                    MCPRemoveLoadDylibFromMachO(stageMain, gadgetName, NO, NULL);
                }
                if (stealthName.length > 0 && ![stealthName isEqualToString:@"-"]) {
                    MCPRemoveLoadDylibFromMachO(stageMain, stealthName, NO, NULL);
                }
                if (!MCPAMSignStageBinary(workDir, @"main.bin", origEnt, &err)) {
                    return MCPAMFail(err);
                }
                NSData *signedMain = [NSData dataWithContentsOfFile:stageMain];
                if (!MCPAMWriteFreshVnode(signedMain, mainExec, origMode, st.st_uid, st.st_gid, YES, &err)) {
                    return MCPAMFail(err);
                }

                NSString *frameworksDir = [appBundle stringByAppendingPathComponent:@"Frameworks"];
                NSMutableArray<NSString *> *deleted = [NSMutableArray array];
                NSMutableArray<NSString *> *candidates = [NSMutableArray array];
                if (stealthName.length > 0 && ![stealthName isEqualToString:@"-"]) {
                    [candidates addObject:[frameworksDir stringByAppendingPathComponent:stealthName]];
                }
                if (gadgetName.length > 0 && ![gadgetName isEqualToString:@"-"]) {
                    NSString *stem = [gadgetName stringByDeletingPathExtension];
                    [candidates addObject:[frameworksDir stringByAppendingPathComponent:gadgetName]];
                    [candidates addObject:[frameworksDir stringByAppendingPathComponent:[stem stringByAppendingString:@".config"]]];
                    [candidates addObject:[frameworksDir stringByAppendingPathComponent:[stem stringByAppendingString:@".js"]]];
                }
                // Also sweep every file this tool could have staged, by its disguise
                // prefixes, so orphans from earlier injects (whose randomized suffix
                // is no longer in the session file) are cleaned up too instead of
                // accumulating ~62 MB per leftover. These prefixes are MCP-specific
                // (real Apple frameworks are not named "libAppleCoreSVG_<hex>"), and
                // the LC_LOAD_DYLIB for each has already been stripped from the main
                // Mach-O above, so nothing references them.
                NSArray<NSString *> *stagePrefixes = @[@"libAppleCoreSVG_", @"libAppleAudioDSP_"];
                NSArray<NSString *> *fwEntries = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:frameworksDir error:nil];
                for (NSString *entry in fwEntries) {
                    for (NSString *prefix in stagePrefixes) {
                        if ([entry hasPrefix:prefix]) {
                            [candidates addObject:[frameworksDir stringByAppendingPathComponent:entry]];
                            break;
                        }
                    }
                }
                for (NSString *f in candidates) {
                    if (MCPAMPathExists(f) && unlink(f.fileSystemRepresentation) == 0) {
                        [deleted addObject:f];
                    }
                }

                MCPAMEmitJSON(@{
                    @"ok": @YES,
                    @"result": @{
                        @"main_executable": mainExec,
                        @"deleted_files": deleted,
                        @"signed": @YES
                    }
                });
                return 0;
            } @finally {
                [[NSFileManager defaultManager] removeItemAtPath:workDir error:nil];
            }
        }

        if ([cmd isEqualToString:@"decompress-xz"]) {
            if (argc < 4) return MCPAMFail(@"usage: mcp-appmod decompress-xz <xz_path> <dest_path>");
            NSString *xzPath = MCPAMResolveExistingPath([NSString stringWithUTF8String:argv[2]]);
            NSString *destPath = MCPAMResolveOutputPath([NSString stringWithUTF8String:argv[3]]);
            NSString *xzTool = MCPAMResolveJBTool(@"/usr/bin/xz");
            if (!MCPAMIsExecutable(xzTool)) return MCPAMFail(@"xz binary not found in bootstrap");
            int exitCode = -1;
            NSData *rawOut = nil;
            NSString *errText = nil;
            NSString *err = nil;
            if (!MCPAMRunCommandInDir(xzTool, @[@"-d", @"-c", xzPath], nil, &exitCode, &rawOut, &errText, &err)) {
                return MCPAMFail(err);
            }
            if (exitCode != 0 || !rawOut.length) {
                return MCPAMFail([NSString stringWithFormat:@"xz failed (%d): %@", exitCode, errText ?: @""]);
            }
            if (!MCPAMWriteFreshVnode(rawOut, destPath, 0755, 501, 501, YES, &err)) {
                return MCPAMFail(err);
            }
            MCPAMEmitJSON(@{@"ok": @YES, @"result": @{@"output_path": destPath, @"bytes": @(rawOut.length)}});
            return 0;
        }

        if ([cmd isEqualToString:@"scoped-keychain"]) {
            if (argc < 5) return MCPAMFail(@"usage: mcp-appmod scoped-keychain <access_group> <app_id> <req_file>");
            NSString *accessGroup = [NSString stringWithUTF8String:argv[2]];
            NSString *appId = [NSString stringWithUTF8String:argv[3]];
            NSString *reqFile = MCPAMResolveExistingPath([NSString stringWithUTF8String:argv[4]]);
            NSString *kcTool = MCPAMResolveJBTool(@"/usr/libexec/ios-mcp/mcp-keychain");
            if (!MCPAMIsExecutable(kcTool)) return MCPAMFail(@"mcp-keychain helper not found");

            NSString *err = nil;
            NSString *workDir = MCPAMCreateWorkDir(&err);
            if (!workDir) return MCPAMFail(err);
            @try {
                NSString *scopedName = @"mcp-kc-scoped";
                NSString *scopedPath = [workDir stringByAppendingPathComponent:scopedName];
                NSData *kcData = [NSData dataWithContentsOfFile:kcTool];
                if (!kcData.length || ![kcData writeToFile:scopedPath options:NSDataWritingAtomic error:nil]) {
                    return MCPAMFail(@"failed to copy mcp-keychain");
                }
                chmod(scopedPath.fileSystemRepresentation, 0755);

                NSMutableArray<NSString *> *groups = [NSMutableArray array];
                if (accessGroup.length > 0) [groups addObject:accessGroup];
                if (appId.length > 0 && ![groups containsObject:appId]) [groups addObject:appId];
                [groups addObject:@"*"];

                NSDictionary *scopedEnt = @{
                    @"application-identifier": appId.length ? appId : (accessGroup.length ? accessGroup : @"com.witchan.mcp-keychain"),
                    @"keychain-access-groups": groups,
                    @"com.apple.keystore.access-keychain-keys": @YES,
                    @"com.apple.private.security.no-sandbox": @YES,
                    @"platform-application": @YES
                };
                if (!MCPAMSignStageBinary(workDir, scopedName, scopedEnt, &err)) {
                    return MCPAMFail(err);
                }
                chmod(scopedPath.fileSystemRepresentation, 0755);

                int exitCode = -1;
                NSData *stdoutData = nil;
                NSString *stderrText = nil;
                if (!MCPAMRunCommandInDir(scopedPath, @[@"--req", reqFile], workDir, &exitCode, &stdoutData, &stderrText, &err)) {
                    return MCPAMFail(err);
                }
                if (stdoutData.length > 0) {
                    fwrite(stdoutData.bytes, 1, stdoutData.length, stdout);
                    fflush(stdout);
                    return exitCode;
                }
                return MCPAMFail(stderrText.length ? stderrText : @"scoped keychain helper produced no output");
            } @finally {
                [[NSFileManager defaultManager] removeItemAtPath:workDir error:nil];
            }
        }

        if ([cmd isEqualToString:@"unix-rpc"]) {
            if (argc < 5) return MCPAMFail(@"usage: mcp-appmod unix-rpc <socket_path> <req_file> <timeout_ms>");
            NSString *rawSock = [NSString stringWithUTF8String:argv[2]];
            NSString *sockPath = MCPAMNormalizeUnixSocketPath(rawSock);
            NSString *reqFile = MCPAMResolveExistingPath([NSString stringWithUTF8String:argv[3]]);
            int timeoutMs = atoi(argv[4]);
            if (timeoutMs <= 0) timeoutMs = 8000;

            NSData *reqData = [NSData dataWithContentsOfFile:reqFile];
            if (!reqData.length) return MCPAMFail(@"cannot read unix-rpc request file");

            const char *sockCStr = sockPath.fileSystemRepresentation;
            struct sockaddr_un addr;
            memset(&addr, 0, sizeof(addr));
            addr.sun_family = AF_UNIX;
            if (!sockCStr || strlen(sockCStr) >= sizeof(addr.sun_path)) {
                return MCPAMFail([NSString stringWithFormat:@"unix socket path exceeds sun_path limit (%zu): %@",
                                  sizeof(addr.sun_path) - 1, sockPath]);
            }
            strncpy(addr.sun_path, sockCStr, sizeof(addr.sun_path) - 1);

            int fd = socket(AF_UNIX, SOCK_STREAM, 0);
            if (fd < 0) return MCPAMFail([NSString stringWithFormat:@"socket(AF_UNIX) failed: %s", strerror(errno)]);
            int noSigPipe = 1;
            setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, sizeof(noSigPipe));

            if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
                int e = errno;
                close(fd);
                return MCPAMFail([NSString stringWithFormat:@"connect(%@) failed: %s", sockPath, strerror(e)]);
            }

            NSMutableData *wireReq = [reqData mutableCopy];
            const uint8_t *b = wireReq.bytes;
            if (wireReq.length == 0 || b[wireReq.length - 1] != '\n') {
                const char nl = '\n';
                [wireReq appendBytes:&nl length:1];
            }

            const uint8_t *wptr = wireReq.bytes;
            size_t wrem = wireReq.length;
            while (wrem > 0) {
                ssize_t w = send(fd, wptr, wrem, 0);
                if (w < 0 && errno == EINTR) continue;
                if (w <= 0) {
                    int e = errno;
                    close(fd);
                    return MCPAMFail([NSString stringWithFormat:@"send(AF_UNIX) failed: %s", strerror(e)]);
                }
                wptr += (size_t)w;
                wrem -= (size_t)w;
            }

            NSMutableData *respBuf = [NSMutableData data];
            CFAbsoluteTime deadline = CFAbsoluteTimeGetCurrent() + ((double)timeoutMs / 1000.0);
            BOOL gotNewline = NO;
            while (!gotNewline) {
                double remSec = deadline - CFAbsoluteTimeGetCurrent();
                if (remSec <= 0) {
                    close(fd);
                    return MCPAMFail(@"timed out waiting for Frida Gadget Unix socket RPC response");
                }
                struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
                int pr = poll(&pfd, 1, MAX(1, (int)(remSec * 1000.0)));
                if (pr < 0 && errno == EINTR) continue;
                if (pr <= 0) {
                    close(fd);
                    return MCPAMFail(@"poll timeout on Frida Gadget Unix socket");
                }
                uint8_t rbuf[8192];
                ssize_t r = recv(fd, rbuf, sizeof(rbuf), 0);
                if (r < 0 && errno == EINTR) continue;
                if (r <= 0) break;
                [respBuf appendBytes:rbuf length:(NSUInteger)r];
                const uint8_t *rb = respBuf.bytes;
                for (NSUInteger i = 0; i < respBuf.length; i++) {
                    if (rb[i] == '\n') {
                        gotNewline = YES;
                        respBuf.length = i;
                        break;
                    }
                }
            }
            close(fd);

            if (!respBuf.length) {
                return MCPAMFail(@"empty response from Frida Gadget Unix socket");
            }
            id parsed = [NSJSONSerialization JSONObjectWithData:respBuf options:0 error:NULL];
            if ([parsed isKindOfClass:[NSDictionary class]]) {
                MCPAMEmitJSON(@{@"ok": @YES, @"result": parsed});
                return 0;
            }
            NSString *rawText = [[NSString alloc] initWithData:respBuf encoding:NSUTF8StringEncoding] ?: @"";
            MCPAMEmitJSON(@{@"ok": @YES, @"result": @{@"raw": rawText}});
            return 0;
        }

        return MCPAMFail([NSString stringWithFormat:@"unknown subcommand: %@", cmd]);
    }
}
