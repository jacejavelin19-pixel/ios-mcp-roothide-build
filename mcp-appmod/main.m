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

    NSMutableArray *signArguments = [NSMutableArray arrayWithObject:signFlag];
    NSString *applicationID = entitlements[@"application-identifier"];
    if ([applicationID isKindOfClass:NSString.class]) {
        NSRange dot = [applicationID rangeOfString:@"."];
        if (dot.location != NSNotFound && dot.location + 1 < applicationID.length) {
            NSString *identifier = [applicationID substringFromIndex:dot.location + 1];
            [signArguments addObject:[@"-I" stringByAppendingString:identifier]];
        }
    }
    [signArguments addObject:stageFileName];
    int exitCode = -1;
    NSData *outData = nil;
    NSString *errText = nil;
    if (!MCPAMRunCommandInDir(ldidPath, signArguments, workDir, &exitCode, &outData, &errText, error)) {
        return NO;
    }
    if (exitCode != 0) {
        NSString *fallbackLdid = MCPAMResolveJBTool(@"/usr/bin/ldid");
        if (MCPAMIsExecutable(fallbackLdid) && ![fallbackLdid isEqualToString:ldidPath]) {
            if (MCPAMRunCommandInDir(fallbackLdid, signArguments, workDir, &exitCode, &outData, &errText, error) && exitCode == 0) {
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

static BOOL MCPAMIsMachOEncrypted(NSString *path) {
    if (!path.length || !MCPAMPathExists(path)) return NO;
    NSDictionary *info = MCPInspectMachOAtPath(path, NULL);
    if (![info[@"slices"] isKindOfClass:[NSArray class]]) return NO;
    for (NSDictionary *slice in (NSArray *)info[@"slices"]) {
        NSDictionary *enc = slice[@"encryption"];
        if ([enc isKindOfClass:[NSDictionary class]] && [enc[@"encrypted"] boolValue]) {
            return YES;
        }
    }
    return NO;
}

// If a FairPlay-encrypted binary had a .mcp_orig backup from an earlier disk-patch attempt,
// restore .mcp_orig immediately without re-signing so its original Apple FairPlay signature is intact.
static BOOL MCPAMIsBinaryEncryptedAndHealIfNeeded(NSString *binaryPath) {
    NSString *origPath = [binaryPath stringByAppendingString:@".mcp_orig"];
    if (MCPAMPathExists(origPath) && MCPAMIsMachOEncrypted(origPath)) {
        struct stat st;
        BOOL hasStat = (stat(binaryPath.fileSystemRepresentation, &st) == 0);
        mode_t mode = hasStat ? (st.st_mode & 07777) : 0755;
        uid_t uid = hasStat ? st.st_uid : 0;
        gid_t gid = hasStat ? st.st_gid : 0;
        NSData *origBytes = [NSData dataWithContentsOfFile:origPath];
        if (origBytes.length) {
            MCPAMWriteFreshVnode(origBytes, binaryPath, mode, uid, gid, hasStat, NULL);
            unlink(origPath.fileSystemRepresentation);
        }
        return YES;
    }
    return MCPAMIsMachOEncrypted(binaryPath);
}

static NSString *MCPAMReadBundleIdFromAppDir(NSString *appDir) {
    if (!appDir.length) return nil;
    NSString *infoPath = [appDir stringByAppendingPathComponent:@"Info.plist"];
    NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:infoPath];
    if ([info[@"CFBundleIdentifier"] isKindOfClass:[NSString class]] && [info[@"CFBundleIdentifier"] length] > 0) {
        return info[@"CFBundleIdentifier"];
    }
    return nil;
}

static NSString *MCPAMResolveTweakInjectDir(void) {
    NSString *dir = MCPAMResolveJBTool(@"/usr/lib/TweakInject");
    if (dir.length && MCPAMPathExists(dir)) return dir;
    NSString *alt = MCPAMResolveJBTool(@"/Library/MobileSubstrate/DynamicLibraries");
    if (alt.length && MCPAMPathExists(alt)) return alt;
    return dir;
}

static BOOL MCPAMStageToTweakInject(NSData *signedDylibData,
                                    NSString *orderPrefix,
                                    NSString *dylibName,
                                    NSString *bundleId,
                                    NSData * _Nullable companionConfigData,
                                    NSData * _Nullable companionJSData,
                                    NSString **outTweakDylibPath,
                                    NSString **error) {
    NSString *tiDir = MCPAMResolveTweakInjectDir();
    if (!tiDir.length || !MCPAMPathExists(tiDir)) {
        if (error) *error = @"TweakInject directory not found in jbroot";
        return NO;
    }
    NSString *prefixedName = orderPrefix.length
        ? [NSString stringWithFormat:@"%@_%@", orderPrefix, dylibName]
        : dylibName;
    NSString *stem = [prefixedName stringByDeletingPathExtension];
    NSString *dylibDest = [tiDir stringByAppendingPathComponent:prefixedName];
    NSString *plistDest = [tiDir stringByAppendingPathComponent:[stem stringByAppendingString:@".plist"]];

    NSDictionary *filterPlist = @{
        @"Filter": @{
            @"Bundles": @[bundleId ?: @""]
        }
    };
    NSData *plistData = [NSPropertyListSerialization dataWithPropertyList:filterPlist
                                                                   format:NSPropertyListXMLFormat_v1_0
                                                                  options:0
                                                                    error:NULL];
    if (!plistData.length) {
        if (error) *error = @"failed to serialize TweakInject filter plist";
        return NO;
    }
    if (!MCPAMWriteFreshVnode(signedDylibData, dylibDest, 0755, 0, 0, YES, error)) {
        return NO;
    }
    if (!MCPAMWriteFreshVnode(plistData, plistDest, 0644, 0, 0, YES, error)) {
        return NO;
    }
    if (companionConfigData.length) {
        NSString *cfgDest = [tiDir stringByAppendingPathComponent:[stem stringByAppendingString:@".config"]];
        MCPAMWriteFreshVnode(companionConfigData, cfgDest, 0644, 0, 0, YES, NULL);
    }
    if (companionJSData.length) {
        NSString *jsDest = [tiDir stringByAppendingPathComponent:[stem stringByAppendingString:@".js"]];
        MCPAMWriteFreshVnode(companionJSData, jsDest, 0644, 0, 0, YES, NULL);
    }
    if (outTweakDylibPath) *outTweakDylibPath = dylibDest;
    return YES;
}

static NSArray<NSString *> *MCPAMUnstageFromTweakInject(NSString * _Nullable bundleId,
                                                        NSArray<NSString *> * _Nullable dylibNames,
                                                        NSArray<NSString *> * _Nullable prefixes) {
    NSMutableArray<NSString *> *deleted = [NSMutableArray array];
    NSString *tiDir = MCPAMResolveTweakInjectDir();
    if (!tiDir.length || !MCPAMPathExists(tiDir)) return deleted;
    NSArray<NSString *> *entries = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:tiDir error:nil];
    NSMutableSet<NSString *> *stemsToRemove = [NSMutableSet set];

    for (NSString *entry in entries) {
        BOOL matchName = NO;
        for (NSString *dn in (dylibNames ?: @[])) {
            if (!dn.length || [dn isEqualToString:@"-"]) continue;
            NSString *dnStem = [dn stringByDeletingPathExtension];
            if ([entry containsString:dnStem]) {
                matchName = YES;
                break;
            }
        }
        if (!matchName && prefixes.count > 0 && bundleId.length == 0) {
            for (NSString *pfx in prefixes) {
                if ([entry containsString:pfx]) {
                    matchName = YES;
                    break;
                }
            }
        }
        if (!matchName && bundleId.length > 0 && [entry hasSuffix:@".plist"]) {
            BOOL isMCP = NO;
            for (NSString *pfx in (prefixes ?: @[@"libAppleCoreSVG_", @"libAppleMediaKit_", @"libAppleAudioDSP_", @"libAppleAVSync_", @"libAppleCoreTLS_"])) {
                if ([entry containsString:pfx]) {
                    isMCP = YES;
                    break;
                }
            }
            if (isMCP) {
                NSString *plistPath = [tiDir stringByAppendingPathComponent:entry];
                NSDictionary *pl = [NSDictionary dictionaryWithContentsOfFile:plistPath];
                NSArray *bundles = [pl[@"Filter"] isKindOfClass:[NSDictionary class]] ? pl[@"Filter"][@"Bundles"] : nil;
                if ([bundles isKindOfClass:[NSArray class]] && [bundles containsObject:bundleId]) {
                    matchName = YES;
                }
            }
        }
        if (matchName) {
            [stemsToRemove addObject:[entry stringByDeletingPathExtension]];
        }
    }

    for (NSString *stem in stemsToRemove) {
        for (NSString *ext in @[@".dylib", @".plist", @".config", @".js"]) {
            NSString *p = [tiDir stringByAppendingPathComponent:[stem stringByAppendingString:ext]];
            if (MCPAMPathExists(p) && unlink(p.fileSystemRepresentation) == 0) {
                [deleted addObject:p];
            }
        }
    }
    return deleted;
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

            BOOL isEncrypted = MCPAMIsBinaryEncryptedAndHealIfNeeded(binaryPath);
            NSString *bundleId = MCPAMReadBundleIdFromAppDir(appDir);

            NSString *err = nil;
            if (!isEncrypted) {
                if (!MCPAMEnsureOrigBackup(binaryPath, origMode, st.st_uid, st.st_gid, YES, &err)) {
                    return MCPAMFail(err);
                }
            }

            NSDictionary *origEnt = isEncrypted ? nil : MCPAMExtractExistingEntitlements(binaryPath);
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

                if (isEncrypted && bundleId.length > 0) {
                    NSString *tiPath = nil;
                    if (!MCPAMStageToTweakInject(signedDylib, @"02", destName, bundleId, nil, nil, &tiPath, &err)) {
                        return MCPAMFail(err ?: @"failed to stage dylib to TweakInject");
                    }
                    MCPAMEmitJSON(@{
                        @"ok": @YES,
                        @"result": @{
                            @"binary_path": binaryPath,
                            @"staged_dylib_path": finalDylibPath,
                            @"tweak_inject_path": tiPath ?: @"",
                            @"load_command_path": tiPath ?: finalDylibPath,
                            @"injection_mode": @"tweak_inject",
                            @"signed": @YES
                        }
                    });
                    return 0;
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
            BOOL isEncrypted = MCPAMIsBinaryEncryptedAndHealIfNeeded(binaryPath);
            NSString *bundleId = MCPAMReadBundleIdFromAppDir(appDir);

            NSString *err = nil;
            NSMutableArray<NSString *> *deletedFiles = [NSMutableArray array];
            NSArray<NSString *> *tiDeleted = MCPAMUnstageFromTweakInject(
                bundleId,
                dylibMatch.length ? @[dylibMatch.lastPathComponent] : @[],
                nil
            );
            [deletedFiles addObjectsFromArray:tiDeleted];

            if (isEncrypted) {
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
                        @"deleted_staged_files": deletedFiles,
                        @"injection_mode": @"tweak_inject"
                    }
                });
                return 0;
            }

            if (restoreOrig) {
                NSString *origPath = [binaryPath stringByAppendingString:@".mcp_orig"];
                if (!MCPAMPathExists(origPath)) {
                    return MCPAMFail(@"no .mcp_orig backup found to restore");
                }
                NSDictionary *origEnt = MCPAMExtractExistingEntitlements(origPath);
                NSString *workDir = MCPAMCreateWorkDir(&err);
                if (!workDir) return MCPAMFail(err);
                @try {
                    NSString *stageMain = [workDir stringByAppendingPathComponent:@"main.bin"];
                    NSData *origData = [NSData dataWithContentsOfFile:origPath];
                    if (!origData.length || ![origData writeToFile:stageMain options:NSDataWritingAtomic error:nil]) {
                        return MCPAMFail(@"failed to stage .mcp_orig backup");
                    }
                    if (!MCPAMSignStageBinary(workDir, @"main.bin", origEnt, &err)) {
                        return MCPAMFail(err);
                    }
                    NSData *signedOrig = [NSData dataWithContentsOfFile:stageMain];
                    if (!MCPAMWriteFreshVnode(signedOrig, binaryPath, origMode, st.st_uid, st.st_gid, YES, &err)) {
                        return MCPAMFail(err);
                    }
                    unlink(origPath.fileSystemRepresentation);
                } @finally {
                    [[NSFileManager defaultManager] removeItemAtPath:workDir error:nil];
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

                NSString *origPath = [binaryPath stringByAppendingString:@".mcp_orig"];
                if (MCPAMPathExists(origPath)) {
                    unlink(origPath.fileSystemRepresentation);
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

        if ([cmd isEqualToString:@"inject-engine"]) {
            // Stage the stealth companion (FIRST) + the custom in-process engine
            // (SECOND) into Frameworks, insert LC_LOAD_DYLIB on all slices, re-sign
            // (which registers trust), and write the engine's socket config. No
            // scrub and no .js: the engine ships no Frida/Gum strings and binds its
            // own Unix socket from its constructor by reading .mcpe_cfg.json.
            if (argc < 9) {
                return MCPAMFail(@"usage: mcp-appmod inject-engine <app_bundle> <main_exec> <engine_src> <stealth_src> <engine_name> <stealth_name> <socket_path>");
            }
            NSString *appBundle = MCPAMResolveExistingPath([NSString stringWithUTF8String:argv[2]]);
            NSString *mainExec = MCPAMResolveExistingPath([NSString stringWithUTF8String:argv[3]]);
            NSString *protErr = nil;
            if (MCPAMIsProtectedTarget(mainExec, &protErr)) return MCPAMFail(protErr);
            NSString *engineSrc = MCPAMResolveExistingPath([NSString stringWithUTF8String:argv[4]]);
            NSString *stealthSrc = MCPAMResolveExistingPath([NSString stringWithUTF8String:argv[5]]);
            NSString *engineName = [[NSString stringWithUTF8String:argv[6]] lastPathComponent];
            NSString *stealthName = [[NSString stringWithUTF8String:argv[7]] lastPathComponent];
            NSString *socketPath = [NSString stringWithUTF8String:argv[8]];

            struct stat st;
            if (stat(mainExec.fileSystemRepresentation, &st) != 0 || !S_ISREG(st.st_mode)) {
                return MCPAMFail(@"main executable not found");
            }
            mode_t origMode = (st.st_mode & 07777) ?: 0755;

            NSString *frameworksDir = [appBundle stringByAppendingPathComponent:@"Frameworks"];
            [[NSFileManager defaultManager] createDirectoryAtPath:frameworksDir withIntermediateDirectories:YES attributes:nil error:nil];
            chmod(frameworksDir.fileSystemRepresentation, 0755);
            chown(frameworksDir.fileSystemRepresentation, st.st_uid, st.st_gid);

            BOOL isEncrypted = MCPAMIsBinaryEncryptedAndHealIfNeeded(mainExec);
            NSString *bundleId = MCPAMReadBundleIdFromAppDir(appBundle);

            NSString *err = nil;
            if (!isEncrypted) {
                if (!MCPAMEnsureOrigBackup(mainExec, origMode, st.st_uid, st.st_gid, YES, &err)) {
                    return MCPAMFail(err);
                }
            }
            NSDictionary *origEnt = isEncrypted ? nil : MCPAMExtractExistingEntitlements(mainExec);
            NSString *workDir = MCPAMCreateWorkDir(&err);
            if (!workDir) return MCPAMFail(err);

            @try {
                // 1. Stealth companion (loaded FIRST).
                NSString *stageStealth = [workDir stringByAppendingPathComponent:stealthName];
                NSData *stealthData = [NSData dataWithContentsOfFile:stealthSrc];
                if (!stealthData.length || ![stealthData writeToFile:stageStealth options:NSDataWritingAtomic error:nil]) {
                    return MCPAMFail(@"failed to read stealth dylib");
                }
                if (!MCPAMSignStageBinary(workDir, stealthName, nil, &err)) return MCPAMFail(err);
                NSData *signedStealth = [NSData dataWithContentsOfFile:stageStealth];
                NSString *destStealth = [frameworksDir stringByAppendingPathComponent:stealthName];
                if (!MCPAMWriteFreshVnode(signedStealth, destStealth, 0755, st.st_uid, st.st_gid, YES, &err)) {
                    return MCPAMFail(err);
                }

                // 2. Engine dylib (loaded SECOND). No scrub.
                NSString *stageEngine = [workDir stringByAppendingPathComponent:engineName];
                NSData *engineData = [NSData dataWithContentsOfFile:engineSrc];
                if (!engineData.length || ![engineData writeToFile:stageEngine options:NSDataWritingAtomic error:nil]) {
                    return MCPAMFail(@"failed to read engine dylib");
                }
                if (!MCPAMSignStageBinary(workDir, engineName, nil, &err)) return MCPAMFail(err);
                NSData *signedEngine = [NSData dataWithContentsOfFile:stageEngine];
                NSString *destEngine = [frameworksDir stringByAppendingPathComponent:engineName];
                if (!MCPAMWriteFreshVnode(signedEngine, destEngine, 0755, st.st_uid, st.st_gid, YES, &err)) {
                    return MCPAMFail(err);
                }

                // 3. Engine socket config at <DataContainer>/tmp/.mcpe_cfg.json
                //    (the engine reads only socket_path from it).
                NSString *cfgDir = [socketPath stringByDeletingLastPathComponent];
                NSString *cfgPath = [cfgDir stringByAppendingPathComponent:@".mcpe_cfg.json"];
                NSData *cfgData = [NSJSONSerialization dataWithJSONObject:@{@"socket_path": socketPath} options:0 error:nil];
                if (!cfgData.length || !MCPAMWriteFreshVnode(cfgData, cfgPath, 0644, st.st_uid, st.st_gid, YES, &err)) {
                    return MCPAMFail(err ?: @"failed to write engine config");
                }

                if (isEncrypted && bundleId.length > 0) {
                    MCPAMUnstageFromTweakInject(bundleId, @[stealthName, engineName], @[@"libAppleCoreSVG_", @"libAppleMediaKit_"]);
                    NSString *tiStealth = nil;
                    NSString *tiEngine = nil;
                    if (!MCPAMStageToTweakInject(signedStealth, @"00", stealthName, bundleId, nil, nil, &tiStealth, &err)) {
                        return MCPAMFail(err ?: @"failed to stage stealth to TweakInject");
                    }
                    if (!MCPAMStageToTweakInject(signedEngine, @"01", engineName, bundleId, nil, nil, &tiEngine, &err)) {
                        return MCPAMFail(err ?: @"failed to stage engine to TweakInject");
                    }
                    MCPAMEmitJSON(@{
                        @"ok": @YES,
                        @"result": @{
                            @"main_executable": mainExec,
                            @"stealth_dylib": destStealth,
                            @"engine_dylib": destEngine,
                            @"tweak_inject_stealth": tiStealth ?: @"",
                            @"tweak_inject_engine": tiEngine ?: @"",
                            @"engine_config": cfgPath,
                            @"socket_path": socketPath,
                            @"load_order": @[tiStealth ?: stealthName, tiEngine ?: engineName],
                            @"injection_mode": @"tweak_inject",
                            @"signed": @YES
                        }
                    });
                    return 0;
                }

                // 4. LC_LOAD_DYLIB: stealth FIRST, engine SECOND; re-sign main.
                NSString *stageMain = [workDir stringByAppendingPathComponent:@"main.bin"];
                NSData *mainData = [NSData dataWithContentsOfFile:mainExec];
                if (!mainData.length || ![mainData writeToFile:stageMain options:NSDataWritingAtomic error:nil]) {
                    return MCPAMFail(@"failed to stage main executable");
                }
                NSString *stealthLC = [NSString stringWithFormat:@"@executable_path/Frameworks/%@", stealthName];
                NSString *engineLC = [NSString stringWithFormat:@"@executable_path/Frameworks/%@", engineName];
                if (!MCPInjectLoadDylibInMachO(stageMain, stealthLC, &err)) return MCPAMFail(err);
                if (!MCPInjectLoadDylibInMachO(stageMain, engineLC, &err)) return MCPAMFail(err);
                if (!MCPAMSignStageBinary(workDir, @"main.bin", origEnt, &err)) return MCPAMFail(err);
                NSData *signedMain = [NSData dataWithContentsOfFile:stageMain];
                if (!MCPAMWriteFreshVnode(signedMain, mainExec, origMode, st.st_uid, st.st_gid, YES, &err)) {
                    return MCPAMFail(err);
                }

                MCPAMEmitJSON(@{
                    @"ok": @YES,
                    @"result": @{
                        @"main_executable": mainExec,
                        @"stealth_dylib": destStealth,
                        @"engine_dylib": destEngine,
                        @"engine_config": cfgPath,
                        @"socket_path": socketPath,
                        @"load_order": @[stealthLC, engineLC],
                        @"signed": @YES
                    }
                });
                return 0;
            } @finally {
                [[NSFileManager defaultManager] removeItemAtPath:workDir error:nil];
            }
        }

        if ([cmd isEqualToString:@"unstage-engine"]) {
            // Mirror unstage-frida: strip both LC_LOAD_DYLIB, re-sign, and sweep the
            // staged payloads by name and by the MCP disguise prefixes.
            if (argc < 6) {
                return MCPAMFail(@"usage: mcp-appmod unstage-engine <app_bundle> <main_exec> <stealth_name> <engine_name>");
            }
            NSString *appBundle = MCPAMResolveExistingPath([NSString stringWithUTF8String:argv[2]]);
            NSString *mainExec = MCPAMResolveExistingPath([NSString stringWithUTF8String:argv[3]]);
            NSString *protErr = nil;
            if (MCPAMIsProtectedTarget(mainExec, &protErr)) return MCPAMFail(protErr);
            NSString *stealthName = [[NSString stringWithUTF8String:argv[4]] lastPathComponent];
            NSString *engineName = [[NSString stringWithUTF8String:argv[5]] lastPathComponent];

            struct stat st;
            if (stat(mainExec.fileSystemRepresentation, &st) != 0 || !S_ISREG(st.st_mode)) {
                return MCPAMFail(@"main executable not found");
            }
            mode_t origMode = (st.st_mode & 07777) ?: 0755;
            BOOL isEncrypted = MCPAMIsBinaryEncryptedAndHealIfNeeded(mainExec);
            NSString *bundleId = MCPAMReadBundleIdFromAppDir(appBundle);

            NSMutableArray<NSString *> *deleted = [NSMutableArray array];
            NSArray<NSString *> *tiDeleted = MCPAMUnstageFromTweakInject(
                bundleId,
                @[stealthName ?: @"", engineName ?: @""],
                @[@"libAppleCoreSVG_", @"libAppleMediaKit_"]
            );
            [deleted addObjectsFromArray:tiDeleted];

            NSString *err = nil;
            if (!isEncrypted) {
                NSDictionary *origEnt = MCPAMExtractExistingEntitlements(mainExec);
                NSString *workDir = MCPAMCreateWorkDir(&err);
                if (!workDir) return MCPAMFail(err);
                @try {
                    NSString *stageMain = [workDir stringByAppendingPathComponent:@"main.bin"];
                    NSData *mainData = [NSData dataWithContentsOfFile:mainExec];
                    if (!mainData.length || ![mainData writeToFile:stageMain options:NSDataWritingAtomic error:nil]) {
                        return MCPAMFail(@"failed to stage main executable");
                    }
                    if (engineName.length > 0 && ![engineName isEqualToString:@"-"]) {
                        MCPRemoveLoadDylibFromMachO(stageMain, engineName, NO, NULL);
                    }
                    if (stealthName.length > 0 && ![stealthName isEqualToString:@"-"]) {
                        MCPRemoveLoadDylibFromMachO(stageMain, stealthName, NO, NULL);
                    }
                    if (!MCPAMSignStageBinary(workDir, @"main.bin", origEnt, &err)) return MCPAMFail(err);
                    NSData *signedMain = [NSData dataWithContentsOfFile:stageMain];
                    if (!MCPAMWriteFreshVnode(signedMain, mainExec, origMode, st.st_uid, st.st_gid, YES, &err)) {
                        return MCPAMFail(err);
                    }
                    NSString *origPath = [mainExec stringByAppendingString:@".mcp_orig"];
                    if (MCPAMPathExists(origPath)) {
                        unlink(origPath.fileSystemRepresentation);
                    }
                } @finally {
                    [[NSFileManager defaultManager] removeItemAtPath:workDir error:nil];
                }
            }

            NSString *frameworksDir = [appBundle stringByAppendingPathComponent:@"Frameworks"];
            NSMutableArray<NSString *> *candidates = [NSMutableArray array];
            if (stealthName.length) [candidates addObject:[frameworksDir stringByAppendingPathComponent:stealthName]];
            if (engineName.length) [candidates addObject:[frameworksDir stringByAppendingPathComponent:engineName]];
            NSArray<NSString *> *stagePrefixes = @[@"libAppleCoreSVG_", @"libAppleMediaKit_"];
            for (NSString *entry in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:frameworksDir error:nil]) {
                for (NSString *prefix in stagePrefixes) {
                    if ([entry hasPrefix:prefix]) { [candidates addObject:[frameworksDir stringByAppendingPathComponent:entry]]; break; }
                }
            }
            for (NSString *f in candidates) {
                if (MCPAMPathExists(f) && unlink(f.fileSystemRepresentation) == 0) [deleted addObject:f];
            }
            MCPAMEmitJSON(@{
                @"ok": @YES,
                @"result": @{
                    @"main_executable": mainExec,
                    @"deleted_files": deleted,
                    @"signed": @(!isEncrypted),
                    @"injection_mode": isEncrypted ? @"tweak_inject" : @"lc_load_dylib"
                }
            });
            return 0;
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

            BOOL isEncrypted = MCPAMIsBinaryEncryptedAndHealIfNeeded(mainExec);
            NSString *bundleId = MCPAMReadBundleIdFromAppDir(appBundle);

            NSString *err = nil;
            if (!isEncrypted) {
                if (!MCPAMEnsureOrigBackup(mainExec, origMode, st.st_uid, st.st_gid, YES, &err)) {
                    return MCPAMFail(err);
                }
            }
            NSDictionary *origEnt = isEncrypted ? nil : MCPAMExtractExistingEntitlements(mainExec);
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

                if (isEncrypted && bundleId.length > 0) {
                    MCPAMUnstageFromTweakInject(bundleId, @[stealthName, gadgetName], @[@"libAppleCoreSVG_", @"libAppleAudioDSP_"]);
                    NSString *tiStealth = nil;
                    NSString *tiGadget = nil;
                    if (!MCPAMStageToTweakInject(signedStealth, @"00", stealthName, bundleId, nil, nil, &tiStealth, &err)) {
                        return MCPAMFail(err ?: @"failed to stage stealth to TweakInject");
                    }
                    if (!MCPAMStageToTweakInject(signedGadget, @"01", gadgetName, bundleId, cfgData, jsData, &tiGadget, &err)) {
                        return MCPAMFail(err ?: @"failed to stage gadget to TweakInject");
                    }
                    MCPAMEmitJSON(@{
                        @"ok": @YES,
                        @"result": @{
                            @"main_executable": mainExec,
                            @"stealth_dylib": destStealth,
                            @"gadget_dylib": destGadget,
                            @"gadget_config": destCfg,
                            @"gadget_script": destJS,
                            @"stealth_load_command": tiStealth ?: stealthName,
                            @"gadget_load_command": tiGadget ?: gadgetName,
                            @"load_order": @[tiStealth ?: stealthName, tiGadget ?: gadgetName],
                            @"scrub": scrubInfo,
                            @"injection_mode": @"tweak_inject",
                            @"signed": @YES
                        }
                    });
                    return 0;
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
            BOOL isEncrypted = MCPAMIsBinaryEncryptedAndHealIfNeeded(mainExec);
            NSString *bundleId = MCPAMReadBundleIdFromAppDir(appBundle);

            NSMutableArray<NSString *> *deleted = [NSMutableArray array];
            NSArray<NSString *> *tiDeleted = MCPAMUnstageFromTweakInject(
                bundleId,
                @[stealthName ?: @"", gadgetName ?: @""],
                @[@"libAppleCoreSVG_", @"libAppleAudioDSP_"]
            );
            [deleted addObjectsFromArray:tiDeleted];

            NSString *err = nil;
            if (!isEncrypted) {
                NSDictionary *origEnt = MCPAMExtractExistingEntitlements(mainExec);
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
                    NSString *origPath = [mainExec stringByAppendingString:@".mcp_orig"];
                    if (MCPAMPathExists(origPath)) {
                        unlink(origPath.fileSystemRepresentation);
                    }
                } @finally {
                    [[NSFileManager defaultManager] removeItemAtPath:workDir error:nil];
                }
            }

            NSString *frameworksDir = [appBundle stringByAppendingPathComponent:@"Frameworks"];
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
                    @"signed": @(!isEncrypted),
                    @"injection_mode": isEncrypted ? @"tweak_inject" : @"lc_load_dylib"
                }
            });
            return 0;
        }

        if ([cmd isEqualToString:@"cleanup-all"]) {
            NSMutableArray<NSString *> *restoredBinaries = [NSMutableArray array];
            NSMutableArray<NSString *> *deletedFiles = [NSMutableArray array];
            NSArray<NSString *> *mcpPrefixes = @[
                @"libAppleCoreSVG_",
                @"libAppleMediaKit_",
                @"libAppleAudioDSP_",
                @"libAppleAVSync_",
                @"libAppleCoreTLS_",
                @"libmcp_"
            ];
            NSArray<NSString *> *tiCleaned = MCPAMUnstageFromTweakInject(nil, nil, mcpPrefixes);
            [deletedFiles addObjectsFromArray:tiCleaned];

            NSFileManager *fm = [NSFileManager defaultManager];
            NSMutableSet<NSString *> *appBundles = [NSMutableSet set];

            for (NSString *sessDir in @[@"/var/mobile/Library/ios-mcp/engine-sessions",
                                        @"/var/mobile/Library/ios-mcp/frida/sessions"]) {
                for (NSString *f in [fm contentsOfDirectoryAtPath:sessDir error:nil]) {
                    if (![f hasSuffix:@".json"]) continue;
                    NSString *sp = [sessDir stringByAppendingPathComponent:f];
                    NSData *d = [NSData dataWithContentsOfFile:sp];
                    if (d.length) {
                        NSDictionary *j = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
                        if ([j isKindOfClass:[NSDictionary class]]) {
                            if ([j[@"bundle_path"] isKindOfClass:[NSString class]] && [j[@"bundle_path"] length]) {
                                [appBundles addObject:j[@"bundle_path"]];
                            }
                            if ([j[@"socket_path"] isKindOfClass:[NSString class]] && [j[@"socket_path"] length]) {
                                NSString *sock = j[@"socket_path"];
                                unlink(sock.fileSystemRepresentation);
                                NSString *cfg = [[sock stringByDeletingLastPathComponent] stringByAppendingPathComponent:@".mcpe_cfg.json"];
                                unlink(cfg.fileSystemRepresentation);
                            }
                        }
                    }
                    if (unlink(sp.fileSystemRepresentation) == 0) {
                        [deletedFiles addObject:sp];
                    }
                }
            }

            NSString *bundleContainerRoot = @"/var/containers/Bundle/Application";
            for (NSString *uuidDir in [fm contentsOfDirectoryAtPath:bundleContainerRoot error:nil]) {
                if ([uuidDir hasPrefix:@"."]) continue;
                NSString *uuidPath = [bundleContainerRoot stringByAppendingPathComponent:uuidDir];
                for (NSString *sub in [fm contentsOfDirectoryAtPath:uuidPath error:nil]) {
                    if ([sub hasSuffix:@".app"]) {
                        [appBundles addObject:[uuidPath stringByAppendingPathComponent:sub]];
                    }
                }
            }

            NSString *dataContainerRoot = @"/var/mobile/Containers/Data/Application";
            for (NSString *uuidDir in [fm contentsOfDirectoryAtPath:dataContainerRoot error:nil]) {
                if ([uuidDir hasPrefix:@"."]) continue;
                NSString *tmpPath = [[dataContainerRoot stringByAppendingPathComponent:uuidDir] stringByAppendingPathComponent:@"tmp"];
                if (!MCPAMPathExists(tmpPath)) continue;
                for (NSString *tmpEntry in [fm contentsOfDirectoryAtPath:tmpPath error:nil]) {
                    if ([tmpEntry isEqualToString:@".mcpe_cfg.json"] ||
                        [tmpEntry isEqualToString:@".mcp_stealth_cfg.json"] ||
                        [tmpEntry isEqualToString:@".mcp_stealth_status.json"] ||
                        [tmpEntry isEqualToString:@".mcpcap.jsonl"] ||
                        [tmpEntry isEqualToString:@".mcp_netcap.jsonl"] ||
                        [tmpEntry hasPrefix:@".me_"] ||
                        [tmpEntry hasPrefix:@".fc_"]) {
                        NSString *tp = [tmpPath stringByAppendingPathComponent:tmpEntry];
                        if (unlink(tp.fileSystemRepresentation) == 0) {
                            [deletedFiles addObject:tp];
                        }
                    }
                }
            }

            for (NSString *appPath in appBundles) {
                if (!MCPAMPathExists(appPath)) continue;
                for (NSString *entry in [fm contentsOfDirectoryAtPath:appPath error:nil]) {
                    if ([entry hasSuffix:@".mcp_orig"]) {
                        NSString *origPath = [appPath stringByAppendingPathComponent:entry];
                        NSString *mainPath = [appPath stringByAppendingPathComponent:[entry substringToIndex:entry.length - 9]];
                        struct stat st;
                        BOOL hasStat = (stat(mainPath.fileSystemRepresentation, &st) == 0);
                        mode_t mode = hasStat ? (st.st_mode & 07777) : 0755;
                        uid_t uid = hasStat ? st.st_uid : 0;
                        gid_t gid = hasStat ? st.st_gid : 0;
                        if (MCPAMIsMachOEncrypted(origPath)) {
                            NSData *origBytes = [NSData dataWithContentsOfFile:origPath];
                            if (origBytes.length) {
                                MCPAMWriteFreshVnode(origBytes, mainPath, mode, uid, gid, hasStat, NULL);
                                [restoredBinaries addObject:mainPath];
                            }
                            unlink(origPath.fileSystemRepresentation);
                        } else {
                            NSDictionary *origEnt = MCPAMExtractExistingEntitlements(origPath);
                            NSString *workDir = MCPAMCreateWorkDir(NULL);
                            if (workDir) {
                                NSString *stageMain = [workDir stringByAppendingPathComponent:@"main.bin"];
                                NSData *origBytes = [NSData dataWithContentsOfFile:origPath];
                                if (origBytes.length && [origBytes writeToFile:stageMain options:NSDataWritingAtomic error:nil]) {
                                    if (MCPAMSignStageBinary(workDir, @"main.bin", origEnt, NULL)) {
                                        NSData *signedBytes = [NSData dataWithContentsOfFile:stageMain];
                                        if (signedBytes.length) {
                                            MCPAMWriteFreshVnode(signedBytes, mainPath, mode, uid, gid, hasStat, NULL);
                                            [restoredBinaries addObject:mainPath];
                                        }
                                    } else {
                                        MCPAMWriteFreshVnode(origBytes, mainPath, mode, uid, gid, hasStat, NULL);
                                        [restoredBinaries addObject:mainPath];
                                    }
                                }
                                [fm removeItemAtPath:workDir error:nil];
                            }
                            unlink(origPath.fileSystemRepresentation);
                        }
                    }
                }
                NSString *fwDir = [appPath stringByAppendingPathComponent:@"Frameworks"];
                for (NSString *fwEntry in [fm contentsOfDirectoryAtPath:fwDir error:nil]) {
                    for (NSString *pfx in mcpPrefixes) {
                        if ([fwEntry hasPrefix:pfx]) {
                            NSString *p = [fwDir stringByAppendingPathComponent:fwEntry];
                            if (unlink(p.fileSystemRepresentation) == 0) {
                                [deletedFiles addObject:p];
                            }
                            break;
                        }
                    }
                }
            }

            MCPAMEmitJSON(@{
                @"ok": @YES,
                @"result": @{
                    @"restored_binaries": restoredBinaries,
                    @"deleted_files": deletedFiles
                }
            });
            return 0;
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
