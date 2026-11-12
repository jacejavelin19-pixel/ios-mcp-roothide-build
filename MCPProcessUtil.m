#import "MCPProcessUtil.h"
#ifdef MCP_ROOTHIDE
#include <roothide.h>
#endif
#import <arpa/inet.h>
#import <dispatch/dispatch.h>
#import <errno.h>
#import <fcntl.h>
#import <netinet/in.h>
#import <signal.h>
#import <spawn.h>
#import <string.h>
#import <sys/socket.h>
#import <sys/stat.h>
#import <sys/un.h>
#import <sys/wait.h>
#import <unistd.h>

extern char **environ;

#define MCP_HELPERD_SOCK_REL  "/var/tmp/.mcp-helperd.sock"
#define MCP_HELPERD_TCP_PORT  48091

// SpringBoard may have closed stdio descriptors 0/1/2. Move pipe FDs >= 3 so
// posix_spawn dup2/close actions never clobber child stdout/stderr pipes.
static BOOL MCPKeepFDAboveStdio(int *fd) {
    if (!fd || *fd < 0) return NO;
    if (*fd >= 3) return YES;
    int moved = fcntl(*fd, F_DUPFD_CLOEXEC, 3);
    if (moved < 0) return NO;
    close(*fd);
    *fd = moved;
    return YES;
}

static BOOL MCPWriteAllSocket(int fd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return NO;
        p += (size_t)n;
        len -= (size_t)n;
    }
    return YES;
}

static BOOL MCPReadExactSocket(int fd, void *buf, size_t len) {
    uint8_t *p = (uint8_t *)buf;
    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return NO;
        p += (size_t)n;
        len -= (size_t)n;
    }
    return YES;
}

int MCPConnectHelperDaemon(void) {
    int tcpFD = socket(AF_INET, SOCK_STREAM, 0);
    if (tcpFD >= 0) {
        fcntl(tcpFD, F_SETFD, FD_CLOEXEC);
        int yes = 1;
        setsockopt(tcpFD, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes));
        struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
        setsockopt(tcpFD, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(tcpFD, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(MCP_HELPERD_TCP_PORT);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (connect(tcpFD, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            MCPKeepFDAboveStdio(&tcpFD);
            return tcpFD;
        }
        close(tcpFD);
    }

    int unixFD = socket(AF_UNIX, SOCK_STREAM, 0);
    if (unixFD >= 0) {
        fcntl(unixFD, F_SETFD, FD_CLOEXEC);
        int yes = 1;
        setsockopt(unixFD, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes));
        struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
        setsockopt(unixFD, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(unixFD, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
#ifdef MCP_ROOTHIDE
        NSString *sockPathObj = jbroot(@MCP_HELPERD_SOCK_REL);
#elif defined(MCP_ROOTLESS)
        NSString *sockPathObj = [@"/var/jb" stringByAppendingString:@MCP_HELPERD_SOCK_REL];
#else
        NSString *sockPathObj = @MCP_HELPERD_SOCK_REL;
#endif
        const char *sockPath = sockPathObj.fileSystemRepresentation ?: MCP_HELPERD_SOCK_REL;
        strlcpy(addr.sun_path, sockPath, sizeof(addr.sun_path));
        if (connect(unixFD, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            MCPKeepFDAboveStdio(&unixFD);
            return unixFD;
        }
        close(unixFD);
    }
    return -1;
}

static BOOL MCPRunProcessViaHelperDaemon(NSString *launchPath,
                                         NSArray<NSString *> *arguments,
                                         NSDictionary<NSString *, NSString *> *environmentOverrides,
                                         NSTimeInterval timeout,
                                         NSUInteger maxOutputBytes,
                                         NSData **outputData,
                                         BOOL *truncatedOut,
                                         int *exitCode,
                                         NSString **errorMessage) {
    int sock = MCPConnectHelperDaemon();
    if (sock < 0) {
        if (errorMessage) *errorMessage = [NSString stringWithFormat:@"posix_spawn denied in SpringBoard and mcp-helperd is unreachable for %@", launchPath];
        return NO;
    }

    NSTimeInterval effectiveTimeout = MAX(timeout, 1.0);
    int rcvSec = (int)ceil(effectiveTimeout) + 5;
    if (rcvSec < 5) rcvSec = 5;
    struct timeval rcvTv = {.tv_sec = rcvSec, .tv_usec = 0};
    struct timeval sndTv = {.tv_sec = 5, .tv_usec = 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &rcvTv, sizeof(rcvTv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &sndTv, sizeof(sndTv));

    NSMutableDictionary *req = [NSMutableDictionary dictionary];
    req[@"launch_path"] = launchPath ?: @"";
    req[@"arguments"] = arguments ?: @[];
    if (environmentOverrides.count > 0) {
        req[@"environment"] = environmentOverrides;
    }
    req[@"timeout"] = @(effectiveTimeout);
    req[@"max_output_bytes"] = @(maxOutputBytes > 0 ? maxOutputBytes : (512 * 1024));

    NSData *reqData = [NSJSONSerialization dataWithJSONObject:req options:0 error:nil];
    if (!reqData || reqData.length == 0 || reqData.length > 4 * 1024 * 1024) {
        close(sock);
        if (errorMessage) *errorMessage = @"Failed to serialize helperd spawn request";
        return NO;
    }

    uint32_t netReqLen = htonl((uint32_t)reqData.length);
    if (!MCPWriteAllSocket(sock, &netReqLen, sizeof(netReqLen)) ||
        !MCPWriteAllSocket(sock, reqData.bytes, reqData.length)) {
        close(sock);
        if (errorMessage) *errorMessage = @"Failed to send spawn request to mcp-helperd";
        return NO;
    }

    uint32_t netRespLen = 0;
    if (!MCPReadExactSocket(sock, &netRespLen, sizeof(netRespLen))) {
        close(sock);
        if (errorMessage) *errorMessage = [NSString stringWithFormat:@"Command timed out after %.0fs", effectiveTimeout];
        return NO;
    }

    uint32_t respLen = ntohl(netRespLen);
    if (respLen == 0 || respLen > 32 * 1024 * 1024) {
        close(sock);
        if (errorMessage) *errorMessage = @"Invalid response length from mcp-helperd";
        return NO;
    }

    NSMutableData *respBytes = [NSMutableData dataWithLength:respLen];
    if (!respBytes || !MCPReadExactSocket(sock, respBytes.mutableBytes, respLen)) {
        close(sock);
        if (errorMessage) *errorMessage = @"Failed to read response payload from mcp-helperd";
        return NO;
    }
    close(sock);

    NSDictionary *resp = [NSJSONSerialization JSONObjectWithData:respBytes options:0 error:nil];
    if (![resp isKindOfClass:[NSDictionary class]]) {
        if (errorMessage) *errorMessage = @"Malformed JSON response from mcp-helperd";
        return NO;
    }

    BOOL ok = [resp[@"ok"] respondsToSelector:@selector(boolValue)] && [resp[@"ok"] boolValue];
    if (!ok) {
        NSString *err = [resp[@"error"] isKindOfClass:[NSString class]] ? resp[@"error"] : @"mcp-helperd execution failed";
        if (errorMessage) *errorMessage = err;
        return NO;
    }

    int code = [resp[@"exit_code"] respondsToSelector:@selector(intValue)] ? [resp[@"exit_code"] intValue] : -1;
    BOOL trunc = [resp[@"truncated"] respondsToSelector:@selector(boolValue)] && [resp[@"truncated"] boolValue];
    NSString *b64 = [resp[@"output_base64"] isKindOfClass:[NSString class]] ? resp[@"output_base64"] : @"";
    NSData *decoded = b64.length > 0 ? [[NSData alloc] initWithBase64EncodedString:b64 options:0] : [NSData data];

    if (outputData) *outputData = decoded ?: [NSData data];
    if (truncatedOut) *truncatedOut = trunc;
    if (exitCode) *exitCode = code;
    return YES;
}

static char **MCPCreateCStringArray(NSArray<NSString *> *strings) {
    NSUInteger count = strings.count;
    char **array = calloc(count + 1, sizeof(char *));
    if (!array) return NULL;

    for (NSUInteger i = 0; i < count; i++) {
        const char *utf8 = [strings[i] UTF8String];
        array[i] = strdup(utf8 ?: "");
        if (!array[i]) {
            for (NSUInteger j = 0; j < i; j++) free(array[j]);
            free(array);
            return NULL;
        }
    }

    array[count] = NULL;
    return array;
}

static void MCPFreeCStringArray(char **array, NSUInteger count) {
    if (!array) return;
    for (NSUInteger i = 0; i < count; i++) {
        free(array[i]);
    }
    free(array);
}

static void MCPInitSpawnAttributes(posix_spawnattr_t *attr) {
    posix_spawnattr_init(attr);
#ifdef POSIX_SPAWN_CLOEXEC_DEFAULT
    short flags = 0;
    if (posix_spawnattr_getflags(attr, &flags) == 0) {
        flags |= POSIX_SPAWN_CLOEXEC_DEFAULT;
        posix_spawnattr_setflags(attr, flags);
    }
#endif
}

BOOL MCPIsExecutableFile(NSString *path) {
    if (!path.length) return NO;
    if ([[NSFileManager defaultManager] isExecutableFileAtPath:path]) {
        return YES;
    }
    // On iOS 18.5 Dopamine RootHide, SpringBoard's Seatbelt sandbox denies unhooked
    // access(path, X_OK) inside .jbroot with EPERM even though systemhook's
    // posix_spawn hook grants jbd execution trust at spawn time. Fall back to stat()
    // regular-file + execute-mode bit check.
    const char *fsPath = path.fileSystemRepresentation;
    if (!fsPath || !*fsPath) return NO;
    struct stat st;
    if (stat(fsPath, &st) != 0) return NO;
    return S_ISREG(st.st_mode) && ((st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0);
}

NSString *MCPResolvedJailbreakPath(NSString *path) {
    if (!path.length) return @"";

    NSFileManager *fm = [NSFileManager defaultManager];
#ifdef MCP_ROOTHIDE
    if ([path rangeOfString:@"/.jbroot-"].location != NSNotFound) {
        return path;
    }
    NSString *jbRootBase = jbroot(@"/");
    while (jbRootBase.length > 1 && [jbRootBase hasSuffix:@"/"]) {
        jbRootBase = [jbRootBase substringToIndex:jbRootBase.length - 1];
    }
    if (jbRootBase.length > 1) {
        NSString *privateJBRoot = [@"/private" stringByAppendingString:jbRootBase];
        if ([path hasPrefix:jbRootBase] || [path hasPrefix:privateJBRoot]) {
            return path;
        }
    }

    BOOL forceJBRoot =
        [path isEqualToString:@"/var/mobile/Library/ios-mcp"] ||
        [path hasPrefix:@"/var/mobile/Library/ios-mcp/"] ||
        [path isEqualToString:@"/private/var/mobile/Library/ios-mcp"] ||
        [path hasPrefix:@"/private/var/mobile/Library/ios-mcp/"] ||
        [path isEqualToString:@"/var/mobile/Library/Caches/ios-mcp-work"] ||
        [path hasPrefix:@"/var/mobile/Library/Caches/ios-mcp-work/"] ||
        [path isEqualToString:@"/var/mobile/Library/Caches/ios-mcp-uploads"] ||
        [path hasPrefix:@"/var/mobile/Library/Caches/ios-mcp-uploads/"] ||
        [path isEqualToString:@"/var/mobile/Library/Caches/ios-mcp-appmod"] ||
        [path hasPrefix:@"/var/mobile/Library/Caches/ios-mcp-appmod/"] ||
        [path isEqualToString:@"/var/mobile/Library/RootHide"] ||
        [path hasPrefix:@"/var/mobile/Library/RootHide/"];
    if (forceJBRoot) {
        NSString *jb = jbroot(path);
        if (jb.length) return jb;
    }

    BOOL preferRealRootFS =
        [path hasPrefix:@"/var/mobile/"] || [path isEqualToString:@"/var/mobile"] ||
        [path hasPrefix:@"/private/var/mobile/"] || [path isEqualToString:@"/private/var/mobile"] ||
        [path hasPrefix:@"/var/containers/"] || [path hasPrefix:@"/private/var/containers/"] ||
        [path hasPrefix:@"/var/tmp/"] || [path isEqualToString:@"/var/tmp"] ||
        [path hasPrefix:@"/private/var/tmp/"] || [path hasPrefix:@"/tmp/"] || [path isEqualToString:@"/tmp"] ||
        [path hasPrefix:@"/System/"] || [path hasPrefix:@"/Developer/"];

    if (preferRealRootFS) {
        if ([fm fileExistsAtPath:path]) return path;
        NSString *parent = [path stringByDeletingLastPathComponent];
        if (parent.length > 0 && [fm fileExistsAtPath:parent]) return path;
    }

    NSString *resolved = jbroot(path);
    if (resolved.length && [fm fileExistsAtPath:resolved]) return resolved;
    if ([fm fileExistsAtPath:path]) return path;
    NSString *resolvedParent = [resolved stringByDeletingLastPathComponent];
    if (resolved.length && resolvedParent.length > 0 && [fm fileExistsAtPath:resolvedParent]) return resolved;
    NSString *parent = [path stringByDeletingLastPathComponent];
    if (parent.length > 0 && [fm fileExistsAtPath:parent]) return path;
    return resolved.length ? resolved : path;
#elif defined(MCP_ROOTLESS)
    if ([path hasPrefix:@"/"] && ![path hasPrefix:@"/var/jb/"]) {
        NSString *candidate = [@"/var/jb" stringByAppendingString:path];
        if ([fm fileExistsAtPath:candidate]) return candidate;
    }
    return path;
#else
    return path;
#endif
}

NSString *MCPBootstrapPathForRootHide(NSString *path) {
    if (!path.length) return @"";
#ifdef MCP_ROOTHIDE
    NSString *converted = rootfs(path);
    return converted.length > 0 ? converted : path;
#else
    return path;
#endif
}

NSDictionary<NSString *, NSString *> *MCPJailbreakEnvironment(void) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSMutableOrderedSet<NSString *> *pathEntries = [NSMutableOrderedSet orderedSet];

    for (NSString *candidate in @[
        MCPResolvedJailbreakPath(@"/usr/bin"),
        MCPResolvedJailbreakPath(@"/bin"),
        MCPResolvedJailbreakPath(@"/usr/sbin"),
        MCPResolvedJailbreakPath(@"/sbin"),
        @"/usr/bin",
        @"/bin",
        @"/usr/sbin",
        @"/sbin"
    ]) {
        BOOL isDir = NO;
        if (candidate.length && [fm fileExistsAtPath:candidate isDirectory:&isDir] && isDir) {
            [pathEntries addObject:candidate];
        }
    }

    NSMutableDictionary<NSString *, NSString *> *environment = [NSMutableDictionary dictionary];
    if (pathEntries.count > 0) {
        environment[@"PATH"] = [[pathEntries array] componentsJoinedByString:@":"];
    }

    NSString *libraryPath = MCPResolvedJailbreakPath(@"/usr/lib");
    BOOL isDir = NO;
    if (libraryPath.length &&
        ![libraryPath isEqualToString:@"/usr/lib"] &&
        [fm fileExistsAtPath:libraryPath isDirectory:&isDir] &&
        isDir) {
        environment[@"DYLD_LIBRARY_PATH"] = libraryPath;
        environment[@"DYLD_FALLBACK_LIBRARY_PATH"] = libraryPath;
    }

    return environment;
}

BOOL MCPRunProcess(NSString *launchPath,
                   NSArray<NSString *> *arguments,
                   NSDictionary<NSString *, NSString *> *environmentOverrides,
                   NSTimeInterval timeout,
                   NSUInteger maxOutputBytes,
                   NSString **output,
                   int *exitCode,
                   NSString **errorMessage) {
    if (output) *output = @"";
    if (exitCode) *exitCode = -1;
    if (errorMessage) *errorMessage = nil;

    if (!launchPath.length) {
        if (errorMessage) *errorMessage = @"Empty launch path";
        return NO;
    }

    if (!MCPIsExecutableFile(launchPath)) {
        if (errorMessage) *errorMessage = [NSString stringWithFormat:@"Executable not found: %@", launchPath];
        return NO;
    }

    int pipeFDs[2] = {-1, -1};
    if (pipe(pipeFDs) != 0) {
        if (errorMessage) *errorMessage = [NSString stringWithFormat:@"pipe failed: %s", strerror(errno)];
        return NO;
    }
    if (!MCPKeepFDAboveStdio(&pipeFDs[0]) || !MCPKeepFDAboveStdio(&pipeFDs[1])) {
        if (pipeFDs[0] >= 0) close(pipeFDs[0]);
        if (pipeFDs[1] >= 0) close(pipeFDs[1]);
        if (errorMessage) *errorMessage = @"Failed to reserve process pipe descriptors above stdio";
        return NO;
    }

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
    posix_spawn_file_actions_adddup2(&actions, pipeFDs[1], STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions, pipeFDs[1], STDERR_FILENO);
    posix_spawn_file_actions_addclose(&actions, pipeFDs[0]);
    posix_spawn_file_actions_addclose(&actions, pipeFDs[1]);

    NSMutableArray<NSString *> *argvStrings = [NSMutableArray arrayWithObject:launchPath.lastPathComponent ?: launchPath];
    if (arguments.count > 0) {
        [argvStrings addObjectsFromArray:arguments];
    }

    char **argv = MCPCreateCStringArray(argvStrings);
    if (!argv) {
        close(pipeFDs[0]);
        close(pipeFDs[1]);
        posix_spawn_file_actions_destroy(&actions);
        if (errorMessage) *errorMessage = @"Failed to allocate argv";
        return NO;
    }

    char **envp = environ;
    NSUInteger envCount = 0;
    NSDictionary<NSString *, NSString *> *baseEnvironment = [[NSProcessInfo processInfo] environment] ?: @{};
    NSMutableDictionary<NSString *, NSString *> *mergedEnvironment = nil;
    if (environmentOverrides.count > 0) {
        mergedEnvironment = [NSMutableDictionary dictionaryWithDictionary:baseEnvironment];
        [mergedEnvironment addEntriesFromDictionary:environmentOverrides];

        NSMutableArray<NSString *> *envStrings = [NSMutableArray arrayWithCapacity:mergedEnvironment.count];
        [mergedEnvironment enumerateKeysAndObjectsUsingBlock:^(NSString *key, NSString *value, BOOL *stop) {
            [envStrings addObject:[NSString stringWithFormat:@"%@=%@", key, value ?: @""]];
        }];
        envCount = envStrings.count;
        envp = MCPCreateCStringArray(envStrings);
        if (!envp) {
            MCPFreeCStringArray(argv, argvStrings.count);
            close(pipeFDs[0]);
            close(pipeFDs[1]);
            posix_spawn_file_actions_destroy(&actions);
            if (errorMessage) *errorMessage = @"Failed to allocate environment";
            return NO;
        }
    }

    pid_t pid = 0;
    posix_spawnattr_t attr;
    MCPInitSpawnAttributes(&attr);
    int spawnStatus = posix_spawn(&pid, launchPath.fileSystemRepresentation, &actions, &attr, argv, envp);
    posix_spawnattr_destroy(&attr);

    MCPFreeCStringArray(argv, argvStrings.count);
    if (environmentOverrides.count > 0) {
        MCPFreeCStringArray(envp, envCount);
    }
    posix_spawn_file_actions_destroy(&actions);
    close(pipeFDs[1]);

    if (spawnStatus != 0) {
        close(pipeFDs[0]);
        if (spawnStatus == EPERM || spawnStatus == EACCES) {
            NSData *proxiedData = nil;
            BOOL proxiedTruncated = NO;
            int proxiedExit = -1;
            if (MCPRunProcessViaHelperDaemon(launchPath,
                                             arguments,
                                             environmentOverrides,
                                             timeout,
                                             maxOutputBytes,
                                             &proxiedData,
                                             &proxiedTruncated,
                                             &proxiedExit,
                                             errorMessage)) {
                NSString *decoded = [[NSString alloc] initWithData:proxiedData encoding:NSUTF8StringEncoding];
                if (!decoded) {
                    decoded = [[NSString alloc] initWithData:proxiedData encoding:NSISOLatin1StringEncoding] ?: @"(binary output)";
                }
                if (proxiedTruncated) {
                    decoded = [decoded stringByAppendingString:@"\n... (output truncated)"];
                }
                if (output) *output = decoded ?: @"";
                if (exitCode) *exitCode = proxiedExit;
                return YES;
            }
            return NO;
        }
        if (errorMessage) *errorMessage = [NSString stringWithFormat:@"posix_spawn failed for %@: %s", launchPath, strerror(spawnStatus)];
        return NO;
    }

    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    __block NSMutableData *captured = [NSMutableData data];
    __block NSString *capturedOutput = @"";
    __block int localExitCode = -1;
    __block BOOL truncated = NO;
    int readFD = pipeFDs[0];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        char buffer[4096];
        ssize_t bytesRead = 0;

        while ((bytesRead = read(readFD, buffer, sizeof(buffer))) > 0) {
            NSUInteger remaining = maxOutputBytes > captured.length ? (maxOutputBytes - captured.length) : 0;
            if (remaining > 0) {
                NSUInteger chunk = (NSUInteger)MIN((NSUInteger)bytesRead, remaining);
                [captured appendBytes:buffer length:chunk];
            }
            if (captured.length >= maxOutputBytes) {
                truncated = YES;
            }
        }

        close(readFD);

        int status = 0;
        if (waitpid(pid, &status, 0) > 0) {
            if (WIFEXITED(status)) {
                localExitCode = WEXITSTATUS(status);
            } else if (WIFSIGNALED(status)) {
                localExitCode = 128 + WTERMSIG(status);
            }
        }

        capturedOutput = [[NSString alloc] initWithData:captured encoding:NSUTF8StringEncoding];
        if (!capturedOutput) {
            capturedOutput = [[NSString alloc] initWithData:captured encoding:NSISOLatin1StringEncoding] ?: @"(binary output)";
        }
        if (truncated) {
            capturedOutput = [capturedOutput stringByAppendingString:@"\n... (output truncated)"];
        }

        dispatch_semaphore_signal(sem);
    });

    long waitResult = dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(MAX(timeout, 0.1) * NSEC_PER_SEC)));
    if (waitResult != 0) {
        kill(pid, SIGKILL);
        if (errorMessage) *errorMessage = [NSString stringWithFormat:@"Command timed out after %.0fs", timeout];
        return NO;
    }

    if (output) *output = capturedOutput ?: @"";
    if (exitCode) *exitCode = localExitCode;
    return YES;
}

BOOL MCPRunProcessData(NSString *launchPath,
                       NSArray<NSString *> *arguments,
                       NSDictionary<NSString *, NSString *> *environmentOverrides,
                       NSTimeInterval timeout,
                       NSUInteger maxOutputBytes,
                       NSData **outputData,
                       BOOL *truncatedOut,
                       int *exitCode,
                       NSString **errorMessage) {
    if (outputData) *outputData = [NSData data];
    if (truncatedOut) *truncatedOut = NO;
    if (exitCode) *exitCode = -1;
    if (errorMessage) *errorMessage = nil;

    if (!launchPath.length) {
        if (errorMessage) *errorMessage = @"Empty launch path";
        return NO;
    }

    if (!MCPIsExecutableFile(launchPath)) {
        if (errorMessage) *errorMessage = [NSString stringWithFormat:@"Executable not found: %@", launchPath];
        return NO;
    }

    int pipeFDs[2] = {-1, -1};
    if (pipe(pipeFDs) != 0) {
        if (errorMessage) *errorMessage = [NSString stringWithFormat:@"pipe failed: %s", strerror(errno)];
        return NO;
    }
    if (!MCPKeepFDAboveStdio(&pipeFDs[0]) || !MCPKeepFDAboveStdio(&pipeFDs[1])) {
        if (pipeFDs[0] >= 0) close(pipeFDs[0]);
        if (pipeFDs[1] >= 0) close(pipeFDs[1]);
        if (errorMessage) *errorMessage = @"Failed to reserve process pipe descriptors above stdio";
        return NO;
    }

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
    posix_spawn_file_actions_adddup2(&actions, pipeFDs[1], STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions, pipeFDs[1], STDERR_FILENO);
    posix_spawn_file_actions_addclose(&actions, pipeFDs[0]);
    posix_spawn_file_actions_addclose(&actions, pipeFDs[1]);

    NSMutableArray<NSString *> *argvStrings = [NSMutableArray arrayWithObject:launchPath.lastPathComponent ?: launchPath];
    if (arguments.count > 0) {
        [argvStrings addObjectsFromArray:arguments];
    }

    char **argv = MCPCreateCStringArray(argvStrings);
    if (!argv) {
        close(pipeFDs[0]);
        close(pipeFDs[1]);
        posix_spawn_file_actions_destroy(&actions);
        if (errorMessage) *errorMessage = @"Failed to allocate argv";
        return NO;
    }

    char **envp = environ;
    NSUInteger envCount = 0;
    NSDictionary<NSString *, NSString *> *baseEnvironment = [[NSProcessInfo processInfo] environment] ?: @{};
    NSMutableDictionary<NSString *, NSString *> *mergedEnvironment = nil;
    if (environmentOverrides.count > 0) {
        mergedEnvironment = [NSMutableDictionary dictionaryWithDictionary:baseEnvironment];
        [mergedEnvironment addEntriesFromDictionary:environmentOverrides];

        NSMutableArray<NSString *> *envStrings = [NSMutableArray arrayWithCapacity:mergedEnvironment.count];
        [mergedEnvironment enumerateKeysAndObjectsUsingBlock:^(NSString *key, NSString *value, BOOL *stop) {
            [envStrings addObject:[NSString stringWithFormat:@"%@=%@", key, value ?: @""]];
        }];
        envCount = envStrings.count;
        envp = MCPCreateCStringArray(envStrings);
        if (!envp) {
            MCPFreeCStringArray(argv, argvStrings.count);
            close(pipeFDs[0]);
            close(pipeFDs[1]);
            posix_spawn_file_actions_destroy(&actions);
            if (errorMessage) *errorMessage = @"Failed to allocate environment";
            return NO;
        }
    }

    pid_t pid = 0;
    posix_spawnattr_t attr;
    MCPInitSpawnAttributes(&attr);
    int spawnStatus = posix_spawn(&pid, launchPath.fileSystemRepresentation, &actions, &attr, argv, envp);
    posix_spawnattr_destroy(&attr);

    MCPFreeCStringArray(argv, argvStrings.count);
    if (environmentOverrides.count > 0) {
        MCPFreeCStringArray(envp, envCount);
    }
    posix_spawn_file_actions_destroy(&actions);
    close(pipeFDs[1]);

    if (spawnStatus != 0) {
        close(pipeFDs[0]);
        if (spawnStatus == EPERM || spawnStatus == EACCES) {
            return MCPRunProcessViaHelperDaemon(launchPath,
                                                arguments,
                                                environmentOverrides,
                                                timeout,
                                                maxOutputBytes,
                                                outputData,
                                                truncatedOut,
                                                exitCode,
                                                errorMessage);
        }
        if (errorMessage) *errorMessage = [NSString stringWithFormat:@"posix_spawn failed for %@: %s", launchPath, strerror(spawnStatus)];
        return NO;
    }

    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    __block NSMutableData *captured = [NSMutableData data];
    __block int localExitCode = -1;
    __block BOOL truncated = NO;
    int readFD = pipeFDs[0];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        char buffer[4096];
        ssize_t bytesRead = 0;

        while ((bytesRead = read(readFD, buffer, sizeof(buffer))) > 0) {
            NSUInteger remaining = maxOutputBytes > captured.length ? (maxOutputBytes - captured.length) : 0;
            if (remaining > 0) {
                NSUInteger chunk = (NSUInteger)MIN((NSUInteger)bytesRead, remaining);
                [captured appendBytes:buffer length:chunk];
            }
            if (captured.length >= maxOutputBytes) {
                truncated = YES;
            }
        }

        close(readFD);

        int status = 0;
        if (waitpid(pid, &status, 0) > 0) {
            if (WIFEXITED(status)) {
                localExitCode = WEXITSTATUS(status);
            } else if (WIFSIGNALED(status)) {
                localExitCode = 128 + WTERMSIG(status);
            }
        }

        dispatch_semaphore_signal(sem);
    });

    long waitResult = dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(MAX(timeout, 0.1) * NSEC_PER_SEC)));
    if (waitResult != 0) {
        kill(pid, SIGKILL);
        if (errorMessage) *errorMessage = [NSString stringWithFormat:@"Command timed out after %.0fs", timeout];
        return NO;
    }

    if (outputData) *outputData = [captured copy];
    if (truncatedOut) *truncatedOut = truncated;
    if (exitCode) *exitCode = localExitCode;
    return YES;
}

NSString *MCPRootHelperPath(void) {
    NSString *path = MCPResolvedJailbreakPath(@"/usr/bin/mcp-root");
    if (path.length && MCPIsExecutableFile(path)) {
        return path;
    }
    return nil;
}

BOOL MCPRunRootProcess(NSString *launchPath,
                       NSArray<NSString *> *arguments,
                       NSTimeInterval timeout,
                       NSUInteger maxOutputBytes,
                       NSString **output,
                       int *exitCode,
                       NSString **errorMessage) {
    NSString *rootHelper = MCPRootHelperPath();
    if (!rootHelper.length) {
        if (errorMessage) *errorMessage = @"mcp-root helper not available";
        return NO;
    }
    NSMutableArray<NSString *> *argv = [NSMutableArray arrayWithObject:launchPath ?: @""];
    if (arguments.count > 0) {
        [argv addObjectsFromArray:arguments];
    }
    return MCPRunProcess(rootHelper,
                         argv,
                         MCPJailbreakEnvironment(),
                         timeout,
                         maxOutputBytes,
                         output,
                         exitCode,
                         errorMessage);
}

BOOL MCPRunRootProcessData(NSString *launchPath,
                           NSArray<NSString *> *arguments,
                           NSTimeInterval timeout,
                           NSUInteger maxOutputBytes,
                           NSData **outputData,
                           BOOL *truncated,
                           int *exitCode,
                           NSString **errorMessage) {
    NSString *rootHelper = MCPRootHelperPath();
    if (!rootHelper.length) {
        if (errorMessage) *errorMessage = @"mcp-root helper not available";
        return NO;
    }

    NSMutableArray<NSString *> *argv = [NSMutableArray arrayWithObject:launchPath ?: @""];
    if (arguments.count > 0) {
        [argv addObjectsFromArray:arguments];
    }
    return MCPRunProcessData(rootHelper,
                             argv,
                             MCPJailbreakEnvironment(),
                             timeout,
                             maxOutputBytes,
                             outputData,
                             truncated,
                             exitCode,
                             errorMessage);
}

NSString *MCPJailbreakRoot(void) {
#ifdef MCP_ROOTHIDE
    NSString *r = jbroot(@"/");
    if ([r hasSuffix:@"/"] && r.length > 1) {
        r = [r substringToIndex:r.length - 1];
    }
    return r.length ? r : @"/";
#elif defined(MCP_ROOTLESS)
    return @"/var/jb";
#else
    NSString *resolved = MCPResolvedJailbreakPath(@"/Library/MobileSubstrate");
    if ([resolved hasPrefix:@"/var/jb/"]) return @"/var/jb";
    NSRange r = [resolved rangeOfString:@"/Library/MobileSubstrate"];
    if (r.location != NSNotFound && r.location > 0) {
        return [resolved substringToIndex:r.location];
    }
    return @"/";
#endif
}

NSString *MCPSubPath(NSString *relPath) {
    if (!relPath.length) return MCPJailbreakRoot();
    NSString *withSlash = [relPath hasPrefix:@"/"] ? relPath : [@"/" stringByAppendingString:relPath];
    return MCPResolvedJailbreakPath(withSlash);
}

NSString *MCPCommandSearchPath(void) {
    NSDictionary<NSString *, NSString *> *env = MCPJailbreakEnvironment();
    return env[@"PATH"] ?: @"/var/jb/usr/bin:/var/jb/bin:/var/jb/usr/sbin:/var/jb/sbin:/usr/bin:/bin:/usr/sbin:/sbin";
}

NSString *MCPReadCommandOutput(NSArray<NSString *> *cmdAndArgs,
                               NSTimeInterval timeout,
                               int *exitCodeOut) {
    if (exitCodeOut) *exitCodeOut = -1;
    if (![cmdAndArgs isKindOfClass:[NSArray class]] || cmdAndArgs.count == 0) {
        return @"";
    }
    NSString *cmd = [cmdAndArgs[0] description];
    NSArray<NSString *> *args = cmdAndArgs.count > 1
        ? [cmdAndArgs subarrayWithRange:NSMakeRange(1, cmdAndArgs.count - 1)]
        : @[];

    NSString *launchPath = nil;
    if ([cmd hasPrefix:@"/"]) {
        NSString *resolved = MCPResolvedJailbreakPath(cmd);
        launchPath = MCPIsExecutableFile(resolved) ? resolved : cmd;
    } else {
        NSArray<NSString *> *dirs = [MCPCommandSearchPath() componentsSeparatedByString:@":"];
        for (NSString *d in dirs) {
            if (!d.length) continue;
            NSString *cand = [d stringByAppendingPathComponent:cmd];
            if (MCPIsExecutableFile(cand)) {
                launchPath = cand;
                break;
            }
        }
        if (!launchPath.length) {
            NSString *cand = MCPSubPath([@"usr/bin/" stringByAppendingString:cmd]);
            if (MCPIsExecutableFile(cand)) launchPath = cand;
        }
        if (!launchPath.length) {
            NSString *cand = MCPSubPath([@"bin/" stringByAppendingString:cmd]);
            if (MCPIsExecutableFile(cand)) launchPath = cand;
        }
        if (!launchPath.length) {
            launchPath = [@"/usr/bin/" stringByAppendingString:cmd];
        }
    }

    NSString *output = nil;
    NSString *errMsg = nil;
    int code = -1;
    BOOL ok = MCPRunRootProcess(launchPath, args, timeout > 0 ? timeout : 15.0, 512 * 1024, &output, &code, &errMsg);
    if (!ok) {
        ok = MCPRunProcess(launchPath, args, MCPJailbreakEnvironment(), timeout > 0 ? timeout : 15.0, 512 * 1024, &output, &code, &errMsg);
    }
    if (exitCodeOut) *exitCodeOut = code;
    if (output.length) return output;
    if (errMsg.length) return errMsg;
    return @"";
}

