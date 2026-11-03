#import <Foundation/Foundation.h>
#ifdef MCP_ROOTHIDE
#include <roothide.h>
#endif
#import <arpa/inet.h>
#import <dispatch/dispatch.h>
#import <errno.h>
#import <fcntl.h>
#import <mach-o/dyld.h>
#import <netinet/in.h>
#import <poll.h>
#import <signal.h>
#import <spawn.h>
#import <stdlib.h>
#import <string.h>
#import <sys/socket.h>
#import <sys/stat.h>
#import <sys/un.h>
#import <sys/wait.h>
#import <unistd.h>

extern char **environ;

#define MCP_HELPERD_WORK_DIR  "/var/mobile/Library/Caches/ios-mcp-work"
#define MCP_HELPERD_SOCK_PATH "/var/mobile/Library/Caches/ios-mcp-work/.helperd.sock"
#define MCP_HELPERD_PID_PATH  "/var/mobile/Library/Caches/ios-mcp-work/.helperd.pid"
#define MCP_HELPERD_TCP_PORT  48091
#define MCP_HELPERD_OCR_MAGIC 0x4F435231U

static BOOL MCPKeepFDAboveStdio(int *fd) {
    if (!fd || *fd < 0) return NO;
    if (*fd >= 3) return YES;
    int moved = fcntl(*fd, F_DUPFD_CLOEXEC, 3);
    if (moved < 0) return NO;
    close(*fd);
    *fd = moved;
    return YES;
}

static BOOL MCPWriteAll(int fd, const void *buf, size_t len) {
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

static BOOL MCPReadExact(int fd, void *buf, size_t len) {
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

static NSString *MCPResolveJBPath(NSString *path) {
    if (!path.length) return @"";
#ifdef MCP_ROOTHIDE
    if ([path rangeOfString:@"/.jbroot-"].location != NSNotFound) {
        return path;
    }
    NSString *resolved = jbroot(path);
    if (resolved.length && [[NSFileManager defaultManager] fileExistsAtPath:resolved]) {
        return resolved;
    }
    return resolved.length ? resolved : path;
#else
    if ([path hasPrefix:@"/"] && ![path hasPrefix:@"/var/jb/"]) {
        NSString *cand = [@"/var/jb" stringByAppendingString:path];
        if ([[NSFileManager defaultManager] fileExistsAtPath:cand]) return cand;
    }
    return path;
#endif
}

static void MCPHandleOCRStreamSession(int clientFD) {
    NSString *workerPath = MCPResolveJBPath(@"/usr/libexec/ios-mcp/mcp-ocr-worker");
    NSString *resourcesPath = MCPResolveJBPath(@"/usr/share/ios-mcp/paddleocr");

    int pair[2] = {-1, -1};
    int diag[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) {
        uint32_t zero = 0;
        MCPWriteAll(clientFD, &zero, sizeof(zero));
        close(clientFD);
        return;
    }
    if (pipe(diag) != 0) {
        close(pair[0]);
        close(pair[1]);
        uint32_t zero = 0;
        MCPWriteAll(clientFD, &zero, sizeof(zero));
        close(clientFD);
        return;
    }
    if (!MCPKeepFDAboveStdio(&pair[0]) || !MCPKeepFDAboveStdio(&pair[1]) ||
        !MCPKeepFDAboveStdio(&diag[0]) || !MCPKeepFDAboveStdio(&diag[1])) {
        close(pair[0]);
        close(pair[1]);
        close(diag[0]);
        close(diag[1]);
        uint32_t zero = 0;
        MCPWriteAll(clientFD, &zero, sizeof(zero));
        close(clientFD);
        return;
    }

    int yes = 1;
    setsockopt(pair[0], SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes));
    setsockopt(clientFD, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes));
    fcntl(diag[0], F_SETFL, O_NONBLOCK);
    fcntl(diag[0], F_SETFD, FD_CLOEXEC);
    fcntl(diag[1], F_SETFD, FD_CLOEXEC);
    fcntl(pair[0], F_SETFD, FD_CLOEXEC);
    fcntl(pair[1], F_SETFD, FD_CLOEXEC);

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, pair[1], STDIN_FILENO);
    posix_spawn_file_actions_adddup2(&actions, pair[1], STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions, diag[1], STDERR_FILENO);
    posix_spawn_file_actions_addclose(&actions, diag[0]);
    posix_spawn_file_actions_addclose(&actions, diag[1]);
    posix_spawn_file_actions_addclose(&actions, pair[0]);
    posix_spawn_file_actions_addclose(&actions, pair[1]);

    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
#ifdef POSIX_SPAWN_CLOEXEC_DEFAULT
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_CLOEXEC_DEFAULT);
#endif

    char *argv[] = {
        (char *)workerPath.fileSystemRepresentation,
        "--resources",
        (char *)resourcesPath.fileSystemRepresentation,
        NULL
    };
    char *env[] = {"PATH=/usr/bin:/bin", "LANG=en_US.UTF-8", NULL};
    pid_t workerPid = -1;
    int status = posix_spawn(&workerPid, workerPath.fileSystemRepresentation, &actions, &attr, argv, env);
    posix_spawnattr_destroy(&attr);
    posix_spawn_file_actions_destroy(&actions);
    close(pair[1]);
    close(diag[1]);

    if (status != 0 || workerPid <= 0) {
        close(pair[0]);
        close(diag[0]);
        uint32_t zero = 0;
        MCPWriteAll(clientFD, &zero, sizeof(zero));
        close(clientFD);
        return;
    }

    uint32_t netPid = htonl((uint32_t)workerPid);
    if (!MCPWriteAll(clientFD, &netPid, sizeof(netPid))) {
        close(pair[0]);
        close(diag[0]);
        close(clientFD);
        kill(workerPid, SIGKILL);
        int st = 0;
        while (waitpid(workerPid, &st, 0) < 0 && errno == EINTR) {}
        return;
    }

    uint8_t buf[16384];
    uint8_t drainBuf[1024];
    while (1) {
        struct pollfd pfd[3];
        pfd[0].fd = clientFD;
        pfd[0].events = POLLIN;
        pfd[0].revents = 0;
        pfd[1].fd = pair[0];
        pfd[1].events = POLLIN;
        pfd[1].revents = 0;
        pfd[2].fd = diag[0];
        pfd[2].events = POLLIN;
        pfd[2].revents = 0;

        int ready = poll(pfd, 3, 1000);
        if (ready < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (pfd[2].revents & POLLIN) {
            while (read(diag[0], drainBuf, sizeof(drainBuf)) > 0) {}
        }
        if (pfd[0].revents & POLLIN) {
            ssize_t n = read(clientFD, buf, sizeof(buf));
            if (n <= 0) break;
            if (!MCPWriteAll(pair[0], buf, (size_t)n)) break;
        } else if (pfd[0].revents & (POLLHUP | POLLERR | POLLNVAL)) {
            break;
        }
        if (pfd[1].revents & POLLIN) {
            ssize_t n = read(pair[0], buf, sizeof(buf));
            if (n <= 0) break;
            if (!MCPWriteAll(clientFD, buf, (size_t)n)) break;
        } else if (pfd[1].revents & (POLLHUP | POLLERR | POLLNVAL)) {
            break;
        }
    }

    close(pair[0]);
    close(diag[0]);
    close(clientFD);

    int st = 0;
    pid_t w = 0;
    do { w = waitpid(workerPid, &st, WNOHANG); } while (w < 0 && errno == EINTR);
    if (w == 0) {
        kill(workerPid, SIGKILL);
        while (waitpid(workerPid, &st, 0) < 0 && errno == EINTR) {}
    }
}

static NSDictionary *MCPRunSyncProcessRequest(NSDictionary *req) {
    NSString *launchPath = [req[@"launch_path"] isKindOfClass:[NSString class]] ? req[@"launch_path"] : @"";
    NSArray<NSString *> *arguments = [req[@"arguments"] isKindOfClass:[NSArray class]] ? req[@"arguments"] : @[];
    NSDictionary<NSString *, NSString *> *envOverrides = [req[@"environment"] isKindOfClass:[NSDictionary class]] ? req[@"environment"] : nil;
    NSTimeInterval timeout = [req[@"timeout"] respondsToSelector:@selector(doubleValue)] ? [req[@"timeout"] doubleValue] : 15.0;
    NSUInteger maxOutputBytes = [req[@"max_output_bytes"] respondsToSelector:@selector(unsignedIntegerValue)] ? [req[@"max_output_bytes"] unsignedIntegerValue] : (512 * 1024);

    if (!launchPath.length) {
        return @{@"ok": @NO, @"exit_code": @(-1), @"error": @"Empty launch path"};
    }
    if (timeout <= 0) timeout = 15.0;
    if (maxOutputBytes == 0) maxOutputBytes = 512 * 1024;
    if (maxOutputBytes > 16 * 1024 * 1024) maxOutputBytes = 16 * 1024 * 1024;

    int pipeFDs[2] = {-1, -1};
    if (pipe(pipeFDs) != 0) {
        return @{@"ok": @NO, @"exit_code": @(-1), @"error": [NSString stringWithFormat:@"pipe failed: %s", strerror(errno)]};
    }
    if (!MCPKeepFDAboveStdio(&pipeFDs[0]) || !MCPKeepFDAboveStdio(&pipeFDs[1])) {
        if (pipeFDs[0] >= 0) close(pipeFDs[0]);
        if (pipeFDs[1] >= 0) close(pipeFDs[1]);
        return @{@"ok": @NO, @"exit_code": @(-1), @"error": @"Failed to reserve process pipe descriptors"};
    }

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
    posix_spawn_file_actions_adddup2(&actions, pipeFDs[1], STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions, pipeFDs[1], STDERR_FILENO);
    posix_spawn_file_actions_addclose(&actions, pipeFDs[0]);
    posix_spawn_file_actions_addclose(&actions, pipeFDs[1]);

    NSMutableArray<NSString *> *argvStrings = [NSMutableArray arrayWithObject:launchPath.lastPathComponent ?: launchPath];
    for (id item in arguments) {
        if ([item isKindOfClass:[NSString class]]) {
            [argvStrings addObject:item];
        } else if ([item respondsToSelector:@selector(description)]) {
            [argvStrings addObject:[item description]];
        }
    }

    char **argv = MCPCreateCStringArray(argvStrings);
    if (!argv) {
        close(pipeFDs[0]);
        close(pipeFDs[1]);
        posix_spawn_file_actions_destroy(&actions);
        return @{@"ok": @NO, @"exit_code": @(-1), @"error": @"Failed to allocate argv"};
    }

    char **envp = environ;
    NSUInteger envCount = 0;
    NSDictionary<NSString *, NSString *> *baseEnv = [[NSProcessInfo processInfo] environment] ?: @{};
    if ([envOverrides isKindOfClass:[NSDictionary class]] && envOverrides.count > 0) {
        NSMutableDictionary<NSString *, NSString *> *merged = [NSMutableDictionary dictionaryWithDictionary:baseEnv];
        [envOverrides enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
            if ([key isKindOfClass:[NSString class]] && [obj isKindOfClass:[NSString class]]) {
                merged[key] = obj;
            }
        }];
        NSMutableArray<NSString *> *envStrings = [NSMutableArray arrayWithCapacity:merged.count];
        [merged enumerateKeysAndObjectsUsingBlock:^(NSString *key, NSString *val, BOOL *stop) {
            [envStrings addObject:[NSString stringWithFormat:@"%@=%@", key, val ?: @""]];
        }];
        envCount = envStrings.count;
        envp = MCPCreateCStringArray(envStrings);
        if (!envp) {
            MCPFreeCStringArray(argv, argvStrings.count);
            close(pipeFDs[0]);
            close(pipeFDs[1]);
            posix_spawn_file_actions_destroy(&actions);
            return @{@"ok": @NO, @"exit_code": @(-1), @"error": @"Failed to allocate environment"};
        }
    }

    pid_t pid = 0;
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
#ifdef POSIX_SPAWN_CLOEXEC_DEFAULT
    short flags = 0;
    if (posix_spawnattr_getflags(&attr, &flags) == 0) {
        flags |= POSIX_SPAWN_CLOEXEC_DEFAULT;
        posix_spawnattr_setflags(&attr, flags);
    }
#endif

    int spawnStatus = posix_spawn(&pid, launchPath.fileSystemRepresentation, &actions, &attr, argv, envp);
    posix_spawnattr_destroy(&attr);
    MCPFreeCStringArray(argv, argvStrings.count);
    if (envCount > 0) {
        MCPFreeCStringArray(envp, envCount);
    }
    posix_spawn_file_actions_destroy(&actions);
    close(pipeFDs[1]);

    if (spawnStatus != 0) {
        close(pipeFDs[0]);
        return @{
            @"ok": @NO,
            @"exit_code": @(-1),
            @"error": [NSString stringWithFormat:@"posix_spawn failed for %@: %s", launchPath, strerror(spawnStatus)]
        };
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
        pid_t w = 0;
        do { w = waitpid(pid, &status, 0); } while (w < 0 && errno == EINTR);
        if (w > 0) {
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
        return @{
            @"ok": @NO,
            @"timed_out": @YES,
            @"exit_code": @(-1),
            @"error": [NSString stringWithFormat:@"Command timed out after %.0fs", timeout]
        };
    }

    return @{
        @"ok": @YES,
        @"exit_code": @(localExitCode),
        @"truncated": @(truncated),
        @"output_base64": [captured base64EncodedStringWithOptions:0] ?: @""
    };
}

static void MCPHandleClientConnection(int clientFD) {
    @autoreleasepool {
        int yes = 1;
        setsockopt(clientFD, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes));

        uint32_t netHeader = 0;
        if (!MCPReadExact(clientFD, &netHeader, sizeof(netHeader))) {
            close(clientFD);
            return;
        }
        uint32_t header = ntohl(netHeader);
        if (header == MCP_HELPERD_OCR_MAGIC) {
            MCPHandleOCRStreamSession(clientFD);
            return;
        }
        if (header == 0 || header > 4 * 1024 * 1024) {
            close(clientFD);
            return;
        }

        NSMutableData *reqData = [NSMutableData dataWithLength:header];
        if (!reqData || !MCPReadExact(clientFD, reqData.mutableBytes, header)) {
            close(clientFD);
            return;
        }

        NSDictionary *req = [NSJSONSerialization JSONObjectWithData:reqData options:0 error:nil];
        NSDictionary *resp = nil;
        if ([req isKindOfClass:[NSDictionary class]]) {
            resp = MCPRunSyncProcessRequest(req);
        } else {
            resp = @{@"ok": @NO, @"exit_code": @(-1), @"error": @"Malformed helperd request JSON"};
        }

        NSData *respData = [NSJSONSerialization dataWithJSONObject:resp options:0 error:nil];
        if (respData.length > 0 && respData.length <= 32 * 1024 * 1024) {
            uint32_t netRespLen = htonl((uint32_t)respData.length);
            if (MCPWriteAll(clientFD, &netRespLen, sizeof(netRespLen))) {
                MCPWriteAll(clientFD, respData.bytes, respData.length);
            }
        }
        close(clientFD);
    }
}

static int MCPCreateUnixListener(const char *sockPath) {
    unlink(sockPath);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    fcntl(fd, F_SETFD, FD_CLOEXEC);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strlcpy(addr.sun_path, sockPath, sizeof(addr.sun_path));

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    chmod(sockPath, 0666);
    if (listen(fd, 64) != 0) {
        close(fd);
        unlink(sockPath);
        return -1;
    }
    return fd;
}

static int MCPCreateTCPListener(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    fcntl(fd, F_SETFD, FD_CLOEXEC);

    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, 64) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void MCPKillPreviousHelperDaemon(void) {
    FILE *f = fopen(MCP_HELPERD_PID_PATH, "r");
    if (!f) return;
    int oldPid = 0;
    if (fscanf(f, "%d", &oldPid) == 1 && oldPid > 1 && oldPid != (int)getpid()) {
        kill((pid_t)oldPid, SIGKILL);
        usleep(50000);
    }
    fclose(f);
    unlink(MCP_HELPERD_PID_PATH);
}

static void MCPWritePidFile(void) {
    FILE *f = fopen(MCP_HELPERD_PID_PATH, "w");
    if (!f) return;
    fprintf(f, "%d\n", (int)getpid());
    fclose(f);
    chmod(MCP_HELPERD_PID_PATH, 0644);
}

static int MCPSpawnDetachedDaemon(const char *arg0) {
    char exePath[1024];
    uint32_t size = sizeof(exePath);
    const char *spawnPath = arg0;
    if (_NSGetExecutablePath(exePath, &size) == 0 && exePath[0] != '\0') {
        spawnPath = exePath;
    }

    for (int fd = 3; fd < 1024; fd++) {
        close(fd);
    }

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
    posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);

    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
#ifdef POSIX_SPAWN_CLOEXEC_DEFAULT
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_CLOEXEC_DEFAULT);
#endif

    char *argv[] = {(char *)spawnPath, NULL};
    pid_t pid = 0;
    int rc = posix_spawn(&pid, spawnPath, &actions, &attr, argv, environ);
    posix_spawnattr_destroy(&attr);
    posix_spawn_file_actions_destroy(&actions);
    return rc == 0 ? 0 : 1;
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        signal(SIGPIPE, SIG_IGN);

        mkdir(MCP_HELPERD_WORK_DIR, 0755);
        chmod(MCP_HELPERD_WORK_DIR, 0755);
        chown(MCP_HELPERD_WORK_DIR, 501, 501);

        if (argc > 1 && strcmp(argv[1], "--daemon") == 0) {
            MCPKillPreviousHelperDaemon();
            return MCPSpawnDetachedDaemon(argv[0]);
        }

        setsid();
        MCPKillPreviousHelperDaemon();

        if (getuid() == 0 || geteuid() == 0) {
            setgid(501);
            setegid(501);
            setuid(501);
            seteuid(501);
        }

        mkdir(MCP_HELPERD_WORK_DIR, 0755);
        chmod(MCP_HELPERD_WORK_DIR, 0755);
        MCPWritePidFile();

        int unixFD = MCPCreateUnixListener(MCP_HELPERD_SOCK_PATH);
        int tcpFD = MCPCreateTCPListener(MCP_HELPERD_TCP_PORT);
        if (unixFD < 0 && tcpFD < 0) {
            return 1;
        }

        NSMutableArray *activeSources = [NSMutableArray array];
        dispatch_queue_t acceptQueue = dispatch_queue_create("com.witchan.mcp-helperd.accept", DISPATCH_QUEUE_CONCURRENT);
        void (^registerListener)(int) = ^(int listenFD) {
            if (listenFD < 0) return;
            dispatch_source_t src = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, (uintptr_t)listenFD, 0, acceptQueue);
            if (!src) return;
            [activeSources addObject:src];
            dispatch_source_set_event_handler(src, ^{
                int clientFD = accept(listenFD, NULL, NULL);
                if (clientFD >= 0) {
                    fcntl(clientFD, F_SETFD, FD_CLOEXEC);
                    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                        MCPHandleClientConnection(clientFD);
                    });
                }
            });
            dispatch_resume(src);
        };

        registerListener(unixFD);
        registerListener(tcpFD);

        dispatch_main();
    }
    return 0;
}
