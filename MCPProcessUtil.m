#import "MCPProcessUtil.h"
#ifdef MCP_ROOTHIDE
#include <roothide.h>
#endif
#import <dispatch/dispatch.h>
#import <errno.h>
#import <fcntl.h>
#import <signal.h>
#import <spawn.h>
#import <string.h>
#import <sys/stat.h>
#import <sys/wait.h>
#import <unistd.h>

extern char **environ;

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
