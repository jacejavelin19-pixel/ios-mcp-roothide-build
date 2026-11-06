#import "MCPEngineManager.h"
#import "AppManager.h"
#import "MCPProcessUtil.h"
#import <sys/socket.h>
#import <sys/un.h>
#import <poll.h>
#import <errno.h>
#import <string.h>
#import <stdatomic.h>

static NSString *const kMCPEngineLogicalPath  = @"/usr/lib/ios-mcp/libmcpengine.dylib";
static NSString *const kMCPStealthLogicalPath = @"/usr/lib/ios-mcp/libmcp_stealth.dylib";
static NSString *const kMCPEngineSessionsDir  = @"/var/mobile/Library/ios-mcp/engine-sessions";

static NSString *MCPEngineRandomHex(NSUInteger n) {
    NSMutableData *buf = [NSMutableData dataWithLength:n];
    arc4random_buf(buf.mutableBytes, n);
    const uint8_t *b = buf.bytes;
    NSMutableString *s = [NSMutableString stringWithCapacity:n * 2];
    for (NSUInteger i = 0; i < n; i++) [s appendFormat:@"%02x", b[i]];
    return s;
}

static NSString *MCPEngineNormalizeSocket(NSString *p) {
    // Keep sun_path within AF_UNIX's 104-byte limit (strip the /private alias).
    if ([p hasPrefix:@"/private/var/"]) return [p substringFromIndex:8];
    return p;
}

@implementation MCPEngineManager

+ (instancetype)sharedInstance {
    static MCPEngineManager *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ instance = [[MCPEngineManager alloc] init]; });
    return instance;
}

#pragma mark - Session persistence

- (NSString *)sessionsDirectory {
    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *dir = MCPResolvedJailbreakPath(kMCPEngineSessionsDir);
    [fm createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:NULL];
    if ([fm isWritableFileAtPath:dir]) return dir;
    // A legacy jbroot directory may be owned by root. Keep engine sessions in
    // the server user's writable cache rather than silently discarding them.
    NSString *cache = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES).firstObject;
    dir = [cache stringByAppendingPathComponent:@"ios-mcp/engine-sessions"];
    [fm createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:NULL];
    return dir;
}

- (NSString *)sessionFileForBundleId:(NSString *)bundleId {
    NSString *safe = [[bundleId componentsSeparatedByCharactersInSet:
                       [[NSCharacterSet characterSetWithCharactersInString:
                         @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"] invertedSet]]
                      componentsJoinedByString:@"_"];
    return [[self sessionsDirectory] stringByAppendingPathComponent:[NSString stringWithFormat:@"%@.json", safe]];
}

- (NSDictionary *)loadSessionForBundleId:(NSString *)bundleId {
    NSData *d = [NSData dataWithContentsOfFile:[self sessionFileForBundleId:bundleId]];
    if (!d.length) return nil;
    NSDictionary *s = [NSJSONSerialization JSONObjectWithData:d options:0 error:NULL];
    return [s isKindOfClass:[NSDictionary class]] ? s : nil;
}

- (BOOL)saveSession:(NSDictionary *)session forBundleId:(NSString *)bundleId {
    NSData *d = [NSJSONSerialization dataWithJSONObject:session options:NSJSONWritingPrettyPrinted error:NULL];
    return d && [d writeToFile:[self sessionFileForBundleId:bundleId] options:NSDataWritingAtomic error:NULL];
}

- (void)deleteSessionForBundleId:(NSString *)bundleId {
    [[NSFileManager defaultManager] removeItemAtPath:[self sessionFileForBundleId:bundleId] error:nil];
}

#pragma mark - Unix socket RPC

- (NSDictionary *)sendEnvelope:(NSDictionary *)envelope
                    socketPath:(NSString *)rawSocketPath
                     timeoutMs:(NSInteger)timeoutMs
                         error:(NSString **)error {
    if (error) *error = nil;
    NSString *socketPath = MCPEngineNormalizeSocket(rawSocketPath);
    if (!socketPath.length) { if (error) *error = @"Missing engine socket path"; return nil; }
    if (timeoutMs <= 0) timeoutMs = 10000;

    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:envelope options:0 error:NULL];
    if (!jsonData) { if (error) *error = @"Failed to serialize request"; return nil; }

    struct sockaddr_un addr; memset(&addr, 0, sizeof(addr)); addr.sun_family = AF_UNIX;
    const char *cpath = socketPath.fileSystemRepresentation;
    if (!cpath || strlen(cpath) >= sizeof(addr.sun_path)) {
        if (error) *error = @"Engine socket path too long"; return nil;
    }
    strncpy(addr.sun_path, cpath, sizeof(addr.sun_path) - 1);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { if (error) *error = @"socket() failed"; return nil; }
    int one = 1; setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        if (error) *error = @"Engine not reachable (inject the engine and keep the app foregrounded)";
        return nil;
    }

    NSMutableData *wire = [jsonData mutableCopy];
    [wire appendBytes:"\n" length:1];
    const uint8_t *wp = wire.bytes; size_t wr = wire.length; BOOL sentOK = YES;
    while (wr > 0) {
        ssize_t w = send(fd, wp, wr, 0);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) { sentOK = NO; break; }
        wp += (size_t)w; wr -= (size_t)w;
    }
    if (!sentOK) { close(fd); if (error) *error = @"Failed to send request"; return nil; }

    NSMutableData *rbuf = [NSMutableData data];
    CFAbsoluteTime deadline = CFAbsoluteTimeGetCurrent() + ((double)timeoutMs / 1000.0);
    BOOL done = NO;
    while (!done) {
        double rem = deadline - CFAbsoluteTimeGetCurrent();
        if (rem <= 0) break;
        struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
        int pr = poll(&pfd, 1, MAX(1, (int)(rem * 1000.0)));
        if (pr < 0 && errno == EINTR) continue;
        if (pr <= 0) break;
        uint8_t chunk[8192];
        ssize_t r = recv(fd, chunk, sizeof(chunk), 0);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        [rbuf appendBytes:chunk length:(NSUInteger)r];
        const uint8_t *b = rbuf.bytes;
        for (NSUInteger i = 0; i < rbuf.length; i++) {
            if (b[i] == '\n') { rbuf.length = i; done = YES; break; }
        }
    }
    close(fd);

    if (!done || rbuf.length == 0) { if (error) *error = @"Engine response timed out"; return nil; }
    NSDictionary *parsed = [NSJSONSerialization JSONObjectWithData:rbuf options:0 error:NULL];
    if (![parsed isKindOfClass:[NSDictionary class]]) { if (error) *error = @"Malformed engine response"; return nil; }
    if (![parsed[@"ok"] boolValue]) {
        if (error) *error = [parsed[@"error"] isKindOfClass:[NSString class]] ? parsed[@"error"] : @"Engine op failed";
        return nil;
    }
    id result = parsed[@"result"];
    return [result isKindOfClass:[NSDictionary class]] ? result : @{};
}

- (NSDictionary *)sendOp:(NSString *)op
             forBundleId:(NSString *)bundleId
                    args:(NSDictionary *)args
               timeoutMs:(NSInteger)timeoutMs
                   error:(NSString **)error {
    NSDictionary *session = [self loadSessionForBundleId:bundleId];
    NSString *socketPath = [session[@"socket_path"] isKindOfClass:[NSString class]] ? session[@"socket_path"] : nil;
    if (!socketPath.length) {
        if (error) *error = [NSString stringWithFormat:@"No active engine session for %@; call engine_inject first", bundleId];
        return nil;
    }
    static atomic_int counter = 0;
    NSDictionary *envelope = @{ @"id": @(atomic_fetch_add(&counter, 1) + 1),
                                @"op": op,
                                @"args": args ?: @{} };
    return [self sendEnvelope:envelope socketPath:socketPath timeoutMs:(timeoutMs > 0 ? timeoutMs : 10000) error:error];
}

#pragma mark - Inject / Remove

- (NSDictionary *)injectEngineForBundleId:(NSString *)bundleId
                            stealthConfig:(NSDictionary *)stealthConfig
                                   launch:(BOOL)launch
                                    error:(NSString **)error {
    if (error) *error = nil;
    if (![bundleId isKindOfClass:[NSString class]] || !bundleId.length) {
        if (error) *error = @"bundle_id is required"; return nil;
    }

    NSString *engineSrc = MCPResolvedJailbreakPath(kMCPEngineLogicalPath);
    NSString *stealthSrc = MCPResolvedJailbreakPath(kMCPStealthLogicalPath);
    if (!MCPIsExecutableFile(engineSrc)) { if (error) *error = @"libmcpengine.dylib not installed"; return nil; }
    if (!MCPIsExecutableFile(stealthSrc)) { if (error) *error = @"libmcp_stealth.dylib not installed"; return nil; }

    NSString *appErr = nil;
    NSDictionary *appInfo = [[AppManager sharedInstance] appInfoForBundleId:bundleId error:&appErr];
    NSString *bundlePath = appInfo[@"bundle_path"];
    NSString *mainExec = appInfo[@"executable_path"];
    NSString *dataContainer = appInfo[@"data_container"] ?: appInfo[@"data_container_path"];
    if (!bundlePath.length || !mainExec.length || !dataContainer.length) {
        if (error) *error = appErr ?: [NSString stringWithFormat:@"App %@ missing bundle/exec/data-container", bundleId];
        return nil;
    }

    // A foreground request can return the existing process. Stop it before
    // changing load commands so the subsequent launch loads the new vnode.
    if (launch && [appInfo[@"running"] boolValue]) {
        NSString *stopError = nil;
        if (![[AppManager sharedInstance] killApp:bundleId error:&stopError]) {
            if (error) *error = stopError ?: @"Failed to stop app before engine injection";
            return nil;
        }
    }
    NSString *engineName = [NSString stringWithFormat:@"libAppleMediaKit_%@.dylib", MCPEngineRandomHex(3)];
    NSString *stealthName = [NSString stringWithFormat:@"libAppleCoreSVG_%@.dylib", MCPEngineRandomHex(3)];
    NSString *normContainer = MCPEngineNormalizeSocket(dataContainer);
    NSString *socketPath = [normContainer stringByAppendingPathComponent:
                            [NSString stringWithFormat:@"tmp/.me_%@", MCPEngineRandomHex(6)]];

    // Stealth companion config (same file the companion reads for the frida path).
    NSString *stealthCfgPath = [dataContainer stringByAppendingPathComponent:@"tmp/.mcp_stealth_cfg.json"];
    NSMutableDictionary *cfg = [NSMutableDictionary dictionaryWithDictionary:
        (stealthConfig.count ? stealthConfig : @{})];
    cfg[@"hidden_dylib_names"] = @[stealthName, engineName];
    NSData *cfgData = [NSJSONSerialization dataWithJSONObject:cfg options:0 error:nil];
    [cfgData writeToFile:stealthCfgPath options:NSDataWritingAtomic error:nil];

    NSString *outStr = nil, *runErr = nil; int exitCode = -1;
    BOOL ok = MCPRunRootProcess(@"/usr/libexec/ios-mcp/mcp-appmod",
                                @[@"inject-engine", bundlePath, mainExec, engineSrc, stealthSrc,
                                  engineName, stealthName, socketPath],
                                60.0, 512 * 1024, &outStr, &exitCode, &runErr);
    NSDictionary *resp = outStr.length ? [NSJSONSerialization JSONObjectWithData:[outStr dataUsingEncoding:NSUTF8StringEncoding] options:0 error:NULL] : nil;
    if (!ok || exitCode != 0 || ![resp isKindOfClass:[NSDictionary class]] || ![resp[@"ok"] boolValue]) {
        if (error) *error = [resp[@"error"] isKindOfClass:[NSString class]] ? resp[@"error"] : (runErr ?: @"inject-engine failed");
        return nil;
    }

    BOOL sessionSaved = [self saveSession:@{ @"socket_path": socketPath,
                         @"engine_dylib_name": engineName,
                         @"stealth_dylib_name": stealthName,
                         @"data_container_path": dataContainer,
                         @"stealth_cfg_path": stealthCfgPath,
                         @"main_executable": mainExec,
                         @"bundle_path": bundlePath }
          forBundleId:bundleId];
    if (!sessionSaved) { if (error) *error = @"Engine staged but session could not be saved; check session directory permissions"; return nil; }

    BOOL launched = NO; BOOL socketReady = NO;
    if (launch) {
        NSString *launchErr = nil;
        launched = [[AppManager sharedInstance] launchApp:bundleId error:&launchErr];
        if (launched) {
            for (int i = 0; i < 20 && !socketReady; i++) {
                usleep(250 * 1000);
                NSString *pingErr = nil;
                if ([self sendEnvelope:@{@"id":@0,@"op":@"engine.ping",@"args":@{}} socketPath:socketPath timeoutMs:1500 error:&pingErr]) {
                    socketReady = YES;
                }
            }
        }
    }

    return @{ @"bundle_id": bundleId,
              @"socket_path": socketPath,
              @"engine_dylib_name": engineName,
              @"stealth_dylib_name": stealthName,
              @"load_order": @[[NSString stringWithFormat:@"@executable_path/Frameworks/%@", stealthName],
                               [NSString stringWithFormat:@"@executable_path/Frameworks/%@", engineName]],
              @"data_container_path": dataContainer,
              @"transport": @"unix_domain_socket_only",
              @"tcp_ports_opened": @0,
              @"launched": @(launched),
              @"socket_ready": @(socketReady) };
}

- (NSDictionary *)removeEngineForBundleId:(NSString *)bundleId error:(NSString **)error {
    if (error) *error = nil;
    NSString *appErr = nil;
    NSDictionary *appInfo = [[AppManager sharedInstance] appInfoForBundleId:bundleId error:&appErr];
    NSString *bundlePath = appInfo[@"bundle_path"] ?: @"";
    NSString *mainExec = appInfo[@"executable_path"] ?: @"";
    if (!bundlePath.length || !mainExec.length) { if (error) *error = appErr ?: @"App not found"; return nil; }

    NSDictionary *session = [self loadSessionForBundleId:bundleId];
    NSString *stealthName = [session[@"stealth_dylib_name"] isKindOfClass:[NSString class]] ? session[@"stealth_dylib_name"] : @"libAppleCoreSVG_";
    NSString *engineName = [session[@"engine_dylib_name"] isKindOfClass:[NSString class]] ? session[@"engine_dylib_name"] : @"libAppleMediaKit_";

    pid_t pid = [[AppManager sharedInstance] pidForBundleId:bundleId];
    if (pid > 0) { [[AppManager sharedInstance] killApp:bundleId error:nil]; usleep(250 * 1000); }

    NSString *outStr = nil, *runErr = nil; int exitCode = -1;
    BOOL ok = MCPRunRootProcess(@"/usr/libexec/ios-mcp/mcp-appmod",
                                @[@"unstage-engine", bundlePath, mainExec, stealthName, engineName],
                                45.0, 512 * 1024, &outStr, &exitCode, &runErr);
    NSDictionary *resp = outStr.length ? [NSJSONSerialization JSONObjectWithData:[outStr dataUsingEncoding:NSUTF8StringEncoding] options:0 error:NULL] : nil;
    if (!ok || exitCode != 0 || ![resp isKindOfClass:[NSDictionary class]] || ![resp[@"ok"] boolValue]) {
        if (error) *error = [resp[@"error"] isKindOfClass:[NSString class]] ? resp[@"error"] : (runErr ?: @"unstage-engine failed");
        return nil;
    }

    // Clean up socket + config + the engine's own cfg inside the container tmp.
    NSString *dataContainer = session[@"data_container_path"];
    NSMutableArray *cleanup = [NSMutableArray array];
    if ([session[@"socket_path"] isKindOfClass:[NSString class]]) [cleanup addObject:session[@"socket_path"]];
    if ([session[@"stealth_cfg_path"] isKindOfClass:[NSString class]]) [cleanup addObject:session[@"stealth_cfg_path"]];
    if (dataContainer.length) [cleanup addObject:[dataContainer stringByAppendingPathComponent:@"tmp/.mcpe_cfg.json"]];
    for (NSString *p in cleanup) {
        if (![[NSFileManager defaultManager] removeItemAtPath:p error:nil]) {
            NSString *o = nil, *e = nil; int c = -1;
            MCPRunRootProcess(@"/usr/libexec/ios-mcp/mcp-appmod", @[@"delete-file", p], 10.0, 16384, &o, &c, &e);
        }
    }
    [self deleteSessionForBundleId:bundleId];

    NSMutableDictionary *res = [([resp[@"result"] isKindOfClass:[NSDictionary class]] ? resp[@"result"] : @{}) mutableCopy];
    res[@"bundle_id"] = bundleId;
    res[@"removed"] = @YES;
    return res;
}

#pragma mark - Typed wrappers

- (NSDictionary *)pingForBundleId:(NSString *)bundleId error:(NSString **)error {
    return [self sendOp:@"engine.ping" forBundleId:bundleId args:@{} timeoutMs:5000 error:error];
}
- (NSDictionary *)listModulesForBundleId:(NSString *)bundleId filter:(NSString *)filter limit:(NSUInteger)limit error:(NSString **)error {
    NSMutableDictionary *a = [NSMutableDictionary dictionary];
    if (filter.length) a[@"filter"] = filter; if (limit) a[@"limit"] = @(limit);
    return [self sendOp:@"engine.modules" forBundleId:bundleId args:a timeoutMs:10000 error:error];
}
- (NSDictionary *)listClassesForBundleId:(NSString *)bundleId filter:(NSString *)filter includeSystem:(BOOL)includeSystem limit:(NSUInteger)limit error:(NSString **)error {
    NSMutableDictionary *a = [NSMutableDictionary dictionary];
    if (filter.length) a[@"filter"] = filter; a[@"include_system"] = @(includeSystem); if (limit) a[@"limit"] = @(limit);
    return [self sendOp:@"engine.classes" forBundleId:bundleId args:a timeoutMs:15000 error:error];
}
- (NSDictionary *)describeClassForBundleId:(NSString *)bundleId className:(NSString *)className error:(NSString **)error {
    return [self sendOp:@"engine.describe" forBundleId:bundleId args:@{@"class": className ?: @""} timeoutMs:10000 error:error];
}
- (NSDictionary *)hookObjCForBundleId:(NSString *)bundleId args:(NSDictionary *)args error:(NSString **)error {
    return [self sendOp:@"engine.hook_objc" forBundleId:bundleId args:args timeoutMs:10000 error:error];
}
- (NSDictionary *)hookEventsForBundleId:(NSString *)bundleId key:(NSString *)hookKey maxEvents:(NSUInteger)maxEvents error:(NSString **)error {
    NSMutableDictionary *a = [NSMutableDictionary dictionaryWithObject:(hookKey ?: @"") forKey:@"hook_key"];
    if (maxEvents) a[@"max_events"] = @(maxEvents);
    return [self sendOp:@"engine.hook_events" forBundleId:bundleId args:a timeoutMs:10000 error:error];
}
- (NSDictionary *)unhookForBundleId:(NSString *)bundleId key:(NSString *)hookKey error:(NSString **)error {
    return [self sendOp:@"engine.unhook" forBundleId:bundleId args:@{@"hook_key": hookKey ?: @""} timeoutMs:10000 error:error];
}
- (NSDictionary *)invokeForBundleId:(NSString *)bundleId args:(NSDictionary *)args error:(NSString **)error {
    return [self sendOp:@"engine.invoke" forBundleId:bundleId args:args timeoutMs:15000 error:error];
}
- (NSDictionary *)ivarForBundleId:(NSString *)bundleId args:(NSDictionary *)args error:(NSString **)error {
    NSString *op = args[@"set"] ? @"engine.set_ivar" : @"engine.get_ivar";
    return [self sendOp:op forBundleId:bundleId args:args timeoutMs:10000 error:error];
}
- (NSDictionary *)hookNativeForBundleId:(NSString *)bundleId args:(NSDictionary *)args error:(NSString **)error {
    return [self sendOp:@"engine.hook_native" forBundleId:bundleId args:args timeoutMs:10000 error:error];
}
- (NSDictionary *)callNativeForBundleId:(NSString *)bundleId args:(NSDictionary *)args error:(NSString **)error {
    return [self sendOp:@"engine.call" forBundleId:bundleId args:args timeoutMs:10000 error:error];
}
- (NSDictionary *)readMemoryForBundleId:(NSString *)bundleId address:(NSString *)address length:(NSUInteger)length error:(NSString **)error {
    return [self sendOp:@"engine.read_mem" forBundleId:bundleId args:@{@"address": address ?: @"", @"length": @(length)} timeoutMs:10000 error:error];
}
- (NSDictionary *)writeMemoryForBundleId:(NSString *)bundleId address:(NSString *)address dataBase64:(NSString *)dataBase64 error:(NSString **)error {
    return [self sendOp:@"engine.write_mem" forBundleId:bundleId args:@{@"address": address ?: @"", @"data_base64": dataBase64 ?: @""} timeoutMs:10000 error:error];
}
- (NSDictionary *)searchMemoryForBundleId:(NSString *)bundleId args:(NSDictionary *)args error:(NSString **)error {
    return [self sendOp:@"engine.search_mem" forBundleId:bundleId args:args timeoutMs:30000 error:error];
}

@end
