#import "ClassDumpManager.h"
#import "AppManager.h"
#import "MCPProcessUtil.h"
#import "MemoryManager.h"
#import <unistd.h>

@implementation ClassDumpManager

+ (instancetype)sharedInstance {
    static ClassDumpManager *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[ClassDumpManager alloc] init];
    });
    return instance;
}

- (NSDictionary *)dumpClassesForBundleId:(NSString *)bundleId
                                  filter:(NSString *)filter
                                   limit:(NSUInteger)limit
                           includeSystem:(BOOL)includeSystem
                              autoLaunch:(BOOL)autoLaunch
                                   error:(NSString **)error {
    if (error) *error = nil;
    if (![bundleId isKindOfClass:[NSString class]] || !bundleId.length) {
        if (error) *error = @"bundle_id is required";
        return nil;
    }

    pid_t pid = 0;
    BOOL launchedNow = NO;
    if ([bundleId isEqualToString:@"com.apple.springboard"]) {
        pid = getpid();
    } else {
        NSString *appErr = nil;
        NSDictionary *appInfo = [[AppManager sharedInstance] appInfoForBundleId:bundleId error:&appErr];
        if (!appInfo) {
            if (error) *error = appErr ?: [NSString stringWithFormat:@"App not found: %@", bundleId];
            return nil;
        }
        pid = [[AppManager sharedInstance] pidForBundleId:bundleId];
        if (pid <= 0 && autoLaunch) {
            NSString *launchErr = nil;
            if ([[AppManager sharedInstance] launchApp:bundleId error:&launchErr]) {
                launchedNow = YES;
                for (int attempt = 0; attempt < 15; attempt++) {
                    pid = [[AppManager sharedInstance] pidForBundleId:bundleId];
                    if (pid > 0) break;
                    usleep(200 * 1000);
                }
            } else {
                if (error) *error = [NSString stringWithFormat:@"Target app %@ is not running and auto_launch failed: %@",
                                     bundleId, launchErr ?: @"unknown"];
                return nil;
            }
        }
        if (pid <= 0) {
            if (error) *error = [NSString stringWithFormat:@"Target app %@ is not currently running; launch it first with launch_app or pass auto_launch=true", bundleId];
            return nil;
        }
    }

    if (limit == 0) limit = 200;
    if (limit > 2000) limit = 2000;

    if (pid == getpid()) {
        NSString *inProcErr = nil;
        NSDictionary *inProc = [[MemoryManager sharedInstance] dumpClassesPID:pid
                                                                       filter:(filter.length > 0 ? filter : nil)
                                                                        limit:limit
                                                                includeSystem:includeSystem
                                                                        error:&inProcErr];
        if (inProc) {
            NSMutableDictionary *result = [inProc mutableCopy];
            result[@"bundle_id"] = bundleId;
            result[@"pid"] = @(pid);
            return result;
        }
    }

    NSArray<NSString *> *helperArgs = @[
        @"classdump",
        [NSString stringWithFormat:@"%d", pid],
        (filter.length > 0 ? filter : @"-"),
        [NSString stringWithFormat:@"%lu", (unsigned long)limit],
        (includeSystem ? @"1" : @"0")
    ];

    NSString *outStr = nil;
    NSString *runErr = nil;
    int exitCode = -1;
    BOOL launched = MCPRunRootProcess(@"/usr/libexec/ios-mcp/mcp-memory",
                                      helperArgs,
                                      45.0,
                                      8 * 1024 * 1024,
                                      &outStr,
                                      &exitCode,
                                      &runErr);
    if (!launched) {
        NSString *helperPath = MCPResolvedJailbreakPath(@"/usr/libexec/ios-mcp/mcp-memory");
        launched = MCPRunProcess(helperPath,
                                 helperArgs,
                                 MCPJailbreakEnvironment(),
                                 45.0,
                                 8 * 1024 * 1024,
                                 &outStr,
                                 &exitCode,
                                 &runErr);
    }

    if (!launched) {
        if (error) *error = runErr ?: @"Failed to launch mcp-memory classdump helper";
        return nil;
    }

    NSData *respData = [outStr dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *resp = respData ? [NSJSONSerialization JSONObjectWithData:respData options:0 error:NULL] : nil;
    if (![resp isKindOfClass:[NSDictionary class]]) {
        if (error) *error = @"mcp-memory classdump returned invalid JSON";
        return nil;
    }
    if (exitCode != 0 || ![resp[@"ok"] boolValue]) {
        if (error) *error = [resp[@"error"] isKindOfClass:[NSString class]] ? resp[@"error"] : @"dump_classes failed";
        return nil;
    }

    NSMutableDictionary *result = [([resp[@"result"] isKindOfClass:[NSDictionary class]] ? resp[@"result"] : @{}) mutableCopy];
    result[@"bundle_id"] = bundleId;
    result[@"pid"] = @(pid);
    if (launchedNow) result[@"auto_launched"] = @YES;
    return result;
}

@end
