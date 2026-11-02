#import "SSLKillSwitchManager.h"
#import "AppManager.h"
#import "DylibInjectManager.h"
#import "MCPProcessUtil.h"

static NSString *const kMCPSSLKillSwitchLogicalPath = @"/usr/lib/ios-mcp/libmcp_sslks.dylib";
static NSString *const kMCPSSLKillSwitchDestName = @"libmcp_sslks.dylib";

@implementation SSLKillSwitchManager

+ (instancetype)sharedInstance {
    static SSLKillSwitchManager *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[SSLKillSwitchManager alloc] init];
    });
    return instance;
}

- (NSDictionary *)bypassPinningForBundleId:(NSString *)bundleId
                                  relaunch:(BOOL)relaunch
                                     error:(NSString **)error {
    if (error) *error = nil;
    NSString *resolvedPayload = MCPResolvedJailbreakPath(kMCPSSLKillSwitchLogicalPath);
    if (![[NSFileManager defaultManager] fileExistsAtPath:resolvedPayload]) {
        if (error) *error = [NSString stringWithFormat:@"SSL Kill Switch companion dylib missing at %@", resolvedPayload];
        return nil;
    }

    NSDictionary *inj = [[DylibInjectManager sharedInstance] injectDylibForBundleId:bundleId
                                                                          dylibPath:resolvedPayload
                                                                           destName:kMCPSSLKillSwitchDestName
                                                                              error:error];
    if (!inj) return nil;

    BOOL relaunched = NO;
    NSString *launchErr = nil;
    if (relaunch) {
        relaunched = [[AppManager sharedInstance] launchApp:bundleId error:&launchErr];
    }

    NSMutableDictionary *res = [NSMutableDictionary dictionaryWithDictionary:inj];
    res[@"pinning_bypass"] = @"enabled";
    res[@"companion_dylib"] = kMCPSSLKillSwitchDestName;
    res[@"hooked_apis"] = @[
        @"SecTrustEvaluate",
        @"SecTrustEvaluateWithError",
        @"SecTrustEvaluateAsync",
        @"SecTrustEvaluateAsyncWithError",
        @"SSLSetSessionOption",
        @"SSLHandshake",
        @"sec_protocol_options_set_verify_block",
        @"NSURLSessionDelegate(ServerTrust)"
    ];
    res[@"relaunched"] = @(relaunched);
    if (launchErr.length > 0) res[@"relaunch_warning"] = launchErr;
    return res;
}

- (NSDictionary *)restorePinningForBundleId:(NSString *)bundleId
                                   relaunch:(BOOL)relaunch
                                      error:(NSString **)error {
    if (error) *error = nil;
    NSDictionary *rem = [[DylibInjectManager sharedInstance] removeDylibForBundleId:bundleId
                                                                          dylibName:kMCPSSLKillSwitchDestName
                                                                    restoreOriginal:NO
                                                                       deleteStaged:YES
                                                                              error:error];
    if (!rem) return nil;

    NSDictionary *appInfo = [[AppManager sharedInstance] appInfoForBundleId:bundleId error:nil];
    id rawContainer = appInfo[@"data_container"] ?: appInfo[@"data_container_path"];
    NSString *dataContainer = [rawContainer isKindOfClass:[NSString class]] ? rawContainer : nil;
    if (dataContainer.length > 0) {
        NSString *statusFile = [dataContainer stringByAppendingPathComponent:@"tmp/.mcp_sslks_status.json"];
        NSString *outStr = nil, *runErr = nil;
        int code = -1;
        MCPRunRootProcess(@"/usr/libexec/ios-mcp/mcp-appmod", @[@"delete-file", statusFile], 10.0, 16384, &outStr, &code, &runErr);
    }

    BOOL relaunched = NO;
    NSString *launchErr = nil;
    if (relaunch) {
        relaunched = [[AppManager sharedInstance] launchApp:bundleId error:&launchErr];
    }

    NSMutableDictionary *res = [NSMutableDictionary dictionaryWithDictionary:rem];
    res[@"pinning_bypass"] = @"restored";
    res[@"companion_dylib"] = kMCPSSLKillSwitchDestName;
    res[@"relaunched"] = @(relaunched);
    if (launchErr.length > 0) res[@"relaunch_warning"] = launchErr;
    return res;
}

@end
