#import "EntitlementManager.h"
#import "AppManager.h"
#import "MCPMachOUtil.h"
#import "MCPProcessUtil.h"

@implementation EntitlementManager

+ (instancetype)sharedInstance {
    static EntitlementManager *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[EntitlementManager alloc] init];
    });
    return instance;
}

- (NSDictionary *)dumpEntitlementsForBundleId:(NSString *)bundleId error:(NSString **)error {
    if (error) *error = nil;
    if (![bundleId isKindOfClass:[NSString class]] || !bundleId.length) {
        if (error) *error = @"bundle_id is required";
        return nil;
    }

    NSString *appErr = nil;
    NSDictionary *appInfo = [[AppManager sharedInstance] appInfoForBundleId:bundleId error:&appErr];
    if (!appInfo) {
        if (error) *error = appErr ?: [NSString stringWithFormat:@"App not found: %@", bundleId];
        return nil;
    }

    NSString *execPath = [appInfo[@"executable_path"] isKindOfClass:[NSString class]] ? appInfo[@"executable_path"] : nil;
    if (!execPath.length) {
        if (error) *error = [NSString stringWithFormat:@"Could not locate main executable for %@", bundleId];
        return nil;
    }

    NSString *machErr = nil;
    NSDictionary *direct = MCPExtractEntitlementsFromMachO(execPath, &machErr);
    if (direct && [direct[@"entitlements"] isKindOfClass:[NSDictionary class]]) {
        NSDictionary *ent = direct[@"entitlements"];
        return @{
            @"bundle_id": bundleId,
            @"binary_path": execPath,
            @"bundle_path": appInfo[@"bundle_path"] ?: @"",
            @"has_entitlements": direct[@"has_entitlements"] ?: @(ent.count > 0),
            @"entitlement_count": @(ent.count),
            @"entitlements": ent,
            @"xml": direct[@"xml"] ?: @""
        };
    }

    NSString *outStr = nil;
    NSString *runErr = nil;
    int exitCode = -1;
    BOOL ok = MCPRunRootProcess(@"/usr/libexec/ios-mcp/mcp-appmod",
                                @[@"dump-entitlements", execPath],
                                20.0,
                                1024 * 1024,
                                &outStr,
                                &exitCode,
                                &runErr);
    if (!ok) {
        if (error) *error = runErr ?: machErr ?: @"Failed to invoke mcp-appmod dump-entitlements";
        return nil;
    }

    NSData *respData = [outStr dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *resp = respData ? [NSJSONSerialization JSONObjectWithData:respData options:0 error:NULL] : nil;
    if (![resp isKindOfClass:[NSDictionary class]] || exitCode != 0 || ![resp[@"ok"] boolValue]) {
        if (error) *error = [resp[@"error"] isKindOfClass:[NSString class]] ? resp[@"error"] : (machErr ?: @"dump_entitlements failed");
        return nil;
    }

    NSDictionary *res = [resp[@"result"] isKindOfClass:[NSDictionary class]] ? resp[@"result"] : @{};
    NSDictionary *ent = [res[@"entitlements"] isKindOfClass:[NSDictionary class]] ? res[@"entitlements"] : @{};
    return @{
        @"bundle_id": bundleId,
        @"binary_path": execPath,
        @"bundle_path": appInfo[@"bundle_path"] ?: @"",
        @"has_entitlements": res[@"has_entitlements"] ?: @(ent.count > 0),
        @"entitlement_count": @(ent.count),
        @"entitlements": ent,
        @"xml": res[@"xml"] ?: @""
    };
}

- (NSDictionary *)patchEntitlementsForBundleId:(NSString *)bundleId
                                         patch:(NSDictionary *)patch
                                         error:(NSString **)error {
    if (error) *error = nil;
    if (![bundleId isKindOfClass:[NSString class]] || !bundleId.length) {
        if (error) *error = @"bundle_id is required";
        return nil;
    }
    if (![patch isKindOfClass:[NSDictionary class]] || patch.count == 0) {
        if (error) *error = @"plist_patch must be a non-empty dictionary";
        return nil;
    }
    if ([bundleId isEqualToString:@"com.apple.springboard"]) {
        if (error) *error = @"Refusing to patch SpringBoard entitlements";
        return nil;
    }

    NSString *appErr = nil;
    NSDictionary *appInfo = [[AppManager sharedInstance] appInfoForBundleId:bundleId error:&appErr];
    if (!appInfo) {
        if (error) *error = appErr ?: [NSString stringWithFormat:@"App not found: %@", bundleId];
        return nil;
    }

    NSString *execPath = [appInfo[@"executable_path"] isKindOfClass:[NSString class]] ? appInfo[@"executable_path"] : nil;
    if (!execPath.length) {
        if (error) *error = [NSString stringWithFormat:@"Could not locate main executable for %@", bundleId];
        return nil;
    }
    if ([execPath hasPrefix:@"/System/"] || [execPath hasPrefix:@"/Applications/"]) {
        if (error) *error = [NSString stringWithFormat:@"Refusing to modify system binary: %@", execPath];
        return nil;
    }

    pid_t runningPid = [[AppManager sharedInstance] pidForBundleId:bundleId];
    BOOL wasRunning = (runningPid > 0);
    if (wasRunning) {
        [[AppManager sharedInstance] killApp:bundleId error:nil];
        usleep(200 * 1000);
    }

    NSString *workCache = @"/var/mobile/Library/Caches/ios-mcp-work";
    [[NSFileManager defaultManager] createDirectoryAtPath:workCache withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *patchFile = [workCache stringByAppendingPathComponent:
                           [NSString stringWithFormat:@"ent-patch-%@.json", [NSUUID UUID].UUIDString]];

    NSError *jsonErr = nil;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:patch options:0 error:&jsonErr];
    if (!jsonData || ![jsonData writeToFile:patchFile options:NSDataWritingAtomic error:&jsonErr]) {
        if (error) *error = jsonErr.localizedDescription ?: @"Failed to serialize entitlement patch";
        return nil;
    }

    NSString *outStr = nil;
    NSString *runErr = nil;
    int exitCode = -1;
    BOOL ok = MCPRunRootProcess(@"/usr/libexec/ios-mcp/mcp-appmod",
                                @[@"patch-entitlements", execPath, patchFile],
                                30.0,
                                1024 * 1024,
                                &outStr,
                                &exitCode,
                                &runErr);
    [[NSFileManager defaultManager] removeItemAtPath:patchFile error:nil];

    if (!ok) {
        if (error) *error = runErr ?: @"Failed to invoke mcp-appmod patch-entitlements";
        return nil;
    }

    NSData *respData = [outStr dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *resp = respData ? [NSJSONSerialization JSONObjectWithData:respData options:0 error:NULL] : nil;
    if (![resp isKindOfClass:[NSDictionary class]] || exitCode != 0 || ![resp[@"ok"] boolValue]) {
        if (error) *error = [resp[@"error"] isKindOfClass:[NSString class]] ? resp[@"error"] : @"patch_entitlements failed";
        return nil;
    }

    NSMutableDictionary *result = [([resp[@"result"] isKindOfClass:[NSDictionary class]] ? resp[@"result"] : @{}) mutableCopy];
    result[@"bundle_id"] = bundleId;
    result[@"was_running"] = @(wasRunning);
    return result;
}

@end
