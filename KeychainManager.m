#import "KeychainManager.h"
#import "EntitlementManager.h"
#import "MCPProcessUtil.h"

@implementation KeychainManager

+ (instancetype)sharedInstance {
    static KeychainManager *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[KeychainManager alloc] init];
    });
    return instance;
}

- (NSDictionary *)runKeychainAction:(NSString *)action
                               args:(NSDictionary *)args
                              error:(NSString **)error {
    if (error) *error = nil;
    NSMutableDictionary *req = [NSMutableDictionary dictionaryWithDictionary:(args ?: @{})];
    req[@"action"] = action;

    NSString *bundleId = [args[@"bundle_id"] isKindOfClass:[NSString class]] ? args[@"bundle_id"] : nil;
    NSString *explicitGroup = [args[@"access_group"] isKindOfClass:[NSString class]] ? args[@"access_group"] : nil;
    NSString *resolvedAppId = nil;
    NSString *resolvedAccessGroup = explicitGroup;

    if (bundleId.length > 0 && !resolvedAccessGroup.length) {
        NSDictionary *entInfo = [[EntitlementManager sharedInstance] dumpEntitlementsForBundleId:bundleId error:nil];
        NSDictionary *ents = [entInfo[@"entitlements"] isKindOfClass:[NSDictionary class]] ? entInfo[@"entitlements"] : nil;
        if (ents) {
            if ([ents[@"application-identifier"] isKindOfClass:[NSString class]]) {
                resolvedAppId = ents[@"application-identifier"];
            }
            NSArray *groups = [ents[@"keychain-access-groups"] isKindOfClass:[NSArray class]] ? ents[@"keychain-access-groups"] : nil;
            if ([groups.firstObject isKindOfClass:[NSString class]]) {
                resolvedAccessGroup = groups.firstObject;
            } else if (resolvedAppId.length > 0) {
                resolvedAccessGroup = resolvedAppId;
            }
        }
        if (resolvedAccessGroup.length > 0 && !req[@"access_group"]) {
            req[@"access_group"] = resolvedAccessGroup;
        }
    }

    NSString *workDir = @"/var/mobile/Library/Caches/ios-mcp-work";
    [[NSFileManager defaultManager] createDirectoryAtPath:workDir withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *reqFile = [workDir stringByAppendingPathComponent:
                         [NSString stringWithFormat:@"kc-req-%@.json", [NSUUID UUID].UUIDString]];

    NSError *jsonErr = nil;
    NSData *reqData = [NSJSONSerialization dataWithJSONObject:req options:0 error:&jsonErr];
    if (!reqData || ![reqData writeToFile:reqFile options:NSDataWritingAtomic error:&jsonErr]) {
        if (error) *error = jsonErr.localizedDescription ?: @"Failed to prepare keychain request";
        return nil;
    }

    @try {
        NSString *outStr = nil;
        NSString *runErr = nil;
        int exitCode = -1;
        BOOL launched = MCPRunRootProcess(@"/usr/libexec/ios-mcp/mcp-keychain",
                                          @[@"--req", reqFile],
                                          20.0,
                                          2 * 1024 * 1024,
                                          &outStr,
                                          &exitCode,
                                          &runErr);
        if (!launched) {
            NSString *kcPath = MCPResolvedJailbreakPath(@"/usr/libexec/ios-mcp/mcp-keychain");
            launched = MCPRunProcess(kcPath,
                                     @[@"--req", reqFile],
                                     MCPJailbreakEnvironment(),
                                     20.0,
                                     2 * 1024 * 1024,
                                     &outStr,
                                     &exitCode,
                                     &runErr);
        }

        NSData *respData = [outStr dataUsingEncoding:NSUTF8StringEncoding];
        NSDictionary *resp = respData ? [NSJSONSerialization JSONObjectWithData:respData options:0 error:NULL] : nil;

        int osStatus = [resp[@"osstatus"] respondsToSelector:@selector(intValue)] ? [resp[@"osstatus"] intValue] : 0;
        BOOL needScopedFallback = (![resp[@"ok"] boolValue] && (osStatus == -34018 || osStatus == -25291)) &&
                                  (resolvedAccessGroup.length > 0 || resolvedAppId.length > 0);
        if (needScopedFallback) {
            NSString *scopedOut = nil;
            NSString *scopedErr = nil;
            int scopedCode = -1;
            NSString *grp = resolvedAccessGroup.length ? resolvedAccessGroup : resolvedAppId;
            NSString *aid = resolvedAppId.length ? resolvedAppId : grp;
            if (MCPRunRootProcess(@"/usr/libexec/ios-mcp/mcp-appmod",
                                  @[@"scoped-keychain", grp, aid, reqFile],
                                  30.0,
                                  2 * 1024 * 1024,
                                  &scopedOut,
                                  &scopedCode,
                                  &scopedErr)) {
                NSData *sData = [scopedOut dataUsingEncoding:NSUTF8StringEncoding];
                NSDictionary *sResp = sData ? [NSJSONSerialization JSONObjectWithData:sData options:0 error:NULL] : nil;
                if ([sResp isKindOfClass:[NSDictionary class]]) {
                    resp = sResp;
                    exitCode = scopedCode;
                }
            }
        }

        if (!launched || ![resp isKindOfClass:[NSDictionary class]]) {
            if (error) *error = runErr ?: @"Keychain helper returned invalid JSON";
            return nil;
        }
        if (exitCode != 0 || ![resp[@"ok"] boolValue]) {
            if (error) *error = [resp[@"error"] isKindOfClass:[NSString class]] ? resp[@"error"] : @"Keychain operation failed";
            return nil;
        }
        NSDictionary *result = [resp[@"result"] isKindOfClass:[NSDictionary class]] ? resp[@"result"] : @{};
        return result;
    } @finally {
        [[NSFileManager defaultManager] removeItemAtPath:reqFile error:nil];
    }
}

- (NSDictionary *)getKeychainItemsWithArgs:(NSDictionary *)args error:(NSString **)error {
    return [self runKeychainAction:@"get" args:args error:error];
}

- (NSDictionary *)setKeychainItemWithArgs:(NSDictionary *)args error:(NSString **)error {
    NSString *service = [args[@"service"] isKindOfClass:[NSString class]] ? args[@"service"] : nil;
    NSString *account = [args[@"account"] isKindOfClass:[NSString class]] ? args[@"account"] : nil;
    if (!service.length && !account.length) {
        if (error) *error = @"set_keychain_item requires at least service or account";
        return nil;
    }
    if (!args[@"data"] && !args[@"data_base64"] && !args[@"value"]) {
        if (error) *error = @"set_keychain_item requires data (UTF-8 string) or data_base64";
        return nil;
    }
    NSMutableDictionary *norm = [NSMutableDictionary dictionaryWithDictionary:args];
    if (!norm[@"data"] && [norm[@"value"] isKindOfClass:[NSString class]]) {
        norm[@"data"] = norm[@"value"];
    }
    return [self runKeychainAction:@"set" args:norm error:error];
}

- (NSDictionary *)deleteKeychainItemWithArgs:(NSDictionary *)args error:(NSString **)error {
    NSString *service = [args[@"service"] isKindOfClass:[NSString class]] ? args[@"service"] : nil;
    NSString *account = [args[@"account"] isKindOfClass:[NSString class]] ? args[@"account"] : nil;
    NSString *label = [args[@"label"] isKindOfClass:[NSString class]] ? args[@"label"] : nil;
    if (!service.length && !account.length && !label.length) {
        if (error) *error = @"delete_keychain_item requires at least one of service, account, or label (refusing broad delete)";
        return nil;
    }
    return [self runKeychainAction:@"delete" args:args error:error];
}

@end
