#import "DylibInjectManager.h"
#import "AppManager.h"
#import "MCPMachOUtil.h"
#import "MCPProcessUtil.h"

@implementation DylibInjectManager

+ (instancetype)sharedInstance {
    static DylibInjectManager *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[DylibInjectManager alloc] init];
    });
    return instance;
}

- (NSDictionary *)injectDylibForBundleId:(NSString *)bundleId
                               dylibPath:(NSString *)dylibPath
                                destName:(NSString *)destName
                                   error:(NSString **)error {
    if (error) *error = nil;
    if (![bundleId isKindOfClass:[NSString class]] || !bundleId.length) {
        if (error) *error = @"bundle_id is required";
        return nil;
    }
    if (![dylibPath isKindOfClass:[NSString class]] || !dylibPath.length) {
        if (error) *error = @"dylib_path is required";
        return nil;
    }
    if ([bundleId isEqualToString:@"com.apple.springboard"]) {
        if (error) *error = @"Refusing to inject load commands into SpringBoard";
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

    NSString *resolvedDylib = MCPResolvedJailbreakPath(dylibPath);
    if (!resolvedDylib.length) resolvedDylib = dylibPath;

    NSString *effectiveDestName = destName.length ? destName.lastPathComponent : resolvedDylib.lastPathComponent;
    if (!effectiveDestName.length) {
        if (error) *error = @"Could not determine destination dylib filename";
        return nil;
    }

    pid_t runningPid = [[AppManager sharedInstance] pidForBundleId:bundleId];
    BOOL wasRunning = (runningPid > 0);
    if (wasRunning) {
        [[AppManager sharedInstance] killApp:bundleId error:nil];
        usleep(200 * 1000);
    }

    NSString *outStr = nil;
    NSString *runErr = nil;
    int exitCode = -1;
    BOOL ok = MCPRunRootProcess(@"/usr/libexec/ios-mcp/mcp-appmod",
                                @[@"inject-dylib", execPath, resolvedDylib, effectiveDestName],
                                45.0,
                                1024 * 1024,
                                &outStr,
                                &exitCode,
                                &runErr);
    if (!ok) {
        if (error) *error = runErr ?: @"Failed to invoke mcp-appmod inject-dylib";
        return nil;
    }

    NSData *respData = [outStr dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *resp = respData ? [NSJSONSerialization JSONObjectWithData:respData options:0 error:NULL] : nil;
    if (![resp isKindOfClass:[NSDictionary class]] || exitCode != 0 || ![resp[@"ok"] boolValue]) {
        if (error) *error = [resp[@"error"] isKindOfClass:[NSString class]] ? resp[@"error"] : @"inject_dylib failed";
        return nil;
    }

    NSMutableDictionary *result = [([resp[@"result"] isKindOfClass:[NSDictionary class]] ? resp[@"result"] : @{}) mutableCopy];
    result[@"bundle_id"] = bundleId;
    result[@"source_dylib_path"] = resolvedDylib;
    result[@"was_running"] = @(wasRunning);
    return result;
}

- (NSDictionary *)removeDylibForBundleId:(NSString *)bundleId
                               dylibName:(NSString *)dylibName
                         restoreOriginal:(BOOL)restoreOriginal
                            deleteStaged:(BOOL)deleteStaged
                                   error:(NSString **)error {
    if (error) *error = nil;
    if (![bundleId isKindOfClass:[NSString class]] || !bundleId.length) {
        if (error) *error = @"bundle_id is required";
        return nil;
    }
    if (!restoreOriginal && (![dylibName isKindOfClass:[NSString class]] || !dylibName.length)) {
        if (error) *error = @"dylib_name is required unless restore_original is true";
        return nil;
    }
    if ([bundleId isEqualToString:@"com.apple.springboard"]) {
        if (error) *error = @"Refusing to modify SpringBoard";
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

    NSMutableArray<NSString *> *args = [NSMutableArray arrayWithObjects:@"remove-dylib", execPath, nil];
    if (dylibName.length > 0) {
        [args addObject:dylibName];
    } else {
        [args addObject:@"-"];
    }
    if (restoreOriginal) [args addObject:@"--restore-orig"];
    if (deleteStaged) [args addObject:@"--delete-staged"];

    NSString *outStr = nil;
    NSString *runErr = nil;
    int exitCode = -1;
    BOOL ok = MCPRunRootProcess(@"/usr/libexec/ios-mcp/mcp-appmod",
                                args,
                                30.0,
                                1024 * 1024,
                                &outStr,
                                &exitCode,
                                &runErr);
    if (!ok) {
        if (error) *error = runErr ?: @"Failed to invoke mcp-appmod remove-dylib";
        return nil;
    }

    NSData *respData = [outStr dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *resp = respData ? [NSJSONSerialization JSONObjectWithData:respData options:0 error:NULL] : nil;
    if (![resp isKindOfClass:[NSDictionary class]] || exitCode != 0 || ![resp[@"ok"] boolValue]) {
        if (error) *error = [resp[@"error"] isKindOfClass:[NSString class]] ? resp[@"error"] : @"remove_dylib failed";
        return nil;
    }

    NSMutableDictionary *result = [([resp[@"result"] isKindOfClass:[NSDictionary class]] ? resp[@"result"] : @{}) mutableCopy];
    result[@"bundle_id"] = bundleId;
    result[@"was_running"] = @(wasRunning);
    return result;
}

- (NSDictionary *)inspectMachOAtPath:(NSString *)path error:(NSString **)error {
    if (error) *error = nil;
    if (![path isKindOfClass:[NSString class]] || !path.length) {
        if (error) *error = @"path is required";
        return nil;
    }
    NSString *resolved = MCPResolvedJailbreakPath(path);
    if (!resolved.length) resolved = path;

    NSString *directErr = nil;
    NSDictionary *direct = MCPInspectMachOAtPath(resolved, &directErr);
    if (direct) return direct;

    NSString *outStr = nil;
    NSString *runErr = nil;
    int exitCode = -1;
    BOOL ok = MCPRunRootProcess(@"/usr/libexec/ios-mcp/mcp-appmod",
                                @[@"inspect-macho", resolved],
                                20.0,
                                2 * 1024 * 1024,
                                &outStr,
                                &exitCode,
                                &runErr);
    if (!ok) {
        if (error) *error = directErr ?: runErr ?: @"inspect_macho failed";
        return nil;
    }
    NSData *respData = [outStr dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *resp = respData ? [NSJSONSerialization JSONObjectWithData:respData options:0 error:NULL] : nil;
    if (![resp isKindOfClass:[NSDictionary class]] || exitCode != 0 || ![resp[@"ok"] boolValue]) {
        if (error) *error = [resp[@"error"] isKindOfClass:[NSString class]] ? resp[@"error"] : (directErr ?: @"inspect_macho failed");
        return nil;
    }
    return [resp[@"result"] isKindOfClass:[NSDictionary class]] ? resp[@"result"] : nil;
}

@end
