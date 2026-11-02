#import "NetworkCaptureManager.h"
#import "AppManager.h"
#import "DylibInjectManager.h"
#import "MCPProcessUtil.h"

static NSString *const kMCPNetCapLogicalPath = @"/usr/lib/ios-mcp/libmcp_netcap.dylib";
static NSString *const kMCPNetCapDestName = @"libmcp_netcap.dylib";

@implementation NetworkCaptureManager

+ (instancetype)sharedInstance {
    static NetworkCaptureManager *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[NetworkCaptureManager alloc] init];
    });
    return instance;
}

- (NSString *)captureLogPathForBundleId:(NSString *)bundleId error:(NSString **)error {
    NSString *appErr = nil;
    NSDictionary *info = [[AppManager sharedInstance] appInfoForBundleId:bundleId error:&appErr];
    if (!info) {
        if (error) *error = appErr ?: [NSString stringWithFormat:@"App not found: %@", bundleId];
        return nil;
    }
    NSString *container = [info[@"data_container_path"] isKindOfClass:[NSString class]] ? info[@"data_container_path"] : nil;
    if (!container.length) {
        if (error) *error = [NSString stringWithFormat:@"App %@ has no data_container_path", bundleId];
        return nil;
    }
    return [container stringByAppendingPathComponent:@"tmp/.mcp_netcap.jsonl"];
}

- (void)deleteCaptureLogAtPath:(NSString *)logPath {
    if (!logPath.length) return;
    if ([[NSFileManager defaultManager] removeItemAtPath:logPath error:nil]) return;
    NSString *outStr = nil, *runErr = nil;
    int code = -1;
    MCPRunRootProcess(@"/usr/libexec/ios-mcp/mcp-appmod", @[@"delete-file", logPath], 10.0, 16384, &outStr, &code, &runErr);
}

- (NSDictionary *)startCaptureForBundleId:(NSString *)bundleId
                            clearExisting:(BOOL)clearExisting
                                 relaunch:(BOOL)relaunch
                                    error:(NSString **)error {
    if (error) *error = nil;
    NSString *logPath = [self captureLogPathForBundleId:bundleId error:error];
    if (!logPath) return nil;

    NSString *resolvedPayload = MCPResolvedJailbreakPath(kMCPNetCapLogicalPath);
    if (![[NSFileManager defaultManager] fileExistsAtPath:resolvedPayload]) {
        if (error) *error = [NSString stringWithFormat:@"Network capture companion dylib missing at %@", resolvedPayload];
        return nil;
    }

    if (clearExisting) {
        [self deleteCaptureLogAtPath:logPath];
    }

    NSDictionary *inj = [[DylibInjectManager sharedInstance] injectDylibForBundleId:bundleId
                                                                          dylibPath:resolvedPayload
                                                                           destName:kMCPNetCapDestName
                                                                              error:error];
    if (!inj) return nil;

    BOOL relaunched = NO;
    NSString *launchErr = nil;
    if (relaunch) {
        relaunched = [[AppManager sharedInstance] launchApp:bundleId error:&launchErr];
    }

    NSMutableDictionary *res = [NSMutableDictionary dictionaryWithDictionary:inj];
    res[@"capture_status"] = @"started";
    res[@"companion_dylib"] = kMCPNetCapDestName;
    res[@"capture_log_path"] = logPath;
    res[@"cleared_existing"] = @(clearExisting);
    res[@"relaunched"] = @(relaunched);
    if (launchErr.length > 0) res[@"relaunch_warning"] = launchErr;
    return res;
}

- (NSDictionary *)stopCaptureForBundleId:(NSString *)bundleId
                               clearLogs:(BOOL)clearLogs
                                relaunch:(BOOL)relaunch
                                   error:(NSString **)error {
    if (error) *error = nil;
    NSString *logPath = [self captureLogPathForBundleId:bundleId error:nil];

    NSDictionary *rem = [[DylibInjectManager sharedInstance] removeDylibForBundleId:bundleId
                                                                          dylibName:kMCPNetCapDestName
                                                                    restoreOriginal:NO
                                                                       deleteStaged:YES
                                                                              error:error];
    if (!rem) return nil;

    if (clearLogs && logPath.length > 0) {
        [self deleteCaptureLogAtPath:logPath];
    }

    BOOL relaunched = NO;
    NSString *launchErr = nil;
    if (relaunch) {
        relaunched = [[AppManager sharedInstance] launchApp:bundleId error:&launchErr];
    }

    NSMutableDictionary *res = [NSMutableDictionary dictionaryWithDictionary:rem];
    res[@"capture_status"] = @"stopped";
    res[@"companion_dylib"] = kMCPNetCapDestName;
    res[@"capture_log_path"] = logPath ?: @"";
    res[@"logs_cleared"] = @(clearLogs);
    res[@"relaunched"] = @(relaunched);
    if (launchErr.length > 0) res[@"relaunch_warning"] = launchErr;
    return res;
}

- (NSDictionary *)getCapturedRequestsForBundleId:(NSString *)bundleId
                                           limit:(NSUInteger)limit
                                       urlFilter:(NSString *)urlFilter
                                           clear:(BOOL)clear
                                           error:(NSString **)error {
    if (error) *error = nil;
    NSString *logPath = [self captureLogPathForBundleId:bundleId error:error];
    if (!logPath) return nil;

    if (limit == 0) limit = 100;
    if (limit > 1000) limit = 1000;

    NSData *rawData = [NSData dataWithContentsOfFile:logPath];
    if (!rawData) {
        NSData *rootData = nil;
        BOOL truncated = NO;
        int code = -1;
        NSString *runErr = nil;
        if (MCPRunRootProcessData(@"/usr/libexec/ios-mcp/mcp-appmod",
                                  @[@"read-file", logPath, @"8388608"],
                                  15.0,
                                  8 * 1024 * 1024,
                                  &rootData,
                                  &truncated,
                                  &code,
                                  &runErr) && code == 0) {
            rawData = rootData;
        }
    }

    NSMutableArray<NSDictionary *> *matched = [NSMutableArray array];
    NSUInteger totalLines = 0;

    if (rawData.length > 0) {
        NSString *text = [[NSString alloc] initWithData:rawData encoding:NSUTF8StringEncoding];
        if (text.length > 0) {
            NSArray<NSString *> *lines = [text componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
            for (NSString *line in lines) {
                if (!line.length) continue;
                NSData *lineData = [line dataUsingEncoding:NSUTF8StringEncoding];
                NSDictionary *entry = lineData ? [NSJSONSerialization JSONObjectWithData:lineData options:0 error:NULL] : nil;
                if (![entry isKindOfClass:[NSDictionary class]]) continue;
                totalLines++;
                if (urlFilter.length > 0) {
                    NSString *u = [entry[@"url"] isKindOfClass:[NSString class]] ? entry[@"url"] : @"";
                    if ([u rangeOfString:urlFilter options:NSCaseInsensitiveSearch].location == NSNotFound) {
                        continue;
                    }
                }
                [matched addObject:entry];
            }
        }
    }

    NSArray<NSDictionary *> *returned = matched;
    BOOL truncatedCount = NO;
    if (matched.count > limit) {
        truncatedCount = YES;
        returned = [matched subarrayWithRange:NSMakeRange(matched.count - limit, limit)];
    }

    if (clear) {
        [self deleteCaptureLogAtPath:logPath];
    }

    return @{
        @"bundle_id": bundleId,
        @"capture_log_path": logPath,
        @"log_exists": @(rawData != nil),
        @"total_captured": @(totalLines),
        @"matched_count": @(matched.count),
        @"returned_count": @(returned.count),
        @"truncated": @(truncatedCount),
        @"cleared": @(clear),
        @"requests": returned
    };
}

@end
