#import "NetworkCaptureManager.h"
#import "AppManager.h"
#import "DylibInjectManager.h"
#import "MCPEngineManager.h"
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

- (NSString *)captureContainerForBundleId:(NSString *)bundleId error:(NSString **)error {
    NSString *appErr = nil;
    NSDictionary *info = [[AppManager sharedInstance] appInfoForBundleId:bundleId error:&appErr];
    if (!info) {
        if (error) *error = appErr ?: [NSString stringWithFormat:@"App not found: %@", bundleId];
        return nil;
    }
    id rawContainer = info[@"data_container"] ?: info[@"data_container_path"];
    NSString *container = [rawContainer isKindOfClass:[NSString class]] ? rawContainer : nil;
    if (!container.length) {
        if (error) *error = [NSString stringWithFormat:@"App %@ has no data_container_path", bundleId];
        return nil;
    }
    return container;
}

- (NSString *)primaryCaptureLogPathForBundleId:(NSString *)bundleId error:(NSString **)error {
    NSString *container = [self captureContainerForBundleId:bundleId error:error];
    if (!container) return nil;
    return [container stringByAppendingPathComponent:@"tmp/.mcpcap.jsonl"];
}

- (NSString *)captureLogPathForBundleId:(NSString *)bundleId error:(NSString **)error {
    NSString *container = [self captureContainerForBundleId:bundleId error:error];
    if (!container) return nil;
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
    NSString *primaryLogPath = [self primaryCaptureLogPathForBundleId:bundleId error:error];
    if (!primaryLogPath) return nil;
    NSString *legacyLogPath = [self captureLogPathForBundleId:bundleId error:nil];

    if (clearExisting) {
        [self deleteCaptureLogAtPath:primaryLogPath];
        if (legacyLogPath.length) [self deleteCaptureLogAtPath:legacyLogPath];
    }

    NSDictionary *ping = !relaunch ? [[MCPEngineManager sharedInstance] pingForBundleId:bundleId error:nil] : nil;
    NSDictionary *inj = nil;
    if (!ping) {
        inj = [[MCPEngineManager sharedInstance] injectEngineForBundleId:bundleId
                                                           stealthConfig:nil
                                                                  launch:relaunch
                                                                   error:error];
        if (!inj) return nil;
    }

    NSString *capErr = nil;
    NSDictionary *engineCap = [[MCPEngineManager sharedInstance] startCaptureForBundleId:bundleId
                                                                                    args:@{@"clear": @NO}
                                                                                   error:&capErr];

    NSMutableDictionary *res = [NSMutableDictionary dictionaryWithDictionary:(inj ?: @{})];
    res[@"bundle_id"] = bundleId;
    res[@"capture_status"] = @"started";
    res[@"capture_log_path"] = primaryLogPath;
    res[@"legacy_capture_log_path"] = legacyLogPath ?: @"";
    res[@"cleared_existing"] = @(clearExisting);
    res[@"relaunched"] = @(relaunch ? [inj[@"launched"] boolValue] : NO);
    if (engineCap) res[@"engine_capture"] = engineCap;
    if (capErr.length > 0 && !engineCap) res[@"engine_capture_warning"] = capErr;
    return res;
}

- (NSDictionary *)stopCaptureForBundleId:(NSString *)bundleId
                               clearLogs:(BOOL)clearLogs
                                relaunch:(BOOL)relaunch
                                   error:(NSString **)error {
    if (error) *error = nil;
    NSString *primaryLogPath = [self primaryCaptureLogPathForBundleId:bundleId error:nil];
    NSString *legacyLogPath = [self captureLogPathForBundleId:bundleId error:nil];

    // 1. If the engine is live, stop capture & restore any BoringSSL GOT slots first.
    NSDictionary *engineStop = [[MCPEngineManager sharedInstance] stopCaptureForBundleId:bundleId
                                                                                    args:@{}
                                                                                   error:nil];

    // 2. Preserve log files across engine removal if clearLogs == NO.
    NSData *savedPrimary = (!clearLogs && primaryLogPath.length) ? [NSData dataWithContentsOfFile:primaryLogPath] : nil;
    NSData *savedLegacy = (!clearLogs && legacyLogPath.length) ? [NSData dataWithContentsOfFile:legacyLogPath] : nil;

    NSString *remErr = nil;
    NSDictionary *rem = [[MCPEngineManager sharedInstance] removeEngineForBundleId:bundleId error:&remErr];

    // Also remove standalone libmcp_netcap.dylib if it was ever staged.
    [[DylibInjectManager sharedInstance] removeDylibForBundleId:bundleId
                                                      dylibName:kMCPNetCapDestName
                                                restoreOriginal:NO
                                                   deleteStaged:YES
                                                          error:nil];

    if (clearLogs) {
        if (primaryLogPath.length) [self deleteCaptureLogAtPath:primaryLogPath];
        if (legacyLogPath.length) [self deleteCaptureLogAtPath:legacyLogPath];
    } else {
        if (savedPrimary.length && primaryLogPath.length && ![[NSFileManager defaultManager] fileExistsAtPath:primaryLogPath]) {
            [savedPrimary writeToFile:primaryLogPath options:NSDataWritingAtomic error:nil];
        }
        if (savedLegacy.length && legacyLogPath.length && ![[NSFileManager defaultManager] fileExistsAtPath:legacyLogPath]) {
            [savedLegacy writeToFile:legacyLogPath options:NSDataWritingAtomic error:nil];
        }
    }

    BOOL relaunched = NO;
    NSString *launchErr = nil;
    if (relaunch) {
        relaunched = [[AppManager sharedInstance] launchApp:bundleId error:&launchErr];
    }

    NSMutableDictionary *res = [NSMutableDictionary dictionaryWithDictionary:(rem ?: @{})];
    res[@"bundle_id"] = bundleId;
    res[@"capture_status"] = @"stopped";
    res[@"capture_log_path"] = primaryLogPath ?: @"";
    res[@"logs_cleared"] = @(clearLogs);
    res[@"relaunched"] = @(relaunched);
    if (engineStop) res[@"engine_stop"] = engineStop;
    if (launchErr.length > 0) res[@"relaunch_warning"] = launchErr;
    return res;
}

- (NSData *)readCaptureFileDataAtPath:(NSString *)path {
    if (!path.length) return nil;
    NSData *rawData = [NSData dataWithContentsOfFile:path];
    if (!rawData) {
        NSData *rootData = nil;
        BOOL truncated = NO;
        int code = -1;
        NSString *runErr = nil;
        if (MCPRunRootProcessData(@"/usr/libexec/ios-mcp/mcp-appmod",
                                  @[@"read-file", path, @"8388608"],
                                  15.0,
                                  8 * 1024 * 1024,
                                  &rootData,
                                  &truncated,
                                  &code,
                                  &runErr) && code == 0) {
            rawData = rootData;
        }
    }
    return rawData;
}

- (NSDictionary *)getCapturedRequestsForBundleId:(NSString *)bundleId
                                           limit:(NSUInteger)limit
                                       urlFilter:(NSString *)urlFilter
                                           clear:(BOOL)clear
                                           error:(NSString **)error {
    if (error) *error = nil;
    NSString *primaryLogPath = [self primaryCaptureLogPathForBundleId:bundleId error:error];
    if (!primaryLogPath) return nil;
    NSString *legacyLogPath = [self captureLogPathForBundleId:bundleId error:nil];

    if (limit == 0) limit = 100;
    if (limit > 1000) limit = 1000;

    // Collect entries from engine RPC (if live) plus both on-disk JSONL files.
    NSMutableArray<NSDictionary *> *allEntries = [NSMutableArray array];
    NSDictionary *engineReqs = [[MCPEngineManager sharedInstance] getCapturedRequestsForBundleId:bundleId
                                                                                            args:@{@"limit": @(limit), @"clear": @NO}
                                                                                           error:nil];
    if ([engineReqs[@"requests"] isKindOfClass:[NSArray class]]) {
        [allEntries addObjectsFromArray:engineReqs[@"requests"]];
    }

    NSData *primaryData = [self readCaptureFileDataAtPath:primaryLogPath];
    NSData *legacyData = [self readCaptureFileDataAtPath:legacyLogPath];
    for (NSData *rawData in @[primaryData ?: [NSData data], legacyData ?: [NSData data]]) {
        if (!rawData.length) continue;
        NSString *text = [[NSString alloc] initWithData:rawData encoding:NSUTF8StringEncoding];
        for (NSString *line in [text componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]]) {
            if (!line.length) continue;
            NSData *lineData = [line dataUsingEncoding:NSUTF8StringEncoding];
            NSDictionary *entry = lineData ? [NSJSONSerialization JSONObjectWithData:lineData options:0 error:NULL] : nil;
            if ([entry isKindOfClass:[NSDictionary class]]) {
                [allEntries addObject:entry];
            }
        }
    }

    // Deduplicate and prefer rich nsurlsession entries when both layers saw the same URL+method
    NSMutableSet<NSString *> *richURLMethods = [NSMutableSet set];
    for (NSDictionary *entry in allEntries) {
        NSString *src = entry[@"source"] ?: @"nsurlsession";
        if ([src isEqualToString:@"nsurlsession"]) {
            [richURLMethods addObject:[NSString stringWithFormat:@"%@|%@", entry[@"method"] ?: @"", entry[@"url"] ?: @""]];
        }
    }

    NSMutableArray<NSDictionary *> *matched = [NSMutableArray array];
    NSMutableSet<NSString *> *seenKeys = [NSMutableSet set];
    NSUInteger totalUnique = 0;

    for (NSDictionary *entry in allEntries) {
        NSString *src = entry[@"source"] ?: @"nsurlsession";
        NSString *um = [NSString stringWithFormat:@"%@|%@", entry[@"method"] ?: @"", entry[@"url"] ?: @""];
        if (![src isEqualToString:@"nsurlsession"] && [richURLMethods containsObject:um]) {
            continue;
        }
        NSString *dedupKey = [NSString stringWithFormat:@"%@|%@|%@|%@",
                              src, entry[@"id"] ?: @0, entry[@"method"] ?: @"", entry[@"url"] ?: @""];
        if ([seenKeys containsObject:dedupKey]) continue;
        [seenKeys addObject:dedupKey];
        totalUnique++;

        if (urlFilter.length > 0) {
            NSString *u = [entry[@"url"] isKindOfClass:[NSString class]] ? entry[@"url"] : @"";
            NSString *h = [entry[@"host"] isKindOfClass:[NSString class]] ? entry[@"host"] : @"";
            if ([u rangeOfString:urlFilter options:NSCaseInsensitiveSearch].location == NSNotFound &&
                [h rangeOfString:urlFilter options:NSCaseInsensitiveSearch].location == NSNotFound) {
                continue;
            }
        }
        [matched addObject:entry];
    }

    NSArray<NSDictionary *> *returned = matched;
    BOOL truncatedCount = NO;
    if (matched.count > limit) {
        truncatedCount = YES;
        returned = [matched subarrayWithRange:NSMakeRange(matched.count - limit, limit)];
    }

    if (clear) {
        [self deleteCaptureLogAtPath:primaryLogPath];
        if (legacyLogPath.length) [self deleteCaptureLogAtPath:legacyLogPath];
    }

    return @{
        @"bundle_id": bundleId,
        @"capture_log_path": primaryLogPath,
        @"log_exists": @((primaryData != nil) || (legacyData != nil)),
        @"total_captured": @(totalUnique),
        @"matched_count": @(matched.count),
        @"returned_count": @(returned.count),
        @"truncated": @(truncatedCount),
        @"cleared": @(clear),
        @"requests": returned
    };
}

@end
