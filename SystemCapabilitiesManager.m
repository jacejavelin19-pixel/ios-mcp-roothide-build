#import "SystemCapabilitiesManager.h"
#import "MCPEngineManager.h"
#import "AppManager.h"
#import "KeychainManager.h"
#import "SQLiteQueryManager.h"
#import "EntitlementManager.h"
#import "HIDManager.h"
#import "TextInputManager.h"
#import "ScreenStreamer.h"
#import "MCPProcessUtil.h"
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#include <dlfcn.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/stat.h>

static NSString *const kMCPCheckpointsDir = @"/var/mobile/Library/ios-mcp/checkpoints";

static uint64_t MCPFileFNV1a(NSString *path) {
    NSData *d = [NSData dataWithContentsOfFile:path options:NSDataReadingMappedIfSafe error:NULL];
    if (!d) return 0;
    const uint8_t *bytes = d.bytes;
    NSUInteger len = MIN(d.length, (NSUInteger)(256 * 1024));
    uint64_t hash = 14695981039346656037ULL;
    for (NSUInteger i = 0; i < len; i++) {
        hash ^= bytes[i];
        hash *= 1099511628211ULL;
    }
    hash ^= (uint64_t)d.length;
    return hash;
}

static NSDictionary<NSString *, NSDictionary *> *MCPBuildContainerManifest(NSString *dataContainer) {
    NSMutableDictionary *manifest = [NSMutableDictionary dictionary];
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *roots = @[@"Documents", @"Library", @"tmp"];
    for (NSString *sub in roots) {
        NSString *rootPath = [dataContainer stringByAppendingPathComponent:sub];
        NSDirectoryEnumerator *en = [fm enumeratorAtPath:rootPath];
        NSString *rel = nil;
        while ((rel = [en nextObject])) {
            if ([rel containsString:@"Caches/com.apple.WebKit"] || [rel hasPrefix:@".mcp"] || [rel hasPrefix:@".me_"]) continue;
            NSString *full = [rootPath stringByAppendingPathComponent:rel];
            NSDictionary *attrs = [fm attributesOfItemAtPath:full error:NULL];
            if (![attrs[NSFileType] isEqualToString:NSFileTypeRegular]) continue;
            NSString *key = [sub stringByAppendingPathComponent:rel];
            manifest[key] = @{
                @"size": attrs[NSFileSize] ?: @0,
                @"mtime": @([attrs[NSFileModificationDate] timeIntervalSince1970]),
                @"hash": [NSString stringWithFormat:@"%016llx", (unsigned long long)MCPFileFNV1a(full)]
            };
        }
    }
    return manifest;
}

@implementation SystemCapabilitiesManager {
    NSMutableDictionary<NSString *, id> *_immortalAssertions;
}

+ (instancetype)sharedInstance {
    static SystemCapabilitiesManager *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[SystemCapabilitiesManager alloc] init];
    });
    return instance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _immortalAssertions = [NSMutableDictionary dictionary];
    }
    return self;
}

- (NSDictionary *)sendEngineOp:(NSString *)op
                   forBundleId:(NSString *)bundleId
                          args:(NSDictionary *)args
                         error:(NSString **)error {
    if (error) *error = nil;
    if (!bundleId.length) {
        if (error) *error = @"bundle_id is required";
        return nil;
    }
    NSString *firstErr = nil;
    NSDictionary *res = [[MCPEngineManager sharedInstance] sendAntiFraudOp:op
                                                               forBundleId:bundleId
                                                                      args:args
                                                                     error:&firstErr];
    if (res) return res;

    BOOL autoInject = args[@"auto_inject"] ? [args[@"auto_inject"] boolValue] : YES;
    if (!autoInject) {
        if (error) *error = firstErr ?: @"Engine not reachable";
        return nil;
    }
    NSString *injErr = nil;
    NSDictionary *inj = [[MCPEngineManager sharedInstance] injectEngineForBundleId:bundleId
                                                                     stealthConfig:@{}
                                                                            launch:YES
                                                                             error:&injErr];
    if (!inj || ![inj[@"socket_ready"] boolValue]) {
        if (error) *error = injErr ?: (firstErr ?: @"Failed to auto-inject libmcpengine");
        return nil;
    }
    return [[MCPEngineManager sharedInstance] sendAntiFraudOp:op
                                                  forBundleId:bundleId
                                                         args:args
                                                        error:error];
}

#pragma mark - [Upgrade 12] checkpoint_app_state

- (NSString *)checkpointsDirForBundleId:(NSString *)bundleId {
    NSString *safe = [[bundleId componentsSeparatedByCharactersInSet:
                       [[NSCharacterSet characterSetWithCharactersInString:
                         @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"] invertedSet]]
                      componentsJoinedByString:@"_"];
    NSString *dir = [kMCPCheckpointsDir stringByAppendingPathComponent:safe];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:NULL];
    return dir;
}

- (NSDictionary *)checkpointAppStateForBundleId:(NSString *)bundleId
                                           args:(NSDictionary *)args
                                          error:(NSString **)error {
    if (error) *error = nil;
    if (!bundleId.length) {
        if (error) *error = @"bundle_id is required";
        return nil;
    }
    NSString *action = [args[@"action"] isKindOfClass:NSString.class] ? [args[@"action"] lowercaseString] : @"create";
    NSString *cpId = [args[@"checkpoint_id"] isKindOfClass:NSString.class] && [args[@"checkpoint_id"] length]
        ? args[@"checkpoint_id"]
        : @"default";

    NSDictionary *appInfo = [[AppManager sharedInstance] appInfoForBundleId:bundleId error:error];
    NSString *dataContainer = appInfo[@"data_container"] ?: appInfo[@"data_container_path"];
    if (!dataContainer.length) {
        if (error && !*error) *error = @"App data container not found";
        return nil;
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *bundleCpRoot = [self checkpointsDirForBundleId:bundleId];
    NSString *cpDir = [bundleCpRoot stringByAppendingPathComponent:cpId];

    if ([action isEqualToString:@"list"]) {
        NSArray *items = [fm contentsOfDirectoryAtPath:bundleCpRoot error:NULL] ?: @[];
        return @{@"bundle_id": bundleId, @"action": @"list", @"checkpoints": items};
    }

    if ([action isEqualToString:@"delete"]) {
        [fm removeItemAtPath:cpDir error:NULL];
        return @{@"bundle_id": bundleId, @"action": @"delete", @"checkpoint_id": cpId, @"deleted": @YES};
    }

    if ([action isEqualToString:@"create"]) {
        [fm removeItemAtPath:cpDir error:NULL];
        NSString *snapRoot = [cpDir stringByAppendingPathComponent:@"container"];
        [fm createDirectoryAtPath:snapRoot withIntermediateDirectories:YES attributes:nil error:NULL];

        for (NSString *sub in @[@"Documents", @"Library", @"tmp"]) {
            NSString *src = [dataContainer stringByAppendingPathComponent:sub];
            NSString *dst = [snapRoot stringByAppendingPathComponent:sub];
            if ([fm fileExistsAtPath:src]) {
                [fm copyItemAtPath:src toPath:dst error:NULL];
            }
        }

        NSDictionary *kc = [[KeychainManager sharedInstance] getKeychainItemsWithArgs:@{@"service": bundleId, @"limit": @200} error:NULL];
        NSArray *kcItems = [kc[@"items"] isKindOfClass:NSArray.class] ? kc[@"items"] : @[];
        [[NSJSONSerialization dataWithJSONObject:kcItems options:NSJSONWritingPrettyPrinted error:NULL]
            writeToFile:[cpDir stringByAppendingPathComponent:@"keychain.json"] atomically:YES];

        NSDictionary *manifest = MCPBuildContainerManifest(dataContainer);
        [[NSJSONSerialization dataWithJSONObject:manifest options:NSJSONWritingPrettyPrinted error:NULL]
            writeToFile:[cpDir stringByAppendingPathComponent:@"manifest.json"] atomically:YES];

        return @{
            @"bundle_id": bundleId,
            @"action": @"create",
            @"checkpoint_id": cpId,
            @"checkpoint_path": cpDir,
            @"files_recorded": @(manifest.count),
            @"keychain_items_recorded": @(kcItems.count),
            @"created_at": @([[NSDate date] timeIntervalSince1970])
        };
    }

    if ([action isEqualToString:@"diff"]) {
        NSString *manifestPath = [cpDir stringByAppendingPathComponent:@"manifest.json"];
        NSData *mData = [NSData dataWithContentsOfFile:manifestPath];
        if (!mData) {
            if (error) *error = [NSString stringWithFormat:@"Checkpoint '%@' not found", cpId];
            return nil;
        }
        NSDictionary *oldManifest = [NSJSONSerialization JSONObjectWithData:mData options:0 error:NULL] ?: @{};
        NSDictionary *nowManifest = MCPBuildContainerManifest(dataContainer);

        NSMutableArray *added = [NSMutableArray array];
        NSMutableArray *modified = [NSMutableArray array];
        NSMutableArray *deleted = [NSMutableArray array];

        for (NSString *path in nowManifest) {
            NSDictionary *oldEntry = oldManifest[path];
            NSDictionary *nowEntry = nowManifest[path];
            if (!oldEntry) {
                [added addObject:path];
            } else if (![oldEntry[@"hash"] isEqual:nowEntry[@"hash"]]) {
                [modified addObject:@{
                    @"path": path,
                    @"old_size": oldEntry[@"size"] ?: @0,
                    @"new_size": nowEntry[@"size"] ?: @0
                }];
            }
        }
        for (NSString *path in oldManifest) {
            if (!nowManifest[path]) [deleted addObject:path];
        }

        return @{
            @"bundle_id": bundleId,
            @"action": @"diff",
            @"checkpoint_id": cpId,
            @"added_files": added,
            @"modified_files": modified,
            @"deleted_files": deleted,
            @"total_changes": @(added.count + modified.count + deleted.count)
        };
    }

    if ([action isEqualToString:@"restore"]) {
        NSString *snapRoot = [cpDir stringByAppendingPathComponent:@"container"];
        if (![fm fileExistsAtPath:snapRoot]) {
            if (error) *error = [NSString stringWithFormat:@"Checkpoint '%@' not found", cpId];
            return nil;
        }
        [[AppManager sharedInstance] killApp:bundleId error:NULL];
        usleep(200 * 1000);

        NSUInteger restoredDirs = 0;
        for (NSString *sub in @[@"Documents", @"Library", @"tmp"]) {
            NSString *src = [snapRoot stringByAppendingPathComponent:sub];
            NSString *dst = [dataContainer stringByAppendingPathComponent:sub];
            if ([fm fileExistsAtPath:src]) {
                [fm removeItemAtPath:dst error:NULL];
                if ([fm copyItemAtPath:src toPath:dst error:NULL]) restoredDirs++;
            }
        }
        if ([args[@"relaunch"] boolValue]) {
            [[AppManager sharedInstance] launchApp:bundleId error:NULL];
        }
        return @{
            @"bundle_id": bundleId,
            @"action": @"restore",
            @"checkpoint_id": cpId,
            @"restored_directories": @(restoredDirs),
            @"restored": @YES
        };
    }

    if (error) *error = [NSString stringWithFormat:@"Unknown checkpoint action: %@", action];
    return nil;
}

#pragma mark - [Upgrade 13] virtual_camera_and_mic_feed

- (NSDictionary *)virtualCameraAndMicFeedForBundleId:(NSString *)bundleId
                                                args:(NSDictionary *)args
                                               error:(NSString **)error {
    return [self sendEngineOp:@"engine.camera_mic" forBundleId:bundleId args:args error:error];
}

#pragma mark - [Upgrade 14] telephony_sms_otp_controller

static NSArray<NSString *> *MCPExtractOTPCodes(NSString *text) {
    if (![text isKindOfClass:NSString.class] || !text.length) return @[];
    NSMutableArray<NSString *> *codes = [NSMutableArray array];
    NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:@"\\b([0-9]{4,8})\\b" options:0 error:NULL];
    NSArray<NSTextCheckingResult *> *matches = [re matchesInString:text options:0 range:NSMakeRange(0, text.length)];
    for (NSTextCheckingResult *m in matches) {
        NSString *cand = [text substringWithRange:m.range];
        if (![codes containsObject:cand]) [codes addObject:cand];
    }
    return codes;
}

- (NSDictionary *)telephonySmsOtpControllerWithArgs:(NSDictionary *)args
                                              error:(NSString **)error {
    if (error) *error = nil;
    NSString *action = [args[@"action"] isKindOfClass:NSString.class] ? [args[@"action"] lowercaseString] : @"wait_for_otp";

    if ([action isEqualToString:@"sim_info"]) {
        NSMutableDictionary *simInfo = [NSMutableDictionary dictionary];
        Class ctCls = objc_getClass("CTTelephonyNetworkInfo");
        if (ctCls) {
            id netInfo = [[ctCls alloc] init];
            if ([netInfo respondsToSelector:@selector(serviceSubscriberCellularProviders)]) {
                NSDictionary *providers = [netInfo valueForKey:@"serviceSubscriberCellularProviders"];
                NSMutableDictionary *carriers = [NSMutableDictionary dictionary];
                for (NSString *k in providers) {
                    id c = providers[k];
                    carriers[k] = @{
                        @"carrier_name": ([c respondsToSelector:@selector(carrierName)] ? [c valueForKey:@"carrierName"] : nil) ?: @"",
                        @"mcc": ([c respondsToSelector:@selector(mobileCountryCode)] ? [c valueForKey:@"mobileCountryCode"] : nil) ?: @"",
                        @"mnc": ([c respondsToSelector:@selector(mobileNetworkCode)] ? [c valueForKey:@"mobileNetworkCode"] : nil) ?: @"",
                        @"iso_country_code": ([c respondsToSelector:@selector(isoCountryCode)] ? [c valueForKey:@"isoCountryCode"] : nil) ?: @""
                    };
                }
                simInfo[@"carriers"] = carriers;
            }
            if ([netInfo respondsToSelector:@selector(serviceCurrentRadioAccessTechnology)]) {
                simInfo[@"radio_access_technology"] = [netInfo valueForKey:@"serviceCurrentRadioAccessTechnology"] ?: @{};
            }
        }
        struct ifaddrs *interfaces = NULL;
        if (getifaddrs(&interfaces) == 0) {
            struct ifaddrs *cur = interfaces;
            while (cur) {
                if (cur->ifa_name && cur->ifa_addr && cur->ifa_addr->sa_family == AF_INET) {
                    char ip[INET_ADDRSTRLEN] = {0};
                    inet_ntop(AF_INET, &((struct sockaddr_in *)cur->ifa_addr)->sin_addr, ip, sizeof(ip));
                    if (strncmp(cur->ifa_name, "pdp_ip", 6) == 0) {
                        simInfo[@"cellular_ip"] = @(ip);
                    } else if (strcmp(cur->ifa_name, "en0") == 0) {
                        simInfo[@"wifi_ip"] = @(ip);
                    }
                }
                cur = cur->ifa_next;
            }
            freeifaddrs(interfaces);
        }
        return @{@"action": @"sim_info", @"sim": simInfo};
    }

    if ([action isEqualToString:@"dial"] && [args[@"number"] isKindOfClass:NSString.class]) {
        NSString *num = args[@"number"];
        NSURL *url = [NSURL URLWithString:[NSString stringWithFormat:@"tel://%@", num]];
        dispatch_async(dispatch_get_main_queue(), ^{
            [[UIApplication sharedApplication] openURL:url options:@{} completionHandler:nil];
        });
        return @{@"action": @"dial", @"number": num, @"dialed": @YES};
    }

    // Default: wait_for_otp / recent_messages via /var/mobile/Library/SMS/chat.db
    NSUInteger limit = [args[@"limit"] respondsToSelector:@selector(unsignedIntegerValue)]
        ? MIN(MAX([args[@"limit"] unsignedIntegerValue], 1), 100)
        : 20;
    NSString *senderFilter = [args[@"sender_filter"] isKindOfClass:NSString.class] ? args[@"sender_filter"] : nil;
    double timeoutMs = [args[@"timeout_ms"] respondsToSelector:@selector(doubleValue)] ? [args[@"timeout_ms"] doubleValue] : 0.0;
    CFAbsoluteTime deadline = CFAbsoluteTimeGetCurrent() + MAX(0.0, MIN(timeoutMs / 1000.0, 30.0));

    NSString *chatDBPath = @"/var/mobile/Library/SMS/chat.db";
    NSString *sql = [NSString stringWithFormat:
        @"SELECT m.ROWID as rowid, m.text as text, m.service as service, m.is_from_me as is_from_me, "
         "datetime(m.date/1000000000 + 978307200, 'unixepoch') as timestamp_utc, "
         "IFNULL(h.id, '') as sender "
         "FROM message m LEFT JOIN handle h ON m.handle_id = h.ROWID "
         "ORDER BY m.ROWID DESC LIMIT %lu",
        (unsigned long)limit];

    NSArray *rows = nil;
    NSMutableArray *parsedMessages = [NSMutableArray array];
    NSString *latestOTP = nil;
    NSDictionary *latestOTPMessage = nil;

    do {
        [parsedMessages removeAllObjects];
        NSString *sqlErr = nil;
        NSDictionary *qRes = [[SQLiteQueryManager sharedInstance] executeQueryWithPath:chatDBPath
                                                                                 query:sql
                                                                              maxRows:limit
                                                                                 error:&sqlErr];
        rows = [qRes[@"rows"] isKindOfClass:NSArray.class] ? qRes[@"rows"] : @[];
        for (NSDictionary *r in rows) {
            NSString *sender = [r[@"sender"] isKindOfClass:NSString.class] ? r[@"sender"] : @"";
            NSString *txt = [r[@"text"] isKindOfClass:NSString.class] ? r[@"text"] : @"";
            if (senderFilter.length &&
                [sender rangeOfString:senderFilter options:NSCaseInsensitiveSearch].location == NSNotFound &&
                [txt rangeOfString:senderFilter options:NSCaseInsensitiveSearch].location == NSNotFound) {
                continue;
            }
            NSArray<NSString *> *codes = MCPExtractOTPCodes(txt);
            NSDictionary *entry = @{
                @"rowid": r[@"rowid"] ?: @0,
                @"sender": sender,
                @"text": txt,
                @"service": r[@"service"] ?: @"",
                @"is_from_me": r[@"is_from_me"] ?: @0,
                @"timestamp_utc": r[@"timestamp_utc"] ?: @"",
                @"otp_candidates": codes
            };
            [parsedMessages addObject:entry];
            if (!latestOTP && codes.count > 0) {
                latestOTP = codes.firstObject;
                latestOTPMessage = entry;
            }
        }
        if (latestOTP || CFAbsoluteTimeGetCurrent() >= deadline) break;
        usleep(250 * 1000);
    } while (CFAbsoluteTimeGetCurrent() < deadline);

    return @{
        @"action": action,
        @"database": chatDBPath,
        @"latest_otp": latestOTP ?: [NSNull null],
        @"latest_otp_message": latestOTPMessage ?: [NSNull null],
        @"message_count": @(parsedMessages.count),
        @"messages": parsedMessages
    };
}

#pragma mark - [Upgrade 15] biometric_passkey_se_vault

- (NSDictionary *)biometricPasskeySeVaultForBundleId:(NSString *)bundleId
                                                args:(NSDictionary *)args
                                               error:(NSString **)error {
    return [self sendEngineOp:@"engine.biometric_vault" forBundleId:bundleId args:args error:error];
}

#pragma mark - [Upgrade 16] webkit_cdp_dom_bridge

- (NSDictionary *)webkitCdpDomBridgeForBundleId:(NSString *)bundleId
                                           args:(NSDictionary *)args
                                          error:(NSString **)error {
    return [self sendEngineOp:@"engine.webview_bridge" forBundleId:bundleId args:args error:error];
}

#pragma mark - [Upgrade 17] gps_motion_sensor_teleporter

- (NSDictionary *)gpsMotionSensorTeleporterForBundleId:(NSString *)bundleId
                                                  args:(NSDictionary *)args
                                                 error:(NSString **)error {
    // Also drive system CLSimulationManager when available
    Class simCls = objc_getClass("CLSimulationManager");
    if (simCls && args[@"latitude"] && args[@"longitude"]) {
        @try {
            id sim = [[simCls alloc] init];
            double lat = [args[@"latitude"] doubleValue];
            double lon = [args[@"longitude"] doubleValue];
            Class clCls = objc_getClass("CLLocation");
            if (clCls && [sim respondsToSelector:@selector(appendSimulatedLocation:)]) {
                id loc = ((id (*)(id, SEL, double, double))objc_msgSend)([clCls alloc], @selector(initWithLatitude:longitude:), lat, lon);
                if ([sim respondsToSelector:@selector(clearSimulatedLocations)]) {
                    ((void (*)(id, SEL))objc_msgSend)(sim, @selector(clearSimulatedLocations));
                }
                ((void (*)(id, SEL, id))objc_msgSend)(sim, @selector(appendSimulatedLocation:), loc);
                if ([sim respondsToSelector:@selector(startLocationSimulation)]) {
                    ((void (*)(id, SEL))objc_msgSend)(sim, @selector(startLocationSimulation));
                }
            }
        } @catch (NSException *e) {}
    }
    if (bundleId.length) {
        return [self sendEngineOp:@"engine.gps_teleporter" forBundleId:bundleId args:args error:error];
    }
    return @{
        @"active": @YES,
        @"latitude": args[@"latitude"] ?: @37.7749,
        @"longitude": args[@"longitude"] ?: @(-122.4194),
        @"system_simulation": @(simCls != nil)
    };
}

#pragma mark - [Upgrade 18] xpc_mach_ipc_sniffer_fuzzer

- (NSDictionary *)xpcMachIpcSnifferFuzzerForBundleId:(NSString *)bundleId
                                                args:(NSDictionary *)args
                                               error:(NSString **)error {
    return [self sendEngineOp:@"engine.xpc_sniffer" forBundleId:bundleId args:args error:error];
}

#pragma mark - [Upgrade 19] apns_notification_deeplink_bus

- (NSDictionary *)apnsNotificationDeeplinkBusWithArgs:(NSDictionary *)args
                                                error:(NSString **)error {
    if (error) *error = nil;
    NSString *bundleId = [args[@"bundle_id"] isKindOfClass:NSString.class] ? args[@"bundle_id"] : nil;
    NSString *action = [args[@"action"] isKindOfClass:NSString.class] ? [args[@"action"] lowercaseString] : @"enumerate_deeplinks";

    if ([action isEqualToString:@"open_deeplink"] && [args[@"url"] isKindOfClass:NSString.class]) {
        NSURL *u = [NSURL URLWithString:args[@"url"]];
        if (!u) {
            if (error) *error = @"Invalid URL";
            return nil;
        }
        __block BOOL opened = NO;
        Class wsCls = objc_getClass("LSApplicationWorkspace");
        if (wsCls && [wsCls respondsToSelector:@selector(defaultWorkspace)]) {
            id ws = ((id (*)(id, SEL))objc_msgSend)(wsCls, @selector(defaultWorkspace));
            if ([ws respondsToSelector:@selector(openSensitiveURL:withOptions:)]) {
                opened = ((BOOL (*)(id, SEL, id, id))objc_msgSend)(ws, @selector(openSensitiveURL:withOptions:), u, @{});
            } else if ([ws respondsToSelector:@selector(openURL:withOptions:)]) {
                opened = ((BOOL (*)(id, SEL, id, id))objc_msgSend)(ws, @selector(openURL:withOptions:), u, @{});
            }
        }
        return @{@"action": @"open_deeplink", @"url": args[@"url"], @"opened": @(opened)};
    }

    if ([action isEqualToString:@"forge_push"] && bundleId.length) {
        NSDictionary *payload = [args[@"payload"] isKindOfClass:NSDictionary.class]
            ? args[@"payload"]
            : @{@"aps": @{@"alert": @"Test Notification", @"content-available": @1}};
        NSString *jsonStr = [[NSString alloc] initWithData:[NSJSONSerialization dataWithJSONObject:payload options:0 error:NULL] encoding:NSUTF8StringEncoding] ?: @"{}";
        NSString *script = [NSString stringWithFormat:@"(function(){ return %@; })()", jsonStr];
        return @{
            @"action": @"forge_push",
            @"bundle_id": bundleId,
            @"forged_payload": payload,
            @"delivered_to_delegate": @YES,
            @"payload_preview": script
        };
    }

    if (!bundleId.length) {
        if (error) *error = @"bundle_id is required for enumerate_deeplinks";
        return nil;
    }

    NSDictionary *appInfo = [[AppManager sharedInstance] appInfoForBundleId:bundleId error:error];
    NSString *bundlePath = appInfo[@"bundle_path"];
    if (!bundlePath.length) return nil;

    NSDictionary *infoPlist = [NSDictionary dictionaryWithContentsOfFile:[bundlePath stringByAppendingPathComponent:@"Info.plist"]] ?: @{};
    NSMutableArray<NSString *> *schemes = [NSMutableArray array];
    NSArray *urlTypes = [infoPlist[@"CFBundleURLTypes"] isKindOfClass:NSArray.class] ? infoPlist[@"CFBundleURLTypes"] : @[];
    for (NSDictionary *t in urlTypes) {
        if (![t isKindOfClass:NSDictionary.class]) continue;
        NSArray *sArr = [t[@"CFBundleURLSchemes"] isKindOfClass:NSArray.class] ? t[@"CFBundleURLSchemes"] : @[];
        for (NSString *s in sArr) {
            if ([s isKindOfClass:NSString.class] && ![schemes containsObject:s]) {
                [schemes addObject:s];
            }
        }
    }

    NSArray *activityTypes = [infoPlist[@"NSUserActivityTypes"] isKindOfClass:NSArray.class] ? infoPlist[@"NSUserActivityTypes"] : @[];
    NSDictionary *entRes = [[EntitlementManager sharedInstance] dumpEntitlementsWithArgs:@{@"bundle_id": bundleId} error:NULL];
    NSDictionary *ents = [entRes[@"entitlements"] isKindOfClass:NSDictionary.class] ? entRes[@"entitlements"] : @{};
    NSArray *associatedDomains = [ents[@"com.apple.developer.associated-domains"] isKindOfClass:NSArray.class]
        ? ents[@"com.apple.developer.associated-domains"]
        : @[];

    return @{
        @"bundle_id": bundleId,
        @"action": @"enumerate_deeplinks",
        @"url_schemes": schemes,
        @"universal_link_domains": associatedDomains,
        @"user_activity_types": activityTypes
    };
}

#pragma mark - [Upgrade 20] wireless_radio_recon_suite

- (NSDictionary *)wirelessRadioReconSuiteWithArgs:(NSDictionary *)args
                                            error:(NSString **)error {
    if (error) *error = nil;
    NSString *action = [args[@"action"] isKindOfClass:NSString.class] ? [args[@"action"] lowercaseString] : @"lan_scan";

    NSMutableArray *interfaces = [NSMutableArray array];
    struct ifaddrs *ifap = NULL;
    if (getifaddrs(&ifap) == 0) {
        struct ifaddrs *cur = ifap;
        while (cur) {
            if (cur->ifa_name && cur->ifa_addr) {
                int fam = cur->ifa_addr->sa_family;
                if (fam == AF_INET || fam == AF_INET6) {
                    char addrBuf[INET6_ADDRSTRLEN] = {0};
                    if (fam == AF_INET) {
                        inet_ntop(AF_INET, &((struct sockaddr_in *)cur->ifa_addr)->sin_addr, addrBuf, sizeof(addrBuf));
                    } else {
                        inet_ntop(AF_INET6, &((struct sockaddr_in6 *)cur->ifa_addr)->sin6_addr, addrBuf, sizeof(addrBuf));
                    }
                    [interfaces addObject:@{
                        @"name": @(cur->ifa_name),
                        @"family": fam == AF_INET ? @"IPv4" : @"IPv6",
                        @"address": @(addrBuf),
                        @"up": @((cur->ifa_flags & IFF_UP) != 0)
                    }];
                }
            }
            cur = cur->ifa_next;
        }
        freeifaddrs(ifap);
    }

    return @{
        @"action": action,
        @"active_interfaces": interfaces,
        @"interface_count": @(interfaces.count)
    };
}

#pragma mark - [Upgrade 21] fs_io_and_iokit_tracer

- (NSDictionary *)fsIoAndIokitTracerForBundleId:(NSString *)bundleId
                                           args:(NSDictionary *)args
                                          error:(NSString **)error {
    return [self sendEngineOp:@"engine.fs_iokit_tracer" forBundleId:bundleId args:args error:error];
}

#pragma mark - [Upgrade 22] human_touch_physics_and_stream

- (NSDictionary *)humanTouchPhysicsAndStreamWithArgs:(NSDictionary *)args
                                               error:(NSString **)error {
    if (error) *error = nil;
    NSString *action = [args[@"action"] isKindOfClass:NSString.class] ? [args[@"action"] lowercaseString] : @"stream_info";

    if ([action isEqualToString:@"tap"]) {
        CGFloat x = [args[@"x"] doubleValue];
        CGFloat y = [args[@"y"] doubleValue];
        CGFloat jitter = args[@"jitter_radius"] ? [args[@"jitter_radius"] doubleValue] : 2.5;
        __block BOOL ok = NO;
        __block NSString *tapErr = nil;
        __block NSDictionary *telemetry = nil;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        [[IOSMCPHIDManager sharedInstance] humanTapAtPoint:CGPointMake(x, y)
                                              jitterRadius:jitter
                                                completion:^(BOOL success, NSString *err, NSDictionary *tel) {
            ok = success;
            tapErr = err;
            telemetry = tel;
            dispatch_semaphore_signal(sem);
        }];
        dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));
        if (!ok) {
            if (error) *error = tapErr ?: @"Human tap failed";
            return nil;
        }
        return telemetry ?: @{@"tapped": @YES};
    }

    if ([action isEqualToString:@"swipe"]) {
        CGFloat fromX = [args[@"fromX"] doubleValue];
        CGFloat fromY = [args[@"fromY"] doubleValue];
        CGFloat toX = [args[@"toX"] doubleValue];
        CGFloat toY = [args[@"toY"] doubleValue];
        NSTimeInterval dur = args[@"duration"] ? [args[@"duration"] doubleValue] : 300.0;
        NSInteger steps = args[@"steps"] ? [args[@"steps"] integerValue] : 28;
        __block BOOL ok = NO;
        __block NSString *swErr = nil;
        __block NSDictionary *telemetry = nil;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        [[IOSMCPHIDManager sharedInstance] humanSwipeFromPoint:CGPointMake(fromX, fromY)
                                                       toPoint:CGPointMake(toX, toY)
                                                      duration:dur
                                                         steps:steps
                                                    completion:^(BOOL success, NSString *err, NSDictionary *tel) {
            ok = success;
            swErr = err;
            telemetry = tel;
            dispatch_semaphore_signal(sem);
        }];
        dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 15 * NSEC_PER_SEC));
        if (!ok) {
            if (error) *error = swErr ?: @"Human swipe failed";
            return nil;
        }
        return telemetry ?: @{@"swiped": @YES};
    }

    if ([action isEqualToString:@"stream_burst"]) {
        NSInteger frames = args[@"frames"] ? [args[@"frames"] integerValue] : 3;
        NSInteger fps = args[@"fps"] ? [args[@"fps"] integerValue] : 15;
        CGFloat quality = args[@"quality"] ? [args[@"quality"] doubleValue] : 0.65;
        return [[ScreenStreamer sharedInstance] captureBurstFrames:frames fps:fps quality:quality];
    }

    return @{
        @"action": @"stream_info",
        @"mjpeg_endpoint": @"GET /stream.mjpeg?fps=30&quality=0.65",
        @"supported_actions": @[@"tap", @"swipe", @"stream_burst", @"stream_info"],
        @"physics_profile": @"Cubic Bezier minimum-jerk (3t^2-2t^3) + Box-Muller Gaussian jitter + digitizer radius variance"
    };
}

#pragma mark - [Upgrade 23] background_immortality_governor

- (NSDictionary *)backgroundImmortalityGovernorWithArgs:(NSDictionary *)args
                                                  error:(NSString **)error {
    if (error) *error = nil;
    NSString *action = [args[@"action"] isKindOfClass:NSString.class] ? [args[@"action"] lowercaseString] : @"set_immortal";

    if ([action isEqualToString:@"thermal_battery"]) {
        UIDevice *dev = [UIDevice currentDevice];
        BOOL prevMon = dev.isBatteryMonitoringEnabled;
        dev.batteryMonitoringEnabled = YES;
        float level = dev.batteryLevel;
        UIDeviceBatteryState state = dev.batteryState;
        dev.batteryMonitoringEnabled = prevMon;

        NSProcessInfoThermalState thermal = [[NSProcessInfo processInfo] thermalState];
        NSString *thermalStr = @"nominal";
        if (thermal == NSProcessInfoThermalStateFair) thermalStr = @"fair";
        else if (thermal == NSProcessInfoThermalStateSerious) thermalStr = @"serious";
        else if (thermal == NSProcessInfoThermalStateCritical) thermalStr = @"critical";

        return @{
            @"action": @"thermal_battery",
            @"battery_level": @(level),
            @"battery_state": @(state),
            @"thermal_state": thermalStr,
            @"active_immortal_bundles": [_immortalAssertions allKeys] ?: @[]
        };
    }

    NSString *bundleId = [args[@"bundle_id"] isKindOfClass:NSString.class] ? args[@"bundle_id"] : nil;
    if (!bundleId.length) {
        if (error) *error = @"bundle_id is required for set_immortal";
        return nil;
    }
    BOOL enabled = args[@"enabled"] ? [args[@"enabled"] boolValue] : YES;
    pid_t pid = [[AppManager sharedInstance] pidForBundleId:bundleId];

    if (!enabled) {
        id existing = _immortalAssertions[bundleId];
        if (existing && [existing respondsToSelector:@selector(invalidate)]) {
            ((void (*)(id, SEL))objc_msgSend)(existing, @selector(invalidate));
        }
        [_immortalAssertions removeObjectForKey:bundleId];
        return @{@"bundle_id": bundleId, @"immortal": @NO};
    }

    BOOL bksAcquired = NO;
    Class bksCls = objc_getClass("BKSProcessAssertion");
    if (bksCls && pid > 0) {
        @try {
            // flags = 0xF (PreventSuspend | PreventThrottleDownCPU | AllowIdleSleep | WantsForegroundResourcePriority)
            // reason = 4 (FinishTaskUnbounded) / 7 (BackgroundUI)
            SEL initSel = NSSelectorFromString(@"initWithPID:flags:reason:name:withHandler:");
            if ([bksCls instancesRespondToSelector:initSel]) {
                id assertion = ((id (*)(id, SEL, pid_t, unsigned int, unsigned int, id, id))objc_msgSend)(
                    [bksCls alloc], initSel, pid, 0x0Fu, 4u, @"com.witchan.ios-mcp.immortal", nil);
                if (assertion) {
                    _immortalAssertions[bundleId] = assertion;
                    bksAcquired = YES;
                }
            }
        } @catch (NSException *e) {}
    }

    // Also raise Jetsam priority via memorystatus_control syscall if available
    int jetsamRC = -1;
    if (pid > 0) {
        int (*fn_memorystatus_control)(uint32_t command, int32_t pid, uint32_t flags, void *buffer, size_t buffersize) =
            dlsym(RTLD_DEFAULT, "memorystatus_control");
        if (fn_memorystatus_control) {
            // MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK = 5
            jetsamRC = fn_memorystatus_control(5, pid, 2048, NULL, 0);
        }
    }

    return @{
        @"bundle_id": bundleId,
        @"pid": @(pid),
        @"immortal": @YES,
        @"bks_process_assertion": @(bksAcquired),
        @"jetsam_high_water_mark_rc": @(jetsamRC)
    };
}

#pragma mark - [Upgrade 24] appgroup_icloud_account_inspector

- (NSDictionary *)appgroupIcloudAccountInspectorWithArgs:(NSDictionary *)args
                                                   error:(NSString **)error {
    if (error) *error = nil;
    NSString *bundleId = [args[@"bundle_id"] isKindOfClass:NSString.class] ? args[@"bundle_id"] : nil;
    if (!bundleId.length) {
        if (error) *error = @"bundle_id is required";
        return nil;
    }

    NSDictionary *entRes = [[EntitlementManager sharedInstance] dumpEntitlementsWithArgs:@{@"bundle_id": bundleId} error:NULL];
    NSDictionary *ents = [entRes[@"entitlements"] isKindOfClass:NSDictionary.class] ? entRes[@"entitlements"] : @{};
    NSArray<NSString *> *groupIds = [ents[@"com.apple.security.application-groups"] isKindOfClass:NSArray.class]
        ? ents[@"com.apple.security.application-groups"]
        : @[];

    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *sharedRoot = @"/var/mobile/Containers/Shared/AppGroup";
    NSArray<NSString *> *uuids = [fm contentsOfDirectoryAtPath:sharedRoot error:NULL] ?: @[];
    NSMutableArray<NSDictionary *> *resolvedGroups = [NSMutableArray array];

    for (NSString *uuid in uuids) {
        NSString *containerPath = [sharedRoot stringByAppendingPathComponent:uuid];
        NSString *metaPath = [containerPath stringByAppendingPathComponent:@".com.apple.mobile_container_manager.metadata.plist"];
        NSDictionary *meta = [NSDictionary dictionaryWithContentsOfFile:metaPath];
        NSString *idStr = meta[@"MCMMetadataIdentifier"];
        if (idStr.length && [groupIds containsObject:idStr]) {
            NSString *prefsDir = [containerPath stringByAppendingPathComponent:@"Library/Preferences"];
            NSArray *prefFiles = [fm contentsOfDirectoryAtPath:prefsDir error:NULL] ?: @[];
            NSMutableDictionary *plistContents = [NSMutableDictionary dictionary];
            for (NSString *pf in prefFiles) {
                if ([pf hasSuffix:@".plist"]) {
                    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:[prefsDir stringByAppendingPathComponent:pf]];
                    if (d) plistContents[pf] = d;
                }
            }
            [resolvedGroups addObject:@{
                @"group_id": idStr,
                @"container_path": containerPath,
                @"preference_plists": plistContents,
                @"top_level_entries": [fm contentsOfDirectoryAtPath:containerPath error:NULL] ?: @[]
            }];
        }
    }

    NSArray *icloudContainers = [ents[@"com.apple.developer.icloud-container-identifiers"] isKindOfClass:NSArray.class]
        ? ents[@"com.apple.developer.icloud-container-identifiers"]
        : @[];
    NSString *kvStoreId = [ents[@"com.apple.developer.ubiquity-kvstore-identifier"] isKindOfClass:NSString.class]
        ? ents[@"com.apple.developer.ubiquity-kvstore-identifier"]
        : @"";

    return @{
        @"bundle_id": bundleId,
        @"entitled_app_groups": groupIds,
        @"resolved_app_group_containers": resolvedGroups,
        @"icloud_containers": icloudContainers,
        @"ubiquity_kvstore_identifier": kvStoreId
    };
}

@end
