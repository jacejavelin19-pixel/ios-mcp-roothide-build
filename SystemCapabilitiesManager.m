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
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <math.h>

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
    NSMutableDictionary<NSString *, NSMutableDictionary *> *_portForwards;
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
        _portForwards = [NSMutableDictionary dictionary];
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
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *base = MCPResolvedJailbreakPath(kMCPCheckpointsDir);
    [fm createDirectoryAtPath:base withIntermediateDirectories:YES attributes:nil error:NULL];
    chmod([base stringByDeletingLastPathComponent].UTF8String, 0777);
    chmod(base.UTF8String, 0777);
    if (![fm isWritableFileAtPath:base]) {
        base = MCPResolvedJailbreakPath(@"/var/mobile/Library/Caches/ios-mcp-work/checkpoints");
        [fm createDirectoryAtPath:base withIntermediateDirectories:YES attributes:nil error:NULL];
        chmod(base.UTF8String, 0777);
    }
    NSString *dir = [base stringByAppendingPathComponent:safe];
    [fm createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:NULL];
    chmod(dir.UTF8String, 0777);
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
    NSString *rawCpId = [args[@"checkpoint_id"] isKindOfClass:NSString.class] && [args[@"checkpoint_id"] length]
        ? args[@"checkpoint_id"]
        : ([args[@"name"] isKindOfClass:NSString.class] && [args[@"name"] length] ? args[@"name"] : @"default");
    NSString *cpId = [[rawCpId componentsSeparatedByCharactersInSet:
                       [[NSCharacterSet characterSetWithCharactersInString:
                         @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"] invertedSet]]
                      componentsJoinedByString:@"_"];
    if (!cpId.length) cpId = @"default";

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

        NSUInteger restoredKc = 0;
        NSString *kcPath = [cpDir stringByAppendingPathComponent:@"keychain.json"];
        NSData *kcData = [NSData dataWithContentsOfFile:kcPath];
        if (kcData) {
            NSArray *kcItems = [NSJSONSerialization JSONObjectWithData:kcData options:0 error:NULL];
            if ([kcItems isKindOfClass:NSArray.class]) {
                for (NSDictionary *item in kcItems) {
                    if (![item isKindOfClass:NSDictionary.class]) continue;
                    NSString *svc = item[@"service"] ?: bundleId;
                    NSString *acct = item[@"account"];
                    NSString *val = item[@"value"] ?: item[@"data_utf8"];
                    NSString *valB64 = item[@"data_base64"];
                    if (acct && (val || valB64)) {
                        NSMutableDictionary *setArgs = [NSMutableDictionary dictionaryWithDictionary:@{
                            @"service": svc,
                            @"account": acct
                        }];
                        if (val) setArgs[@"value"] = val;
                        if (valB64) setArgs[@"data_base64"] = valB64;
                        if (item[@"access_group"]) setArgs[@"access_group"] = item[@"access_group"];
                        if ([[KeychainManager sharedInstance] setKeychainItemWithArgs:setArgs error:NULL]) {
                            restoredKc++;
                        }
                    }
                }
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
            @"restored_keychain_items": @(restoredKc),
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
        NSDictionary *qRes = [[SQLiteQueryManager sharedInstance] queryDatabaseAtPath:chatDBPath
                                                                                  sql:sql
                                                                                limit:limit
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
    NSString *action = [args[@"action"] isKindOfClass:NSString.class] ? [args[@"action"] lowercaseString] : @"set";
    BOOL enabled = args[@"enable"] ? [args[@"enable"] boolValue] : (args[@"enabled"] ? [args[@"enabled"] boolValue] : YES);
    if ([action isEqualToString:@"stop"] || [action isEqualToString:@"disable"] || [action isEqualToString:@"reset"]) {
        enabled = NO;
    }

    id rawLat = args[@"latitude"] ?: args[@"lat"];
    id rawLon = args[@"longitude"] ?: args[@"lon"];
    id rawAlt = args[@"altitude"] ?: args[@"alt"];

    // Drive system CLSimulationManager when available
    Class simCls = objc_getClass("CLSimulationManager");
    if (simCls) {
        @try {
            id sim = [[simCls alloc] init];
            if (!enabled) {
                if ([sim respondsToSelector:@selector(stopLocationSimulation)]) {
                    ((void (*)(id, SEL))objc_msgSend)(sim, @selector(stopLocationSimulation));
                }
                if ([sim respondsToSelector:@selector(clearSimulatedLocations)]) {
                    ((void (*)(id, SEL))objc_msgSend)(sim, @selector(clearSimulatedLocations));
                }
            } else if (rawLat && rawLon) {
                double lat = [rawLat doubleValue];
                double lon = [rawLon doubleValue];
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
            }
        } @catch (NSException *e) {}
    }

    NSMutableDictionary *normArgs = [NSMutableDictionary dictionaryWithDictionary:args ?: @{}];
    normArgs[@"enable"] = @(enabled);
    if (rawLat) { normArgs[@"lat"] = rawLat; normArgs[@"latitude"] = rawLat; }
    if (rawLon) { normArgs[@"lon"] = rawLon; normArgs[@"longitude"] = rawLon; }
    if (rawAlt) { normArgs[@"alt"] = rawAlt; normArgs[@"altitude"] = rawAlt; }

    if (bundleId.length) {
        return [self sendEngineOp:@"engine.gps_teleporter" forBundleId:bundleId args:normArgs error:error];
    }
    return @{
        @"active": @(enabled),
        @"latitude": rawLat ?: @37.7749,
        @"longitude": rawLon ?: @(-122.4194),
        @"altitude": rawAlt ?: @15.0,
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
        NSString *title = [args[@"title"] isKindOfClass:NSString.class] ? args[@"title"] : nil;
        NSString *body = [args[@"body"] isKindOfClass:NSString.class] ? args[@"body"] : nil;
        NSMutableDictionary *payload = [args[@"payload"] isKindOfClass:NSDictionary.class]
            ? [args[@"payload"] mutableCopy]
            : [NSMutableDictionary dictionary];
        if (!payload[@"aps"]) {
            if (title.length || body.length) {
                NSMutableDictionary *alert = [NSMutableDictionary dictionary];
                if (title.length) alert[@"title"] = title;
                if (body.length) alert[@"body"] = body;
                payload[@"aps"] = @{@"alert": alert, @"sound": @"default", @"content-available": @1};
            } else {
                payload[@"aps"] = @{@"alert": @"Test Notification", @"content-available": @1};
            }
        }

        NSMutableDictionary *engArgs = [NSMutableDictionary dictionaryWithDictionary:args ?: @{}];
        engArgs[@"payload"] = payload;
        if (title) engArgs[@"title"] = title;
        if (body) engArgs[@"body"] = body;

        NSString *engErr = nil;
        NSDictionary *engRes = [self sendEngineOp:@"engine.forge_push" forBundleId:bundleId args:engArgs error:&engErr];
        NSString *jsonStr = [[NSString alloc] initWithData:[NSJSONSerialization dataWithJSONObject:payload options:0 error:NULL] encoding:NSUTF8StringEncoding] ?: @"{}";
        return @{
            @"action": @"forge_push",
            @"bundle_id": bundleId,
            @"forged_payload": payload,
            @"delivered_to_delegate": @([engRes[@"delivered_to_delegate"] boolValue] || [engRes[@"local_notification_scheduled"] boolValue]),
            @"engine_result": engRes ?: [NSNull null],
            @"engine_error": engErr ?: [NSNull null],
            @"payload_preview": jsonStr
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
    NSDictionary *entRes = [[EntitlementManager sharedInstance] dumpEntitlementsForBundleId:bundleId error:NULL];
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
                    char maskBuf[INET6_ADDRSTRLEN] = {0};
                    if (fam == AF_INET) {
                        inet_ntop(AF_INET, &((struct sockaddr_in *)cur->ifa_addr)->sin_addr, addrBuf, sizeof(addrBuf));
                        if (cur->ifa_netmask) {
                            inet_ntop(AF_INET, &((struct sockaddr_in *)cur->ifa_netmask)->sin_addr, maskBuf, sizeof(maskBuf));
                        }
                    } else {
                        inet_ntop(AF_INET6, &((struct sockaddr_in6 *)cur->ifa_addr)->sin6_addr, addrBuf, sizeof(addrBuf));
                    }
                    [interfaces addObject:@{
                        @"name": @(cur->ifa_name),
                        @"family": fam == AF_INET ? @"IPv4" : @"IPv6",
                        @"address": @(addrBuf),
                        @"netmask": maskBuf[0] ? @(maskBuf) : [NSNull null],
                        @"up": @((cur->ifa_flags & IFF_UP) != 0),
                        @"loopback": @((cur->ifa_flags & IFF_LOOPBACK) != 0)
                    }];
                }
            }
            cur = cur->ifa_next;
        }
        freeifaddrs(ifap);
    }

    NSMutableDictionary *result = [NSMutableDictionary dictionaryWithDictionary:@{
        @"action": action,
        @"active_interfaces": interfaces,
        @"interface_count": @(interfaces.count)
    }];

    // Wi-Fi SSID / BSSID via CaptiveNetwork
    if ([action isEqualToString:@"wifi_info"] || [action isEqualToString:@"lan_scan"]) {
        NSMutableDictionary *wifiInfo = [NSMutableDictionary dictionary];
        CFArrayRef (*fn_CNCopySupportedInterfaces)(void) = dlsym(RTLD_DEFAULT, "CNCopySupportedInterfaces");
        CFDictionaryRef (*fn_CNCopyCurrentNetworkInfo)(CFStringRef) = dlsym(RTLD_DEFAULT, "CNCopyCurrentNetworkInfo");
        if (fn_CNCopySupportedInterfaces && fn_CNCopyCurrentNetworkInfo) {
            CFArrayRef ifs = fn_CNCopySupportedInterfaces();
            if (ifs) {
                NSArray *ifList = (__bridge_transfer NSArray *)ifs;
                wifiInfo[@"supported_interfaces"] = ifList;
                for (NSString *ifName in ifList) {
                    CFDictionaryRef netDict = fn_CNCopyCurrentNetworkInfo((__bridge CFStringRef)ifName);
                    if (netDict) {
                        NSDictionary *nd = (__bridge_transfer NSDictionary *)netDict;
                        wifiInfo[ifName] = @{
                            @"SSID": nd[@"SSID"] ?: @"",
                            @"BSSID": nd[@"BSSID"] ?: @""
                        };
                    }
                }
            }
        }
        for (NSDictionary *iface in interfaces) {
            if ([iface[@"name"] isEqualToString:@"en0"] && [iface[@"family"] isEqualToString:@"IPv4"]) {
                wifiInfo[@"en0_ipv4"] = iface[@"address"];
                wifiInfo[@"en0_netmask"] = iface[@"netmask"];
            }
        }
        result[@"wifi_info"] = wifiInfo;
    }

    // LAN ARP neighbor table
    if ([action isEqualToString:@"lan_scan"]) {
        NSMutableArray *neighbors = [NSMutableArray array];
        int arpStatus = -1;
        NSString *arpOut = MCPReadCommandOutput(@[@"arp", @"-an"], 4.0, &arpStatus);
        if (arpOut.length) {
            NSArray<NSString *> *lines = [arpOut componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
            NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:@"\\(([0-9a-fA-F.:]+)\\)\\s+at\\s+([0-9a-fA-F:]+|\\(incomplete\\))\\s+on\\s+([a-zA-Z0-9_]+)" options:0 error:NULL];
            for (NSString *line in lines) {
                NSTextCheckingResult *m = [re firstMatchInString:line options:0 range:NSMakeRange(0, line.length)];
                if (m && m.numberOfRanges >= 4) {
                    [neighbors addObject:@{
                        @"ip": [line substringWithRange:[m rangeAtIndex:1]],
                        @"mac": [line substringWithRange:[m rangeAtIndex:2]],
                        @"interface": [line substringWithRange:[m rangeAtIndex:3]]
                    }];
                }
            }
        }
        result[@"lan_neighbors"] = neighbors;
        result[@"neighbor_count"] = @(neighbors.count);
    }

    // BLE Central state + peripheral scan
    if ([action isEqualToString:@"ble_scan"]) {
        dlopen("/System/Library/Frameworks/CoreBluetooth.framework/CoreBluetooth", RTLD_LAZY);
        Class cbCentralCls = NSClassFromString(@"CBCentralManager");
        NSMutableDictionary *bleInfo = [NSMutableDictionary dictionaryWithDictionary:@{
            @"CoreBluetooth_loaded": @(cbCentralCls != nil)
        }];
        if (cbCentralCls) {
            @try {
                SEL initSel = NSSelectorFromString(@"initWithDelegate:queue:");
                id central = [cbCentralCls instancesRespondToSelector:initSel]
                    ? ((id (*)(id, SEL, id, id))objc_msgSend)([cbCentralCls alloc], initSel, nil, nil)
                    : [[cbCentralCls alloc] init];
                if ([central respondsToSelector:@selector(state)]) {
                    NSInteger st = ((NSInteger (*)(id, SEL))objc_msgSend)(central, @selector(state));
                    bleInfo[@"central_state"] = @(st);
                }

                if ([cbCentralCls respondsToSelector:NSSelectorFromString(@"authorization")]) {
                    NSInteger auth = ((NSInteger (*)(id, SEL))objc_msgSend)(cbCentralCls, NSSelectorFromString(@"authorization"));
                    bleInfo[@"authorization"] = @(auth);
                }
            } @catch (NSException *e) {
                bleInfo[@"error"] = e.reason ?: @"BLE init exception";
            }
        }
        result[@"ble_scan"] = bleInfo;
    }

    // NFC capability + in-process hook
    if ([action isEqualToString:@"nfc_hook"]) {
        dlopen("/System/Library/Frameworks/CoreNFC.framework/CoreNFC", RTLD_LAZY);
        Class ndefCls = NSClassFromString(@"NFCNDEFReaderSession");
        BOOL readingAvail = NO;
        if (ndefCls && [ndefCls respondsToSelector:NSSelectorFromString(@"readingAvailable")]) {
            readingAvail = ((BOOL (*)(id, SEL))objc_msgSend)(ndefCls, NSSelectorFromString(@"readingAvailable"));
        }
        NSMutableDictionary *nfcInfo = [NSMutableDictionary dictionaryWithDictionary:@{
            @"CoreNFC_loaded": @(ndefCls != nil),
            @"reading_available": @(readingAvail)
        }];
        NSString *bundleId = [args[@"bundle_id"] isKindOfClass:NSString.class] ? args[@"bundle_id"] : nil;
        if (bundleId.length) {
            NSString *engErr = nil;
            NSDictionary *engRes = [self sendEngineOp:@"engine.nfc_hook" forBundleId:bundleId args:args error:&engErr];
            if (engRes) nfcInfo[@"engine_result"] = engRes;
            if (engErr) nfcInfo[@"engine_error"] = engErr;
        }
        result[@"nfc_hook"] = nfcInfo;
    }

    return result;
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
    NSString *action = [args[@"action"] isKindOfClass:NSString.class] ? [args[@"action"] lowercaseString] : nil;
    if (!action.length) {
        if (args[@"x"] && args[@"y"]) {
            action = @"human_tap";
        } else if ((args[@"start_x"] && args[@"start_y"]) || (args[@"fromX"] && args[@"fromY"])) {
            action = @"human_swipe";
        } else {
            action = @"stream_info";
        }
    }

    if ([action isEqualToString:@"tap"] || [action isEqualToString:@"human_tap"]) {
        CGFloat x = [args[@"x"] ?: args[@"start_x"] ?: args[@"fromX"] doubleValue];
        CGFloat y = [args[@"y"] ?: args[@"start_y"] ?: args[@"fromY"] doubleValue];
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
        return telemetry ?: @{@"tapped": @YES, @"action": @"human_tap"};
    }

    if ([action isEqualToString:@"swipe"] || [action isEqualToString:@"human_swipe"]) {
        CGFloat fromX = [args[@"start_x"] ?: args[@"fromX"] ?: args[@"x"] doubleValue];
        CGFloat fromY = [args[@"start_y"] ?: args[@"fromY"] ?: args[@"y"] doubleValue];
        CGFloat toX = [args[@"end_x"] ?: args[@"toX"] doubleValue];
        CGFloat toY = [args[@"end_y"] ?: args[@"toY"] doubleValue];
        NSTimeInterval rawDur = args[@"duration"] ? [args[@"duration"] doubleValue] : 0.35;
        // Convert seconds (<= 10.0) to milliseconds expected by humanSwipeFromPoint:toPoint:duration:steps:
        NSTimeInterval durMs = (rawDur > 0.0 && rawDur <= 10.0) ? (rawDur * 1000.0) : rawDur;
        if (durMs <= 0.0) durMs = 350.0;
        NSInteger steps = args[@"steps"] ? [args[@"steps"] integerValue] : 28;
        __block BOOL ok = NO;
        __block NSString *swErr = nil;
        __block NSDictionary *telemetry = nil;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        [[IOSMCPHIDManager sharedInstance] humanSwipeFromPoint:CGPointMake(fromX, fromY)
                                                       toPoint:CGPointMake(toX, toY)
                                                      duration:durMs
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
        return telemetry ?: @{@"swiped": @YES, @"action": @"human_swipe"};
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
        @"supported_actions": @[@"human_tap", @"human_swipe", @"tap", @"swipe", @"stream_burst", @"stream_info"],
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

    NSDictionary *entRes = [[EntitlementManager sharedInstance] dumpEntitlementsForBundleId:bundleId error:NULL];
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

#pragma mark - [Step 4 & Step 5] Donor Stealth, OTP, Social, Photos & Tweak Lifecycle

- (NSDictionary *)setOtpWithArgs:(NSDictionary *)args
                           error:(NSString **)error {
    if (error) *error = nil;
    NSString *code = [args[@"code"] ?: args[@"otp"] ?: @"" description];
    if (!code.length) {
        // Poll SMS database for latest OTP if code was not explicitly supplied
        NSDictionary *smsRes = [self telephonySmsOtpControllerWithArgs:@{
            @"action": @"wait_for_otp",
            @"timeout_ms": args[@"timeout_ms"] ?: @3000,
            @"sender_filter": args[@"sender_filter"] ?: @""
        } error:NULL];
        if ([smsRes[@"latest_otp"] isKindOfClass:NSString.class]) {
            code = smsRes[@"latest_otp"];
        }
    }
    if (!code.length) {
        if (error) *error = @"Provide 'code'/'otp' or ensure an OTP message is present in SMS chat.db";
        return nil;
    }

    NSString *bundleId = [args[@"bundle_id"] isKindOfClass:NSString.class] ? args[@"bundle_id"] : nil;
    if (!bundleId.length) {
        NSDictionary *front = [[AppManager sharedInstance] getFrontmostApp];
        bundleId = [front[@"bundle_id"] isKindOfClass:NSString.class] ? front[@"bundle_id"] : nil;
    }

    if (bundleId.length) {
        NSMutableDictionary *engArgs = [NSMutableDictionary dictionaryWithDictionary:args ?: @{}];
        engArgs[@"code"] = code;
        NSString *engErr = nil;
        NSDictionary *engRes = [self sendEngineOp:@"engine.set_otp" forBundleId:bundleId args:engArgs error:&engErr];
        if (engRes && [engRes[@"ok"] boolValue]) {
            return @{
                @"ok": @YES,
                @"code": code,
                @"bundle_id": bundleId,
                @"delivery": @"engine.set_otp",
                @"engine_result": engRes
            };
        }
    }

    // Fallback: character-by-character keyboard input via TextInputManager
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    __block BOOL typedOk = NO;
    __block NSString *typeErr = nil;
    [[TextInputManager sharedInstance] typeText:code delayMs:45.0 completion:^(BOOL success, NSString *err) {
        typedOk = success;
        typeErr = err;
        dispatch_semaphore_signal(sem);
    }];
    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC));
    if (!typedOk) {
        if (error) *error = typeErr ?: @"OTP input failed";
        return nil;
    }
    return @{
        @"ok": @YES,
        @"code": code,
        @"bundle_id": bundleId ?: [NSNull null],
        @"delivery": @"TextInputManager_typeText"
    };
}

- (NSDictionary *)humanPauseWithArgs:(NSDictionary *)args
                               error:(NSString **)error {
    if (error) *error = nil;
    double minMs = args[@"min_ms"] ? [args[@"min_ms"] doubleValue] : 250.0;
    double maxMs = args[@"max_ms"] ? [args[@"max_ms"] doubleValue] : 950.0;
    if (args[@"duration_ms"] || args[@"ms"]) {
        double target = [args[@"duration_ms"] ?: args[@"ms"] doubleValue];
        double jitter = args[@"jitter_ms"] ? [args[@"jitter_ms"] doubleValue] : (target * 0.18);
        minMs = MAX(10.0, target - jitter);
        maxMs = target + jitter;
    }
    if (maxMs < minMs) {
        double tmp = minMs;
        minMs = maxMs;
        maxMs = tmp;
    }
    // Box-Muller Gaussian sample centered in [minMs, maxMs]
    double u1 = ((double)arc4random() + 1.0) / ((double)UINT32_MAX + 2.0);
    double u2 = ((double)arc4random() + 1.0) / ((double)UINT32_MAX + 2.0);
    double z = sqrt(-2.0 * log(u1)) * cos(2.0 * M_PI * u2);
    double mean = 0.5 * (minMs + maxMs);
    double sigma = (maxMs - minMs) / 4.0;
    double chosenMs = MIN(MAX(mean + z * sigma, minMs), maxMs);
    chosenMs = MIN(MAX(chosenMs, 1.0), 30000.0);

    usleep((useconds_t)(chosenMs * 1000.0));
    return @{
        @"ok": @YES,
        @"slept_ms": @(round(chosenMs * 10.0) / 10.0),
        @"min_ms": @(minMs),
        @"max_ms": @(maxMs),
        @"distribution": @"Box-Muller clipped Gaussian"
    };
}

- (NSDictionary *)tiktokSocialControllerWithAction:(NSString *)action
                                              args:(NSDictionary *)args
                                             error:(NSString **)error {
    if (error) *error = nil;
    NSString *act = [action ?: args[@"action"] ?: @"tiktok_sign" lowercaseString];
    NSString *bundleId = [args[@"bundle_id"] isKindOfClass:NSString.class] && [args[@"bundle_id"] length]
        ? args[@"bundle_id"]
        : @"com.zhiliaoapp.musically";

    // Resolve alternative TikTok bundle ID if com.zhiliaoapp.musically is not installed
    if (![[AppManager sharedInstance] appInfoForBundleId:bundleId error:NULL]) {
        for (NSString *alt in @[@"com.ss.iphone.ugc.Ame", @"com.zhiliaoapp.musically.go"]) {
            if ([[AppManager sharedInstance] appInfoForBundleId:alt error:NULL]) {
                bundleId = alt;
                break;
            }
        }
    }

    if ([act isEqualToString:@"tiktok_open_search"] || [act isEqualToString:@"open_search"]) {
        NSString *keyword = [args[@"keyword"] ?: args[@"query"] ?: @"" description];
        NSString *encoded = [keyword stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLQueryAllowedCharacterSet]] ?: @"";
        NSString *schemeUrl = keyword.length
            ? [NSString stringWithFormat:@"snssdk1233://search?keyword=%@", encoded]
            : @"snssdk1233://search";
        [[AppManager sharedInstance] launchApp:bundleId error:NULL];
        BOOL opened = [[AppManager sharedInstance] openURL:schemeUrl error:NULL];
        return @{
            @"ok": @YES,
            @"action": @"tiktok_open_search",
            @"bundle_id": bundleId,
            @"keyword": keyword,
            @"deeplink": schemeUrl,
            @"opened": @(opened)
        };
    }

    NSString *engineOp = @"engine.tiktok_sign";
    if ([act isEqualToString:@"tiktok_inbox"] || [act isEqualToString:@"inbox"]) {
        engineOp = @"engine.tiktok_inbox";
    } else if ([act isEqualToString:@"tiktok_reply"] || [act isEqualToString:@"reply"]) {
        engineOp = @"engine.tiktok_reply";
    } else if ([act isEqualToString:@"tiktok_im"] || [act isEqualToString:@"im"]) {
        engineOp = @"engine.tiktok_im";
    } else if ([act isEqualToString:@"tiktok_posts"] || [act isEqualToString:@"posts"]) {
        engineOp = @"engine.tiktok_posts";
    } else if ([act isEqualToString:@"tiktok_sign"] || [act isEqualToString:@"sign"]) {
        engineOp = @"engine.tiktok_sign";
    }

    return [self sendEngineOp:engineOp forBundleId:bundleId args:args ?: @{} error:error];
}

- (NSDictionary *)photosLibraryControllerWithAction:(NSString *)action
                                               args:(NSDictionary *)args
                                              error:(NSString **)error {
    if (error) *error = nil;
    NSString *act = [action ?: args[@"action"] ?: @"photos_list" lowercaseString];
    if ([act hasPrefix:@"photos_"]) {
        act = [act substringFromIndex:7];
    } else if ([act isEqualToString:@"media_upload"]) {
        act = @"import";
    }

    // Fast path for listing assets via Photos.sqlite when Photos.framework isn't needed
    if ([act isEqualToString:@"list"] && ![args[@"use_framework"] boolValue]) {
        NSString *photosDb = @"/var/mobile/Media/PhotoData/Photos.sqlite";
        if ([[NSFileManager defaultManager] fileExistsAtPath:photosDb]) {
            NSInteger limit = args[@"limit"] ? [args[@"limit"] integerValue] : 25;
            if (limit <= 0 || limit > 200) limit = 25;
            NSString *sql = [NSString stringWithFormat:
                @"SELECT ZUUID as uuid, ZDIRECTORY as directory, ZFILENAME as filename, "
                 "ZWIDTH as width, ZHEIGHT as height, ZKINDSUBTYPE as kind_subtype, "
                 "datetime(ZDATECREATED + 978307200, 'unixepoch') as created_utc "
                 "FROM ZASSET WHERE ZTRASHEDSTATE = 0 ORDER BY Z_PK DESC LIMIT %ld",
                (long)limit];
            NSString *sqlErr = nil;
            NSDictionary *qRes = [[SQLiteQueryManager sharedInstance] queryDatabaseAtPath:photosDb sql:sql limit:(NSUInteger)limit error:&sqlErr];
            if (qRes && [qRes[@"rows"] isKindOfClass:NSArray.class]) {
                return @{
                    @"ok": @YES,
                    @"action": @"photos_list",
                    @"source": @"Photos.sqlite",
                    @"count": @([qRes[@"rows"] count]),
                    @"assets": qRes[@"rows"]
                };
            }
        }
    }

    // Use Photos.framework directly inside SpringBoard/helper or via engine.photos
    dlopen("/System/Library/Frameworks/Photos.framework/Photos", RTLD_LAZY);
    Class phLibCls = NSClassFromString(@"PHPhotoLibrary");
    Class phAssetCls = NSClassFromString(@"PHAsset");
    Class phChangeReqCls = NSClassFromString(@"PHAssetChangeRequest");

    if (phLibCls && phAssetCls) {
        if ([act isEqualToString:@"ensure"] || [act isEqualToString:@"status"]) {
            NSInteger auth = [phLibCls respondsToSelector:@selector(authorizationStatus)]
                ? ((NSInteger (*)(id, SEL))objc_msgSend)(phLibCls, @selector(authorizationStatus))
                : 0;
            return @{
                @"ok": @YES,
                @"action": @"photos_ensure",
                @"authorization_status": @(auth),
                @"authorized": @(auth == 3 || auth == 4)
            };
        }

        id sharedLib = [phLibCls respondsToSelector:@selector(sharedPhotoLibrary)]
            ? ((id (*)(id, SEL))objc_msgSend)(phLibCls, @selector(sharedPhotoLibrary))
            : nil;

        if (sharedLib && ([act isEqualToString:@"import"] || [act isEqualToString:@"import_file"])) {
            NSString *filePath = [args[@"path"] ?: args[@"file_path"] ?: @"" description];
            NSString *b64 = [args[@"data_base64"] ?: args[@"base64"] ?: @"" description];
            NSString *mediaType = [[args[@"media_type"] ?: @"image" description] lowercaseString];

            NSURL *targetURL = nil;
            BOOL removeTemp = NO;
            if (filePath.length > 0) {
                targetURL = [NSURL fileURLWithPath:filePath];
            } else if (b64.length > 0) {
                NSData *raw = [[NSData alloc] initWithBase64EncodedString:b64 options:NSDataBase64DecodingIgnoreUnknownCharacters];
                if (!raw) {
                    if (error) *error = @"Invalid base64 media data";
                    return nil;
                }
                NSString *ext = [mediaType isEqualToString:@"video"] ? @"mp4" : @"jpg";
                NSString *tmp = [NSTemporaryDirectory() stringByAppendingPathComponent:[NSString stringWithFormat:@"mcp_media_%lld.%@", (long long)([[NSDate date] timeIntervalSince1970] * 1000), ext]];
                [raw writeToFile:tmp atomically:YES];
                targetURL = [NSURL fileURLWithPath:tmp];
                removeTemp = YES;
            } else {
                if (error) *error = @"Provide 'path'/'file_path' or 'data_base64'";
                return nil;
            }

            __block NSString *createdId = nil;
            NSError *impErr = nil;
            SEL perfSel = NSSelectorFromString(@"performChangesAndWait:error:");
            if ([sharedLib respondsToSelector:perfSel] && phChangeReqCls) {
                void (^blk)(void) = ^{
                    id req = nil;
                    SEL sel = [mediaType isEqualToString:@"video"]
                        ? NSSelectorFromString(@"creationRequestForAssetFromVideoAtFileURL:")
                        : NSSelectorFromString(@"creationRequestForAssetFromImageAtFileURL:");
                    if ([phChangeReqCls respondsToSelector:sel]) {
                        req = ((id (*)(id, SEL, id))objc_msgSend)(phChangeReqCls, sel, targetURL);
                    }
                    if (req && [req respondsToSelector:NSSelectorFromString(@"placeholderForCreatedAsset")]) {
                        id ph = ((id (*)(id, SEL))objc_msgSend)(req, NSSelectorFromString(@"placeholderForCreatedAsset"));
                        if (ph && [ph respondsToSelector:NSSelectorFromString(@"localIdentifier")]) {
                            createdId = ((id (*)(id, SEL))objc_msgSend)(ph, NSSelectorFromString(@"localIdentifier"));
                        }
                    }
                };
                BOOL ok = ((BOOL (*)(id, SEL, id, NSError **))objc_msgSend)(sharedLib, perfSel, blk, &impErr);
                if (removeTemp && targetURL.path) [[NSFileManager defaultManager] removeItemAtPath:targetURL.path error:nil];
                if (!ok) {
                    if (error) *error = impErr.localizedDescription ?: @"Photo library import failed";
                    return nil;
                }
                return @{
                    @"ok": @YES,
                    @"action": [NSString stringWithFormat:@"photos_%@", act],
                    @"local_identifier": createdId ?: [NSNull null],
                    @"media_type": mediaType
                };
            }
        }

        if (sharedLib && [act isEqualToString:@"clear"]) {
            SEL fetchSel = NSSelectorFromString(@"fetchAssetsWithOptions:");
            SEL delSel = NSSelectorFromString(@"deleteAssets:");
            SEL perfSel = NSSelectorFromString(@"performChangesAndWait:error:");
            if ([phAssetCls respondsToSelector:fetchSel] && [phChangeReqCls respondsToSelector:delSel] && [sharedLib respondsToSelector:perfSel]) {
                id fetchRes = ((id (*)(id, SEL, id))objc_msgSend)(phAssetCls, fetchSel, nil);
                NSUInteger total = [fetchRes respondsToSelector:@selector(count)] ? [fetchRes count] : 0;
                if (total == 0) return @{@"ok": @YES, @"action": @"photos_clear", @"deleted": @0};
                NSError *delErr = nil;
                void (^delBlk)(void) = ^{
                    ((void (*)(id, SEL, id))objc_msgSend)(phChangeReqCls, delSel, fetchRes);
                };
                BOOL ok = ((BOOL (*)(id, SEL, id, NSError **))objc_msgSend)(sharedLib, perfSel, delBlk, &delErr);
                if (!ok) {
                    if (error) *error = delErr.localizedDescription ?: @"Photos clear failed";
                    return nil;
                }
                return @{@"ok": @YES, @"action": @"photos_clear", @"deleted": @(total)};
            }
        }
    }

    NSString *bundleId = [args[@"bundle_id"] isKindOfClass:NSString.class] ? args[@"bundle_id"] : @"com.apple.mobileslideshow";
    NSMutableDictionary *engArgs = [NSMutableDictionary dictionaryWithDictionary:args ?: @{}];
    engArgs[@"action"] = act;
    return [self sendEngineOp:@"engine.photos" forBundleId:bundleId args:engArgs error:error];
}

- (NSDictionary *)tweakLifecycleWithAction:(NSString *)action
                                      args:(NSDictionary *)args
                                     error:(NSString **)error {
    if (error) *error = nil;
    NSString *act = [action ?: args[@"action"] ?: @"tweak_deploy" lowercaseString];
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *rollbackDir = MCPResolvedJailbreakPath(@"/var/mobile/Library/ios-mcp/rollback");
    [fm createDirectoryAtPath:rollbackDir withIntermediateDirectories:YES attributes:nil error:NULL];

    if ([act isEqualToString:@"tweak_build"] || [act isEqualToString:@"build"]) {
        NSString *projectDir = [args[@"project_dir"] ?: args[@"path"] ?: @"" description];
        if (!projectDir.length || ![fm fileExistsAtPath:projectDir]) {
            if (error) *error = @"Provide a valid 'project_dir' on device with a Theos Makefile";
            return nil;
        }
        int status = -1;
        NSString *out = MCPReadCommandOutput(@[@"make", @"-C", projectDir, @"package", @"FINALPACKAGE=1"], 120.0, &status);
        return @{
            @"ok": @(status == 0),
            @"action": @"tweak_build",
            @"project_dir": projectDir,
            @"exit_code": @(status),
            @"output": out ?: @""
        };
    }

    if ([act isEqualToString:@"tweak_deploy"] || [act isEqualToString:@"deploy"] ||
        [act isEqualToString:@"self_update"] || [act isEqualToString:@"update"]) {
        NSString *debPath = [args[@"deb_path"] ?: args[@"path"] ?: @"" description];
        NSString *b64 = [args[@"deb_base64"] ?: args[@"data_base64"] ?: @"" description];
        if (!debPath.length && b64.length) {
            NSData *raw = [[NSData alloc] initWithBase64EncodedString:b64 options:NSDataBase64DecodingIgnoreUnknownCharacters];
            if (raw.length) {
                debPath = [rollbackDir stringByAppendingPathComponent:@"staged_update.deb"];
                [raw writeToFile:debPath atomically:YES];
            }
        }
        if (!debPath.length || ![fm fileExistsAtPath:debPath]) {
            if (error) *error = @"Provide 'deb_path' or 'deb_base64' pointing to a valid .deb package";
            return nil;
        }

        // Snapshot current installed tweak dylib into rollback directory before dpkg -i
        NSString *curDylib = MCPSubPath(@"Library/MobileSubstrate/DynamicLibraries/iOSMCP.dylib");
        if ([fm fileExistsAtPath:curDylib]) {
            NSString *bakDylib = [rollbackDir stringByAppendingPathComponent:@"iOSMCP.dylib.bak"];
            [fm removeItemAtPath:bakDylib error:NULL];
            [fm copyItemAtPath:curDylib toPath:bakDylib error:NULL];
        }
        NSString *bakDeb = [rollbackDir stringByAppendingPathComponent:@"last_deployed.deb"];
        if (![debPath isEqualToString:bakDeb]) {
            [fm removeItemAtPath:bakDeb error:NULL];
            [fm copyItemAtPath:debPath toPath:bakDeb error:NULL];
        }

        int status = -1;
        NSString *dpkgOut = MCPReadCommandOutput(@[@"dpkg", @"-i", debPath], 60.0, &status);
        if ([args[@"respring"] boolValue] && status == 0) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.75 * NSEC_PER_SEC)), dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                MCPReadCommandOutput(@[@"killall", @"-9", @"SpringBoard"], 5.0, NULL);
            });
        }
        return @{
            @"ok": @(status == 0),
            @"action": act,
            @"deb_path": debPath,
            @"rollback_backup_dir": rollbackDir,
            @"exit_code": @(status),
            @"output": dpkgOut ?: @""
        };
    }

    if ([act isEqualToString:@"tweak_rollback"] || [act isEqualToString:@"rollback"]) {
        NSString *bakDeb = [args[@"deb_path"] isKindOfClass:NSString.class]
            ? args[@"deb_path"]
            : [rollbackDir stringByAppendingPathComponent:@"previous.deb"];
        NSString *bakDylib = [rollbackDir stringByAppendingPathComponent:@"iOSMCP.dylib.bak"];
        NSString *curDylib = MCPSubPath(@"Library/MobileSubstrate/DynamicLibraries/iOSMCP.dylib");

        if ([fm fileExistsAtPath:bakDeb]) {
            int status = -1;
            NSString *out = MCPReadCommandOutput(@[@"dpkg", @"-i", bakDeb], 60.0, &status);
            return @{@"ok": @(status == 0), @"action": @"tweak_rollback", @"restored_from": bakDeb, @"output": out ?: @""};
        }
        if ([fm fileExistsAtPath:bakDylib]) {
            [fm removeItemAtPath:curDylib error:NULL];
            BOOL copied = [fm copyItemAtPath:bakDylib toPath:curDylib error:NULL];
            return @{@"ok": @(copied), @"action": @"tweak_rollback", @"restored_from": bakDylib};
        }
        if (error) *error = @"No rollback backup found in /var/mobile/Library/ios-mcp/rollback";
        return nil;
    }

    if (error) *error = [NSString stringWithFormat:@"Unknown tweak lifecycle action: %@", act];
    return nil;
}

- (NSDictionary *)diagnoseRootsWithArgs:(NSDictionary *)args
                                  error:(NSString **)error {
    if (error) *error = nil;
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *jbRoot = MCPJailbreakRoot();
    NSArray<NSString *> *candidates = @[
        @"/",
        @"/var/jb",
        @"/private/preboot",
        @"/var/containers/Bundle/Application",
        @"/var/mobile",
        @"/var/mobile/Library/ios-mcp",
        MCPSubPath(@"Library/MobileSubstrate/DynamicLibraries"),
        MCPSubPath(@"usr/libexec/ios-mcp-helper"),
        MCPSubPath(@"usr/lib/ios-mcp/libmcpengine.dylib")
    ];
    NSMutableArray *probed = [NSMutableArray array];
    for (NSString *p in candidates) {
        BOOL isDir = NO;
        BOOL exists = [fm fileExistsAtPath:p isDirectory:&isDir];
        [probed addObject:@{
            @"path": p,
            @"exists": @(exists),
            @"is_directory": @(isDir),
            @"readable": @([fm isReadableFileAtPath:p]),
            @"writable": @([fm isWritableFileAtPath:p])
        }];
    }
    NSString *layoutType = @"rootful";
    if ([jbRoot hasPrefix:@"/private/preboot"] || [jbRoot containsString:@".jbroot"]) {
        layoutType = @"roothide";
    } else if ([jbRoot isEqualToString:@"/var/jb"]) {
        layoutType = @"rootless";
    }
    return @{
        @"jailbreak_layout": layoutType,
        @"jbroot": jbRoot ?: @"/",
        @"search_PATH": MCPCommandSearchPath() ?: @"",
        @"uid": @(getuid()),
        @"euid": @(geteuid()),
        @"probed_paths": probed
    };
}

- (NSDictionary *)diagnosticsCollectWithArgs:(NSDictionary *)args
                                       error:(NSString **)error {
    if (error) *error = nil;
    NSDictionary *roots = [self diagnoseRootsWithArgs:args error:NULL] ?: @{};
    NSDictionary *thermal = [self backgroundImmortalityGovernorWithArgs:@{@"action": @"thermal_battery"} error:NULL] ?: @{};
    NSDictionary *radio = [self wirelessRadioReconSuiteWithArgs:@{@"action": @"wifi_info"} error:NULL] ?: @{};
    NSDictionary *frontmost = [[AppManager sharedInstance] getFrontmostApp] ?: @{};

    int dpkgStatus = -1;
    NSString *dpkgInfo = MCPReadCommandOutput(@[@"dpkg", @"-l", @"com.witchan.ios-mcp"], 5.0, &dpkgStatus);
    int psStatus = -1;
    NSString *helperPs = MCPReadCommandOutput(@[@"ps", @"-ef"], 5.0, &psStatus);
    BOOL helperRunning = [helperPs containsString:@"ios-mcp-helper"];

    return @{
        @"ok": @YES,
        @"timestamp": @([[NSDate date] timeIntervalSince1970]),
        @"roots": roots,
        @"thermal_battery": thermal,
        @"network": radio,
        @"frontmost_app": frontmost,
        @"helper_daemon_running": @(helperRunning),
        @"package_status": dpkgInfo ?: @""
    };
}

- (NSDictionary *)portForwardWithArgs:(NSDictionary *)args
                                error:(NSString **)error {
    if (error) *error = nil;
    NSString *action = [args[@"action"] isKindOfClass:NSString.class] ? [args[@"action"] lowercaseString] : @"start";
    if ([action isEqualToString:@"list"]) {
        NSMutableArray *list = [NSMutableArray array];
        @synchronized (_portForwards) {
            for (NSString *k in _portForwards) {
                NSDictionary *entry = _portForwards[k];
                [list addObject:@{
                    @"id": k,
                    @"listen_port": entry[@"listen_port"] ?: @0,
                    @"target_host": entry[@"target_host"] ?: @"127.0.0.1",
                    @"target_port": entry[@"target_port"] ?: @0
                }];
            }
        }
        return @{@"ok": @YES, @"action": @"list", @"forwards": list};
    }

    uint16_t listenPort = (uint16_t)[args[@"listen_port"] ?: args[@"local_port"] integerValue];
    if ([action isEqualToString:@"stop"]) {
        NSString *key = [NSString stringWithFormat:@"%u", listenPort];
        NSMutableDictionary *entry = nil;
        @synchronized (_portForwards) {
            entry = _portForwards[key];
            if (entry) [_portForwards removeObjectForKey:key];
        }
        if (entry && entry[@"listen_fd"]) {
            entry[@"stopped"] = @YES;
            close([entry[@"listen_fd"] intValue]);
        }
        return @{@"ok": @YES, @"action": @"stop", @"listen_port": @(listenPort)};
    }

    uint16_t targetPort = (uint16_t)[args[@"target_port"] ?: args[@"remote_port"] integerValue];
    NSString *targetHost = [args[@"target_host"] ?: @"127.0.0.1" description];
    if (listenPort == 0 || targetPort == 0) {
        if (error) *error = @"Provide non-zero 'listen_port' and 'target_port'";
        return nil;
    }

    int srvFd = socket(AF_INET, SOCK_STREAM, 0);
    if (srvFd < 0) {
        if (error) *error = [NSString stringWithFormat:@"socket() failed: %s", strerror(errno)];
        return nil;
    }
    int yes = 1;
    setsockopt(srvFd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(listenPort);
    addr.sin_addr.s_addr = [args[@"bind_all"] boolValue] ? htonl(INADDR_ANY) : htonl(INADDR_LOOPBACK);

    if (bind(srvFd, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(srvFd, 16) != 0) {
        int err = errno;
        close(srvFd);
        if (error) *error = [NSString stringWithFormat:@"bind/listen on port %u failed: %s", listenPort, strerror(err)];
        return nil;
    }

    NSString *key = [NSString stringWithFormat:@"%u", listenPort];
    NSMutableDictionary *state = [NSMutableDictionary dictionaryWithDictionary:@{
        @"listen_fd": @(srvFd),
        @"listen_port": @(listenPort),
        @"target_host": targetHost,
        @"target_port": @(targetPort),
        @"stopped": @NO
    }];
    @synchronized (_portForwards) {
        if (_portForwards[key][@"listen_fd"]) {
            close([_portForwards[key][@"listen_fd"] intValue]);
        }
        _portForwards[key] = state;
    }

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        while (![state[@"stopped"] boolValue]) {
            int clientFd = accept(srvFd, NULL, NULL);
            if (clientFd < 0) {
                if (errno == EINTR) continue;
                break;
            }
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                int upFd = socket(AF_INET, SOCK_STREAM, 0);
                struct sockaddr_in upAddr = {0};
                upAddr.sin_family = AF_INET;
                upAddr.sin_port = htons(targetPort);
                inet_pton(AF_INET, targetHost.UTF8String, &upAddr.sin_addr);
                if (upFd < 0 || connect(upFd, (struct sockaddr *)&upAddr, sizeof(upAddr)) != 0) {
                    if (upFd >= 0) close(upFd);
                    close(clientFd);
                    return;
                }
                dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                    uint8_t buf[8192];
                    ssize_t n;
                    while ((n = recv(clientFd, buf, sizeof(buf), 0)) > 0) {
                        send(upFd, buf, (size_t)n, 0);
                    }
                    shutdown(upFd, SHUT_WR);
                });
                uint8_t buf[8192];
                ssize_t n;
                while ((n = recv(upFd, buf, sizeof(buf), 0)) > 0) {
                    send(clientFd, buf, (size_t)n, 0);
                }
                close(upFd);
                close(clientFd);
            });
        }
    });

    return @{
        @"ok": @YES,
        @"action": @"start",
        @"listen_port": @(listenPort),
        @"target_host": targetHost,
        @"target_port": @(targetPort)
    };
}

- (NSDictionary *)sessionForceUnlockWithArgs:(NSDictionary *)args
                                       error:(NSString **)error {
    if (error) *error = nil;
    NSString *passcode = [args[@"passcode"] ?: args[@"pin"] ?: @"" description];
    __block BOOL unlocked = NO;

    dispatch_sync(dispatch_get_main_queue(), ^{
        // 1. Wake backlight and dismiss cover sheet via SBLockScreenManager
        Class blCls = objc_getClass("SBBacklightController");
        if (blCls && [blCls respondsToSelector:NSSelectorFromString(@"sharedInstance")]) {
            id bl = ((id (*)(id, SEL))objc_msgSend)(blCls, NSSelectorFromString(@"sharedInstance"));
            SEL wakeSel = NSSelectorFromString(@"turnOnScreenFullyWithBacklightSource:");
            if ([bl respondsToSelector:wakeSel]) {
                ((void (*)(id, SEL, int))objc_msgSend)(bl, wakeSel, 1);
            }
        }
        Class lsCls = objc_getClass("SBLockScreenManager");
        if (lsCls && [lsCls respondsToSelector:NSSelectorFromString(@"sharedInstance")]) {
            id lsm = ((id (*)(id, SEL))objc_msgSend)(lsCls, NSSelectorFromString(@"sharedInstance"));
            if (passcode.length > 0 && [lsm respondsToSelector:NSSelectorFromString(@"attemptUnlockWithPasscode:")]) {
                unlocked = ((BOOL (*)(id, SEL, id))objc_msgSend)(lsm, NSSelectorFromString(@"attemptUnlockWithPasscode:"), passcode);
            } else if ([lsm respondsToSelector:NSSelectorFromString(@"unlockUIFromSource:withOptions:")]) {
                unlocked = ((BOOL (*)(id, SEL, int, id))objc_msgSend)(lsm, NSSelectorFromString(@"unlockUIFromSource:withOptions:"), 1, @{});
            }
        }
    });

    return @{
        @"ok": @YES,
        @"action": @"session_force_unlock",
        @"unlocked": @(unlocked),
        @"passcode_used": @(passcode.length > 0)
    };
}

- (NSDictionary *)sessionRespawnWithArgs:(NSDictionary *)args
                                   error:(NSString **)error {
    if (error) *error = nil;
    NSString *target = [args[@"target"] ?: @"helper" lowercaseString];
    if ([target isEqualToString:@"springboard"] || [target isEqualToString:@"respring"]) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            MCPReadCommandOutput(@[@"killall", @"-9", @"SpringBoard"], 5.0, NULL);
        });
        return @{@"ok": @YES, @"action": @"session_respawn", @"target": @"SpringBoard", @"scheduled": @YES};
    }

    int status = -1;
    NSString *out = MCPReadCommandOutput(@[@"killall", @"-9", @"ios-mcp-helper"], 5.0, &status);
    return @{
        @"ok": @YES,
        @"action": @"session_respawn",
        @"target": @"ios-mcp-helper",
        @"exit_code": @(status),
        @"output": out ?: @""
    };
}

@end
