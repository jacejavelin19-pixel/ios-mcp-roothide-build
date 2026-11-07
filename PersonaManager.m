#import "PersonaManager.h"
#import "MCPEngineManager.h"
#import "AppManager.h"
#import "KeychainManager.h"
#import "MCPProcessUtil.h"

static NSString *const kMCPSpoofDir = @"/var/mobile/Library/ios-mcp/spoof";

static NSString *MCPPersonaRandomHex(NSUInteger bytes, BOOL uppercase) {
    NSMutableData *buf = [NSMutableData dataWithLength:bytes];
    arc4random_buf(buf.mutableBytes, bytes);
    const uint8_t *b = buf.bytes;
    NSMutableString *s = [NSMutableString stringWithCapacity:bytes * 2];
    NSString *fmt = uppercase ? @"%02X" : @"%02x";
    for (NSUInteger i = 0; i < bytes; i++) {
        [s appendFormat:fmt, b[i]];
    }
    return s;
}

static NSString *MCPPersonaRandomMAC(void) {
    uint8_t b[6];
    arc4random_buf(b, sizeof(b));
    b[0] = (b[0] & 0xFE) | 0x02;
    return [NSString stringWithFormat:@"%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5]];
}

static NSDictionary *MCPCountryPreset(NSString *countryCode) {
    NSString *cc = countryCode.uppercaseString ?: @"US";
    NSDictionary *presets = @{
        @"US": @{
            @"country_code": @"US",
            @"iso_country_code": @"us",
            @"timezone": @"America/New_York",
            @"locale": @"en_US",
            @"languages": @[@"en-US", @"en"],
            @"carrier_name": @"T-Mobile",
            @"mcc": @"310",
            @"mnc": @"260",
            @"currency_code": @"USD"
        },
        @"GB": @{
            @"country_code": @"GB",
            @"iso_country_code": @"gb",
            @"timezone": @"Europe/London",
            @"locale": @"en_GB",
            @"languages": @[@"en-GB", @"en"],
            @"carrier_name": @"EE",
            @"mcc": @"234",
            @"mnc": @"30",
            @"currency_code": @"GBP"
        },
        @"DE": @{
            @"country_code": @"DE",
            @"iso_country_code": @"de",
            @"timezone": @"Europe/Berlin",
            @"locale": @"de_DE",
            @"languages": @[@"de-DE", @"en-US"],
            @"carrier_name": @"Telekom.de",
            @"mcc": @"262",
            @"mnc": @"01",
            @"currency_code": @"EUR"
        },
        @"JP": @{
            @"country_code": @"JP",
            @"iso_country_code": @"jp",
            @"timezone": @"Asia/Tokyo",
            @"locale": @"ja_JP",
            @"languages": @[@"ja-JP", @"en-US"],
            @"carrier_name": @"NTT DOCOMO",
            @"mcc": @"440",
            @"mnc": @"10",
            @"currency_code": @"JPY"
        },
        @"CA": @{
            @"country_code": @"CA",
            @"iso_country_code": @"ca",
            @"timezone": @"America/Toronto",
            @"locale": @"en_CA",
            @"languages": @[@"en-CA", @"fr-CA"],
            @"carrier_name": @"Rogers",
            @"mcc": @"302",
            @"mnc": @"720",
            @"currency_code": @"CAD"
        },
        @"AU": @{
            @"country_code": @"AU",
            @"iso_country_code": @"au",
            @"timezone": @"Australia/Sydney",
            @"locale": @"en_AU",
            @"languages": @[@"en-AU", @"en"],
            @"carrier_name": @"Telstra",
            @"mcc": @"505",
            @"mnc": @"01",
            @"currency_code": @"AUD"
        }
    };
    return presets[cc] ?: presets[@"US"];
}

@implementation PersonaManager

+ (instancetype)sharedInstance {
    static PersonaManager *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[PersonaManager alloc] init];
    });
    return instance;
}

- (NSString *)spoofDirectory {
    NSFileManager *fm = [NSFileManager defaultManager];
    [fm createDirectoryAtPath:kMCPSpoofDir withIntermediateDirectories:YES attributes:nil error:NULL];
    if ([fm isWritableFileAtPath:kMCPSpoofDir]) return kMCPSpoofDir;
    NSString *cache = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES).firstObject;
    NSString *fallback = [cache stringByAppendingPathComponent:@"ios-mcp/spoof"];
    [fm createDirectoryAtPath:fallback withIntermediateDirectories:YES attributes:nil error:NULL];
    return fallback;
}

- (NSString *)spoofFileForBundleId:(NSString *)bundleId {
    NSString *safe = [[bundleId componentsSeparatedByCharactersInSet:
                       [[NSCharacterSet characterSetWithCharactersInString:
                         @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"] invertedSet]]
                      componentsJoinedByString:@"_"];
    return [[self spoofDirectory] stringByAppendingPathComponent:[NSString stringWithFormat:@"%@.json", safe]];
}

- (NSString *)dataContainerForBundleId:(NSString *)bundleId {
    NSDictionary *appInfo = [[AppManager sharedInstance] appInfoForBundleId:bundleId error:NULL];
    NSString *dc = appInfo[@"data_container"] ?: appInfo[@"data_container_path"];
    return [dc isKindOfClass:[NSString class]] ? dc : nil;
}

- (NSDictionary *)loadPersonaForBundleId:(NSString *)bundleId {
    NSString *path = [self spoofFileForBundleId:bundleId];
    NSData *d = [NSData dataWithContentsOfFile:path];
    if (!d.length) {
        NSString *dc = [self dataContainerForBundleId:bundleId];
        if (dc.length) {
            d = [NSData dataWithContentsOfFile:[dc stringByAppendingPathComponent:@"tmp/.mcp_persona.json"]];
        }
    }
    if (!d.length) return nil;
    NSDictionary *dict = [NSJSONSerialization JSONObjectWithData:d options:0 error:NULL];
    return [dict isKindOfClass:[NSDictionary class]] ? dict : nil;
}

- (BOOL)savePersona:(NSDictionary *)persona forBundleId:(NSString *)bundleId {
    if (![persona isKindOfClass:[NSDictionary class]] || !bundleId.length) return NO;
    NSData *json = [NSJSONSerialization dataWithJSONObject:persona options:NSJSONWritingPrettyPrinted error:NULL];
    if (!json.length) return NO;
    BOOL ok = [json writeToFile:[self spoofFileForBundleId:bundleId] options:NSDataWritingAtomic error:NULL];
    NSString *dc = [self dataContainerForBundleId:bundleId];
    if (dc.length) {
        NSString *tmpPersona = [dc stringByAppendingPathComponent:@"tmp/.mcp_persona.json"];
        [json writeToFile:tmpPersona options:NSDataWritingAtomic error:NULL];
    }
    return ok;
}

- (NSDictionary *)generateOrUpdatePersonaForBundleId:(NSString *)bundleId
                                           overrides:(NSDictionary *)overrides
                                               error:(NSString **)error {
    if (error) *error = nil;
    if (![bundleId isKindOfClass:[NSString class]] || !bundleId.length) {
        if (error) *error = @"bundle_id is required";
        return nil;
    }

    BOOL forceRotate = [overrides[@"rotate"] boolValue] || [overrides[@"regenerate"] boolValue] || [overrides[@"fresh_persona"] boolValue];
    NSDictionary *existing = forceRotate ? nil : [self loadPersonaForBundleId:bundleId];
    NSMutableDictionary *p = [NSMutableDictionary dictionaryWithDictionary:(existing ?: @{})];

    NSString *country = [overrides[@"country_code"] isKindOfClass:[NSString class]]
        ? overrides[@"country_code"]
        : (p[@"country_code"] ?: @"US");
    NSDictionary *preset = MCPCountryPreset(country);
    for (NSString *k in preset) {
        if (!p[k] || overrides[@"country_code"]) {
            p[k] = preset[k];
        }
    }

    p[@"bundle_id"] = bundleId;
    if (!p[@"persona_id"] || forceRotate) p[@"persona_id"] = [[NSUUID UUID] UUIDString];
    if (!p[@"idfv"] || forceRotate) p[@"idfv"] = [[NSUUID UUID] UUIDString];
    if (!p[@"idfa"] || forceRotate) p[@"idfa"] = [[NSUUID UUID] UUIDString];
    if (!p[@"boot_session_uuid"] || forceRotate) p[@"boot_session_uuid"] = [[NSUUID UUID] UUIDString];
    if (!p[@"udid"] || forceRotate) {
        p[@"udid"] = [NSString stringWithFormat:@"00008120-%@", MCPPersonaRandomHex(8, YES)];
    }
    if (!p[@"serial_number"] || forceRotate) {
        p[@"serial_number"] = [NSString stringWithFormat:@"F2L%@", MCPPersonaRandomHex(4, YES)];
    }
    if (!p[@"mlb_serial"] || forceRotate) {
        p[@"mlb_serial"] = [NSString stringWithFormat:@"C02%@", MCPPersonaRandomHex(7, YES)];
    }
    if (!p[@"ecid"] || forceRotate) {
        p[@"ecid"] = [NSString stringWithFormat:@"0x%@", MCPPersonaRandomHex(8, YES)];
    }
    if (!p[@"wifi_mac"] || forceRotate) p[@"wifi_mac"] = MCPPersonaRandomMAC();
    if (!p[@"bt_mac"] || forceRotate) p[@"bt_mac"] = MCPPersonaRandomMAC();
    if (!p[@"machine"]) p[@"machine"] = @"iPhone15,2";
    if (!p[@"model"]) p[@"model"] = @"D73AP";
    if (!p[@"os_version"]) p[@"os_version"] = @"16.5";
    if (!p[@"os_build"]) p[@"os_build"] = @"20F66";
    if (!p[@"device_name"] || forceRotate) p[@"device_name"] = @"iPhone";
    if (!p[@"gpu_name"]) p[@"gpu_name"] = @"Apple A16 GPU";
    if (!p[@"canvas_seed"] || forceRotate) {
        uint64_t seed = ((uint64_t)arc4random() << 32) | (uint64_t)arc4random() | 1ULL;
        p[@"canvas_seed"] = @(seed);
    }
    if (!p[@"disk_free_jitter"] || forceRotate) {
        p[@"disk_free_jitter"] = @((uint64_t)(arc4random_uniform(64000) + 1024));
    }
    if (!p[@"birthtime_jitter_sec"] || forceRotate) {
        p[@"birthtime_jitter_sec"] = @((int64_t)arc4random_uniform(86400 * 30) + 3600);
    }
    if (!p[@"birthtime_jitter_nsec"] || forceRotate) {
        p[@"birthtime_jitter_nsec"] = @((int64_t)arc4random_uniform(899999999) + 100000000);
    }
    if (!p[@"battery_level"] || forceRotate) {
        double lvl = 0.42 + ((double)arc4random_uniform(46) / 100.0);
        p[@"battery_level"] = @(lvl);
    }
    if (!p[@"keychain_prefix"] || forceRotate) {
        p[@"keychain_prefix"] = [NSString stringWithFormat:@"vp_%@_", [MCPPersonaRandomHex(4, NO) lowercaseString]];
    }
    p[@"updated_at"] = @([[NSDate date] timeIntervalSince1970]);

    if ([overrides[@"persona"] isKindOfClass:[NSDictionary class]]) {
        [p addEntriesFromDictionary:overrides[@"persona"]];
    }
    NSArray *directKeys = @[
        @"idfv", @"idfa", @"udid", @"serial_number", @"mlb_serial", @"ecid",
        @"wifi_mac", @"bt_mac", @"machine", @"model", @"os_version", @"os_build",
        @"device_name", @"gpu_name", @"timezone", @"locale", @"languages",
        @"carrier_name", @"mcc", @"mnc", @"iso_country_code", @"country_code",
        @"canvas_seed", @"battery_level", @"birthtime_jitter_sec", @"birthtime_jitter_nsec"
    ];
    for (NSString *k in directKeys) {
        if (overrides[k] != nil) p[k] = overrides[k];
    }

    [self savePersona:p forBundleId:bundleId];
    return p;
}

- (NSDictionary *)ensureEngineAndSendOp:(NSString *)op
                            forBundleId:(NSString *)bundleId
                                   args:(NSDictionary *)args
                             autoInject:(BOOL)autoInject
                                  error:(NSString **)error {
    if (error) *error = nil;
    if (![bundleId isKindOfClass:[NSString class]] || !bundleId.length) {
        if (error) *error = @"bundle_id is required";
        return nil;
    }

    NSString *firstErr = nil;
    NSDictionary *res = [[MCPEngineManager sharedInstance] sendAntiFraudOp:op
                                                               forBundleId:bundleId
                                                                      args:args
                                                                     error:&firstErr];
    if (res) return res;

    if (!autoInject) {
        if (error) *error = firstErr ?: @"Engine not reachable";
        return nil;
    }

    NSString *injErr = nil;
    NSDictionary *injRes = [[MCPEngineManager sharedInstance] injectEngineForBundleId:bundleId
                                                                        stealthConfig:@{}
                                                                               launch:YES
                                                                                error:&injErr];
    if (!injRes || ![injRes[@"socket_ready"] boolValue]) {
        if (error) *error = injErr ?: (firstErr ?: @"Failed to auto-inject and launch libmcpengine for target app");
        return nil;
    }

    return [[MCPEngineManager sharedInstance] sendAntiFraudOp:op
                                                  forBundleId:bundleId
                                                         args:args
                                                        error:error];
}

- (NSDictionary *)stealthSyscallShieldForBundleId:(NSString *)bundleId args:(NSDictionary *)args error:(NSString **)error {
    BOOL autoInject = args[@"auto_inject"] ? [args[@"auto_inject"] boolValue] : YES;
    return [self ensureEngineAndSendOp:@"engine.antifraud_shield" forBundleId:bundleId args:args autoInject:autoInject error:error];
}

- (NSDictionary *)spoofDeviceFingerprintForBundleId:(NSString *)bundleId args:(NSDictionary *)args error:(NSString **)error {
    NSDictionary *persona = [self generateOrUpdatePersonaForBundleId:bundleId overrides:args error:error];
    if (!persona) return nil;
    NSMutableDictionary *opArgs = [NSMutableDictionary dictionaryWithDictionary:(args ?: @{})];
    opArgs[@"persona"] = persona;
    BOOL autoInject = args[@"auto_inject"] ? [args[@"auto_inject"] boolValue] : YES;
    return [self ensureEngineAndSendOp:@"engine.spoof_fingerprint" forBundleId:bundleId args:opArgs autoInject:autoInject error:error];
}

- (NSDictionary *)kernelProcCloakForBundleId:(NSString *)bundleId args:(NSDictionary *)args error:(NSString **)error {
    BOOL autoInject = args[@"auto_inject"] ? [args[@"auto_inject"] boolValue] : YES;
    return [self ensureEngineAndSendOp:@"engine.kernel_proc_cloak" forBundleId:bundleId args:args autoInject:autoInject error:error];
}

- (NSDictionary *)proxyVpnNetworkCloakForBundleId:(NSString *)bundleId args:(NSDictionary *)args error:(NSString **)error {
    BOOL autoInject = args[@"auto_inject"] ? [args[@"auto_inject"] boolValue] : YES;
    return [self ensureEngineAndSendOp:@"engine.network_cloak" forBundleId:bundleId args:args autoInject:autoInject error:error];
}

- (NSDictionary *)hardwareCanvasGpuAudioRandomizerForBundleId:(NSString *)bundleId args:(NSDictionary *)args error:(NSString **)error {
    NSDictionary *persona = [self generateOrUpdatePersonaForBundleId:bundleId overrides:args error:NULL];
    NSMutableDictionary *opArgs = [NSMutableDictionary dictionaryWithDictionary:(args ?: @{})];
    if (persona[@"canvas_seed"] && !opArgs[@"canvas_seed"]) opArgs[@"canvas_seed"] = persona[@"canvas_seed"];
    if (persona[@"gpu_name"] && !opArgs[@"gpu_name"]) opArgs[@"gpu_name"] = persona[@"gpu_name"];
    BOOL autoInject = args[@"auto_inject"] ? [args[@"auto_inject"] boolValue] : YES;
    return [self ensureEngineAndSendOp:@"engine.canvas_gpu_audio" forBundleId:bundleId args:opArgs autoInject:autoInject error:error];
}

- (NSDictionary *)behavioralBiometricsGhostPlayerForBundleId:(NSString *)bundleId args:(NSDictionary *)args error:(NSString **)error {
    BOOL autoInject = args[@"auto_inject"] ? [args[@"auto_inject"] boolValue] : YES;
    return [self ensureEngineAndSendOp:@"engine.ghost_player" forBundleId:bundleId args:args autoInject:autoInject error:error];
}

- (NSDictionary *)perimeterxAkamaiDatadomeKasadaTapForBundleId:(NSString *)bundleId args:(NSDictionary *)args error:(NSString **)error {
    BOOL autoInject = args[@"auto_inject"] ? [args[@"auto_inject"] boolValue] : YES;
    return [self ensureEngineAndSendOp:@"engine.sdk_tap" forBundleId:bundleId args:args autoInject:autoInject error:error];
}

- (NSDictionary *)threatmetrixSardineForterSeonNeutralizerForBundleId:(NSString *)bundleId args:(NSDictionary *)args error:(NSString **)error {
    BOOL autoInject = args[@"auto_inject"] ? [args[@"auto_inject"] boolValue] : YES;
    return [self ensureEngineAndSendOp:@"engine.risk_neutralizer" forBundleId:bundleId args:args autoInject:autoInject error:error];
}

- (NSDictionary *)appleAppAttestDevicecheckBridgeForBundleId:(NSString *)bundleId args:(NSDictionary *)args error:(NSString **)error {
    BOOL autoInject = args[@"auto_inject"] ? [args[@"auto_inject"] boolValue] : YES;
    return [self ensureEngineAndSendOp:@"engine.app_attest" forBundleId:bundleId args:args autoInject:autoInject error:error];
}

- (NSDictionary *)syncFraudPersonaForBundleId:(NSString *)bundleId args:(NSDictionary *)args error:(NSString **)error {
    NSDictionary *persona = [self generateOrUpdatePersonaForBundleId:bundleId overrides:args error:error];
    if (!persona) return nil;
    NSMutableDictionary *opArgs = [NSMutableDictionary dictionaryWithDictionary:(args ?: @{})];
    opArgs[@"persona"] = persona;
    BOOL autoInject = args[@"auto_inject"] ? [args[@"auto_inject"] boolValue] : YES;
    return [self ensureEngineAndSendOp:@"engine.sync_persona" forBundleId:bundleId args:opArgs autoInject:autoInject error:error];
}

- (NSDictionary *)objcSwizzleAndDladdrIntegrityCloakForBundleId:(NSString *)bundleId args:(NSDictionary *)args error:(NSString **)error {
    BOOL autoInject = args[@"auto_inject"] ? [args[@"auto_inject"] boolValue] : YES;
    return [self ensureEngineAndSendOp:@"engine.objc_integrity_cloak" forBundleId:bundleId args:args autoInject:autoInject error:error];
}

- (NSDictionary *)threadMachPortAndStackCloakerForBundleId:(NSString *)bundleId args:(NSDictionary *)args error:(NSString **)error {
    BOOL autoInject = args[@"auto_inject"] ? [args[@"auto_inject"] boolValue] : YES;
    return [self ensureEngineAndSendOp:@"engine.thread_stack_cloak" forBundleId:bundleId args:args autoInject:autoInject error:error];
}

- (NSDictionary *)wipeFraudCanariesForBundleId:(NSString *)bundleId args:(NSDictionary *)args error:(NSString **)error {
    if (error) *error = nil;
    if (![bundleId isKindOfClass:[NSString class]] || !bundleId.length) {
        if (error) *error = @"bundle_id is required";
        return nil;
    }

    NSMutableArray<NSString *> *wipedVectors = [NSMutableArray array];
    NSFileManager *fm = [NSFileManager defaultManager];

    // Vector 1: Out-of-process Keychain wipe for bundleId prefix / service
    NSString *kcErr = nil;
    [[KeychainManager sharedInstance] deleteKeychainItemWithArgs:@{@"service": bundleId} error:&kcErr];
    [wipedVectors addObject:@"keychain_service_canaries"];

    // Vector 2-6: Sandbox Caches, Cookies, WebKit, NSURLCache, tmp tracking artifacts
    NSString *dc = [self dataContainerForBundleId:bundleId];
    NSUInteger deletedFiles = 0;
    if (dc.length) {
        NSArray<NSString *> *relDirs = @[
            @"Library/Caches",
            @"Library/Cookies",
            @"Library/WebKit",
            @"Library/Saved Application State",
            @"SystemData/com.apple.SafariViewService"
        ];
        for (NSString *rel in relDirs) {
            NSString *dirPath = [dc stringByAppendingPathComponent:rel];
            NSArray<NSString *> *items = [fm contentsOfDirectoryAtPath:dirPath error:NULL];
            for (NSString *item in items) {
                if ([item hasPrefix:@".mcp"] || [item hasPrefix:@".me_"]) continue;
                if ([fm removeItemAtPath:[dirPath stringByAppendingPathComponent:item] error:NULL]) {
                    deletedFiles++;
                }
            }
        }
        NSString *tmpDir = [dc stringByAppendingPathComponent:@"tmp"];
        NSArray<NSString *> *tmpItems = [fm contentsOfDirectoryAtPath:tmpDir error:NULL];
        for (NSString *item in tmpItems) {
            if ([item hasPrefix:@".mcp"] || [item hasPrefix:@".me_"]) continue;
            if ([fm removeItemAtPath:[tmpDir stringByAppendingPathComponent:item] error:NULL]) {
                deletedFiles++;
            }
        }
        [wipedVectors addObjectsFromArray:@[
            @"sandbox_library_caches",
            @"sandbox_http_cookies_hsts",
            @"sandbox_webkit_localstorage_indexeddb",
            @"sandbox_tmp_canaries"
        ]];
    }

    // Vector 7: Rotate birthtime_jitter_nsec in persisted persona
    NSMutableDictionary *rotOverrides = [NSMutableDictionary dictionaryWithDictionary:(args ?: @{})];
    rotOverrides[@"birthtime_jitter_nsec"] = @((int64_t)arc4random_uniform(899999999) + 100000000);
    rotOverrides[@"birthtime_jitter_sec"] = @((int64_t)arc4random_uniform(86400 * 30) + 3600);
    NSDictionary *persona = [self generateOrUpdatePersonaForBundleId:bundleId overrides:rotOverrides error:NULL];
    [wipedVectors addObject:@"birthtime_nanosecond_jitter"];

    // If engine is reachable in-process, also run in-process canary wipe (pasteboards, iCloud KVS, live NSURLCache)
    NSString *inProcErr = nil;
    NSDictionary *inProcRes = [[MCPEngineManager sharedInstance] sendAntiFraudOp:@"engine.wipe_canaries"
                                                                     forBundleId:bundleId
                                                                            args:(args ?: @{})
                                                                           error:&inProcErr];
    return @{
        @"bundle_id": bundleId,
        @"wiped": @YES,
        @"wiped_vectors": wipedVectors,
        @"sandbox_files_removed": @(deletedFiles),
        @"birthtime_jitter_nsec": persona[@"birthtime_jitter_nsec"] ?: @0,
        @"in_process_wipe": inProcRes ?: @{@"status": @"app_not_attached_cleaned_on_disk"}
    };
}

- (NSDictionary *)applyFraudPersonaForBundleId:(NSString *)bundleId args:(NSDictionary *)args error:(NSString **)error {
    if (error) *error = nil;
    if (![bundleId isKindOfClass:[NSString class]] || !bundleId.length) {
        if (error) *error = @"bundle_id is required";
        return nil;
    }

    // Step 1: Generate or update coherent persona profile and write to disk
    NSMutableDictionary *genArgs = [NSMutableDictionary dictionaryWithDictionary:(args ?: @{})];
    if (args[@"wipe_canaries"] == nil || [args[@"wipe_canaries"] boolValue]) {
        [self wipeFraudCanariesForBundleId:bundleId args:args error:NULL];
    }
    NSDictionary *persona = [self generateOrUpdatePersonaForBundleId:bundleId overrides:genArgs error:error];
    if (!persona) return nil;

    // Step 2: Ensure engine is injected and invoke engine.apply_persona (plus out-of-proc slot patching)
    NSMutableDictionary *opArgs = [NSMutableDictionary dictionaryWithDictionary:(args ?: @{})];
    opArgs[@"persona"] = persona;
    BOOL autoInject = args[@"auto_inject"] ? [args[@"auto_inject"] boolValue] : YES;
    NSDictionary *applyRes = [self ensureEngineAndSendOp:@"engine.apply_persona"
                                             forBundleId:bundleId
                                                    args:opArgs
                                              autoInject:autoInject
                                                   error:error];
    if (!applyRes) return nil;

    // Step 3: Re-run 50-point audit after out-of-process __DATA_CONST / __AUTH_GOT slot patching completes
    NSDictionary *postPatchAudit = [[MCPEngineManager sharedInstance] sendAntiFraudOp:@"engine.audit_fraud_surface"
                                                                          forBundleId:bundleId
                                                                                 args:@{}
                                                                                error:NULL];
    NSMutableDictionary *finalRes = [applyRes mutableCopy];
    finalRes[@"bundle_id"] = bundleId;
    finalRes[@"persona_path"] = [self spoofFileForBundleId:bundleId];
    if (postPatchAudit) {
        finalRes[@"audit"] = postPatchAudit;
    }
    return finalRes;
}

- (NSDictionary *)auditFraudSurfaceForBundleId:(NSString *)bundleId args:(NSDictionary *)args error:(NSString **)error {
    BOOL autoInject = args[@"auto_inject"] ? [args[@"auto_inject"] boolValue] : YES;
    return [self ensureEngineAndSendOp:@"engine.audit_fraud_surface" forBundleId:bundleId args:args autoInject:autoInject error:error];
}

@end
