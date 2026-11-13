#import "AppStoreManager.h"
#import "AppManager.h"
#import "AccessibilityManager.h"
#import "OCRManager.h"
#import "HIDManager.h"
#import "TextInputManager.h"
#import "ClassDumpManager.h"
#import "EntitlementManager.h"
#import "MCPMachOUtil.h"
#import "MCPProcessUtil.h"
#import <mach-o/loader.h>
#import <mach-o/fat.h>
#import <stdatomic.h>
#import <sys/stat.h>

static void MCPTouchAppStoreAuthFlag(void) {
    NSString *stamp = [NSString stringWithFormat:@"%.0f\n", [[NSDate date] timeIntervalSince1970]];
    NSData *data = [stamp dataUsingEncoding:NSUTF8StringEncoding];
    NSString *jbWorkDir = MCPResolvedJailbreakPath(@"/var/mobile/Library/Caches/ios-mcp-work");
    [[NSFileManager defaultManager] createDirectoryAtPath:jbWorkDir withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *jbFlag = [jbWorkDir stringByAppendingPathComponent:@"appstore-auth-active.flag"];
    [data writeToFile:jbFlag atomically:YES];
    chmod(jbFlag.UTF8String, 0666);

    NSString *rawWorkDir = @"/var/mobile/Library/Caches/ios-mcp-work";
    [[NSFileManager defaultManager] createDirectoryAtPath:rawWorkDir withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *rawFlag = [rawWorkDir stringByAppendingPathComponent:@"appstore-auth-active.flag"];
    if (![rawFlag isEqualToString:jbFlag]) {
        [data writeToFile:rawFlag atomically:YES];
        chmod(rawFlag.UTF8String, 0666);
    }
}

static NSString *MCPResolveConfiguredAppleIDPassword(NSString *explicitPassword) {
    if ([explicitPassword isKindOfClass:[NSString class]] && explicitPassword.length > 0) {
        return explicitPassword;
    }
    NSArray<NSString *> *candidates = @[
        MCPResolvedJailbreakPath(@"/var/mobile/Library/ios-mcp/apple_id_password.txt"),
        MCPResolvedJailbreakPath(@"/var/mobile/Library/Caches/ios-mcp-work/apple_id_password.txt"),
        @"/var/mobile/Library/ios-mcp/apple_id_password.txt"
    ];
    for (NSString *path in candidates) {
        if (path.length && [[NSFileManager defaultManager] fileExistsAtPath:path]) {
            NSString *raw = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil];
            NSString *trimmed = [raw stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
            if (trimmed.length > 0) return trimmed;
        }
    }
    return nil;
}

static NSDictionary *MCPTryAutoConfirmAppStorePromptOnce(NSString *explicitPassword) {
    static NSTimeInterval sLastPasswordTypedAt = 0;
    NSString *password = MCPResolveConfiguredAppleIDPassword(explicitPassword);
    // 1. Check Accessibility compact UI elements for an App Store / StoreKit confirmation button
    __block NSDictionary *axPayload = nil;
    dispatch_semaphore_t axSem = dispatch_semaphore_create(0);
    [[AccessibilityManager sharedInstance] getCompactUIElementsWithMaxElements:250
                                                                   visibleOnly:YES
                                                                 clickableOnly:NO
                                                                    completion:^(NSDictionary *payload, __unused NSString *error) {
        axPayload = payload;
        dispatch_semaphore_signal(axSem);
    }];
    dispatch_semaphore_wait(axSem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)));

    NSArray *elements = [axPayload[@"elements"] isKindOfClass:[NSArray class]] ? axPayload[@"elements"] : @[];
    BOOL axHasDialogContext = NO;
    BOOL axHasPasswordPrompt = NO;
    for (NSDictionary *el in elements) {
        if (![el isKindOfClass:[NSDictionary class]]) continue;
        NSString *type = [el[@"type"] isKindOfClass:[NSString class]] ? [el[@"type"] lowercaseString] : @"";
        if ([type containsString:@"securetextfield"]) {
            axHasPasswordPrompt = YES;
            axHasDialogContext = YES;
        }
        for (NSString *k in @[@"text", @"label", @"value", @"identifier"]) {
            NSString *val = [el[k] isKindOfClass:[NSString class]] ? [el[k] lowercaseString] : nil;
            if (!val.length) continue;
            if ([val containsString:@"password"] || [val containsString:@"enter the password"]) {
                axHasPasswordPrompt = YES;
                axHasDialogContext = YES;
            }
            if ([val containsString:@"app store"] ||
                [val isEqualToString:@"cancel"] ||
                [val containsString:@"apple id"] ||
                [val containsString:@"apple account"] ||
                [val containsString:@"account"] ||
                [val isEqualToString:@"free"] ||
                [val containsString:@"confirm"] ||
                [val containsString:@"redownload"]) {
                axHasDialogContext = YES;
            }
        }
    }

    if (axHasDialogContext || axHasPasswordPrompt) {
        MCPTouchAppStoreAuthFlag();
    }
    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
    if (axHasPasswordPrompt) {
        if (password.length > 0 && (now - sLastPasswordTypedAt) >= 14.0) {
            sLastPasswordTypedAt = now;
            dispatch_semaphore_t typeSem = dispatch_semaphore_create(0);
            [[TextInputManager sharedInstance] inputText:password completion:^(__unused BOOL ok, __unused NSString *err) {
                dispatch_semaphore_signal(typeSem);
            }];
            dispatch_semaphore_wait(typeSem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(4.0 * NSEC_PER_SEC)));
            usleep(250 * 1000);
            dispatch_semaphore_t retSem = dispatch_semaphore_create(0);
            [[TextInputManager sharedInstance] pressKey:@"enter" completion:^(__unused BOOL ok, __unused NSString *err) {
                dispatch_semaphore_signal(retSem);
            }];
            dispatch_semaphore_wait(retSem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)));
            return @{
                @"source": @"accessibility_password_entry",
                @"button": @"Return (Password Submitted)",
                @"x": @(0),
                @"y": @(0),
                @"timestamp": @(now)
            };
        }
        return nil;
    }

    for (NSDictionary *el in elements) {
        if (![el isKindOfClass:[NSDictionary class]]) continue;
        NSString *matchedLabel = nil;
        for (NSString *k in @[@"text", @"label", @"identifier"]) {
            NSString *raw = [el[k] isKindOfClass:[NSString class]] ? el[k] : nil;
            NSString *trim = [[raw stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] lowercaseString];
            if (!trim.length) continue;
            if ([trim isEqualToString:@"install"] ||
                [trim isEqualToString:@"get"] ||
                [trim isEqualToString:@"redownload"] ||
                [trim isEqualToString:@"confirm"] ||
                (axHasDialogContext && ([trim isEqualToString:@"buy"] || [trim isEqualToString:@"ok"] || [trim isEqualToString:@"continue"] || [trim isEqualToString:@"always require"] || [trim isEqualToString:@"require after 15 minutes"]))) {
                matchedLabel = raw;
                break;
            }
        }
        if (!matchedLabel) continue;

        double tapX = 0, tapY = 0;
        BOOL hasTap = NO;
        NSDictionary *tap = [el[@"tap"] isKindOfClass:[NSDictionary class]] ? el[@"tap"] : nil;
        if ([tap[@"x"] respondsToSelector:@selector(doubleValue)] && [tap[@"y"] respondsToSelector:@selector(doubleValue)]) {
            tapX = [tap[@"x"] doubleValue];
            tapY = [tap[@"y"] doubleValue];
            hasTap = YES;
        } else if ([el[@"frame"] isKindOfClass:[NSDictionary class]]) {
            NSDictionary *fr = el[@"frame"];
            if ([fr[@"x"] respondsToSelector:@selector(doubleValue)] &&
                [fr[@"y"] respondsToSelector:@selector(doubleValue)] &&
                [fr[@"width"] respondsToSelector:@selector(doubleValue)] &&
                [fr[@"height"] respondsToSelector:@selector(doubleValue)]) {
                tapX = [fr[@"x"] doubleValue] + [fr[@"width"] doubleValue] * 0.5;
                tapY = [fr[@"y"] doubleValue] + [fr[@"height"] doubleValue] * 0.5;
                hasTap = YES;
            }
        }
        if (hasTap && tapY >= 160.0 && (axHasDialogContext || tapY >= 240.0)) {
            __block BOOL tappedOK = NO;
            dispatch_semaphore_t tapSem = dispatch_semaphore_create(0);
            [[IOSMCPHIDManager sharedInstance] tapAtPoint:CGPointMake(tapX, tapY) completion:^(BOOL success, __unused NSString *err) {
                tappedOK = success;
                dispatch_semaphore_signal(tapSem);
            }];
            dispatch_semaphore_wait(tapSem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)));
            if (tappedOK) {
                return @{
                    @"source": @"accessibility",
                    @"button": matchedLabel,
                    @"x": @(tapX),
                    @"y": @(tapY),
                    @"timestamp": @([[NSDate date] timeIntervalSince1970])
                };
            }
        }
    }

    // 2. Fallback to fast Vision OCR for out-of-process payment/confirmation sheets (StoreKitUIService / PassbookUIService)
    NSString *ocrErr = nil;
    NSDictionary *ocrRes = [[OCRManager sharedInstance] recognizeTextWithLanguages:@[@"en-US"]
                                                                     minConfidence:0.35
                                                                            region:nil
                                                                              fast:YES
                                                                            engine:@"vision"
                                                                             error:&ocrErr];
    NSArray *texts = [ocrRes[@"texts"] isKindOfClass:[NSArray class]] ? ocrRes[@"texts"] : @[];
    if (!texts.count) return nil;

    BOOL ocrHasSheetContext = NO;
    BOOL ocrHasPasswordPrompt = NO;
    for (NSDictionary *item in texts) {
        if (![item isKindOfClass:[NSDictionary class]]) continue;
        NSString *t = [item[@"text"] isKindOfClass:[NSString class]] ? [item[@"text"] lowercaseString] : @"";
        if ([t containsString:@"password"] || [t containsString:@"enter the password"]) {
            ocrHasPasswordPrompt = YES;
            ocrHasSheetContext = YES;
        }
        if ([t containsString:@"app store"] ||
            [t isEqualToString:@"cancel"] ||
            [t containsString:@"account"] ||
            [t containsString:@"apple id"] ||
            [t containsString:@"apple account"] ||
            [t isEqualToString:@"free"] ||
            [t containsString:@"price"] ||
            [t containsString:@"age"] ||
            [t containsString:@"confirm"] ||
            [t containsString:@"sign in"] ||
            [t containsString:@"password"]) {
            ocrHasSheetContext = YES;
        }
    }
    if (!ocrHasSheetContext) return nil;
    MCPTouchAppStoreAuthFlag();
    if (ocrHasPasswordPrompt) {
        if (password.length > 0 && (now - sLastPasswordTypedAt) >= 14.0) {
            sLastPasswordTypedAt = now;
            dispatch_semaphore_t typeSem = dispatch_semaphore_create(0);
            [[TextInputManager sharedInstance] inputText:password completion:^(__unused BOOL ok, __unused NSString *err) {
                dispatch_semaphore_signal(typeSem);
            }];
            dispatch_semaphore_wait(typeSem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(4.0 * NSEC_PER_SEC)));
            usleep(250 * 1000);
            dispatch_semaphore_t retSem = dispatch_semaphore_create(0);
            [[TextInputManager sharedInstance] pressKey:@"enter" completion:^(__unused BOOL ok, __unused NSString *err) {
                dispatch_semaphore_signal(retSem);
            }];
            dispatch_semaphore_wait(retSem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)));
            return @{
                @"source": @"vision_ocr_password_entry",
                @"button": @"Return (Password Submitted)",
                @"x": @(0),
                @"y": @(0),
                @"timestamp": @(now)
            };
        }
        return nil;
    }

    for (NSDictionary *item in texts) {
        if (![item isKindOfClass:[NSDictionary class]]) continue;
        NSString *raw = [item[@"text"] isKindOfClass:[NSString class]] ? item[@"text"] : @"";
        NSString *clean = [[raw stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] lowercaseString];
        if (!clean.length) continue;

        BOOL isConfirmBtn =
            [clean isEqualToString:@"install"] ||
            [clean isEqualToString:@"get"] ||
            [clean isEqualToString:@"redownload"] ||
            [clean isEqualToString:@"confirm"] ||
            [clean isEqualToString:@"ok"] ||
            [clean isEqualToString:@"continue"] ||
            [clean isEqualToString:@"buy"];
        if (!isConfirmBtn) continue;

        NSDictionary *tap = [item[@"tap"] isKindOfClass:[NSDictionary class]] ? item[@"tap"] : nil;
        if (![tap[@"x"] respondsToSelector:@selector(doubleValue)] || ![tap[@"y"] respondsToSelector:@selector(doubleValue)]) {
            continue;
        }
        double tapX = [tap[@"x"] doubleValue];
        double tapY = [tap[@"y"] doubleValue];
        if (tapY < 180.0) continue;

        __block BOOL tappedOK = NO;
        dispatch_semaphore_t tapSem = dispatch_semaphore_create(0);
        [[IOSMCPHIDManager sharedInstance] tapAtPoint:CGPointMake(tapX, tapY) completion:^(BOOL success, __unused NSString *err) {
            tappedOK = success;
            dispatch_semaphore_signal(tapSem);
        }];
        dispatch_semaphore_wait(tapSem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)));
        if (tappedOK) {
            return @{
                @"source": @"vision_ocr",
                @"button": raw,
                @"x": @(tapX),
                @"y": @(tapY),
                @"timestamp": @([[NSDate date] timeIntervalSince1970])
            };
        }
    }

    return nil;
}

@implementation AppStoreManager

+ (instancetype)sharedInstance {
    static AppStoreManager *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[AppStoreManager alloc] init];
    });
    return instance;
}

- (NSDictionary *)runAppStoreHelperOp:(NSString *)op
                                 args:(NSDictionary *)args
                              timeout:(NSTimeInterval)timeout
                                error:(NSString **)error {
    if (error) *error = nil;
    NSString *workDir = MCPResolvedJailbreakPath(@"/var/mobile/Library/Caches/ios-mcp-work");
    [[NSFileManager defaultManager] createDirectoryAtPath:workDir
                              withIntermediateDirectories:YES
                                               attributes:@{NSFilePosixPermissions: @0777}
                                                    error:nil];
    chmod(workDir.UTF8String, 0777);

    NSString *uuid = [[NSUUID UUID] UUIDString];
    NSString *reqFile = [workDir stringByAppendingPathComponent:[NSString stringWithFormat:@"appstore-req-%@.json", uuid]];

    NSMutableDictionary *payload = [NSMutableDictionary dictionaryWithDictionary:(args ?: @{})];
    payload[@"op"] = op ?: @"";
    payload[@"timeout"] = @(timeout > 0 ? timeout : 90.0);

    NSError *jsonErr = nil;
    NSData *reqData = [NSJSONSerialization dataWithJSONObject:payload options:0 error:&jsonErr];
    if (!reqData || ![reqData writeToFile:reqFile atomically:YES]) {
        if (error) *error = [NSString stringWithFormat:@"Failed to write AppStore request payload: %@", jsonErr.localizedDescription ?: @"io error"];
        return nil;
    }
    chmod(reqFile.UTF8String, 0666);

    BOOL watchPrompts = ([op isEqualToString:@"install"] || [op isEqualToString:@"downgrade"]) &&
                        (!args[@"auto_confirm"] || [args[@"auto_confirm"] boolValue]);
    __block atomic_bool watcherStop = ATOMIC_VAR_INIT(false);
    NSMutableArray<NSDictionary *> *confirmedPrompts = [NSMutableArray array];
    NSLock *promptsLock = [[NSLock alloc] init];
    NSString *explicitPassword = [args[@"password"] isKindOfClass:[NSString class]] ? args[@"password"] : ([args[@"apple_id_password"] isKindOfClass:[NSString class]] ? args[@"apple_id_password"] : nil);

    if (watchPrompts) {
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            usleep(1200 * 1000);
            while (!atomic_load(&watcherStop)) {
                @autoreleasepool {
                    NSDictionary *hit = MCPTryAutoConfirmAppStorePromptOnce(explicitPassword);
                    if (hit) {
                        [promptsLock lock];
                        [confirmedPrompts addObject:hit];
                        [promptsLock unlock];
                        // Give the sheet 2.0s to dismiss after tapping before polling again
                        for (int i = 0; i < 10 && !atomic_load(&watcherStop); i++) {
                            usleep(200 * 1000);
                        }
                    } else {
                        for (int i = 0; i < 6 && !atomic_load(&watcherStop); i++) {
                            usleep(200 * 1000);
                        }
                    }
                }
            }
        });
    }

    @try {
        NSString *outStr = nil;
        NSString *runErr = nil;
        int exitCode = -1;
        NSTimeInterval effectiveTimeout = MAX(timeout, 30.0);

        BOOL launched = MCPRunRootProcess(@"/usr/libexec/ios-mcp/mcp-appstore",
                                          @[@"--req", reqFile],
                                          effectiveTimeout,
                                          4 * 1024 * 1024,
                                          &outStr,
                                          &exitCode,
                                          &runErr);
        if (!launched) {
            NSString *helperPath = MCPResolvedJailbreakPath(@"/usr/libexec/ios-mcp/mcp-appstore");
            launched = MCPRunProcess(helperPath,
                                     @[@"--req", reqFile],
                                     MCPJailbreakEnvironment(),
                                     effectiveTimeout,
                                     4 * 1024 * 1024,
                                     &outStr,
                                     &exitCode,
                                     &runErr);
        }

        atomic_store(&watcherStop, true);

        NSData *respData = [outStr dataUsingEncoding:NSUTF8StringEncoding];
        NSDictionary *resp = respData ? [NSJSONSerialization JSONObjectWithData:respData options:0 error:NULL] : nil;
        if (!launched || ![resp isKindOfClass:[NSDictionary class]]) {
            if (error) *error = runErr ?: (outStr.length ? outStr : @"mcp-appstore helper returned invalid JSON");
            return nil;
        }
        if (exitCode != 0 || ![resp[@"ok"] boolValue]) {
            if (error) *error = [resp[@"error"] isKindOfClass:[NSString class]] ? resp[@"error"] : @"mcp-appstore operation failed";
            return nil;
        }
        NSMutableDictionary *result = [([resp[@"result"] isKindOfClass:[NSDictionary class]] ? resp[@"result"] : @{}) mutableCopy];
        [promptsLock lock];
        if (confirmedPrompts.count > 0) {
            result[@"auto_confirmed_prompts"] = [confirmedPrompts copy];
            result[@"auto_confirmed_count"] = @(confirmedPrompts.count);
        }
        [promptsLock unlock];
        return result;
    } @finally {
        atomic_store(&watcherStop, true);
        [[NSFileManager defaultManager] removeItemAtPath:reqFile error:nil];
    }
}

#pragma mark - Upgrade 37: Search & Version History

- (NSDictionary *)searchAndVersionsWithArgs:(NSDictionary *)args error:(NSString **)error {
    NSString *op = [args[@"op"] isKindOfClass:[NSString class]] ? args[@"op"] : @"search_and_versions";
    return [self runAppStoreHelperOp:op args:args timeout:30.0 error:error];
}

#pragma mark - Upgrade 38: Headless App Store Install

- (NSDictionary *)installAppWithArgs:(NSDictionary *)args error:(NSString **)error {
    double timeout = [args[@"timeout"] respondsToSelector:@selector(doubleValue)] ? [args[@"timeout"] doubleValue] : 120.0;
    if (timeout < 15.0) timeout = 15.0;
    if (timeout > 300.0) timeout = 300.0;
    return [self runAppStoreHelperOp:@"install" args:args timeout:(timeout + 15.0) error:error];
}

#pragma mark - Upgrade 39: MuffinStore Historical Downgrade

- (NSDictionary *)downgradeAppWithArgs:(NSDictionary *)args error:(NSString **)error {
    NSString *bundleId = [args[@"bundle_id"] isKindOfClass:[NSString class]] ? args[@"bundle_id"] : nil;
    if (bundleId.length > 0) {
        // Ensure target app is not actively running while its bundle is downgraded in-place
        [[AppManager sharedInstance] killApp:bundleId error:nil];
    }
    double timeout = [args[@"timeout"] respondsToSelector:@selector(doubleValue)] ? [args[@"timeout"] doubleValue] : 150.0;
    if (timeout < 15.0) timeout = 15.0;
    if (timeout > 300.0) timeout = 300.0;
    return [self runAppStoreHelperOp:@"downgrade" args:args timeout:(timeout + 20.0) error:error];
}

#pragma mark - Upgrade 40: Autonomous Multi-Version Hardening Profiler & Diff Engine

static NSDictionary *MCPAnalyzeBinarySecurityMarkersAtPath(NSString *binaryPath) {
    if (!binaryPath.length || ![[NSFileManager defaultManager] fileExistsAtPath:binaryPath]) {
        return @{};
    }

    NSData *data = [NSData dataWithContentsOfFile:binaryPath options:NSDataReadingMappedIfSafe error:nil];
    if (!data || data.length < 64) return @{};

    const uint8_t *bytes = (const uint8_t *)data.bytes;
    NSUInteger len = data.length;

    // 1. Scan for known anti-fraud, bot-defense, RASP, and SSL-pinning signatures in binary strings
    NSDictionary<NSString *, NSArray<NSString *> *> *sdkSignatures = @{
        @"Promon_Shield": @[@"Promon", @"libshield", @"PromonShield"],
        @"Guardsquare_iXGuard": @[@"iXGuard", @"Guardsquare"],
        @"AppDome": @[@"AppDome", @"AD_"],
        @"PerimeterX_HUMAN": @[@"PerimeterX", @"PXManager", @"PXPolicy", @"_px3", @"x-px-authorization"],
        @"Akamai_BMP": @[@"CYFMonitor", @"AkamaiBMP", @"_abck", @"X-acf-sensor-data"],
        @"DataDome": @[@"DataDome", @"DataDomeSDK"],
        @"Kasada": @[@"KPSDK", @"Kasada", @"x-kpsdk-ct"],
        @"ThreatMetrix": @[@"TMXProfiling", @"ThreatMetrix", @"TMXProfileHandle"],
        @"Sardine": @[@"SardineMobile", @"SardineSDK"],
        @"Forter": @[@"ForterSDK", @"ForterToken"],
        @"BioCatch": @[@"BioCatch", @"BCManager"],
        @"Seon": @[@"SEONFingerprint", @"SEONSDK"],
        @"Apple_AppAttest_DeviceCheck": @[@"DCAppAttestService", @"DCDevice", @"FIRAppCheck"],
        @"SSL_Pinning": @[@"TrustKit", @"TSKPinningValidator", @"AFSecurityPolicy", @"SSL_CTX_set_custom_verify", @"SecTrustEvaluateWithError"],
        @"Anti_Jailbreak_Probes": @[@"/var/jb", @"/.jbroot", @"sileo://", @"cydia://", @"SubstrateLoader", @"frida-agent"]
    };

    NSMutableArray<NSString *> *detectedCategories = [NSMutableArray array];
    NSMutableDictionary<NSString *, NSArray<NSString *> *> *matchedTokensByCategory = [NSMutableDictionary dictionary];

    for (NSString *category in sdkSignatures) {
        NSMutableArray<NSString *> *hits = [NSMutableArray array];
        for (NSString *token in sdkSignatures[category]) {
            NSData *needle = [token dataUsingEncoding:NSUTF8StringEncoding];
            if (!needle.length) continue;
            NSRange found = [data rangeOfData:needle options:0 range:NSMakeRange(0, len)];
            if (found.location != NSNotFound) {
                [hits addObject:token];
            }
        }
        if (hits.count > 0) {
            [detectedCategories addObject:category];
            matchedTokensByCategory[category] = hits;
        }
    }

    // 2. Count raw inline `SVC #0x80` (0xD4001001 -> little-endian 01 10 00 D4) instructions
    NSUInteger svc80Count = 0;
    for (NSUInteger off = 0; off + 4 <= len; off += 4) {
        uint32_t insn = *(const uint32_t *)(bytes + off);
        if (insn == 0xD4001001u) {
            svc80Count++;
        }
    }

    return @{
        @"binary_size_bytes": @(len),
        @"detected_security_categories": [detectedCategories sortedArrayUsingSelector:@selector(compare:)],
        @"matched_tokens": matchedTokensByCategory,
        @"inline_svc_0x80_count": @(svc80Count)
    };
}

- (NSDictionary *)profileInstalledVersionForBundleId:(NSString *)bundleId {
    if (!bundleId.length) return nil;
    NSString *infoErr = nil;
    NSDictionary *appInfo = [[AppManager sharedInstance] appInfoForBundleId:bundleId error:&infoErr];
    if (!appInfo) return nil;

    NSString *bundlePath = [appInfo[@"bundle_path"] isKindOfClass:[NSString class]] ? appInfo[@"bundle_path"] : nil;
    NSString *execPath = [appInfo[@"executable_path"] isKindOfClass:[NSString class]] ? appInfo[@"executable_path"] : nil;

    NSDictionary *machoInfo = execPath.length ? MCPInspectMachOAtPath(execPath, NULL) : nil;
    NSDictionary *markerInfo = execPath.length ? MCPAnalyzeBinarySecurityMarkersAtPath(execPath) : @{};

    // Enumerate Frameworks directory
    NSMutableArray<NSString *> *frameworks = [NSMutableArray array];
    if (bundlePath.length) {
        NSString *fwDir = [bundlePath stringByAppendingPathComponent:@"Frameworks"];
        NSArray<NSString *> *items = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:fwDir error:nil];
        for (NSString *item in items) {
            [frameworks addObject:item];
        }
        [frameworks sortUsingSelector:@selector(compare:)];
    }

    // Extract load_dylibs and encryption state from first Mach-O slice
    NSArray *slices = [machoInfo[@"slices"] isKindOfClass:[NSArray class]] ? machoInfo[@"slices"] : @[];
    NSDictionary *firstSlice = [slices.firstObject isKindOfClass:[NSDictionary class]] ? slices.firstObject : @{};
    NSArray *loadDylibs = [firstSlice[@"load_dylibs"] isKindOfClass:[NSArray class]] ? firstSlice[@"load_dylibs"] : @[];
    BOOL encrypted = [firstSlice[@"encrypted"] boolValue];

    // Check iTunesMetadata.plist for exact appExtVrsId
    NSString *containerRoot = bundlePath.length ? [bundlePath stringByDeletingLastPathComponent] : nil;
    NSString *metaPath = containerRoot.length ? [containerRoot stringByAppendingPathComponent:@"iTunesMetadata.plist"] : nil;
    NSDictionary *itunesMeta = (metaPath.length && [[NSFileManager defaultManager] fileExistsAtPath:metaPath])
        ? [NSDictionary dictionaryWithContentsOfFile:metaPath] : nil;
    uint64_t extVrsId = [itunesMeta[@"softwareVersionExternalIdentifier"] respondsToSelector:@selector(unsignedLongLongValue)]
        ? [itunesMeta[@"softwareVersionExternalIdentifier"] unsignedLongLongValue] : 0;

    // Compute composite security hardening score
    NSArray<NSString *> *secCategories = [markerInfo[@"detected_security_categories"] isKindOfClass:[NSArray class]]
        ? markerInfo[@"detected_security_categories"] : @[];
    NSUInteger svcCount = [markerInfo[@"inline_svc_0x80_count"] unsignedIntegerValue];
    NSInteger hardeningScore = (NSInteger)(secCategories.count * 15) + (NSInteger)MIN(svcCount * 5, (NSUInteger)50);
    for (NSString *fw in frameworks) {
        NSString *low = fw.lowercaseString;
        if ([low containsString:@"promon"] || [low containsString:@"ixguard"] ||
            [low containsString:@"perimeterx"] || [low containsString:@"datadome"] ||
            [low containsString:@"akamai"] || [low containsString:@"tmx"] ||
            [low containsString:@"sardine"] || [low containsString:@"forter"] ||
            [low containsString:@"biocatch"] || [low containsString:@"trustkit"]) {
            hardeningScore += 20;
        }
    }

    NSMutableDictionary *profile = [NSMutableDictionary dictionary];
    profile[@"bundle_id"] = bundleId;
    profile[@"short_version"] = appInfo[@"short_version"] ?: @"";
    profile[@"bundle_version"] = appInfo[@"version"] ?: @"";
    if (extVrsId > 0) {
        profile[@"appExtVrsId"] = [NSString stringWithFormat:@"%llu", extVrsId];
        profile[@"external_version_id"] = @(extVrsId);
    }
    profile[@"bundle_path"] = bundlePath ?: @"";
    profile[@"executable_path"] = execPath ?: @"";
    profile[@"fairplay_encrypted"] = @(encrypted);
    profile[@"frameworks"] = frameworks;
    profile[@"load_dylibs"] = loadDylibs;
    profile[@"security_analysis"] = markerInfo ?: @{};
    profile[@"hardening_score"] = @(hardeningScore);
    return profile;
}

static NSArray<NSString *> *MCPArraySetDifference(NSArray<NSString *> *minuend, NSArray<NSString *> *subtrahend) {
    NSMutableOrderedSet<NSString *> *set = [NSMutableOrderedSet orderedSetWithArray:(minuend ?: @[])];
    for (NSString *item in (subtrahend ?: @[])) {
        [set removeObject:item];
    }
    return [set array];
}

- (NSDictionary *)autoRollbackAndDiffWithArgs:(NSDictionary *)args error:(NSString **)error {
    if (error) *error = nil;
    NSString *bundleId = [args[@"bundle_id"] isKindOfClass:[NSString class]] ? args[@"bundle_id"] : nil;
    uint64_t adamId = [args[@"adam_id"] respondsToSelector:@selector(unsignedLongLongValue)] ? [args[@"adam_id"] unsignedLongLongValue] : 0;
    if (!bundleId.length && adamId == 0) {
        if (error) *error = @"appstore_auto_rollback_diff requires bundle_id or adam_id";
        return nil;
    }

    // Step 1: Query version history
    NSString *histErr = nil;
    NSDictionary *history = [self searchAndVersionsWithArgs:args error:&histErr];
    if (!history) {
        if (error) *error = histErr ?: @"Failed to query App Store version history";
        return nil;
    }
    if (!bundleId.length && [history[@"bundle_id"] isKindOfClass:[NSString class]]) {
        bundleId = history[@"bundle_id"];
    }
    adamId = [history[@"adam_id"] respondsToSelector:@selector(unsignedLongLongValue)] ? [history[@"adam_id"] unsignedLongLongValue] : adamId;

    // Step 2: Ensure baseline version is installed (install latest if not installed)
    NSDictionary *baselineProfile = [self profileInstalledVersionForBundleId:bundleId];
    if (!baselineProfile) {
        NSString *instErr = nil;
        NSMutableDictionary *instArgs = [NSMutableDictionary dictionaryWithDictionary:(args ?: @{})];
        if (bundleId.length) instArgs[@"bundle_id"] = bundleId;
        if (adamId > 0) instArgs[@"adam_id"] = @(adamId);
        instArgs[@"wait_for_install"] = @YES;
        NSDictionary *instRes = [self installAppWithArgs:instArgs error:&instErr];
        baselineProfile = [self profileInstalledVersionForBundleId:bundleId];
        if (!baselineProfile) {
            NSArray *versions = [history[@"versions"] isKindOfClass:[NSArray class]] ? history[@"versions"] : @[];
            return @{
                @"ok": @YES,
                @"status": @"awaiting_install_or_auth",
                @"bundle_id": bundleId ?: @"",
                @"adam_id": @(adamId),
                @"version_history_count": @(versions.count),
                @"versions": [versions subarrayWithRange:NSMakeRange(0, MIN((NSUInteger)25, versions.count))],
                @"install_result": instRes ?: @{},
                @"install_attempt_error": instErr ?: @"App not installed yet; complete Apple Account sign-in or install first to diff two installed versions"
            };
        }
    }

    // Step 3: Determine target historical version to rollback & diff against
    NSString *targetVerArg = [args[@"target_version"] isKindOfClass:[NSString class]] ? args[@"target_version"]
        : ([args[@"version"] isKindOfClass:[NSString class]] ? args[@"version"] : @"previous");
    id targetExtArg = args[@"target_ext_vrs_id"] ?: args[@"app_ext_vrs_id"];

    NSMutableDictionary *downgradeArgs = [NSMutableDictionary dictionaryWithDictionary:args];
    if (bundleId.length) downgradeArgs[@"bundle_id"] = bundleId;
    if (adamId > 0) downgradeArgs[@"adam_id"] = @(adamId);
    if (targetExtArg) {
        downgradeArgs[@"app_ext_vrs_id"] = targetExtArg;
    } else {
        downgradeArgs[@"version"] = targetVerArg ?: @"previous";
    }
    downgradeArgs[@"preserve_data"] = @YES;
    downgradeArgs[@"wait_for_install"] = @YES;

    NSString *downErr = nil;
    NSDictionary *downgradeResult = [self downgradeAppWithArgs:downgradeArgs error:&downErr];
    NSDictionary *historicalProfile = [self profileInstalledVersionForBundleId:bundleId];

    // Step 4: Compute security & binary hardening diff between baseline and historical version
    NSArray<NSString *> *baseFW = baselineProfile[@"frameworks"] ?: @[];
    NSArray<NSString *> *histFW = historicalProfile[@"frameworks"] ?: @[];
    NSArray<NSString *> *baseDylibs = baselineProfile[@"load_dylibs"] ?: @[];
    NSArray<NSString *> *histDylibs = historicalProfile[@"load_dylibs"] ?: @[];
    NSArray<NSString *> *baseSec = baselineProfile[@"security_analysis"][@"detected_security_categories"] ?: @[];
    NSArray<NSString *> *histSec = historicalProfile[@"security_analysis"][@"detected_security_categories"] ?: @[];

    NSInteger baseScore = [baselineProfile[@"hardening_score"] integerValue];
    NSInteger histScore = historicalProfile ? [historicalProfile[@"hardening_score"] integerValue] : baseScore;

    NSDictionary *diffSummary = @{
        @"frameworks_added_in_newer": MCPArraySetDifference(baseFW, histFW),
        @"frameworks_removed_in_newer": MCPArraySetDifference(histFW, baseFW),
        @"load_dylibs_added_in_newer": MCPArraySetDifference(baseDylibs, histDylibs),
        @"load_dylibs_removed_in_newer": MCPArraySetDifference(histDylibs, baseDylibs),
        @"security_sdks_added_in_newer": MCPArraySetDifference(baseSec, histSec),
        @"security_sdks_removed_in_newer": MCPArraySetDifference(histSec, baseSec),
        @"baseline_hardening_score": @(baseScore),
        @"historical_hardening_score": @(histScore),
        @"hardening_delta": @(baseScore - histScore),
        @"historical_is_less_hardened": @(histScore <= baseScore)
    };

    NSMutableDictionary *response = [NSMutableDictionary dictionary];
    response[@"bundle_id"] = bundleId ?: @"";
    response[@"adam_id"] = @(adamId);
    response[@"baseline_version_profile"] = baselineProfile;
    if (historicalProfile) response[@"historical_version_profile"] = historicalProfile;
    if (downgradeResult) response[@"downgrade_transaction"] = downgradeResult;
    if (downErr.length) response[@"downgrade_warning"] = downErr;
    response[@"security_diff"] = diffSummary;
    response[@"version_history_count"] = history[@"version_count"] ?: @0;
    response[@"active_installed_version"] = historicalProfile[@"short_version"] ?: baselineProfile[@"short_version"];
    return response;
}

@end
