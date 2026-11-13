#import "NetworkCaptureManager.h"
#import "AppManager.h"
#import "DylibInjectManager.h"
#import "MCPEngineManager.h"
#import "MCPProcessUtil.h"
#import "IOSMCPPreferences.h"
#include <libkern/OSByteOrder.h>
#include <math.h>

static NSString *MCPRedactAndFoldString(NSString *input, BOOL foldLarge) {
    if (![input isKindOfClass:[NSString class]] || !input.length) return input;
    NSString *s = input;
    // Fold inline data:...;base64,... payloads
    if ([s containsString:@"data:"] && [s containsString:@";base64,"]) {
        NSRegularExpression *dataRe = [NSRegularExpression regularExpressionWithPattern:@"data:[^;\\s]+;base64,[A-Za-z0-9+/=]{128,}" options:0 error:NULL];
        s = [dataRe stringByReplacingMatchesInString:s options:0 range:NSMakeRange(0, s.length) withTemplate:@"<folded:data-url-base64>"];
    }
    // Redact Bearer / JWT tokens
    NSRegularExpression *jwtRe = [NSRegularExpression regularExpressionWithPattern:@"(Bearer\\s+)?eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}" options:0 error:NULL];
    s = [jwtRe stringByReplacingMatchesInString:s options:0 range:NSMakeRange(0, s.length) withTemplate:@"<redacted:jwt>"];
    // Redact sensitive query/body parameters
    NSRegularExpression *paramRe = [NSRegularExpression regularExpressionWithPattern:@"((?:access_token|refresh_token|id_token|api_key|apikey|client_secret|password|passwd|session_id|sessionid|auth_token)=)([^&\\s\"']+)" options:NSRegularExpressionCaseInsensitive error:NULL];
    s = [paramRe stringByReplacingMatchesInString:s options:0 range:NSMakeRange(0, s.length) withTemplate:@"$1<redacted>"];
    if (foldLarge && s.length > 4096) {
        return [NSString stringWithFormat:@"%@ ... <folded:total_chars=%lu>", [s substringToIndex:2048], (unsigned long)s.length];
    }
    return s;
}

static NSDictionary *MCPRedactRequestEntry(NSDictionary *entry) {
    if (![entry isKindOfClass:[NSDictionary class]]) return entry;
    NSMutableDictionary *out = [entry mutableCopy];
    if ([out[@"url"] isKindOfClass:[NSString class]]) {
        out[@"url"] = MCPRedactAndFoldString(out[@"url"], NO);
    }
    NSSet<NSString *> *sensitiveHeaders = [NSSet setWithObjects:
        @"authorization", @"proxy-authorization", @"cookie", @"set-cookie",
        @"x-api-key", @"x-auth-token", @"x-access-token", @"x-csrf-token", @"x-session-token", nil];
    for (NSString *hdrField in @[@"headers", @"request_headers", @"response_headers"]) {
        if ([out[hdrField] isKindOfClass:[NSDictionary class]]) {
            NSMutableDictionary *hdrs = [out[hdrField] mutableCopy];
            for (NSString *k in [hdrs allKeys]) {
                NSString *lower = [k lowercaseString];
                if ([sensitiveHeaders containsObject:lower] || [lower containsString:@"token"] || [lower containsString:@"secret"] || [lower containsString:@"cookie"]) {
                    hdrs[k] = @"<redacted>";
                } else if ([hdrs[k] isKindOfClass:[NSString class]]) {
                    hdrs[k] = MCPRedactAndFoldString(hdrs[k], NO);
                }
            }
            out[hdrField] = hdrs;
        }
    }
    for (NSString *bodyField in @[@"body", @"request_body", @"response_body", @"body_preview"]) {
        if ([out[bodyField] isKindOfClass:[NSString class]]) {
            out[bodyField] = MCPRedactAndFoldString(out[bodyField], YES);
        }
    }
    return out;
}

static BOOL MCPHostReadVarint(const uint8_t *bytes, size_t len, size_t *offset, uint64_t *outVal) {
    if (!bytes || !offset || !outVal || *offset >= len) return NO;
    uint64_t result = 0;
    int shift = 0;
    size_t pos = *offset;
    while (pos < len && shift < 64) {
        uint8_t b = bytes[pos++];
        result |= ((uint64_t)(b & 0x7F)) << shift;
        if ((b & 0x80) == 0) {
            *offset = pos;
            *outVal = result;
            return YES;
        }
        shift += 7;
    }
    return NO;
}

static NSArray<NSDictionary *> *MCPHostDecodeProtobufFields(const uint8_t *bytes, size_t len, int depth) {
    if (!bytes || len == 0 || depth > 5) return nil;
    size_t pos = 0;
    if (depth == 0 && len >= 5 && (bytes[0] == 0x00 || bytes[0] == 0x01)) {
        uint32_t frameLen = OSSwapBigToHostInt32(*(const uint32_t *)(bytes + 1));
        if ((size_t)frameLen + 5 <= len && frameLen > 0) {
            pos = 5;
            len = 5 + (size_t)frameLen;
        }
    }
    NSMutableArray<NSDictionary *> *fields = [NSMutableArray array];
    while (pos < len && fields.count < 128) {
        uint64_t tag = 0;
        if (!MCPHostReadVarint(bytes, len, &pos, &tag) || tag == 0) return nil;
        uint64_t fieldNum = tag >> 3;
        uint8_t wireType = (uint8_t)(tag & 0x07);
        if (fieldNum == 0 || fieldNum > 536870911ULL) return nil;
        if (wireType == 0) {
            uint64_t val = 0;
            if (!MCPHostReadVarint(bytes, len, &pos, &val)) return nil;
            int64_t zigzag = (int64_t)((val >> 1) ^ (-(int64_t)(val & 1)));
            [fields addObject:@{@"field": @(fieldNum), @"wire_type": @"varint", @"uint64": @(val), @"sint64_zigzag": @(zigzag)}];
        } else if (wireType == 1) {
            if (pos + 8 > len) return nil;
            uint64_t raw64 = OSSwapLittleToHostInt64(*(const uint64_t *)(bytes + pos));
            double dbl = 0;
            memcpy(&dbl, &raw64, sizeof(dbl));
            pos += 8;
            [fields addObject:@{@"field": @(fieldNum), @"wire_type": @"fixed64", @"uint64": @(raw64), @"double": isfinite(dbl) ? @(dbl) : [NSNull null]}];
        } else if (wireType == 2) {
            uint64_t subLen = 0;
            if (!MCPHostReadVarint(bytes, len, &pos, &subLen) || pos + subLen > len) return nil;
            const uint8_t *subBytes = bytes + pos;
            pos += (size_t)subLen;
            BOOL printable = subLen > 0;
            for (size_t i = 0; i < (size_t)subLen; i++) {
                uint8_t c = subBytes[i];
                if (c < 0x09 || (c > 0x0D && c < 0x20)) {
                    printable = NO;
                    break;
                }
            }
            NSString *strVal = printable ? [[NSString alloc] initWithBytes:subBytes length:(NSUInteger)subLen encoding:NSUTF8StringEncoding] : nil;
            if (strVal) {
                [fields addObject:@{@"field": @(fieldNum), @"wire_type": @"length_delimited", @"type": @"string", @"value": strVal}];
            } else {
                NSArray<NSDictionary *> *nested = (subLen >= 2) ? MCPHostDecodeProtobufFields(subBytes, (size_t)subLen, depth + 1) : nil;
                if (nested.count > 0) {
                    [fields addObject:@{@"field": @(fieldNum), @"wire_type": @"length_delimited", @"type": @"embedded_message", @"fields": nested}];
                } else {
                    NSData *rawSub = [NSData dataWithBytes:subBytes length:(NSUInteger)MIN(subLen, (uint64_t)1024)];
                    [fields addObject:@{@"field": @(fieldNum), @"wire_type": @"bytes", @"length": @(subLen), @"base64": [rawSub base64EncodedStringWithOptions:0] ?: @""}];
                }
            }
        } else if (wireType == 5) {
            if (pos + 4 > len) return nil;
            uint32_t raw32 = OSSwapLittleToHostInt32(*(const uint32_t *)(bytes + pos));
            float flt = 0;
            memcpy(&flt, &raw32, sizeof(flt));
            pos += 4;
            [fields addObject:@{@"field": @(fieldNum), @"wire_type": @"fixed32", @"uint32": @(raw32), @"float": isfinite(flt) ? @(flt) : [NSNull null]}];
        } else {
            return nil;
        }
    }
    return (pos == len && fields.count > 0) ? fields : nil;
}

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

- (NSDictionary *)clearCaptureForBundleId:(NSString *)bundleId
                                    error:(NSString **)error {
    if (error) *error = nil;
    NSString *primaryLogPath = [self primaryCaptureLogPathForBundleId:bundleId error:error];
    if (!primaryLogPath) return nil;
    NSString *legacyLogPath = [self captureLogPathForBundleId:bundleId error:nil];
    [self deleteCaptureLogAtPath:primaryLogPath];
    if (legacyLogPath.length) [self deleteCaptureLogAtPath:legacyLogPath];
    [[MCPEngineManager sharedInstance] getCapturedRequestsForBundleId:bundleId args:@{@"limit": @1, @"clear": @YES} error:nil];
    return @{
        @"ok": @YES,
        @"bundle_id": bundleId,
        @"cleared": @YES,
        @"capture_log_path": primaryLogPath
    };
}

- (NSDictionary *)netStatusForBundleId:(NSString *)bundleId
                                 error:(NSString **)error {
    if (error) *error = nil;
    NSString *primaryLogPath = [self primaryCaptureLogPathForBundleId:bundleId error:error];
    if (!primaryLogPath) return nil;
    NSDictionary *ping = [[MCPEngineManager sharedInstance] pingForBundleId:bundleId error:nil];
    NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:primaryLogPath error:NULL];
    return @{
        @"ok": @YES,
        @"bundle_id": bundleId,
        @"engine_active": @(ping != nil),
        @"capture_log_path": primaryLogPath,
        @"log_exists": @(attrs != nil),
        @"log_size_bytes": attrs[NSFileSize] ?: @0,
        @"redaction_enabled_default": @(IOSMCPRedactSensitiveEnabled())
    };
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
    return [self getCapturedRequestsForBundleId:bundleId
                                          limit:limit
                                      urlFilter:urlFilter
                                          clear:clear
                                         redact:IOSMCPRedactSensitiveEnabled()
                                          error:error];
}

- (NSDictionary *)getCapturedRequestsForBundleId:(NSString *)bundleId
                                           limit:(NSUInteger)limit
                                       urlFilter:(NSString *)urlFilter
                                           clear:(BOOL)clear
                                          redact:(BOOL)redact
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
        [matched addObject:redact ? MCPRedactRequestEntry(entry) : entry];
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
        @"redacted": @(redact),
        @"requests": returned
    };
}

- (NSDictionary *)traceCryptoPrimitivesForBundleId:(NSString *)bundleId
                                              args:(NSDictionary *)args
                                             error:(NSString **)error {
    if (error) *error = nil;
    if ([args[@"stop"] boolValue]) {
        return [[MCPEngineManager sharedInstance] stopCryptoForBundleId:bundleId args:args error:error];
    }
    BOOL relaunch = [args[@"relaunch"] boolValue];
    NSDictionary *ping = !relaunch ? [[MCPEngineManager sharedInstance] pingForBundleId:bundleId error:nil] : nil;
    NSDictionary *inj = nil;
    if (!ping) {
        inj = [[MCPEngineManager sharedInstance] injectEngineForBundleId:bundleId
                                                           stealthConfig:nil
                                                                  launch:(args[@"launch"] ? [args[@"launch"] boolValue] : YES)
                                                                   error:error];
        if (!inj) return nil;
    }
    NSDictionary *traceRes = [[MCPEngineManager sharedInstance] traceCryptoForBundleId:bundleId args:args error:error];
    if (!traceRes) return nil;
    NSMutableDictionary *merged = [traceRes mutableCopy];
    merged[@"bundle_id"] = bundleId;
    if (inj) merged[@"engine_injection"] = inj;
    return merged;
}

- (NSDictionary *)getCryptoEventsForBundleId:(NSString *)bundleId
                                        args:(NSDictionary *)args
                                       error:(NSString **)error {
    if (error) *error = nil;
    NSString *container = [self captureContainerForBundleId:bundleId error:error];
    if (!container) return nil;
    NSString *cryptoLogPath = [container stringByAppendingPathComponent:@"tmp/.mcp_crypto.jsonl"];

    NSUInteger limit = [args[@"limit"] respondsToSelector:@selector(unsignedIntegerValue)] ? [args[@"limit"] unsignedIntegerValue] : 100;
    if (limit == 0) limit = 100;
    if (limit > 2000) limit = 2000;
    NSString *primitiveFilter = [args[@"primitive_filter"] isKindOfClass:[NSString class]] ? [args[@"primitive_filter"] lowercaseString] : nil;
    NSString *algorithmFilter = [args[@"algorithm_filter"] isKindOfClass:[NSString class]] ? [args[@"algorithm_filter"] lowercaseString] : nil;
    BOOL clear = [args[@"clear"] boolValue];

    NSMutableArray<NSDictionary *> *allEvents = [NSMutableArray array];
    NSDictionary *liveRes = [[MCPEngineManager sharedInstance] getCryptoEventsForBundleId:bundleId
                                                                                     args:@{@"limit": @(limit), @"clear": @(clear)}
                                                                                    error:nil];
    if ([liveRes[@"events"] isKindOfClass:[NSArray class]]) {
        [allEvents addObjectsFromArray:liveRes[@"events"]];
    }

    NSData *diskData = [self readCaptureFileDataAtPath:cryptoLogPath];
    if (diskData.length) {
        NSString *text = [[NSString alloc] initWithData:diskData encoding:NSUTF8StringEncoding];
        for (NSString *line in [text componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]]) {
            if (!line.length) continue;
            NSData *lineData = [line dataUsingEncoding:NSUTF8StringEncoding];
            NSDictionary *ev = lineData ? [NSJSONSerialization JSONObjectWithData:lineData options:0 error:NULL] : nil;
            if ([ev isKindOfClass:[NSDictionary class]]) {
                [allEvents addObject:ev];
            }
        }
    }

    NSMutableSet<NSString *> *seenIds = [NSMutableSet set];
    NSMutableArray<NSDictionary *> *filtered = [NSMutableArray array];
    for (NSDictionary *ev in allEvents) {
        NSString *key = [NSString stringWithFormat:@"%@|%@|%@", ev[@"id"] ?: @0, ev[@"primitive"] ?: @"", ev[@"timestamp"] ?: @0];
        if ([seenIds containsObject:key]) continue;
        [seenIds addObject:key];
        if (primitiveFilter.length) {
            NSString *p = [ev[@"primitive"] isKindOfClass:[NSString class]] ? [ev[@"primitive"] lowercaseString] : @"";
            if (![p containsString:primitiveFilter]) continue;
        }
        if (algorithmFilter.length) {
            NSString *alg = [ev[@"algorithm"] isKindOfClass:[NSString class]] ? [ev[@"algorithm"] lowercaseString] : @"";
            if (![alg containsString:algorithmFilter]) continue;
        }
        [filtered addObject:ev];
    }

    if (filtered.count > limit) {
        filtered = [[filtered subarrayWithRange:NSMakeRange(filtered.count - limit, limit)] mutableCopy];
    }
    if (clear) {
        [self deleteCaptureLogAtPath:cryptoLogPath];
    }

    return @{
        @"bundle_id": bundleId,
        @"log_path": cryptoLogPath,
        @"tracing": liveRes[@"tracing"] ?: @NO,
        @"count": @(filtered.count),
        @"events": filtered
    };
}

- (NSDictionary *)hookQuicHttp3ForBundleId:(NSString *)bundleId
                                      args:(NSDictionary *)args
                                     error:(NSString **)error {
    if (error) *error = nil;
    BOOL relaunch = [args[@"relaunch"] boolValue];
    NSDictionary *ping = !relaunch ? [[MCPEngineManager sharedInstance] pingForBundleId:bundleId error:nil] : nil;
    NSDictionary *inj = nil;
    if (!ping) {
        inj = [[MCPEngineManager sharedInstance] injectEngineForBundleId:bundleId
                                                           stealthConfig:nil
                                                                  launch:(args[@"launch"] ? [args[@"launch"] boolValue] : YES)
                                                                   error:error];
        if (!inj) return nil;
    }
    NSDictionary *res = [[MCPEngineManager sharedInstance] hookQuicHttp3ForBundleId:bundleId args:args error:error];
    if (!res) return nil;
    NSMutableDictionary *merged = [res mutableCopy];
    merged[@"bundle_id"] = bundleId;
    if (inj) merged[@"engine_injection"] = inj;
    return merged;
}

- (NSDictionary *)decodeProtobufWithArgs:(NSDictionary *)args
                                   error:(NSString **)error {
    if (error) *error = nil;
    NSString *bundleId = [args[@"bundle_id"] isKindOfClass:[NSString class]] ? args[@"bundle_id"] : nil;
    if (bundleId.length) {
        NSDictionary *inProc = [[MCPEngineManager sharedInstance] decodeProtobufForBundleId:bundleId args:args error:nil];
        if (inProc && !inProc[@"error"]) {
            return inProc;
        }
    }
    NSData *raw = nil;
    NSString *b64Str = [args[@"data_base64"] isKindOfClass:[NSString class]] ? args[@"data_base64"]
        : ([args[@"base64"] isKindOfClass:[NSString class]] ? args[@"base64"]
        : ([args[@"payload_base64"] isKindOfClass:[NSString class]] ? args[@"payload_base64"] : nil));
    NSString *hexStr = [args[@"data_hex"] isKindOfClass:[NSString class]] ? args[@"data_hex"]
        : ([args[@"hex"] isKindOfClass:[NSString class]] ? args[@"hex"]
        : ([args[@"payload_hex"] isKindOfClass:[NSString class]] ? args[@"payload_hex"] : nil));
    if (!b64Str && !hexStr && [args[@"data"] isKindOfClass:[NSString class]]) {
        NSString *cand = args[@"data"];
        NSCharacterSet *nonHex = [[NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdefABCDEF xX"] invertedSet];
        if (cand.length >= 2 && [cand rangeOfCharacterFromSet:nonHex].location == NSNotFound) {
            hexStr = cand;
        } else {
            b64Str = cand;
        }
    }
    if (b64Str.length > 0) {
        raw = [[NSData alloc] initWithBase64EncodedString:b64Str options:NSDataBase64DecodingIgnoreUnknownCharacters];
    } else if (hexStr.length > 0) {
        NSString *hex = [[hexStr stringByReplacingOccurrencesOfString:@" " withString:@""]
                         stringByReplacingOccurrencesOfString:@"0x" withString:@""];
        NSMutableData *m = [NSMutableData dataWithCapacity:hex.length / 2];
        for (NSUInteger i = 0; i + 1 < hex.length; i += 2) {
            char byteChars[3] = { (char)[hex characterAtIndex:i], (char)[hex characterAtIndex:i + 1], 0 };
            uint8_t b = (uint8_t)strtoul(byteChars, NULL, 16);
            [m appendBytes:&b length:1];
        }
        raw = m;
    }
    if (!raw.length) {
        if (error) *error = @"Missing or invalid data_base64 or data_hex parameter";
        return nil;
    }
    NSArray<NSDictionary *> *fields = MCPHostDecodeProtobufFields((const uint8_t *)raw.bytes, raw.length, 0);
    return @{
        @"byte_length": @(raw.length),
        @"valid_protobuf": @(fields.count > 0),
        @"field_count": @(fields.count),
        @"fields": fields ?: @[]
    };
}

- (NSDictionary *)replayRequestNativeForBundleId:(NSString *)bundleId
                                            args:(NSDictionary *)args
                                           error:(NSString **)error {
    if (error) *error = nil;
    NSDictionary *ping = [[MCPEngineManager sharedInstance] pingForBundleId:bundleId error:nil];
    if (!ping) {
        NSDictionary *inj = [[MCPEngineManager sharedInstance] injectEngineForBundleId:bundleId
                                                                         stealthConfig:nil
                                                                                launch:YES
                                                                                 error:error];
        if (!inj) return nil;
    }
    return [[MCPEngineManager sharedInstance] replayRequestForBundleId:bundleId args:args error:error];
}

@end
