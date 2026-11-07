#import "engine_rpc.h"
#include "fishhook.h"
#include <dlfcn.h>
#include <fcntl.h>
#include <libkern/OSByteOrder.h>
#include <mach-o/dyld.h>
#include <objc/message.h>
#include <objc/runtime.h>
#include <stdatomic.h>
#include <string.h>
#include <unistd.h>

static NSString *const kMCPCapHandledKey = @"com.iosmcp.netcap.handled";
static NSString *const kMCPCapTaskTrackedKey = @"com.iosmcp.netcap.task_tracked";
static const NSUInteger kMCPCapBodyPreviewLimit = 4096;
static _Atomic uint64_t g_mcpcap_seq = 0;
static _Atomic int g_mcpcap_active = 0;
static NSMutableArray<NSDictionary *> *g_mcpcap_bound_slots = nil;
static NSObject *g_mcpcap_lock = nil;

static void MCPCapInitLock(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        g_mcpcap_lock = [NSObject new];
        g_mcpcap_bound_slots = [NSMutableArray array];
    });
}

static dispatch_queue_t MCPCapLogQueue(void) {
    static dispatch_queue_t q = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        q = dispatch_queue_create("com.iosmcp.engine.netcap", DISPATCH_QUEUE_SERIAL);
    });
    return q;
}

static NSString *MCPCapPrimaryLogPath(void) {
    return [NSTemporaryDirectory() stringByAppendingPathComponent:@".mcpcap.jsonl"];
}

static NSString *MCPCapLegacyLogPath(void) {
    return [NSTemporaryDirectory() stringByAppendingPathComponent:@".mcp_netcap.jsonl"];
}

static NSDictionary *MCPCapSanitizeHeaders(NSDictionary *headers) {
    if (![headers isKindOfClass:[NSDictionary class]]) return @{};
    NSMutableDictionary *clean = [NSMutableDictionary dictionaryWithCapacity:headers.count];
    for (id k in headers) {
        id v = headers[k];
        clean[[k description] ?: @""] = [v description] ?: @"";
    }
    return clean;
}

static NSArray<NSDictionary *> *MCPCapDecodeProtobufFields(const uint8_t *bytes, size_t len, unsigned depth) {
    if (!bytes || len == 0 || depth > 5) return nil;
    size_t pos = 0;
    // Detect 5-byte gRPC length-prefixed header (0x00 uncompressed flag + 4-byte BE length)
    if (depth == 0 && len >= 5 && bytes[0] == 0x00) {
        uint32_t grpcLen = OSSwapBigToHostInt32(*(const uint32_t *)(bytes + 1));
        if ((size_t)grpcLen + 5 == len && grpcLen > 0) {
            pos = 5;
        }
    }

    NSMutableArray<NSDictionary *> *fields = [NSMutableArray array];
    while (pos < len && fields.count < 128) {
        uint64_t tag = 0;
        unsigned shift = 0;
        while (pos < len) {
            uint8_t b = bytes[pos++];
            tag |= (uint64_t)(b & 0x7FU) << shift;
            if ((b & 0x80U) == 0) break;
            shift += 7;
            if (shift > 63) return nil;
        }
        uint32_t fieldNum = (uint32_t)(tag >> 3);
        uint32_t wireType = (uint32_t)(tag & 0x7U);
        if (fieldNum == 0 || fieldNum > 536870911U) return nil;

        if (wireType == 0) { // Varint
            uint64_t val = 0;
            shift = 0;
            BOOL ok = NO;
            while (pos < len) {
                uint8_t b = bytes[pos++];
                val |= (uint64_t)(b & 0x7FU) << shift;
                if ((b & 0x80U) == 0) { ok = YES; break; }
                shift += 7;
                if (shift > 63) return nil;
            }
            if (!ok) return nil;
            int64_t sint = (int64_t)((val >> 1) ^ (~(val & 1ULL) + 1ULL));
            [fields addObject:@{
                @"field": @(fieldNum),
                @"wire_type": @"varint",
                @"uint64": @(val),
                @"sint64": @(sint)
            }];
        } else if (wireType == 1) { // 64-bit
            if (pos + 8 > len) return nil;
            uint64_t raw64 = OSSwapLittleToHostInt64(*(const uint64_t *)(bytes + pos));
            double dbl = 0;
            memcpy(&dbl, &raw64, sizeof(dbl));
            pos += 8;
            [fields addObject:@{
                @"field": @(fieldNum),
                @"wire_type": @"fixed64",
                @"uint64": @(raw64),
                @"double": isfinite(dbl) ? @(dbl) : [NSNull null]
            }];
        } else if (wireType == 2) { // Length-delimited
            uint64_t subLen = 0;
            shift = 0;
            BOOL ok = NO;
            while (pos < len) {
                uint8_t b = bytes[pos++];
                subLen |= (uint64_t)(b & 0x7FU) << shift;
                if ((b & 0x80U) == 0) { ok = YES; break; }
                shift += 7;
                if (shift > 32) return nil;
            }
            if (!ok || pos + subLen > len) return nil;
            const uint8_t *subBytes = bytes + pos;
            pos += (size_t)subLen;

            BOOL isPrintable = (subLen > 0);
            for (size_t k = 0; k < subLen; k++) {
                uint8_t c = subBytes[k];
                if (c < 0x20 && c != '\n' && c != '\r' && c != '\t') { isPrintable = NO; break; }
                if (c > 0x7E) { isPrintable = NO; break; }
            }
            if (isPrintable) {
                NSString *s = [[NSString alloc] initWithBytes:subBytes length:(NSUInteger)subLen encoding:NSUTF8StringEncoding];
                [fields addObject:@{
                    @"field": @(fieldNum),
                    @"wire_type": @"string",
                    @"length": @(subLen),
                    @"value": s ?: @""
                }];
            } else {
                NSArray<NSDictionary *> *nested = (subLen >= 2) ? MCPCapDecodeProtobufFields(subBytes, (size_t)subLen, depth + 1) : nil;
                if (nested.count > 0) {
                    [fields addObject:@{
                        @"field": @(fieldNum),
                        @"wire_type": @"nested_message",
                        @"length": @(subLen),
                        @"fields": nested
                    }];
                } else {
                    NSData *rawSub = [NSData dataWithBytes:subBytes length:(NSUInteger)MIN(subLen, (uint64_t)512)];
                    [fields addObject:@{
                        @"field": @(fieldNum),
                        @"wire_type": @"bytes",
                        @"length": @(subLen),
                        @"base64": [rawSub base64EncodedStringWithOptions:0] ?: @""
                    }];
                }
            }
        } else if (wireType == 5) { // 32-bit
            if (pos + 4 > len) return nil;
            uint32_t raw32 = OSSwapLittleToHostInt32(*(const uint32_t *)(bytes + pos));
            float flt = 0;
            memcpy(&flt, &raw32, sizeof(flt));
            pos += 4;
            [fields addObject:@{
                @"field": @(fieldNum),
                @"wire_type": @"fixed32",
                @"uint32": @(raw32),
                @"float": isfinite(flt) ? @(flt) : [NSNull null]
            }];
        } else {
            return nil;
        }
    }
    return (pos == len && fields.count > 0) ? fields : nil;
}

static NSDictionary *MCPCapEncodeBodyPreview(NSData *data) {
    if (!data || data.length == 0) {
        return @{@"size": @0, @"encoding": @"utf8", @"preview": @"", @"truncated": @NO};
    }
    BOOL truncated = data.length > kMCPCapBodyPreviewLimit;
    NSData *slice = truncated ? [data subdataWithRange:NSMakeRange(0, kMCPCapBodyPreviewLimit)] : data;
    NSString *utf8 = [[NSString alloc] initWithData:slice encoding:NSUTF8StringEncoding];
    if (utf8) {
        return @{
            @"size": @(data.length),
            @"encoding": @"utf8",
            @"preview": utf8,
            @"truncated": @(truncated)
        };
    }
    NSMutableDictionary *res = [NSMutableDictionary dictionaryWithDictionary:@{
        @"size": @(data.length),
        @"encoding": @"base64",
        @"preview": [slice base64EncodedStringWithOptions:0] ?: @"",
        @"truncated": @(truncated)
    }];
    NSArray<NSDictionary *> *pbFields = MCPCapDecodeProtobufFields((const uint8_t *)slice.bytes, slice.length, 0);
    if (pbFields.count > 0) {
        res[@"protobuf_fields"] = pbFields;
    }
    return res;
}

static NSData *MCPCapReadRequestBody(NSURLRequest *request, BOOL allowConsumeStream, NSMutableURLRequest *forwardReq) {
    if (!request) return nil;
    if (request.HTTPBody.length > 0) {
        return request.HTTPBody;
    }
    if (!allowConsumeStream || !request.HTTPBodyStream) {
        return nil;
    }
    NSInputStream *stream = request.HTTPBodyStream;
    if (stream.streamStatus != NSStreamStatusNotOpen) {
        return nil;
    }
    NSMutableData *buf = [NSMutableData data];
    [stream open];
    uint8_t chunk[2048];
    while (stream.hasBytesAvailable && buf.length < 65536) {
        NSInteger n = [stream read:chunk maxLength:sizeof(chunk)];
        if (n <= 0) break;
        [buf appendBytes:chunk length:(NSUInteger)n];
    }
    [stream close];
    if (forwardReq && buf.length > 0) {
        forwardReq.HTTPBody = buf;
    }
    return buf;
}

static void MCPCapWriteLineToPath(NSString *path, NSData *json) {
    if (!path.length || !json.length) return;
    int fd = open(path.fileSystemRepresentation, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (fd < 0) return;
    const uint8_t *bytes = json.bytes;
    size_t rem = json.length;
    while (rem > 0) {
        ssize_t w = write(fd, bytes, rem);
        if (w <= 0) break;
        bytes += (size_t)w;
        rem -= (size_t)w;
    }
    write(fd, "\n", 1);
    close(fd);
}

static void MCPCapAppendRecord(NSDictionary *record) {
    if (!atomic_load(&g_mcpcap_active)) return;
    if (![record isKindOfClass:[NSDictionary class]]) return;
    NSData *json = [NSJSONSerialization dataWithJSONObject:record options:0 error:NULL];
    if (!json.length) return;
    dispatch_async(MCPCapLogQueue(), ^{
        MCPCapWriteLineToPath(MCPCapPrimaryLogPath(), json);
        MCPCapWriteLineToPath(MCPCapLegacyLogPath(), json);
    });
}

#pragma mark - Layer 1: NSURLProtocol + NSURLSession / NSURLSessionTask hooks

@interface MCPCapURLProtocol : NSURLProtocol <NSURLSessionDataDelegate>
@property (nonatomic, strong) NSURLSessionDataTask *forwardTask;
@property (nonatomic, strong) NSData *capturedReqBody;
@property (nonatomic, assign) CFAbsoluteTime startTime;
@property (nonatomic, assign) uint64_t sequenceId;
@end

static NSURLSessionConfiguration *(*orig_cap_defaultConfig)(id, SEL) = NULL;
static NSURLSessionConfiguration *(*orig_cap_ephemeralConfig)(id, SEL) = NULL;
static NSArray<Class> *(*orig_cap_protocolClasses)(id, SEL) = NULL;
static NSURLSession *(*orig_cap_sessionWithConfigDelegate)(id, SEL, NSURLSessionConfiguration *, id, NSOperationQueue *) = NULL;
static NSURLSession *(*orig_cap_sessionWithConfig)(id, SEL, NSURLSessionConfiguration *) = NULL;
static void (*orig_cap_taskResume)(id, SEL) = NULL;

@implementation MCPCapURLProtocol

+ (NSURLSession *)forwardingSession {
    static NSURLSession *s = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSURLSessionConfiguration *cfg = orig_cap_ephemeralConfig
            ? orig_cap_ephemeralConfig([NSURLSessionConfiguration class], @selector(ephemeralSessionConfiguration))
            : [NSURLSessionConfiguration ephemeralSessionConfiguration];
        NSMutableArray *protos = [NSMutableArray array];
        for (Class cls in (cfg.protocolClasses ?: @[])) {
            if (cls != [MCPCapURLProtocol class] && ![NSStringFromClass(cls) containsString:@"MCPNetCap"]) {
                [protos addObject:cls];
            }
        }
        cfg.protocolClasses = protos;
        s = orig_cap_sessionWithConfigDelegate
            ? orig_cap_sessionWithConfigDelegate([NSURLSession class],
                                                 @selector(sessionWithConfiguration:delegate:delegateQueue:),
                                                 cfg, nil, nil)
            : [NSURLSession sessionWithConfiguration:cfg];
    });
    return s;
}

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    if (!atomic_load(&g_mcpcap_active)) return NO;
    if (!request.URL) return NO;
    NSString *scheme = request.URL.scheme.lowercaseString;
    if (![scheme isEqualToString:@"http"] && ![scheme isEqualToString:@"https"]) {
        return NO;
    }
    if ([[NSURLProtocol propertyForKey:kMCPCapHandledKey inRequest:request] boolValue]) {
        return NO;
    }
    return YES;
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request {
    return request;
}

- (void)startLoading {
    self.startTime = CFAbsoluteTimeGetCurrent();
    self.sequenceId = atomic_fetch_add(&g_mcpcap_seq, 1) + 1;

    NSMutableURLRequest *forwardReq = [self.request mutableCopy];
    self.capturedReqBody = MCPCapReadRequestBody(self.request, YES, forwardReq);
    [NSURLProtocol setProperty:@YES forKey:kMCPCapHandledKey inRequest:forwardReq];

    __weak typeof(self) weakSelf = self;
    self.forwardTask = [[MCPCapURLProtocol forwardingSession]
        dataTaskWithRequest:forwardReq
          completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) return;

        double durationMs = (CFAbsoluteTimeGetCurrent() - strongSelf.startTime) * 1000.0;
        NSInteger statusCode = 0;
        NSDictionary *respHeaders = @{};
        if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
            NSHTTPURLResponse *httpResp = (NSHTTPURLResponse *)response;
            statusCode = httpResp.statusCode;
            respHeaders = MCPCapSanitizeHeaders(httpResp.allHeaderFields);
        }

        if (response) {
            [strongSelf.client URLProtocol:strongSelf didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
        }
        if (data.length > 0) {
            [strongSelf.client URLProtocol:strongSelf didLoadData:data];
        }
        if (error) {
            [strongSelf.client URLProtocol:strongSelf didFailWithError:error];
        } else {
            [strongSelf.client URLProtocolDidFinishLoading:strongSelf];
        }

        NSURL *u = strongSelf.request.URL;
        NSDictionary *record = @{
            @"id": @(strongSelf.sequenceId),
            @"pid": @(getpid()),
            @"source": @"nsurlsession",
            @"timestamp": @([[NSDate date] timeIntervalSince1970]),
            @"duration_ms": @(round(durationMs * 100.0) / 100.0),
            @"method": strongSelf.request.HTTPMethod ?: @"GET",
            @"url": u.absoluteString ?: @"",
            @"scheme": u.scheme ?: @"",
            @"host": u.host ?: @"",
            @"path": u.path ?: @"",
            @"request_headers": MCPCapSanitizeHeaders(strongSelf.request.allHTTPHeaderFields),
            @"request_body": MCPCapEncodeBodyPreview(strongSelf.capturedReqBody),
            @"status_code": @(statusCode),
            @"mime_type": response.MIMEType ?: @"",
            @"response_headers": respHeaders,
            @"response_bytes": @(data.length),
            @"response_body": MCPCapEncodeBodyPreview(data),
            @"error": error ? (error.localizedDescription ?: @"request error") : [NSNull null]
        };
        MCPCapAppendRecord(record);
    }];
    [self.forwardTask resume];
}

- (void)stopLoading {
    [self.forwardTask cancel];
    self.forwardTask = nil;
}

@end

static void MCPCapInjectProtocolIntoConfig(NSURLSessionConfiguration *cfg) {
    if (!cfg || !atomic_load(&g_mcpcap_active)) return;
    NSArray *existing = orig_cap_protocolClasses
        ? orig_cap_protocolClasses(cfg, @selector(protocolClasses))
        : cfg.protocolClasses;
    if (existing.firstObject == [MCPCapURLProtocol class]) return;
    NSMutableArray *updated = [NSMutableArray arrayWithObject:[MCPCapURLProtocol class]];
    for (Class cls in (existing ?: @[])) {
        if (cls != [MCPCapURLProtocol class]) {
            [updated addObject:cls];
        }
    }
    cfg.protocolClasses = updated;
}

static NSURLSessionConfiguration *swizzled_cap_defaultConfig(id self, SEL _cmd) {
    NSURLSessionConfiguration *cfg = orig_cap_defaultConfig(self, _cmd);
    MCPCapInjectProtocolIntoConfig(cfg);
    return cfg;
}

static NSURLSessionConfiguration *swizzled_cap_ephemeralConfig(id self, SEL _cmd) {
    NSURLSessionConfiguration *cfg = orig_cap_ephemeralConfig(self, _cmd);
    MCPCapInjectProtocolIntoConfig(cfg);
    return cfg;
}

static NSArray<Class> *swizzled_cap_protocolClasses(id self, SEL _cmd) {
    NSArray<Class> *orig = orig_cap_protocolClasses ? orig_cap_protocolClasses(self, _cmd) : @[];
    if (!atomic_load(&g_mcpcap_active)) return orig;
    if (orig.firstObject == [MCPCapURLProtocol class]) return orig;
    NSMutableArray<Class> *arr = [NSMutableArray arrayWithObject:[MCPCapURLProtocol class]];
    if (orig) [arr addObjectsFromArray:orig];
    return arr;
}

static NSURLSession *swizzled_cap_sessionWithConfigDelegate(id self, SEL _cmd, NSURLSessionConfiguration *cfg, id delegate, NSOperationQueue *queue) {
    MCPCapInjectProtocolIntoConfig(cfg);
    return orig_cap_sessionWithConfigDelegate(self, _cmd, cfg, delegate, queue);
}

static NSURLSession *swizzled_cap_sessionWithConfig(id self, SEL _cmd, NSURLSessionConfiguration *cfg) {
    MCPCapInjectProtocolIntoConfig(cfg);
    return orig_cap_sessionWithConfig(self, _cmd, cfg);
}

static void MCPCapPollTaskCompletion(NSURLSessionTask *task,
                                     NSURLRequest *reqSnapshot,
                                     NSData *reqBodySnapshot,
                                     CFAbsoluteTime startTime,
                                     uint64_t seqId,
                                     int attempt) {
    if (!task || !atomic_load(&g_mcpcap_active)) return;
    if (task.state == NSURLSessionTaskStateCompleted || task.state == NSURLSessionTaskStateCanceling || attempt >= 60) {
        NSURLRequest *finalReq = task.currentRequest ?: reqSnapshot;
        if (finalReq && [[NSURLProtocol propertyForKey:kMCPCapHandledKey inRequest:finalReq] boolValue]) {
            return;
        }
        double durationMs = (CFAbsoluteTimeGetCurrent() - startTime) * 1000.0;
        NSURLResponse *response = task.response;
        NSInteger statusCode = 0;
        NSDictionary *respHeaders = @{};
        if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
            NSHTTPURLResponse *httpResp = (NSHTTPURLResponse *)response;
            statusCode = httpResp.statusCode;
            respHeaders = MCPCapSanitizeHeaders(httpResp.allHeaderFields);
        }
        NSURL *u = finalReq.URL ?: reqSnapshot.URL;
        NSError *error = task.error;
        NSDictionary *record = @{
            @"id": @(seqId),
            @"pid": @(getpid()),
            @"source": @"nsurlsession_task",
            @"timestamp": @([[NSDate date] timeIntervalSince1970]),
            @"duration_ms": @(round(durationMs * 100.0) / 100.0),
            @"method": finalReq.HTTPMethod ?: (reqSnapshot.HTTPMethod ?: @"GET"),
            @"url": u.absoluteString ?: @"",
            @"scheme": u.scheme ?: @"",
            @"host": u.host ?: @"",
            @"path": u.path ?: @"",
            @"request_headers": MCPCapSanitizeHeaders(finalReq.allHTTPHeaderFields ?: reqSnapshot.allHTTPHeaderFields),
            @"request_body": MCPCapEncodeBodyPreview(reqBodySnapshot),
            @"status_code": @(statusCode),
            @"mime_type": response.MIMEType ?: @"",
            @"response_headers": respHeaders,
            @"response_bytes": @(task.countOfBytesReceived > 0 ? task.countOfBytesReceived : 0),
            @"response_body": @{@"size": @(task.countOfBytesReceived > 0 ? task.countOfBytesReceived : 0), @"encoding": @"utf8", @"preview": @"", @"truncated": @NO},
            @"error": error ? (error.localizedDescription ?: @"request error") : [NSNull null]
        };
        MCPCapAppendRecord(record);
        return;
    }
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(100 * NSEC_PER_MSEC)), MCPCapLogQueue(), ^{
        MCPCapPollTaskCompletion(task, reqSnapshot, reqBodySnapshot, startTime, seqId, attempt + 1);
    });
}

static void swizzled_cap_taskResume(id self, SEL _cmd) {
    if (atomic_load(&g_mcpcap_active) && [self isKindOfClass:[NSURLSessionTask class]]) {
        NSURLSessionTask *task = (NSURLSessionTask *)self;
        NSURLRequest *req = task.originalRequest ?: task.currentRequest;
        if (req.URL &&
            ![[NSURLProtocol propertyForKey:kMCPCapHandledKey inRequest:req] boolValue] &&
            !objc_getAssociatedObject(task, &kMCPCapTaskTrackedKey)) {
            NSString *scheme = req.URL.scheme.lowercaseString;
            if ([scheme isEqualToString:@"http"] || [scheme isEqualToString:@"https"]) {
                objc_setAssociatedObject(task, &kMCPCapTaskTrackedKey, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
                NSURLRequest *reqCopy = [req copy];
                NSData *reqBody = MCPCapReadRequestBody(reqCopy, NO, nil);
                CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
                uint64_t seqId = atomic_fetch_add(&g_mcpcap_seq, 1) + 1;
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(100 * NSEC_PER_MSEC)), MCPCapLogQueue(), ^{
                    MCPCapPollTaskCompletion(task, reqCopy, reqBody, start, seqId, 0);
                });
            }
        }
    }
    if (orig_cap_taskResume) {
        orig_cap_taskResume(self, _cmd);
    }
}

static void (*orig_cap_wsSend)(id, SEL, id, void (^)(NSError *)) = NULL;
static void (*orig_cap_wsReceive)(id, SEL, void (^)(id, NSError *)) = NULL;

static void swizzled_cap_wsSend(id self, SEL _cmd, id message, void (^completionHandler)(NSError *error)) {
    if (atomic_load(&g_mcpcap_active) && message) {
        @try {
            NSURLSessionTask *task = [self isKindOfClass:[NSURLSessionTask class]] ? (NSURLSessionTask *)self : nil;
            NSURL *u = task.currentRequest.URL ?: task.originalRequest.URL;
            NSData *payload = nil;
            if ([message respondsToSelector:@selector(data)]) {
                payload = [message valueForKey:@"data"];
            }
            if (!payload && [message respondsToSelector:@selector(string)]) {
                NSString *str = [message valueForKey:@"string"];
                if ([str isKindOfClass:[NSString class]]) {
                    payload = [str dataUsingEncoding:NSUTF8StringEncoding];
                }
            }
            uint64_t seqId = atomic_fetch_add(&g_mcpcap_seq, 1) + 1;
            NSDictionary *record = @{
                @"id": @(seqId),
                @"pid": @(getpid()),
                @"source": @"websocket",
                @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                @"duration_ms": @0,
                @"method": @"WS_SEND",
                @"url": u.absoluteString ?: @"ws://websocket",
                @"scheme": u.scheme ?: @"wss",
                @"host": u.host ?: @"",
                @"path": u.path ?: @"/",
                @"request_headers": MCPCapSanitizeHeaders(task.currentRequest.allHTTPHeaderFields),
                @"request_body": MCPCapEncodeBodyPreview(payload),
                @"status_code": @101,
                @"mime_type": @"application/websocket",
                @"response_headers": @{},
                @"response_bytes": @0,
                @"response_body": @{@"size": @0, @"encoding": @"utf8", @"preview": @"", @"truncated": @NO},
                @"error": [NSNull null]
            };
            MCPCapAppendRecord(record);
        } @catch (NSException *ex) {
            (void)ex;
        }
    }
    if (orig_cap_wsSend) {
        orig_cap_wsSend(self, _cmd, message, completionHandler);
    }
}

static void swizzled_cap_wsReceive(id self, SEL _cmd, void (^completionHandler)(id message, NSError *error)) {
    if (!atomic_load(&g_mcpcap_active) || !completionHandler) {
        if (orig_cap_wsReceive) orig_cap_wsReceive(self, _cmd, completionHandler);
        return;
    }
    __weak id weakSelf = self;
    CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
    void (^wrapped)(id, NSError *) = ^(id message, NSError *error) {
        if (atomic_load(&g_mcpcap_active) && (message || error)) {
            @try {
                id strongSelf = weakSelf;
                NSURLSessionTask *task = [strongSelf isKindOfClass:[NSURLSessionTask class]] ? (NSURLSessionTask *)strongSelf : nil;
                NSURL *u = task.currentRequest.URL ?: task.originalRequest.URL;
                NSData *payload = nil;
                if (message && [message respondsToSelector:@selector(data)]) {
                    payload = [message valueForKey:@"data"];
                }
                if (!payload && message && [message respondsToSelector:@selector(string)]) {
                    NSString *str = [message valueForKey:@"string"];
                    if ([str isKindOfClass:[NSString class]]) {
                        payload = [str dataUsingEncoding:NSUTF8StringEncoding];
                    }
                }
                uint64_t seqId = atomic_fetch_add(&g_mcpcap_seq, 1) + 1;
                double durationMs = (CFAbsoluteTimeGetCurrent() - start) * 1000.0;
                NSDictionary *record = @{
                    @"id": @(seqId),
                    @"pid": @(getpid()),
                    @"source": @"websocket",
                    @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                    @"duration_ms": @(round(durationMs * 100.0) / 100.0),
                    @"method": @"WS_RECV",
                    @"url": u.absoluteString ?: @"ws://websocket",
                    @"scheme": u.scheme ?: @"wss",
                    @"host": u.host ?: @"",
                    @"path": u.path ?: @"/",
                    @"request_headers": @{},
                    @"request_body": @{@"size": @0, @"encoding": @"utf8", @"preview": @"", @"truncated": @NO},
                    @"status_code": @101,
                    @"mime_type": @"application/websocket",
                    @"response_headers": @{},
                    @"response_bytes": @(payload.length),
                    @"response_body": MCPCapEncodeBodyPreview(payload),
                    @"error": error ? (error.localizedDescription ?: @"ws error") : [NSNull null]
                };
                MCPCapAppendRecord(record);
            } @catch (NSException *ex) {
                (void)ex;
            }
        }
        completionHandler(message, error);
    };
    if (orig_cap_wsReceive) {
        orig_cap_wsReceive(self, _cmd, wrapped);
    }
}

static void MCPCapInstallObjCHooksOnce(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        [NSURLProtocol registerClass:[MCPCapURLProtocol class]];

        Method mDef = class_getClassMethod([NSURLSessionConfiguration class], @selector(defaultSessionConfiguration));
        if (mDef) orig_cap_defaultConfig = (typeof(orig_cap_defaultConfig))method_setImplementation(mDef, (IMP)swizzled_cap_defaultConfig);

        Method mEph = class_getClassMethod([NSURLSessionConfiguration class], @selector(ephemeralSessionConfiguration));
        if (mEph) orig_cap_ephemeralConfig = (typeof(orig_cap_ephemeralConfig))method_setImplementation(mEph, (IMP)swizzled_cap_ephemeralConfig);

        Method mProto = class_getInstanceMethod([NSURLSessionConfiguration class], @selector(protocolClasses));
        if (mProto) orig_cap_protocolClasses = (typeof(orig_cap_protocolClasses))method_setImplementation(mProto, (IMP)swizzled_cap_protocolClasses);

        Method mSessDel = class_getClassMethod([NSURLSession class], @selector(sessionWithConfiguration:delegate:delegateQueue:));
        if (mSessDel) orig_cap_sessionWithConfigDelegate = (typeof(orig_cap_sessionWithConfigDelegate))method_setImplementation(mSessDel, (IMP)swizzled_cap_sessionWithConfigDelegate);

        Method mSess = class_getClassMethod([NSURLSession class], @selector(sessionWithConfiguration:));
        if (mSess) orig_cap_sessionWithConfig = (typeof(orig_cap_sessionWithConfig))method_setImplementation(mSess, (IMP)swizzled_cap_sessionWithConfig);

        // Hook -[NSURLSessionTask resume] on the concrete class cluster root(s)
        Class taskCls = [NSURLSessionTask class];
        Method mRes = class_getInstanceMethod(taskCls, @selector(resume));
        if (mRes) {
            orig_cap_taskResume = (typeof(orig_cap_taskResume))method_setImplementation(mRes, (IMP)swizzled_cap_taskResume);
        }
        Class localTaskCls = NSClassFromString(@"__NSCFLocalSessionTask");
        if (localTaskCls && localTaskCls != taskCls) {
            Method mLocalRes = class_getInstanceMethod(localTaskCls, @selector(resume));
            if (mLocalRes && method_getImplementation(mLocalRes) != (IMP)swizzled_cap_taskResume) {
                if (!orig_cap_taskResume) {
                    orig_cap_taskResume = (typeof(orig_cap_taskResume))method_getImplementation(mLocalRes);
                }
                method_setImplementation(mLocalRes, (IMP)swizzled_cap_taskResume);
            }
        }

        // Hook NSURLSessionWebSocketTask send/receive
        NSArray<NSString *> *wsClassNames = @[@"NSURLSessionWebSocketTask", @"__NSURLSessionWebSocketTask"];
        for (NSString *clsName in wsClassNames) {
            Class wsCls = NSClassFromString(clsName);
            if (!wsCls) continue;
            Method mSend = class_getInstanceMethod(wsCls, @selector(sendMessage:completionHandler:));
            if (mSend && method_getImplementation(mSend) != (IMP)swizzled_cap_wsSend) {
                if (!orig_cap_wsSend) {
                    orig_cap_wsSend = (typeof(orig_cap_wsSend))method_getImplementation(mSend);
                }
                method_setImplementation(mSend, (IMP)swizzled_cap_wsSend);
            }
            Method mRecv = class_getInstanceMethod(wsCls, @selector(receiveMessageWithCompletionHandler:));
            if (mRecv && method_getImplementation(mRecv) != (IMP)swizzled_cap_wsReceive) {
                if (!orig_cap_wsReceive) {
                    orig_cap_wsReceive = (typeof(orig_cap_wsReceive))method_getImplementation(mRecv);
                }
                method_setImplementation(mRecv, (IMP)swizzled_cap_wsReceive);
            }
        }
    });
}

#pragma mark - Layer 2: BoringSSL / TLS C hooks (SSL_write / SSL_read)

static int (*orig_cap_SSL_write)(void *ssl, const void *buf, int num) = NULL;
static int (*orig_cap_SSL_read)(void *ssl, void *buf, int num) = NULL;
static const char *(*fn_cap_SSL_get_servername)(const void *ssl, int type) = NULL;

typedef struct {
    const void *ssl;
    CFAbsoluteTime startTime;
    uint64_t seqId;
    char method[16];
    char host[256];
    char path[1024];
    char reqPreview[1024];
    size_t reqSize;
    int active;
} mcp_tls_inflight_t;

#define MCP_MAX_TLS_INFLIGHT 32
static mcp_tls_inflight_t g_tls_inflight[MCP_MAX_TLS_INFLIGHT];

static int MCPCapStartsWithHTTPMethod(const char *buf, int len, char *outMethod, size_t methodCap, char *outPath, size_t pathCap) {
    static const char *const kMethods[] = {"GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS ", "CONNECT "};
    if (!buf || len < 5) return 0;
    for (size_t i = 0; i < sizeof(kMethods) / sizeof(kMethods[0]); i++) {
        size_t mlen = strlen(kMethods[i]);
        if ((size_t)len > mlen && memcmp(buf, kMethods[i], mlen) == 0) {
            if (outMethod && methodCap > 0) {
                size_t copyLen = mlen - 1;
                if (copyLen >= methodCap) copyLen = methodCap - 1;
                memcpy(outMethod, kMethods[i], copyLen);
                outMethod[copyLen] = '\0';
            }
            if (outPath && pathCap > 0) {
                const char *p = buf + mlen;
                const char *end = memchr(p, ' ', (size_t)len - mlen);
                if (!end) end = memchr(p, '\r', (size_t)len - mlen);
                if (!end) end = memchr(p, '\n', (size_t)len - mlen);
                size_t plen = end ? (size_t)(end - p) : 0;
                if (plen >= pathCap) plen = pathCap - 1;
                if (plen > 0) memcpy(outPath, p, plen);
                outPath[plen] = '\0';
            }
            return 1;
        }
    }
    return 0;
}

static void MCPCapExtractHostHeader(const char *buf, int len, char *outHost, size_t hostCap) {
    if (!buf || len <= 0 || !outHost || hostCap == 0) return;
    outHost[0] = '\0';
    size_t maxScan = (size_t)len > 4096 ? 4096 : (size_t)len;
    for (size_t i = 0; i + 6 < maxScan; i++) {
        if ((buf[i] == '\n') && strncasecmp(&buf[i + 1], "Host:", 5) == 0) {
            const char *val = &buf[i + 6];
            while (val < buf + maxScan && (*val == ' ' || *val == '\t')) val++;
            const char *end = val;
            while (end < buf + maxScan && *end != '\r' && *end != '\n') end++;
            size_t hlen = (size_t)(end - val);
            if (hlen >= hostCap) hlen = hostCap - 1;
            memcpy(outHost, val, hlen);
            outHost[hlen] = '\0';
            return;
        }
    }
}

static int hook_cap_SSL_write(void *ssl, const void *buf, int num) {
    int ret = orig_cap_SSL_write ? orig_cap_SSL_write(ssl, buf, num) : -1;
    if (ret > 0 && atomic_load(&g_mcpcap_active) && buf && MEDepth == 0) {
        MEDepth++;
        @try {
            char method[16] = {0};
            char path[1024] = {0};
            char host[256] = {0};
            const char *cbuf = (const char *)buf;
            if (fn_cap_SSL_get_servername && ssl) {
                const char *sni = fn_cap_SSL_get_servername(ssl, 0);
                if (sni && *sni) {
                    strncpy(host, sni, sizeof(host) - 1);
                }
            }
            if (MCPCapStartsWithHTTPMethod(cbuf, ret, method, sizeof(method), path, sizeof(path))) {
                char hdrHost[256] = {0};
                MCPCapExtractHostHeader(cbuf, ret, hdrHost, sizeof(hdrHost));
                if (hdrHost[0]) {
                    strncpy(host, hdrHost, sizeof(host) - 1);
                }
                @synchronized(g_mcpcap_lock) {
                    size_t slot = (size_t)(atomic_fetch_add(&g_mcpcap_seq, 1) % MCP_MAX_TLS_INFLIGHT);
                    mcp_tls_inflight_t *entry = &g_tls_inflight[slot];
                    entry->ssl = ssl;
                    entry->startTime = CFAbsoluteTimeGetCurrent();
                    entry->seqId = atomic_load(&g_mcpcap_seq);
                    strncpy(entry->method, method, sizeof(entry->method) - 1);
                    strncpy(entry->host, host, sizeof(entry->host) - 1);
                    strncpy(entry->path, path[0] ? path : "/", sizeof(entry->path) - 1);
                    entry->reqSize = (size_t)ret;
                    size_t prevLen = (size_t)ret < sizeof(entry->reqPreview) - 1 ? (size_t)ret : sizeof(entry->reqPreview) - 1;
                    memcpy(entry->reqPreview, cbuf, prevLen);
                    entry->reqPreview[prevLen] = '\0';
                    entry->active = 1;
                }
            } else if (host[0]) {
                // Non-HTTP/1.x or HTTP/2 frame over BoringSSL: record if no inflight slot exists for this SSL handle
                BOOL alreadyTracked = NO;
                @synchronized(g_mcpcap_lock) {
                    for (size_t i = 0; i < MCP_MAX_TLS_INFLIGHT; i++) {
                        if (g_tls_inflight[i].active && g_tls_inflight[i].ssl == ssl) {
                            alreadyTracked = YES;
                            break;
                        }
                    }
                    if (!alreadyTracked) {
                        size_t slot = (size_t)(atomic_fetch_add(&g_mcpcap_seq, 1) % MCP_MAX_TLS_INFLIGHT);
                        mcp_tls_inflight_t *entry = &g_tls_inflight[slot];
                        entry->ssl = ssl;
                        entry->startTime = CFAbsoluteTimeGetCurrent();
                        entry->seqId = atomic_load(&g_mcpcap_seq);
                        strncpy(entry->method, "TLS", sizeof(entry->method) - 1);
                        strncpy(entry->host, host, sizeof(entry->host) - 1);
                        strncpy(entry->path, "/", sizeof(entry->path) - 1);
                        entry->reqSize = (size_t)ret;
                        entry->reqPreview[0] = '\0';
                        entry->active = 1;
                    }
                }
            }
        } @catch (NSException *ex) {
            (void)ex;
        } @finally {
            MEDepth--;
        }
    }
    return ret;
}

static int hook_cap_SSL_read(void *ssl, void *buf, int num) {
    int ret = orig_cap_SSL_read ? orig_cap_SSL_read(ssl, buf, num) : -1;
    if (ret > 0 && atomic_load(&g_mcpcap_active) && buf && MEDepth == 0) {
        MEDepth++;
        @try {
            mcp_tls_inflight_t matched = {0};
            BOOL found = NO;
            @synchronized(g_mcpcap_lock) {
                for (size_t i = 0; i < MCP_MAX_TLS_INFLIGHT; i++) {
                    if (g_tls_inflight[i].active && g_tls_inflight[i].ssl == ssl) {
                        matched = g_tls_inflight[i];
                        g_tls_inflight[i].active = 0;
                        found = YES;
                        break;
                    }
                }
            }
            if (found) {
                NSInteger statusCode = 200;
                const char *cbuf = (const char *)buf;
                if (ret >= 12 && memcmp(cbuf, "HTTP/1.", 7) == 0) {
                    statusCode = atoi(cbuf + 9);
                }
                double durationMs = (CFAbsoluteTimeGetCurrent() - matched.startTime) * 1000.0;
                NSString *hostStr = @(matched.host);
                NSString *pathStr = @(matched.path[0] ? matched.path : "/");
                NSString *urlStr = hostStr.length
                    ? [NSString stringWithFormat:@"https://%@%@", hostStr, pathStr]
                    : pathStr;
                NSData *respData = [NSData dataWithBytes:buf length:(NSUInteger)(ret > (int)kMCPCapBodyPreviewLimit ? (int)kMCPCapBodyPreviewLimit : ret)];
                NSData *reqData = matched.reqPreview[0]
                    ? [NSData dataWithBytes:matched.reqPreview length:strlen(matched.reqPreview)]
                    : nil;
                NSDictionary *record = @{
                    @"id": @(matched.seqId),
                    @"pid": @(getpid()),
                    @"source": @"boringssl",
                    @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                    @"duration_ms": @(round(durationMs * 100.0) / 100.0),
                    @"method": @(matched.method[0] ? matched.method : "GET"),
                    @"url": urlStr ?: @"",
                    @"scheme": @"https",
                    @"host": hostStr ?: @"",
                    @"path": pathStr ?: @"/",
                    @"request_headers": @{},
                    @"request_body": MCPCapEncodeBodyPreview(reqData),
                    @"status_code": @(statusCode),
                    @"mime_type": @"",
                    @"response_headers": @{},
                    @"response_bytes": @(ret),
                    @"response_body": MCPCapEncodeBodyPreview(respData),
                    @"error": [NSNull null]
                };
                MCPCapAppendRecord(record);
            }
        } @catch (NSException *ex) {
            (void)ex;
        } @finally {
            MEDepth--;
        }
    }
    return ret;
}

static BOOL MCPCapShouldHookImage(const struct mach_header *hdr, const char *name) {
    if (!hdr || !name || hdr == MESelfHeader()) return NO;
    if (strstr(name, "libApple") || strstr(name, "libmcp") || strstr(name, "systemhook") ||
        strstr(name, "TweakLoader") || strstr(name, "/.jbroot-") || strstr(name, "/TweakInject/")) {
        return NO;
    }
    if (!strstr(name, "/System/Library/") && !strstr(name, "/usr/lib/") && !strstr(name, "/Developer/")) {
        return YES;
    }
    if (strstr(name, "CFNetwork") || strstr(name, "libnetwork.dylib") || strstr(name, "libboringssl.dylib")) {
        return YES;
    }
    return NO;
}

static NSDictionary *MCPCapSlotPatchToDict(const mcp_slot_patch_t *p, NSString *imageName) {
    uint64_t newLE = OSSwapHostToLittleInt64((uint64_t)p->new_val);
    uint64_t origLE = OSSwapHostToLittleInt64((uint64_t)p->orig_val);
    NSString *newB64 = [[NSData dataWithBytes:&newLE length:sizeof(newLE)] base64EncodedStringWithOptions:0];
    NSString *origB64 = [[NSData dataWithBytes:&origLE length:sizeof(origLE)] base64EncodedStringWithOptions:0];
    return @{
        @"slot_address": MEHex(p->slot_addr),
        @"original_value": MEHex(p->orig_val),
        @"replacement_value": MEHex(p->new_val),
        @"bytes_base64": newB64 ?: @"",
        @"original_bytes_base64": origB64 ?: @"",
        @"symbol": @(p->symbol_name),
        @"section": @(p->section_name),
        @"auth_got": @(p->is_auth ? YES : NO),
        @"writable_in_proc": @(p->written_in_proc ? YES : NO),
        @"image": imageName ?: @""
    };
}

static void MCPCapInstallTLSHooks(NSMutableArray<NSDictionary *> *allSlots,
                                  NSMutableArray<NSDictionary *> *pendingSlots,
                                  NSUInteger *outPatchedInProc) {
    MCPCapInitLock();
    void *boring = dlopen("/usr/lib/libboringssl.dylib", RTLD_LAZY | RTLD_NOLOAD);
    if (!boring) boring = dlopen("/usr/lib/libboringssl.dylib", RTLD_LAZY);
    if (boring) {
        if (!orig_cap_SSL_write) orig_cap_SSL_write = dlsym(boring, "SSL_write");
        if (!orig_cap_SSL_read) orig_cap_SSL_read = dlsym(boring, "SSL_read");
        if (!fn_cap_SSL_get_servername) fn_cap_SSL_get_servername = dlsym(boring, "SSL_get_servername");
    }
    if (!orig_cap_SSL_write) orig_cap_SSL_write = dlsym(RTLD_DEFAULT, "SSL_write");
    if (!orig_cap_SSL_read) orig_cap_SSL_read = dlsym(RTLD_DEFAULT, "SSL_read");
    if (!fn_cap_SSL_get_servername) fn_cap_SSL_get_servername = dlsym(RTLD_DEFAULT, "SSL_get_servername");

    struct mcp_rebinding rebindings[] = {
        {"SSL_write", (void *)hook_cap_SSL_write, (void **)&orig_cap_SSL_write},
        {"SSL_read", (void *)hook_cap_SSL_read, (void **)&orig_cap_SSL_read}
    };

    NSUInteger patched = 0;
    uint32_t count = _dyld_image_count();
    MEDepth++;
    @try {
        for (uint32_t i = 0; i < count; i++) {
            const struct mach_header *hdr = _dyld_get_image_header(i);
            const char *name = _dyld_get_image_name(i);
            if (!MCPCapShouldHookImage(hdr, name)) continue;
            intptr_t slide = _dyld_get_image_vmaddr_slide(i);
            mcp_slot_collector_t collector = {0};
            mcp_rebind_symbols_image_collect(hdr, slide, MESelfHeader(), rebindings, 2, &collector);
            NSString *imgName = name ? @(name) : @"";
            for (size_t k = 0; k < collector.count; k++) {
                NSDictionary *slotDict = MCPCapSlotPatchToDict(&collector.patches[k], imgName);
                @synchronized(g_mcpcap_lock) {
                    BOOL exists = NO;
                    for (NSUInteger idx = 0; idx < g_mcpcap_bound_slots.count; idx++) {
                        if ([g_mcpcap_bound_slots[idx][@"slot_address"] isEqualToString:slotDict[@"slot_address"]]) {
                            g_mcpcap_bound_slots[idx] = slotDict;
                            exists = YES;
                            break;
                        }
                    }
                    if (!exists) [g_mcpcap_bound_slots addObject:slotDict];
                }
                [allSlots addObject:slotDict];
                if (collector.patches[k].written_in_proc) {
                    patched++;
                } else {
                    [pendingSlots addObject:slotDict];
                }
            }
            mcp_slot_collector_free(&collector);
        }
    } @finally {
        MEDepth--;
    }
    if (outPatchedInProc) *outPatchedInProc = patched;
}

#pragma mark - Layer 3: Network.framework QUIC / HTTP/3 / nw_connection C hooks

typedef void (^nw_send_completion_block_t)(void *error);
typedef void (^nw_receive_completion_block_t)(dispatch_data_t content, void *context, bool is_complete, void *error);

static void (*orig_cap_nw_connection_send)(void *connection, dispatch_data_t content, void *context, bool is_complete, nw_send_completion_block_t completion) = NULL;
static void (*orig_cap_nw_connection_receive)(void *connection, uint32_t minimum_incomplete_length, uint32_t maximum_length, nw_receive_completion_block_t completion) = NULL;
static void (*orig_cap_nw_connection_receive_message)(void *connection, nw_receive_completion_block_t completion) = NULL;
static void *(*fn_cap_nw_connection_copy_endpoint)(void *connection) = NULL;
static const char *(*fn_cap_nw_endpoint_get_hostname)(void *endpoint) = NULL;
static uint16_t (*fn_cap_nw_endpoint_get_port)(void *endpoint) = NULL;

static NSData *MCPCapDataFromDispatchData(dispatch_data_t ddata) {
    if (!ddata) return nil;
    NSMutableData *acc = [NSMutableData data];
    dispatch_data_apply(ddata, ^bool(dispatch_data_t region, size_t offset, const void *buffer, size_t size) {
        (void)region;
        (void)offset;
        if (buffer && size > 0 && acc.length < kMCPCapBodyPreviewLimit) {
            size_t toCopy = MIN(size, kMCPCapBodyPreviewLimit - acc.length);
            [acc appendBytes:buffer length:toCopy];
        }
        return acc.length < kMCPCapBodyPreviewLimit;
    });
    return acc;
}

static NSString *MCPCapEndpointHostForNWConnection(void *connection, uint16_t *outPort) {
    if (outPort) *outPort = 0;
    if (!connection || !fn_cap_nw_connection_copy_endpoint) return @"";
    void *ep = fn_cap_nw_connection_copy_endpoint(connection);
    if (!ep) return @"";
    NSString *hostStr = @"";
    if (fn_cap_nw_endpoint_get_hostname) {
        const char *h = fn_cap_nw_endpoint_get_hostname(ep);
        if (h && *h) hostStr = @(h);
    }
    if (outPort && fn_cap_nw_endpoint_get_port) {
        *outPort = fn_cap_nw_endpoint_get_port(ep);
    }
    return hostStr ?: @"";
}

static void hook_cap_nw_connection_send(void *connection, dispatch_data_t content, void *context, bool is_complete, nw_send_completion_block_t completion) {
    if (atomic_load(&g_mcpcap_active) && content && MEDepth == 0) {
        MEDepth++;
        @try {
            NSData *payload = MCPCapDataFromDispatchData(content);
            if (payload.length > 0) {
                uint16_t port = 0;
                NSString *host = MCPCapEndpointHostForNWConnection(connection, &port);
                NSString *urlStr = host.length
                    ? (port > 0 ? [NSString stringWithFormat:@"quic://%@:%u/", host, port] : [NSString stringWithFormat:@"quic://%@/", host])
                    : @"quic://nw_connection/";
                uint64_t seqId = atomic_fetch_add(&g_mcpcap_seq, 1) + 1;
                NSDictionary *record = @{
                    @"id": @(seqId),
                    @"pid": @(getpid()),
                    @"source": @"nw_connection_quic",
                    @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                    @"duration_ms": @0,
                    @"method": @"QUIC_SEND",
                    @"url": urlStr,
                    @"scheme": @"quic",
                    @"host": host ?: @"",
                    @"path": @"/",
                    @"request_headers": @{},
                    @"request_body": MCPCapEncodeBodyPreview(payload),
                    @"status_code": @200,
                    @"mime_type": @"application/octet-stream",
                    @"response_headers": @{},
                    @"response_bytes": @0,
                    @"response_body": @{@"size": @0, @"encoding": @"utf8", @"preview": @"", @"truncated": @NO},
                    @"error": [NSNull null]
                };
                MCPCapAppendRecord(record);
            }
        } @catch (NSException *ex) {
            (void)ex;
        } @finally {
            MEDepth--;
        }
    }
    if (orig_cap_nw_connection_send) {
        orig_cap_nw_connection_send(connection, content, context, is_complete, completion);
    }
}

static void hook_cap_nw_connection_receive(void *connection, uint32_t minimum_incomplete_length, uint32_t maximum_length, nw_receive_completion_block_t completion) {
    if (!atomic_load(&g_mcpcap_active) || !completion) {
        if (orig_cap_nw_connection_receive) {
            orig_cap_nw_connection_receive(connection, minimum_incomplete_length, maximum_length, completion);
        }
        return;
    }
    CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
    nw_receive_completion_block_t wrapped = ^(dispatch_data_t content, void *context, bool is_complete, void *error) {
        if (atomic_load(&g_mcpcap_active) && content && MEDepth == 0) {
            MEDepth++;
            @try {
                NSData *payload = MCPCapDataFromDispatchData(content);
                if (payload.length > 0) {
                    uint16_t port = 0;
                    NSString *host = MCPCapEndpointHostForNWConnection(connection, &port);
                    NSString *urlStr = host.length
                        ? (port > 0 ? [NSString stringWithFormat:@"quic://%@:%u/", host, port] : [NSString stringWithFormat:@"quic://%@/", host])
                        : @"quic://nw_connection/";
                    uint64_t seqId = atomic_fetch_add(&g_mcpcap_seq, 1) + 1;
                    double durationMs = (CFAbsoluteTimeGetCurrent() - start) * 1000.0;
                    NSDictionary *record = @{
                        @"id": @(seqId),
                        @"pid": @(getpid()),
                        @"source": @"nw_connection_quic",
                        @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                        @"duration_ms": @(round(durationMs * 100.0) / 100.0),
                        @"method": @"QUIC_RECV",
                        @"url": urlStr,
                        @"scheme": @"quic",
                        @"host": host ?: @"",
                        @"path": @"/",
                        @"request_headers": @{},
                        @"request_body": @{@"size": @0, @"encoding": @"utf8", @"preview": @"", @"truncated": @NO},
                        @"status_code": @200,
                        @"mime_type": @"application/octet-stream",
                        @"response_headers": @{},
                        @"response_bytes": @(payload.length),
                        @"response_body": MCPCapEncodeBodyPreview(payload),
                        @"error": [NSNull null]
                    };
                    MCPCapAppendRecord(record);
                }
            } @catch (NSException *ex) {
                (void)ex;
            } @finally {
                MEDepth--;
            }
        }
        completion(content, context, is_complete, error);
    };
    if (orig_cap_nw_connection_receive) {
        orig_cap_nw_connection_receive(connection, minimum_incomplete_length, maximum_length, wrapped);
    }
}

static void hook_cap_nw_connection_receive_message(void *connection, nw_receive_completion_block_t completion) {
    if (!atomic_load(&g_mcpcap_active) || !completion) {
        if (orig_cap_nw_connection_receive_message) {
            orig_cap_nw_connection_receive_message(connection, completion);
        }
        return;
    }
    CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
    nw_receive_completion_block_t wrapped = ^(dispatch_data_t content, void *context, bool is_complete, void *error) {
        if (atomic_load(&g_mcpcap_active) && content && MEDepth == 0) {
            MEDepth++;
            @try {
                NSData *payload = MCPCapDataFromDispatchData(content);
                if (payload.length > 0) {
                    uint16_t port = 0;
                    NSString *host = MCPCapEndpointHostForNWConnection(connection, &port);
                    NSString *urlStr = host.length
                        ? (port > 0 ? [NSString stringWithFormat:@"quic://%@:%u/", host, port] : [NSString stringWithFormat:@"quic://%@/", host])
                        : @"quic://nw_connection/";
                    uint64_t seqId = atomic_fetch_add(&g_mcpcap_seq, 1) + 1;
                    double durationMs = (CFAbsoluteTimeGetCurrent() - start) * 1000.0;
                    NSDictionary *record = @{
                        @"id": @(seqId),
                        @"pid": @(getpid()),
                        @"source": @"nw_connection_quic",
                        @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                        @"duration_ms": @(round(durationMs * 100.0) / 100.0),
                        @"method": @"QUIC_MSG_RECV",
                        @"url": urlStr,
                        @"scheme": @"quic",
                        @"host": host ?: @"",
                        @"path": @"/",
                        @"request_headers": @{},
                        @"request_body": @{@"size": @0, @"encoding": @"utf8", @"preview": @"", @"truncated": @NO},
                        @"status_code": @200,
                        @"mime_type": @"application/octet-stream",
                        @"response_headers": @{},
                        @"response_bytes": @(payload.length),
                        @"response_body": MCPCapEncodeBodyPreview(payload),
                        @"error": [NSNull null]
                    };
                    MCPCapAppendRecord(record);
                }
            } @catch (NSException *ex) {
                (void)ex;
            } @finally {
                MEDepth--;
            }
        }
        completion(content, context, is_complete, error);
    };
    if (orig_cap_nw_connection_receive_message) {
        orig_cap_nw_connection_receive_message(connection, wrapped);
    }
}

static void MCPCapInstallQuicHooks(NSMutableArray<NSDictionary *> *allSlots,
                                   NSMutableArray<NSDictionary *> *pendingSlots,
                                   NSUInteger *outPatchedInProc) {
    MCPCapInitLock();
    void *netlib = dlopen("/usr/lib/libnetwork.dylib", RTLD_LAZY | RTLD_NOLOAD);
    if (!netlib) netlib = dlopen("/usr/lib/libnetwork.dylib", RTLD_LAZY);
    if (netlib) {
        if (!orig_cap_nw_connection_send) orig_cap_nw_connection_send = dlsym(netlib, "nw_connection_send");
        if (!orig_cap_nw_connection_receive) orig_cap_nw_connection_receive = dlsym(netlib, "nw_connection_receive");
        if (!orig_cap_nw_connection_receive_message) orig_cap_nw_connection_receive_message = dlsym(netlib, "nw_connection_receive_message");
        if (!fn_cap_nw_connection_copy_endpoint) fn_cap_nw_connection_copy_endpoint = dlsym(netlib, "nw_connection_copy_endpoint");
        if (!fn_cap_nw_endpoint_get_hostname) fn_cap_nw_endpoint_get_hostname = dlsym(netlib, "nw_endpoint_get_hostname");
        if (!fn_cap_nw_endpoint_get_port) fn_cap_nw_endpoint_get_port = dlsym(netlib, "nw_endpoint_get_port");
    }
    if (!orig_cap_nw_connection_send) orig_cap_nw_connection_send = dlsym(RTLD_DEFAULT, "nw_connection_send");
    if (!orig_cap_nw_connection_receive) orig_cap_nw_connection_receive = dlsym(RTLD_DEFAULT, "nw_connection_receive");
    if (!orig_cap_nw_connection_receive_message) orig_cap_nw_connection_receive_message = dlsym(RTLD_DEFAULT, "nw_connection_receive_message");
    if (!fn_cap_nw_connection_copy_endpoint) fn_cap_nw_connection_copy_endpoint = dlsym(RTLD_DEFAULT, "nw_connection_copy_endpoint");
    if (!fn_cap_nw_endpoint_get_hostname) fn_cap_nw_endpoint_get_hostname = dlsym(RTLD_DEFAULT, "nw_endpoint_get_hostname");
    if (!fn_cap_nw_endpoint_get_port) fn_cap_nw_endpoint_get_port = dlsym(RTLD_DEFAULT, "nw_endpoint_get_port");

    struct mcp_rebinding rebindings[] = {
        {"nw_connection_send", (void *)hook_cap_nw_connection_send, (void **)&orig_cap_nw_connection_send},
        {"nw_connection_receive", (void *)hook_cap_nw_connection_receive, (void **)&orig_cap_nw_connection_receive},
        {"nw_connection_receive_message", (void *)hook_cap_nw_connection_receive_message, (void **)&orig_cap_nw_connection_receive_message}
    };

    NSUInteger patched = 0;
    uint32_t count = _dyld_image_count();
    MEDepth++;
    @try {
        for (uint32_t i = 0; i < count; i++) {
            const struct mach_header *hdr = _dyld_get_image_header(i);
            const char *name = _dyld_get_image_name(i);
            if (!MCPCapShouldHookImage(hdr, name)) continue;
            intptr_t slide = _dyld_get_image_vmaddr_slide(i);
            mcp_slot_collector_t collector = {0};
            mcp_rebind_symbols_image_collect(hdr, slide, MESelfHeader(), rebindings, 3, &collector);
            NSString *imgName = name ? @(name) : @"";
            for (size_t k = 0; k < collector.count; k++) {
                NSDictionary *slotDict = MCPCapSlotPatchToDict(&collector.patches[k], imgName);
                @synchronized(g_mcpcap_lock) {
                    BOOL exists = NO;
                    for (NSUInteger idx = 0; idx < g_mcpcap_bound_slots.count; idx++) {
                        if ([g_mcpcap_bound_slots[idx][@"slot_address"] isEqualToString:slotDict[@"slot_address"]]) {
                            g_mcpcap_bound_slots[idx] = slotDict;
                            exists = YES;
                            break;
                        }
                    }
                    if (!exists) [g_mcpcap_bound_slots addObject:slotDict];
                }
                [allSlots addObject:slotDict];
                if (collector.patches[k].written_in_proc) {
                    patched++;
                } else {
                    [pendingSlots addObject:slotDict];
                }
            }
            mcp_slot_collector_free(&collector);
        }
    } @finally {
        MEDepth--;
    }
    if (outPatchedInProc) *outPatchedInProc = patched;
}

static NSArray<NSDictionary *> *MCPCapReadRecordsFromFile(NSString *path) {
    if (!path.length) return @[];
    NSData *data = [NSData dataWithContentsOfFile:path];
    if (!data.length) return @[];
    NSString *content = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (!content.length) return @[];
    NSArray<NSString *> *lines = [content componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
    NSMutableArray<NSDictionary *> *records = [NSMutableArray array];
    for (NSString *line in lines) {
        if (!line.length) continue;
        NSData *lineData = [line dataUsingEncoding:NSUTF8StringEncoding];
        if (!lineData) continue;
        NSDictionary *obj = [NSJSONSerialization JSONObjectWithData:lineData options:0 error:NULL];
        if ([obj isKindOfClass:[NSDictionary class]]) {
            [records addObject:obj];
        }
    }
    return records;
}

NSDictionary *MENetCap(NSString *op, NSDictionary *a) {
    MCPCapInitLock();
    if ([op isEqualToString:@"engine.start_capture"]) {
        BOOL clear = a[@"clear"] ? [a[@"clear"] boolValue] : YES;
        if (clear) {
            unlink(MCPCapPrimaryLogPath().fileSystemRepresentation);
            unlink(MCPCapLegacyLogPath().fileSystemRepresentation);
        }
        int fd1 = open(MCPCapPrimaryLogPath().fileSystemRepresentation, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
        if (fd1 >= 0) close(fd1);
        int fd2 = open(MCPCapLegacyLogPath().fileSystemRepresentation, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
        if (fd2 >= 0) close(fd2);

        atomic_store(&g_mcpcap_active, 1);
        MCPCapInstallObjCHooksOnce();

        NSMutableArray<NSDictionary *> *allSlots = [NSMutableArray array];
        NSMutableArray<NSDictionary *> *pendingSlots = [NSMutableArray array];
        NSUInteger patchedInProc = 0;
        MCPCapInstallTLSHooks(allSlots, pendingSlots, &patchedInProc);
        BOOL hookQuic = a[@"hook_quic"] ? [a[@"hook_quic"] boolValue] : YES;
        if (hookQuic) {
            NSUInteger quicPatched = 0;
            MCPCapInstallQuicHooks(allSlots, pendingSlots, &quicPatched);
            patchedInProc += quicPatched;
        }

        return @{
            @"capturing": @YES,
            @"pid": @(getpid()),
            @"log_path": MCPCapPrimaryLogPath(),
            @"legacy_log_path": MCPCapLegacyLogPath(),
            @"patched_in_proc": @(patchedInProc),
            @"slots": allSlots,
            @"pending_slots": pendingSlots
        };
    }

    if ([op isEqualToString:@"engine.hook_quic_http3"]) {
        BOOL clear = [a[@"clear"] boolValue];
        if (clear) {
            unlink(MCPCapPrimaryLogPath().fileSystemRepresentation);
            unlink(MCPCapLegacyLogPath().fileSystemRepresentation);
        }
        int fd1 = open(MCPCapPrimaryLogPath().fileSystemRepresentation, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
        if (fd1 >= 0) close(fd1);
        int fd2 = open(MCPCapLegacyLogPath().fileSystemRepresentation, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
        if (fd2 >= 0) close(fd2);

        atomic_store(&g_mcpcap_active, 1);
        MCPCapInstallObjCHooksOnce();

        NSMutableArray<NSDictionary *> *allSlots = [NSMutableArray array];
        NSMutableArray<NSDictionary *> *pendingSlots = [NSMutableArray array];
        NSUInteger tlsPatched = 0;
        NSUInteger quicPatched = 0;
        MCPCapInstallTLSHooks(allSlots, pendingSlots, &tlsPatched);
        MCPCapInstallQuicHooks(allSlots, pendingSlots, &quicPatched);

        return @{
            @"capturing": @YES,
            @"quic_http3_hooked": @YES,
            @"websocket_hooked": @YES,
            @"pid": @(getpid()),
            @"log_path": MCPCapPrimaryLogPath(),
            @"patched_in_proc": @(tlsPatched + quicPatched),
            @"slots": allSlots,
            @"pending_slots": pendingSlots
        };
    }

    if ([op isEqualToString:@"engine.decode_protobuf"]) {
        NSData *raw = nil;
        if ([a[@"data_base64"] isKindOfClass:[NSString class]]) {
            raw = [[NSData alloc] initWithBase64EncodedString:a[@"data_base64"] options:NSDataBase64DecodingIgnoreUnknownCharacters];
        } else if ([a[@"data_hex"] isKindOfClass:[NSString class]]) {
            NSString *hex = [[a[@"data_hex"] stringByReplacingOccurrencesOfString:@" " withString:@""]
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
            return @{@"error": @"missing or invalid data_base64 / data_hex"};
        }
        NSArray<NSDictionary *> *fields = MCPCapDecodeProtobufFields((const uint8_t *)raw.bytes, raw.length, 0);
        return @{
            @"byte_length": @(raw.length),
            @"valid_protobuf": @(fields.count > 0),
            @"field_count": @(fields.count),
            @"fields": fields ?: @[]
        };
    }

    if ([op isEqualToString:@"engine.replay_request"]) {
        NSString *urlStr = [a[@"url"] isKindOfClass:[NSString class]] ? a[@"url"] : @"";
        NSURL *url = [NSURL URLWithString:urlStr];
        if (!url || !url.scheme.length) {
            return @{@"error": @"valid url is required"};
        }
        NSString *method = [a[@"method"] isKindOfClass:[NSString class]] ? [a[@"method"] uppercaseString] : @"GET";
        NSTimeInterval timeoutSec = [a[@"timeout_ms"] respondsToSelector:@selector(doubleValue)]
            ? MAX(1.0, MIN(60.0, [a[@"timeout_ms"] doubleValue] / 1000.0))
            : 15.0;

        NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url
                                                           cachePolicy:NSURLRequestReloadIgnoringLocalCacheData
                                                       timeoutInterval:timeoutSec];
        req.HTTPMethod = method;
        [NSURLProtocol setProperty:@YES forKey:kMCPCapHandledKey inRequest:req];

        if ([a[@"headers"] isKindOfClass:[NSDictionary class]]) {
            NSDictionary *hdrs = a[@"headers"];
            for (id k in hdrs) {
                id v = hdrs[k];
                [req setValue:[v description] forHTTPHeaderField:[k description]];
            }
        }
        if ([a[@"body_base64"] isKindOfClass:[NSString class]] && [a[@"body_base64"] length] > 0) {
            req.HTTPBody = [[NSData alloc] initWithBase64EncodedString:a[@"body_base64"] options:NSDataBase64DecodingIgnoreUnknownCharacters];
        } else if ([a[@"body"] isKindOfClass:[NSString class]] && [a[@"body"] length] > 0) {
            req.HTTPBody = [a[@"body"] dataUsingEncoding:NSUTF8StringEncoding];
        } else if ([a[@"body_json"] isKindOfClass:[NSDictionary class]] || [a[@"body_json"] isKindOfClass:[NSArray class]]) {
            req.HTTPBody = [NSJSONSerialization dataWithJSONObject:a[@"body_json"] options:0 error:NULL];
            if (![req valueForHTTPHeaderField:@"Content-Type"]) {
                [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
            }
        }

        BOOL useShared = a[@"use_shared_session"] ? [a[@"use_shared_session"] boolValue] : YES;
        NSURLSession *session = useShared ? [NSURLSession sharedSession] : [MCPCapURLProtocol forwardingSession];

        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        __block NSData *respData = nil;
        __block NSURLResponse *respObj = nil;
        __block NSError *respErr = nil;
        CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();

        NSURLSessionDataTask *task = [session dataTaskWithRequest:req
                                                completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            respData = data;
            respObj = response;
            respErr = error;
            dispatch_semaphore_signal(sem);
        }];
        [task resume];

        long waitRes = dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)((timeoutSec + 1.0) * NSEC_PER_SEC)));
        double durationMs = (CFAbsoluteTimeGetCurrent() - start) * 1000.0;
        if (waitRes != 0) {
            [task cancel];
            return @{
                @"error": @"replay_request timed out",
                @"url": urlStr,
                @"method": method,
                @"duration_ms": @(round(durationMs * 100.0) / 100.0)
            };
        }

        NSInteger statusCode = 0;
        NSDictionary *respHeaders = @{};
        if ([respObj isKindOfClass:[NSHTTPURLResponse class]]) {
            NSHTTPURLResponse *httpResp = (NSHTTPURLResponse *)respObj;
            statusCode = httpResp.statusCode;
            respHeaders = MCPCapSanitizeHeaders(httpResp.allHeaderFields);
        }

        id parsedJson = [NSNull null];
        if (respData.length > 0) {
            id obj = [NSJSONSerialization JSONObjectWithData:respData options:0 error:NULL];
            if (obj) parsedJson = obj;
        }

        return @{
            @"replayed_in_process": @YES,
            @"pid": @(getpid()),
            @"tls_stack": @"CFNetwork+libboringssl.dylib (native app JA3/JA4 & HTTP/2 SETTINGS)",
            @"session": useShared ? @"NSURLSession.sharedSession" : @"ephemeral",
            @"url": respObj.URL.absoluteString ?: urlStr,
            @"method": method,
            @"status_code": @(statusCode),
            @"duration_ms": @(round(durationMs * 100.0) / 100.0),
            @"response_headers": respHeaders,
            @"response_bytes": @(respData.length),
            @"response_body": MCPCapEncodeBodyPreview(respData),
            @"response_json": parsedJson,
            @"error": respErr ? (respErr.localizedDescription ?: @"request failed") : [NSNull null]
        };
    }

    if ([op isEqualToString:@"engine.get_requests"]) {
        NSUInteger limit = MELimit(a, @"limit", 100, 2000);
        NSString *hostFilter = [a[@"host_filter"] isKindOfClass:[NSString class]] ? [a[@"host_filter"] lowercaseString] : nil;
        NSString *urlFilter = [a[@"url_filter"] isKindOfClass:[NSString class]] ? [a[@"url_filter"] lowercaseString] : nil;
        NSString *methodFilter = [a[@"method_filter"] isKindOfClass:[NSString class]] ? [a[@"method_filter"] uppercaseString] : nil;
        BOOL clearAfter = [a[@"clear"] boolValue];

        NSMutableArray<NSDictionary *> *combined = [NSMutableArray array];
        [combined addObjectsFromArray:MCPCapReadRecordsFromFile(MCPCapPrimaryLogPath())];
        [combined addObjectsFromArray:MCPCapReadRecordsFromFile(MCPCapLegacyLogPath())];

        // Deduplicate by (source, id, url, method) and prefer rich nsurlsession entries over boringssl/task entries
        NSMutableArray<NSDictionary *> *deduped = [NSMutableArray array];
        NSMutableSet<NSString *> *seenKeys = [NSMutableSet set];
        NSMutableSet<NSString *> *richURLMethods = [NSMutableSet set];

        for (NSDictionary *rec in combined) {
            NSString *src = rec[@"source"] ?: @"nsurlsession";
            if ([src isEqualToString:@"nsurlsession"]) {
                NSString *um = [NSString stringWithFormat:@"%@|%@", rec[@"method"] ?: @"", rec[@"url"] ?: @""];
                [richURLMethods addObject:um];
            }
        }

        for (NSDictionary *rec in combined) {
            NSString *src = rec[@"source"] ?: @"nsurlsession";
            NSString *um = [NSString stringWithFormat:@"%@|%@", rec[@"method"] ?: @"", rec[@"url"] ?: @""];
            if (![src isEqualToString:@"nsurlsession"] && [richURLMethods containsObject:um]) {
                continue;
            }
            NSString *key = [NSString stringWithFormat:@"%@|%@|%@|%@",
                             src, rec[@"id"] ?: @0, rec[@"method"] ?: @"", rec[@"url"] ?: @""];
            if ([seenKeys containsObject:key]) continue;
            [seenKeys addObject:key];
            [deduped addObject:rec];
        }

        NSMutableArray<NSDictionary *> *filtered = [NSMutableArray array];
        for (NSDictionary *rec in deduped) {
            if (hostFilter.length) {
                NSString *h = [rec[@"host"] isKindOfClass:[NSString class]] ? [rec[@"host"] lowercaseString] : @"";
                if (![h containsString:hostFilter]) continue;
            }
            if (urlFilter.length) {
                NSString *u = [rec[@"url"] isKindOfClass:[NSString class]] ? [rec[@"url"] lowercaseString] : @"";
                if (![u containsString:urlFilter]) continue;
            }
            if (methodFilter.length) {
                NSString *m = [rec[@"method"] isKindOfClass:[NSString class]] ? [rec[@"method"] uppercaseString] : @"";
                if (![m isEqualToString:methodFilter]) continue;
            }
            [filtered addObject:rec];
        }

        if (filtered.count > limit) {
            filtered = [[filtered subarrayWithRange:NSMakeRange(filtered.count - limit, limit)] mutableCopy];
        }

        if (clearAfter) {
            int fd1 = open(MCPCapPrimaryLogPath().fileSystemRepresentation, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
            if (fd1 >= 0) close(fd1);
            int fd2 = open(MCPCapLegacyLogPath().fileSystemRepresentation, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
            if (fd2 >= 0) close(fd2);
        }

        return @{
            @"capturing": @(atomic_load(&g_mcpcap_active) ? YES : NO),
            @"count": @(filtered.count),
            @"total_captured": @(deduped.count),
            @"log_path": MCPCapPrimaryLogPath(),
            @"requests": filtered
        };
    }

    if ([op isEqualToString:@"engine.stop_capture"]) {
        atomic_store(&g_mcpcap_active, 0);
        NSMutableArray<NSDictionary *> *restoreSlots = [NSMutableArray array];
        NSUInteger restoredInProc = 0;
        @synchronized(g_mcpcap_lock) {
            for (NSDictionary *slotDict in g_mcpcap_bound_slots) {
                uintptr_t slotAddr = MEWord(slotDict[@"slot_address"]);
                uintptr_t origVal = MEWord(slotDict[@"original_value"]);
                if (!slotAddr || !origVal) continue;
                if (mcp_write_raw_slot_in_proc(slotAddr, origVal)) {
                    restoredInProc++;
                } else {
                    [restoreSlots addObject:@{
                        @"slot_address": slotDict[@"slot_address"] ?: @"0x0",
                        @"original_value": slotDict[@"original_value"] ?: @"0x0",
                        @"bytes_base64": slotDict[@"original_bytes_base64"] ?: @""
                    }];
                }
            }
        }
        return @{
            @"capturing": @NO,
            @"stopped": @YES,
            @"restored_in_proc": @(restoredInProc),
            @"restore_slots": restoreSlots
        };
    }

    return nil;
}

__attribute__((constructor))
static void MENetCapAutoInit(void) {
    @autoreleasepool {
        NSString *cfg = [NSTemporaryDirectory() stringByAppendingPathComponent:@".mcpe_cfg.json"];
        if (access(cfg.fileSystemRepresentation, R_OK) == 0) {
            MCPCapInitLock();
            atomic_store(&g_mcpcap_active, 1);
            MCPCapInstallObjCHooksOnce();
        }
    }
}

