#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include "fishhook.h"
#include <dlfcn.h>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <stdatomic.h>
#include <string.h>
#include <unistd.h>

static NSString *const kMCPNetCapHandledKey = @"com.iosmcp.netcap.handled";
static NSString *const kMCPNetCapTaskTrackedKey = @"com.iosmcp.netcap.task_tracked";
static const NSUInteger kMCPNetCapBodyPreviewLimit = 4096;
static _Atomic uint64_t g_netcap_req_seq = 0;
static const struct mach_header *g_netcap_self_header = NULL;

static dispatch_queue_t MCPNetCapLogQueue(void) {
    static dispatch_queue_t q = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        q = dispatch_queue_create("com.iosmcp.netcap.logger", DISPATCH_QUEUE_SERIAL);
    });
    return q;
}

static NSString *MCPNetCapLogFilePath(void) {
    return [NSTemporaryDirectory() stringByAppendingPathComponent:@".mcp_netcap.jsonl"];
}

static NSString *MCPNetCapPrimaryLogFilePath(void) {
    return [NSTemporaryDirectory() stringByAppendingPathComponent:@".mcpcap.jsonl"];
}

static NSDictionary *MCPNetCapSanitizeHeaders(NSDictionary *headers) {
    if (![headers isKindOfClass:[NSDictionary class]]) return @{};
    NSMutableDictionary *clean = [NSMutableDictionary dictionaryWithCapacity:headers.count];
    for (id k in headers) {
        id v = headers[k];
        clean[[k description] ?: @""] = [v description] ?: @"";
    }
    return clean;
}

static NSDictionary *MCPNetCapEncodeBodyPreview(NSData *data) {
    if (!data || data.length == 0) {
        return @{@"size": @0, @"encoding": @"utf8", @"preview": @"", @"truncated": @NO};
    }
    BOOL truncated = data.length > kMCPNetCapBodyPreviewLimit;
    NSData *slice = truncated ? [data subdataWithRange:NSMakeRange(0, kMCPNetCapBodyPreviewLimit)] : data;
    NSString *utf8 = [[NSString alloc] initWithData:slice encoding:NSUTF8StringEncoding];
    if (utf8) {
        return @{
            @"size": @(data.length),
            @"encoding": @"utf8",
            @"preview": utf8,
            @"truncated": @(truncated)
        };
    }
    return @{
        @"size": @(data.length),
        @"encoding": @"base64",
        @"preview": [slice base64EncodedStringWithOptions:0] ?: @"",
        @"truncated": @(truncated)
    };
}

static NSData *MCPNetCapReadRequestBody(NSURLRequest *request) {
    if (request.HTTPBody.length > 0) {
        return request.HTTPBody;
    }
    if (!request.HTTPBodyStream) {
        return nil;
    }
    NSInputStream *stream = [request.HTTPBodyStream copy];
    if (!stream) return nil;
    NSMutableData *buf = [NSMutableData data];
    [stream open];
    uint8_t chunk[2048];
    while (stream.hasBytesAvailable && buf.length < kMCPNetCapBodyPreviewLimit + 1) {
        NSInteger n = [stream read:chunk maxLength:sizeof(chunk)];
        if (n <= 0) break;
        [buf appendBytes:chunk length:(NSUInteger)n];
    }
    [stream close];
    return buf;
}

static void MCPNetCapWriteLineToFile(NSString *path, NSData *json) {
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

static void MCPNetCapAppendRecord(NSDictionary *record) {
    if (![record isKindOfClass:[NSDictionary class]]) return;
    NSData *json = [NSJSONSerialization dataWithJSONObject:record options:0 error:NULL];
    if (!json.length) return;
    dispatch_async(MCPNetCapLogQueue(), ^{
        MCPNetCapWriteLineToFile(MCPNetCapLogFilePath(), json);
        MCPNetCapWriteLineToFile(MCPNetCapPrimaryLogFilePath(), json);
    });
}

@interface MCPNetCapURLProtocol : NSURLProtocol <NSURLSessionDataDelegate>
@property (nonatomic, strong) NSURLSessionDataTask *forwardTask;
@property (nonatomic, strong) NSMutableData *receivedData;
@property (nonatomic, strong) NSURLResponse *capturedResponse;
@property (nonatomic, assign) CFAbsoluteTime startTime;
@property (nonatomic, assign) uint64_t sequenceId;
@property (nonatomic, strong) NSData *capturedReqBody;
@end

static NSURLSessionConfiguration *(*orig_defaultSessionConfig)(id self, SEL _cmd) = NULL;
static NSURLSessionConfiguration *(*orig_ephemeralSessionConfig)(id self, SEL _cmd) = NULL;
static NSArray<Class> *(*orig_netcap_protocolClasses)(id self, SEL _cmd) = NULL;
static NSURLSession *(*orig_netcap_sessionWithConfig)(id self, SEL _cmd, NSURLSessionConfiguration *cfg, id delegate, NSOperationQueue *queue) = NULL;
static NSURLSession *(*orig_netcap_sessionWithConfigOnly)(id self, SEL _cmd, NSURLSessionConfiguration *cfg) = NULL;
static NSURLSession *(*orig_sharedSession)(id self, SEL _cmd) = NULL;
static void (*orig_netcap_taskResume)(id self, SEL _cmd) = NULL;

@implementation MCPNetCapURLProtocol

+ (NSURLSession *)forwardingSession {
    static NSURLSession *s = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSURLSessionConfiguration *cfg = orig_ephemeralSessionConfig
            ? orig_ephemeralSessionConfig([NSURLSessionConfiguration class], @selector(ephemeralSessionConfiguration))
            : [NSURLSessionConfiguration ephemeralSessionConfiguration];
        NSMutableArray *protos = [NSMutableArray array];
        for (Class cls in (cfg.protocolClasses ?: @[])) {
            if (cls != [MCPNetCapURLProtocol class] && ![NSStringFromClass(cls) containsString:@"MCPCapURLProtocol"]) {
                [protos addObject:cls];
            }
        }
        cfg.protocolClasses = protos;
        s = orig_netcap_sessionWithConfig
            ? orig_netcap_sessionWithConfig([NSURLSession class],
                                            @selector(sessionWithConfiguration:delegate:delegateQueue:),
                                            cfg, nil, nil)
            : [NSURLSession sessionWithConfiguration:cfg];
    });
    return s;
}

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    if (!request.URL) return NO;
    NSString *scheme = request.URL.scheme.lowercaseString;
    if (![scheme isEqualToString:@"http"] && ![scheme isEqualToString:@"https"]) {
        return NO;
    }
    if ([[NSURLProtocol propertyForKey:kMCPNetCapHandledKey inRequest:request] boolValue]) {
        return NO;
    }
    return YES;
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request {
    return request;
}

- (void)startLoading {
    self.startTime = CFAbsoluteTimeGetCurrent();
    self.sequenceId = atomic_fetch_add(&g_netcap_req_seq, 1) + 1;
    self.receivedData = [NSMutableData data];
    self.capturedReqBody = MCPNetCapReadRequestBody(self.request);

    NSMutableURLRequest *forwardReq = [self.request mutableCopy];
    [NSURLProtocol setProperty:@YES forKey:kMCPNetCapHandledKey inRequest:forwardReq];

    __weak typeof(self) weakSelf = self;
    self.forwardTask = [[MCPNetCapURLProtocol forwardingSession]
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
            respHeaders = MCPNetCapSanitizeHeaders(httpResp.allHeaderFields);
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
        NSDictionary *reqPreview = MCPNetCapEncodeBodyPreview(strongSelf.capturedReqBody);
        NSDictionary *respPreview = MCPNetCapEncodeBodyPreview(data);

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
            @"request_headers": MCPNetCapSanitizeHeaders(strongSelf.request.allHTTPHeaderFields),
            @"request_body": reqPreview,
            @"status_code": @(statusCode),
            @"mime_type": response.MIMEType ?: @"",
            @"response_headers": respHeaders,
            @"response_bytes": @(data.length),
            @"response_body": respPreview,
            @"error": error ? (error.localizedDescription ?: @"request error") : [NSNull null]
        };
        MCPNetCapAppendRecord(record);
    }];
    [self.forwardTask resume];
}

- (void)stopLoading {
    [self.forwardTask cancel];
    self.forwardTask = nil;
}

@end

static void MCPNetCapInjectProtocolIntoConfig(NSURLSessionConfiguration *cfg) {
    if (!cfg) return;
    NSArray *existing = orig_netcap_protocolClasses
        ? orig_netcap_protocolClasses(cfg, @selector(protocolClasses))
        : (cfg.protocolClasses ?: @[]);
    if (existing.firstObject == [MCPNetCapURLProtocol class]) return;
    NSMutableArray *updated = [NSMutableArray arrayWithObject:[MCPNetCapURLProtocol class]];
    for (Class cls in existing) {
        if (cls != [MCPNetCapURLProtocol class]) {
            [updated addObject:cls];
        }
    }
    cfg.protocolClasses = updated;
}

static NSURLSessionConfiguration *swizzled_defaultSessionConfig(id self, SEL _cmd) {
    NSURLSessionConfiguration *cfg = orig_defaultSessionConfig(self, _cmd);
    MCPNetCapInjectProtocolIntoConfig(cfg);
    return cfg;
}

static NSURLSessionConfiguration *swizzled_ephemeralSessionConfig(id self, SEL _cmd) {
    NSURLSessionConfiguration *cfg = orig_ephemeralSessionConfig(self, _cmd);
    MCPNetCapInjectProtocolIntoConfig(cfg);
    return cfg;
}

static NSArray<Class> *swizzled_netcap_protocolClasses(id self, SEL _cmd) {
    NSArray<Class> *orig = orig_netcap_protocolClasses ? orig_netcap_protocolClasses(self, _cmd) : @[];
    if (orig.firstObject == [MCPNetCapURLProtocol class]) return orig;
    NSMutableArray<Class> *arr = [NSMutableArray arrayWithObject:[MCPNetCapURLProtocol class]];
    if (orig) [arr addObjectsFromArray:orig];
    return arr;
}

static NSURLSession *swizzled_netcap_sessionWithConfig(id self, SEL _cmd, NSURLSessionConfiguration *cfg, id delegate, NSOperationQueue *queue) {
    MCPNetCapInjectProtocolIntoConfig(cfg);
    return orig_netcap_sessionWithConfig(self, _cmd, cfg, delegate, queue);
}

static NSURLSession *swizzled_netcap_sessionWithConfigOnly(id self, SEL _cmd, NSURLSessionConfiguration *cfg) {
    MCPNetCapInjectProtocolIntoConfig(cfg);
    return orig_netcap_sessionWithConfigOnly(self, _cmd, cfg);
}

static NSURLSession *swizzled_sharedSession(id self, SEL _cmd) {
    static NSURLSession *interceptedShared = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration defaultSessionConfiguration];
        MCPNetCapInjectProtocolIntoConfig(cfg);
        interceptedShared = orig_netcap_sessionWithConfig
            ? orig_netcap_sessionWithConfig(self, @selector(sessionWithConfiguration:delegate:delegateQueue:), cfg, nil, nil)
            : [NSURLSession sessionWithConfiguration:cfg];
    });
    return interceptedShared ?: orig_sharedSession(self, _cmd);
}

static int (*orig_netcap_SSL_write)(void *ssl, const void *buf, int num) = NULL;
static int (*orig_netcap_SSL_read)(void *ssl, void *buf, int num) = NULL;
static const char *(*fn_netcap_SSL_get_servername)(const void *ssl, int type) = NULL;

static int hook_netcap_SSL_write(void *ssl, const void *buf, int num) {
    int ret = orig_netcap_SSL_write ? orig_netcap_SSL_write(ssl, buf, num) : -1;
    if (ret > 0 && buf) {
        const char *cbuf = (const char *)buf;
        if (ret >= 5 && (memcmp(cbuf, "GET ", 4) == 0 || memcmp(cbuf, "POST ", 5) == 0 ||
                         memcmp(cbuf, "PUT ", 4) == 0 || memcmp(cbuf, "DELETE ", 7) == 0)) {
            const char *sni = (fn_netcap_SSL_get_servername && ssl) ? fn_netcap_SSL_get_servername(ssl, 0) : NULL;
            NSString *host = (sni && *sni) ? @(sni) : @"";
            uint64_t seq = atomic_fetch_add(&g_netcap_req_seq, 1) + 1;
            NSData *slice = [NSData dataWithBytes:buf length:(NSUInteger)(ret > 512 ? 512 : ret)];
            NSDictionary *rec = @{
                @"id": @(seq),
                @"pid": @(getpid()),
                @"source": @"boringssl",
                @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                @"duration_ms": @0,
                @"method": (memcmp(cbuf, "POST ", 5) == 0) ? @"POST" : @"GET",
                @"url": host.length ? [NSString stringWithFormat:@"https://%@/", host] : @"https://tls/",
                @"scheme": @"https",
                @"host": host,
                @"path": @"/",
                @"request_headers": @{},
                @"request_body": MCPNetCapEncodeBodyPreview(slice),
                @"status_code": @200,
                @"mime_type": @"",
                @"response_headers": @{},
                @"response_bytes": @0,
                @"response_body": @{@"size": @0, @"encoding": @"utf8", @"preview": @"", @"truncated": @NO},
                @"error": [NSNull null]
            };
            MCPNetCapAppendRecord(rec);
        }
    }
    return ret;
}

static int hook_netcap_SSL_read(void *ssl, void *buf, int num) {
    return orig_netcap_SSL_read ? orig_netcap_SSL_read(ssl, buf, num) : -1;
}

static int mcp_netcap_should_hook_image(const struct mach_header *hdr, const char *name) {
    if (!hdr || !name || hdr == g_netcap_self_header) return 0;
    if (strstr(name, "libApple") || strstr(name, "libmcp") || strstr(name, "systemhook")) return 0;
    if (!strstr(name, "/System/Library/") && !strstr(name, "/usr/lib/") && !strstr(name, "/Developer/")) return 1;
    if (strstr(name, "CFNetwork") || strstr(name, "libnetwork.dylib") || strstr(name, "libboringssl.dylib")) return 1;
    return 0;
}

__attribute__((constructor))
static void mcp_netcap_init(void) {
    @autoreleasepool {
        Dl_info info = {0};
        if (dladdr((const void *)&mcp_netcap_init, &info)) {
            g_netcap_self_header = (const struct mach_header *)info.dli_fbase;
        }
        [NSURLProtocol registerClass:[MCPNetCapURLProtocol class]];

        Method mDef = class_getClassMethod([NSURLSessionConfiguration class], @selector(defaultSessionConfiguration));
        if (mDef) {
            orig_defaultSessionConfig = (typeof(orig_defaultSessionConfig))method_setImplementation(mDef, (IMP)swizzled_defaultSessionConfig);
        }
        Method mEph = class_getClassMethod([NSURLSessionConfiguration class], @selector(ephemeralSessionConfiguration));
        if (mEph) {
            orig_ephemeralSessionConfig = (typeof(orig_ephemeralSessionConfig))method_setImplementation(mEph, (IMP)swizzled_ephemeralSessionConfig);
        }
        Method mProto = class_getInstanceMethod([NSURLSessionConfiguration class], @selector(protocolClasses));
        if (mProto) {
            orig_netcap_protocolClasses = (typeof(orig_netcap_protocolClasses))method_setImplementation(mProto, (IMP)swizzled_netcap_protocolClasses);
        }
        Method mSess = class_getClassMethod([NSURLSession class], @selector(sessionWithConfiguration:delegate:delegateQueue:));
        if (mSess) {
            orig_netcap_sessionWithConfig = (typeof(orig_netcap_sessionWithConfig))method_setImplementation(mSess, (IMP)swizzled_netcap_sessionWithConfig);
        }
        Method mSessOnly = class_getClassMethod([NSURLSession class], @selector(sessionWithConfiguration:));
        if (mSessOnly) {
            orig_netcap_sessionWithConfigOnly = (typeof(orig_netcap_sessionWithConfigOnly))method_setImplementation(mSessOnly, (IMP)swizzled_netcap_sessionWithConfigOnly);
        }
        Method mShared = class_getClassMethod([NSURLSession class], @selector(sharedSession));
        if (mShared) {
            orig_sharedSession = (typeof(orig_sharedSession))method_setImplementation(mShared, (IMP)swizzled_sharedSession);
        }

        void *boring = dlopen("/usr/lib/libboringssl.dylib", RTLD_LAZY | RTLD_NOLOAD);
        if (boring) {
            orig_netcap_SSL_write = dlsym(boring, "SSL_write");
            orig_netcap_SSL_read = dlsym(boring, "SSL_read");
            fn_netcap_SSL_get_servername = dlsym(boring, "SSL_get_servername");
        }
        struct mcp_rebinding rebs[] = {
            {"SSL_write", (void *)hook_netcap_SSL_write, (void **)&orig_netcap_SSL_write},
            {"SSL_read", (void *)hook_netcap_SSL_read, (void **)&orig_netcap_SSL_read}
        };
        mcp_rebind_symbols_filtered(g_netcap_self_header, mcp_netcap_should_hook_image, rebs, 2);

        // Touch the capture log files so NetworkCaptureManager can confirm constructor execution immediately
        int fd1 = open(MCPNetCapLogFilePath().fileSystemRepresentation, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
        if (fd1 >= 0) close(fd1);
        int fd2 = open(MCPNetCapPrimaryLogFilePath().fileSystemRepresentation, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
        if (fd2 >= 0) close(fd2);
    }
}
