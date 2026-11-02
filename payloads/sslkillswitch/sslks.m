#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <Security/SecureTransport.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <stdatomic.h>
#import "fishhook.h"

// Network.framework BoringSSL verify block types from <Security/SecProtocolOptions.h>
typedef void (^mcp_sec_protocol_verify_complete_t)(bool result);
typedef void (^mcp_sec_protocol_verify_t)(id metadata, id trust_ref, mcp_sec_protocol_verify_complete_t complete);

static const struct mach_header *g_sslks_self_header = NULL;
static _Atomic uint64_t g_sslks_bypass_count = 0;

static OSStatus (*orig_SecTrustEvaluate)(SecTrustRef trust, SecTrustResultType *result) = NULL;
static bool (*orig_SecTrustEvaluateWithError)(SecTrustRef trust, CFErrorRef *error) = NULL;
static OSStatus (*orig_SecTrustEvaluateAsync)(SecTrustRef trust, dispatch_queue_t queue, SecTrustCallback result) = NULL;
static OSStatus (*orig_SecTrustEvaluateAsyncWithError)(SecTrustRef trust, dispatch_queue_t queue, SecTrustWithErrorCallback result) = NULL;
static OSStatus (*orig_SSLHandshake)(SSLContextRef context) = NULL;
static OSStatus (*orig_SSLSetSessionOption)(SSLContextRef context, SSLSessionOption option, Boolean value) = NULL;
static void (*orig_sec_protocol_options_set_verify_block)(id options, mcp_sec_protocol_verify_t verify_block, dispatch_queue_t queue) = NULL;

static void mcp_sslks_record_bypass(const char *api) {
    uint64_t count = atomic_fetch_add(&g_sslks_bypass_count, 1) + 1;
    if (count == 1 || (count % 10) == 0) {
        NSString *statusPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@".mcp_sslks_status.json"];
        NSDictionary *doc = @{
            @"active": @YES,
            @"pid": @(getpid()),
            @"bypass_count": @(count),
            @"last_api": [NSString stringWithUTF8String:(api ?: "unknown")] ?: @"unknown",
            @"timestamp": @([[NSDate date] timeIntervalSince1970])
        };
        NSData *json = [NSJSONSerialization dataWithJSONObject:doc options:0 error:NULL];
        [json writeToFile:statusPath options:NSDataWritingAtomic error:NULL];
    }
}

static OSStatus hook_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result) {
    (void)trust;
    if (result) {
        *result = kSecTrustResultProceed;
    }
    mcp_sslks_record_bypass("SecTrustEvaluate");
    return errSecSuccess;
}

static bool hook_SecTrustEvaluateWithError(SecTrustRef trust, CFErrorRef *error) {
    (void)trust;
    if (error) {
        *error = NULL;
    }
    mcp_sslks_record_bypass("SecTrustEvaluateWithError");
    return true;
}

static OSStatus hook_SecTrustEvaluateAsync(SecTrustRef trust, dispatch_queue_t queue, SecTrustCallback result) {
    mcp_sslks_record_bypass("SecTrustEvaluateAsync");
    if (result) {
        dispatch_queue_t q = queue ?: dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
        dispatch_async(q, ^{
            result(trust, kSecTrustResultProceed);
        });
    }
    return errSecSuccess;
}

static OSStatus hook_SecTrustEvaluateAsyncWithError(SecTrustRef trust, dispatch_queue_t queue, SecTrustWithErrorCallback result) {
    mcp_sslks_record_bypass("SecTrustEvaluateAsyncWithError");
    if (result) {
        dispatch_queue_t q = queue ?: dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
        dispatch_async(q, ^{
            result(trust, true, NULL);
        });
    }
    return errSecSuccess;
}

static OSStatus hook_SSLSetSessionOption(SSLContextRef context, SSLSessionOption option, Boolean value) {
    if (option == kSSLSessionOptionBreakOnServerAuth) {
        mcp_sslks_record_bypass("SSLSetSessionOption");
        return noErr;
    }
    if (orig_SSLSetSessionOption) {
        return orig_SSLSetSessionOption(context, option, value);
    }
    return noErr;
}

static OSStatus hook_SSLHandshake(SSLContextRef context) {
    if (!orig_SSLHandshake) return noErr;
    OSStatus status = orig_SSLHandshake(context);
    if (status == errSSLServerAuthCompleted) {
        mcp_sslks_record_bypass("SSLHandshake");
        return orig_SSLHandshake(context);
    }
    return status;
}

static void hook_sec_protocol_options_set_verify_block(id options,
                                                       mcp_sec_protocol_verify_t verify_block,
                                                       dispatch_queue_t queue) {
    (void)verify_block;
    if (!orig_sec_protocol_options_set_verify_block) return;
    mcp_sec_protocol_verify_t allow_all = ^(id metadata, id trust_ref, mcp_sec_protocol_verify_complete_t complete) {
        (void)metadata;
        (void)trust_ref;
        mcp_sslks_record_bypass("sec_protocol_options_set_verify_block");
        if (complete) complete(true);
    };
    orig_sec_protocol_options_set_verify_block(options, allow_all, queue);
}

#pragma mark - NSURLSession ServerTrust Challenge Bypass Proxy

@interface MCPSSLBypassDelegateProxy : NSObject <NSURLSessionDelegate, NSURLSessionTaskDelegate>
@property (nonatomic, strong, nullable) id realDelegate;
@end

@implementation MCPSSLBypassDelegateProxy

- (BOOL)respondsToSelector:(SEL)aSelector {
    if (aSelector == @selector(URLSession:didReceiveChallenge:completionHandler:)) {
        return YES;
    }
    if (self.realDelegate && [self.realDelegate respondsToSelector:aSelector]) {
        return YES;
    }
    return [super respondsToSelector:aSelector];
}

- (id)forwardingTargetForSelector:(SEL)aSelector {
    if (self.realDelegate && [self.realDelegate respondsToSelector:aSelector]) {
        return self.realDelegate;
    }
    return [super forwardingTargetForSelector:aSelector];
}

- (NSMethodSignature *)methodSignatureForSelector:(SEL)sel {
    NSMethodSignature *sig = [super methodSignatureForSelector:sel];
    if (!sig && self.realDelegate) {
        sig = [self.realDelegate methodSignatureForSelector:sel];
    }
    return sig ?: [NSMethodSignature signatureWithObjCTypes:"v@:"];
}

- (void)forwardInvocation:(NSInvocation *)invocation {
    if (self.realDelegate && [self.realDelegate respondsToSelector:invocation.selector]) {
        [invocation invokeWithTarget:self.realDelegate];
    }
}

- (void)URLSession:(NSURLSession *)session
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable))completionHandler {
    if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust] &&
        challenge.protectionSpace.serverTrust != NULL) {
        mcp_sslks_record_bypass("NSURLSession:didReceiveChallenge");
        NSURLCredential *cred = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
        if (completionHandler) {
            completionHandler(NSURLSessionAuthChallengeUseCredential, cred);
        }
        return;
    }
    if (self.realDelegate && [self.realDelegate respondsToSelector:@selector(URLSession:didReceiveChallenge:completionHandler:)]) {
        [self.realDelegate URLSession:session didReceiveChallenge:challenge completionHandler:completionHandler];
        return;
    }
    if (completionHandler) {
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
    }
}

- (void)URLSession:(NSURLSession *)session
              task:(NSURLSessionTask *)task
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable))completionHandler {
    if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust] &&
        challenge.protectionSpace.serverTrust != NULL) {
        mcp_sslks_record_bypass("NSURLSession:task:didReceiveChallenge");
        NSURLCredential *cred = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
        if (completionHandler) {
            completionHandler(NSURLSessionAuthChallengeUseCredential, cred);
        }
        return;
    }
    if (self.realDelegate && [self.realDelegate respondsToSelector:@selector(URLSession:task:didReceiveChallenge:completionHandler:)]) {
        [self.realDelegate URLSession:session task:task didReceiveChallenge:challenge completionHandler:completionHandler];
        return;
    }
    if (completionHandler) {
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
    }
}

@end

static NSURLSession *(*orig_sessionWithConfig)(id self, SEL _cmd, NSURLSessionConfiguration *cfg, id<NSURLSessionDelegate> delegate, NSOperationQueue *queue) = NULL;

static NSURLSession *swizzled_sessionWithConfig(id self, SEL _cmd, NSURLSessionConfiguration *cfg, id<NSURLSessionDelegate> delegate, NSOperationQueue *queue) {
    id<NSURLSessionDelegate> effectiveDelegate = delegate;
    if (![delegate isKindOfClass:[MCPSSLBypassDelegateProxy class]]) {
        MCPSSLBypassDelegateProxy *proxy = [[MCPSSLBypassDelegateProxy alloc] init];
        proxy.realDelegate = delegate;
        effectiveDelegate = proxy;
    }
    return orig_sessionWithConfig(self, _cmd, cfg, effectiveDelegate, queue);
}

static int mcp_sslks_should_hook_image(const struct mach_header *hdr, const char *name) {
    if (!hdr || hdr == g_sslks_self_header) return 0;
    if (hdr->filetype == MH_EXECUTE) return 1;
    if (!name) return 0;
    if (strstr(name, "/System/") == NULL && strstr(name, "/usr/lib/") == NULL) {
        return 1;
    }
    if (strstr(name, "CFNetwork") != NULL || strstr(name, "libnetwork") != NULL) {
        return 1;
    }
    return 0;
}

static void mcp_sslks_on_image_added(const struct mach_header *hdr, intptr_t slide) {
    if (!hdr || hdr == g_sslks_self_header) return;
    Dl_info info;
    const char *name = (dladdr(hdr, &info) && info.dli_fname) ? info.dli_fname : NULL;
    if (!mcp_sslks_should_hook_image(hdr, name)) return;

    struct mcp_rebinding rebindings[] = {
        {"SecTrustEvaluate", (void *)hook_SecTrustEvaluate, (void **)&orig_SecTrustEvaluate},
        {"SecTrustEvaluateWithError", (void *)hook_SecTrustEvaluateWithError, (void **)&orig_SecTrustEvaluateWithError},
        {"SecTrustEvaluateAsync", (void *)hook_SecTrustEvaluateAsync, (void **)&orig_SecTrustEvaluateAsync},
        {"SecTrustEvaluateAsyncWithError", (void *)hook_SecTrustEvaluateAsyncWithError, (void **)&orig_SecTrustEvaluateAsyncWithError},
        {"SSLSetSessionOption", (void *)hook_SSLSetSessionOption, (void **)&orig_SSLSetSessionOption},
        {"SSLHandshake", (void *)hook_SSLHandshake, (void **)&orig_SSLHandshake},
        {"sec_protocol_options_set_verify_block", (void *)hook_sec_protocol_options_set_verify_block, (void **)&orig_sec_protocol_options_set_verify_block},
    };
    mcp_rebind_symbols_image(hdr, slide, g_sslks_self_header, rebindings, sizeof(rebindings) / sizeof(rebindings[0]));
}

__attribute__((constructor))
static void mcp_sslks_init(void) {
    @autoreleasepool {
        Dl_info selfInfo;
        if (dladdr((const void *)&mcp_sslks_init, &selfInfo) && selfInfo.dli_fbase) {
            g_sslks_self_header = (const struct mach_header *)selfInfo.dli_fbase;
        }

        Class sessionMeta = object_getClass([NSURLSession class]);
        SEL sel = @selector(sessionWithConfiguration:delegate:delegateQueue:);
        Method m = class_getClassMethod([NSURLSession class], sel);
        if (m && sessionMeta) {
            orig_sessionWithConfig = (typeof(orig_sessionWithConfig))method_setImplementation(m, (IMP)swizzled_sessionWithConfig);
        }

        _dyld_register_func_for_add_image(mcp_sslks_on_image_added);

        NSString *statusPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@".mcp_sslks_status.json"];
        NSDictionary *doc = @{
            @"active": @YES,
            @"pid": @(getpid()),
            @"bypass_count": @0,
            @"timestamp": @([[NSDate date] timeIntervalSince1970])
        };
        NSData *json = [NSJSONSerialization dataWithJSONObject:doc options:0 error:NULL];
        [json writeToFile:statusPath options:NSDataWritingAtomic error:NULL];
    }
}
