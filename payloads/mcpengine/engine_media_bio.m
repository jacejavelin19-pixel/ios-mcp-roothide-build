#import "engine_rpc.h"
#include "fishhook.h"
#import <UIKit/UIKit.h>
#import <AVFoundation/AVFoundation.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <CoreImage/CoreImage.h>
#import <CoreLocation/CoreLocation.h>
#import <CoreMotion/CoreMotion.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <AuthenticationServices/AuthenticationServices.h>
#import <AudioToolbox/AudioToolbox.h>
#import <objc/runtime.h>
#import <objc/message.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <libkern/OSByteOrder.h>
#include <unistd.h>
#include <sys/stat.h>
#include <mach-o/dyld.h>

static NSObject *MEMBLock(void) {
    static NSObject *l;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ l = [NSObject new]; });
    return l;
}

static NSArray<NSDictionary *> *MEMBRebindAllImages(struct mcp_rebinding *bindings,
                                                    size_t count,
                                                    NSUInteger *outPatchedInProc) {
    NSMutableArray<NSDictionary *> *pending = [NSMutableArray array];
    NSUInteger patchedInProc = 0;
    const struct mach_header *selfHdr = MESelfHeader();
    uint32_t imgCount = _dyld_image_count();
    for (uint32_t i = 0; i < imgCount; i++) {
        const struct mach_header *hdr = _dyld_get_image_header(i);
        const char *name = _dyld_get_image_name(i);
        if (!hdr || !name || hdr == selfHdr) continue;
        if (strstr(name, "libmcp") != NULL || strstr(name, "libApple") != NULL) continue;
        int shouldHook = (hdr->filetype == MH_EXECUTE) ||
                         (strstr(name, "/System/") == NULL && strstr(name, "/usr/lib/") == NULL);
        if (!shouldHook) continue;
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        mcp_slot_collector_t col = {0};
        mcp_rebind_symbols_image_collect(hdr, slide, selfHdr, bindings, count, &col);
        NSString *imgName = @(name);
        for (size_t k = 0; k < col.count; k++) {
            const mcp_slot_patch_t *p = &col.patches[k];
            if (p->written_in_proc) {
                patchedInProc++;
            } else {
                uint64_t newLE = OSSwapHostToLittleInt64((uint64_t)p->new_val);
                uint64_t origLE = OSSwapHostToLittleInt64((uint64_t)p->orig_val);
                NSString *newB64 = [[NSData dataWithBytes:&newLE length:8] base64EncodedStringWithOptions:0];
                NSString *origB64 = [[NSData dataWithBytes:&origLE length:8] base64EncodedStringWithOptions:0];
                [pending addObject:@{
                    @"slot_address": MEHex(p->slot_addr),
                    @"original_value": MEHex(p->orig_val),
                    @"replacement_value": MEHex(p->new_val),
                    @"bytes_base64": newB64 ?: @"",
                    @"original_bytes_base64": origB64 ?: @"",
                    @"symbol": @(p->symbol_name),
                    @"section": @(p->section_name),
                    @"auth_got": @(p->is_auth ? YES : NO),
                    @"image": imgName
                }];
            }
        }
        mcp_slot_collector_free(&col);
    }
    if (outPatchedInProc) *outPatchedInProc = patchedInProc;
    return pending;
}

#pragma mark - [Upgrade 13] Virtual Camera & Microphone Stream Injector

static UIImage *g_virtual_camera_image = nil;
static NSData *g_virtual_mic_pcm = nil;
static NSUInteger g_virtual_mic_offset = 0;
static BOOL g_virtual_cam_active = NO;
static BOOL g_virtual_mic_active = NO;
static uint64_t g_virtual_cam_frames_fed = 0;

static CVPixelBufferRef MECreatePixelBufferFromImage(UIImage *img) {
    if (!img) return NULL;
    CGImageRef cg = img.CGImage;
    size_t w = cg ? CGImageGetWidth(cg) : (size_t)img.size.width;
    size_t h = cg ? CGImageGetHeight(cg) : (size_t)img.size.height;
    if (w == 0 || h == 0) { w = 640; h = 480; }
    NSDictionary *attrs = @{
        (id)kCVPixelBufferCGImageCompatibilityKey: @YES,
        (id)kCVPixelBufferCGBitmapContextCompatibilityKey: @YES,
        (id)kCVPixelBufferIOSurfacePropertiesKey: @{}
    };
    CVPixelBufferRef pb = NULL;
    if (CVPixelBufferCreate(kCFAllocatorDefault, w, h, kCVPixelFormatType_32BGRA, (__bridge CFDictionaryRef)attrs, &pb) != kCVReturnSuccess || !pb) {
        return NULL;
    }
    CVPixelBufferLockBaseAddress(pb, 0);
    void *base = CVPixelBufferGetBaseAddress(pb);
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGContextRef ctx = CGBitmapContextCreate(base, w, h, 8, CVPixelBufferGetBytesPerRow(pb), cs,
                                             kCGBitmapByteOrder32Little | kCGImageAlphaPremultipliedFirst);
    if (ctx) {
        if (cg) {
            CGContextDrawImage(ctx, CGRectMake(0, 0, w, h), cg);
        } else {
            UIGraphicsPushContext(ctx);
            [img drawInRect:CGRectMake(0, 0, w, h)];
            UIGraphicsPopContext();
        }
        CGContextRelease(ctx);
    }
    CGColorSpaceRelease(cs);
    CVPixelBufferUnlockBaseAddress(pb, 0);
    return pb;
}

static CMSampleBufferRef MECreateSampleBufferFromImage(UIImage *img) {
    CVPixelBufferRef pb = MECreatePixelBufferFromImage(img);
    if (!pb) return NULL;
    CMVideoFormatDescriptionRef fmt = NULL;
    CMVideoFormatDescriptionCreateForImageBuffer(kCFAllocatorDefault, pb, &fmt);
    if (!fmt) {
        CFRelease(pb);
        return NULL;
    }
    CMSampleTimingInfo timing = {
        .duration = CMTimeMake(1, 30),
        .presentationTimeStamp = CMClockGetTime(CMClockGetHostTimeClock()),
        .decodeTimeStamp = kCMTimeInvalid
    };
    CMSampleBufferRef sb = NULL;
    CMSampleBufferCreateReadyWithImageBuffer(kCFAllocatorDefault, pb, fmt, &timing, &sb);
    CFRelease(fmt);
    CFRelease(pb);
    return sb;
}

static UIImage *MEGenerateQRImage(NSString *qrText) {
    if (!qrText.length) return nil;
    CIFilter *filter = [CIFilter filterWithName:@"CIQRCodeGenerator"];
    if (!filter) return nil;
    [filter setDefaults];
    [filter setValue:[qrText dataUsingEncoding:NSUTF8StringEncoding] forKey:@"inputMessage"];
    [filter setValue:@"M" forKey:@"inputCorrectionLevel"];
    CIImage *ci = [filter outputImage];
    if (!ci) return nil;
    CIImage *scaled = [ci imageByApplyingTransform:CGAffineTransformMakeScale(12.0, 12.0)];
    CIContext *ctx = [CIContext contextWithOptions:nil];
    CGImageRef cg = [ctx createCGImage:scaled fromRect:scaled.extent];
    if (!cg) return nil;
    UIImage *out = [UIImage imageWithCGImage:cg];
    CGImageRelease(cg);
    return out;
}

static void (*orig_setSampleBufferDelegate)(id, SEL, id, dispatch_queue_t) = NULL;
static void hook_setSampleBufferDelegate(id self, SEL _cmd, id delegate, dispatch_queue_t queue) {
    if (orig_setSampleBufferDelegate) orig_setSampleBufferDelegate(self, _cmd, delegate, queue);
    if (g_virtual_cam_active && delegate && [delegate respondsToSelector:@selector(captureOutput:didOutputSampleBuffer:fromConnection:)]) {
        dispatch_queue_t q = queue ?: dispatch_get_main_queue();
        dispatch_async(q, ^{
            UIImage *img = nil;
            @synchronized(MEMBLock()) { img = g_virtual_camera_image; }
            if (!img) return;
            CMSampleBufferRef sb = MECreateSampleBufferFromImage(img);
            if (sb) {
                NSArray *conns = [self respondsToSelector:@selector(connections)] ? [self valueForKey:@"connections"] : nil;
                id conn = conns.firstObject;
                ((void (*)(id, SEL, id, CMSampleBufferRef, id))objc_msgSend)(
                    delegate, @selector(captureOutput:didOutputSampleBuffer:fromConnection:), self, sb, conn);
                g_virtual_cam_frames_fed++;
                CFRelease(sb);
            }
        });
    }
}

static OSStatus (*orig_AudioUnitRender)(AudioUnit inUnit,
                                        AudioUnitRenderActionFlags *ioActionFlags,
                                        const AudioTimeStamp *inTimeStamp,
                                        UInt32 inOutputBusNumber,
                                        UInt32 inNumberFrames,
                                        AudioBufferList *ioData) = NULL;
static OSStatus hook_AudioUnitRender(AudioUnit inUnit,
                                     AudioUnitRenderActionFlags *ioActionFlags,
                                     const AudioTimeStamp *inTimeStamp,
                                     UInt32 inOutputBusNumber,
                                     UInt32 inNumberFrames,
                                     AudioBufferList *ioData) {
    OSStatus st = orig_AudioUnitRender ? orig_AudioUnitRender(inUnit, ioActionFlags, inTimeStamp, inOutputBusNumber, inNumberFrames, ioData) : noErr;
    if (st == noErr && g_virtual_mic_active && ioData) {
        @synchronized(MEMBLock()) {
            if (g_virtual_mic_pcm.length > 0) {
                const uint8_t *pcm = g_virtual_mic_pcm.bytes;
                NSUInteger totalLen = g_virtual_mic_pcm.length;
                for (UInt32 i = 0; i < ioData->mNumberBuffers; i++) {
                    uint8_t *dst = (uint8_t *)ioData->mBuffers[i].mData;
                    UInt32 sz = ioData->mBuffers[i].mDataByteSize;
                    if (!dst || sz == 0) continue;
                    for (UInt32 b = 0; b < sz; b++) {
                        dst[b] = pcm[(g_virtual_mic_offset + b) % totalLen];
                    }
                    g_virtual_mic_offset = (g_virtual_mic_offset + sz) % totalLen;
                }
            }
        }
    }
    return st;
}

#pragma mark - [Upgrade 15] Biometric & Passkey Secure Enclave Vault

static NSString *g_biometric_mode = @"auto_pass";
static NSMutableArray<NSDictionary *> *g_biometric_events = nil;

static BOOL (*orig_LAContext_canEvaluatePolicy)(id, SEL, NSInteger, NSError **) = NULL;
static BOOL hook_LAContext_canEvaluatePolicy(id self, SEL _cmd, NSInteger policy, NSError **error) {
    if ([g_biometric_mode isEqualToString:@"auto_pass"]) {
        if (error) *error = nil;
        return YES;
    }
    if ([g_biometric_mode isEqualToString:@"auto_fail"]) {
        if (error) *error = [NSError errorWithDomain:LAErrorDomain code:LAErrorBiometryNotAvailable userInfo:nil];
        return NO;
    }
    return orig_LAContext_canEvaluatePolicy ? orig_LAContext_canEvaluatePolicy(self, _cmd, policy, error) : YES;
}

static void (*orig_LAContext_evaluatePolicy)(id, SEL, NSInteger, NSString *, void (^)(BOOL, NSError *)) = NULL;
static void hook_LAContext_evaluatePolicy(id self, SEL _cmd, NSInteger policy, NSString *reason, void (^reply)(BOOL, NSError *)) {
    @synchronized(MEMBLock()) {
        if (!g_biometric_events) g_biometric_events = [NSMutableArray array];
        [g_biometric_events addObject:@{
            @"type": @"LAContext.evaluatePolicy",
            @"policy": @(policy),
            @"reason": reason ?: @"",
            @"mode": g_biometric_mode ?: @"auto_pass",
            @"ts": @([[NSDate date] timeIntervalSince1970])
        }];
    }
    if ([g_biometric_mode isEqualToString:@"auto_pass"]) {
        if (reply) {
            dispatch_async(dispatch_get_main_queue(), ^{
                reply(YES, nil);
            });
        }
        return;
    }
    if ([g_biometric_mode isEqualToString:@"auto_fail"]) {
        if (reply) {
            dispatch_async(dispatch_get_main_queue(), ^{
                NSError *err = [NSError errorWithDomain:LAErrorDomain code:LAErrorAuthenticationFailed userInfo:@{NSLocalizedDescriptionKey: @"Biometric authentication failed"}];
                reply(NO, err);
            });
        }
        return;
    }
    if (orig_LAContext_evaluatePolicy) orig_LAContext_evaluatePolicy(self, _cmd, policy, reason, reply);
}

static void (*orig_LAContext_evaluateAccessControl)(id, SEL, SecAccessControlRef, NSInteger, NSString *, void (^)(BOOL, NSError *)) = NULL;
static void hook_LAContext_evaluateAccessControl(id self, SEL _cmd, SecAccessControlRef ac, NSInteger op, NSString *reason, void (^reply)(BOOL, NSError *)) {
    @synchronized(MEMBLock()) {
        if (!g_biometric_events) g_biometric_events = [NSMutableArray array];
        [g_biometric_events addObject:@{
            @"type": @"LAContext.evaluateAccessControl",
            @"operation": @(op),
            @"reason": reason ?: @"",
            @"mode": g_biometric_mode ?: @"auto_pass",
            @"ts": @([[NSDate date] timeIntervalSince1970])
        }];
    }
    if ([g_biometric_mode isEqualToString:@"auto_pass"]) {
        if (reply) {
            dispatch_async(dispatch_get_main_queue(), ^{
                reply(YES, nil);
            });
        }
        return;
    }
    if (orig_LAContext_evaluateAccessControl) orig_LAContext_evaluateAccessControl(self, _cmd, ac, op, reason, reply);
}

static void (*orig_ASAuth_performRequests)(id, SEL) = NULL;
static void hook_ASAuth_performRequests(id self, SEL _cmd) {
    @synchronized(MEMBLock()) {
        if (!g_biometric_events) g_biometric_events = [NSMutableArray array];
        NSArray *reqs = [self respondsToSelector:@selector(authorizationRequests)] ? [self valueForKey:@"authorizationRequests"] : @[];
        NSMutableArray *reqDescs = [NSMutableArray array];
        for (id r in reqs) {
            [reqDescs addObject:NSStringFromClass([r class]) ?: @"ASAuthorizationRequest"];
        }
        [g_biometric_events addObject:@{
            @"type": @"ASAuthorizationController.performRequests",
            @"requests": reqDescs,
            @"ts": @([[NSDate date] timeIntervalSince1970])
        }];
    }
    if (orig_ASAuth_performRequests) orig_ASAuth_performRequests(self, _cmd);
}

#pragma mark - [Upgrade 17] GPS & Motion Sensor Teleporter

static BOOL g_gps_spoof_active = NO;
static double g_gps_lat = 37.7749;
static double g_gps_lon = -122.4194;
static double g_gps_alt = 12.5;
static double g_gps_speed = 0.0;
static double g_gps_course = 0.0;
static double g_gps_accuracy = 4.8;

static CLLocation *MESpoofedCLLocation(void) {
    CLLocationCoordinate2D coord = CLLocationCoordinate2DMake(g_gps_lat, g_gps_lon);
    return [[CLLocation alloc] initWithCoordinate:coord
                                         altitude:g_gps_alt
                               horizontalAccuracy:g_gps_accuracy
                                 verticalAccuracy:3.2
                                           course:g_gps_course
                                            speed:g_gps_speed
                                        timestamp:[NSDate date]];
}

static CLLocation *(*orig_CLLocationManager_location)(id, SEL) = NULL;
static CLLocation *hook_CLLocationManager_location(id self, SEL _cmd) {
    if (g_gps_spoof_active) {
        return MESpoofedCLLocation();
    }
    return orig_CLLocationManager_location ? orig_CLLocationManager_location(self, _cmd) : nil;
}

static void (*orig_CLLocationManager_startUpdatingLocation)(id, SEL) = NULL;
static void hook_CLLocationManager_startUpdatingLocation(id self, SEL _cmd) {
    if (orig_CLLocationManager_startUpdatingLocation) orig_CLLocationManager_startUpdatingLocation(self, _cmd);
    if (g_gps_spoof_active) {
        id del = [self respondsToSelector:@selector(delegate)] ? [self valueForKey:@"delegate"] : nil;
        if (del && [del respondsToSelector:@selector(locationManager:didUpdateLocations:)]) {
            CLLocation *loc = MESpoofedCLLocation();
            dispatch_async(dispatch_get_main_queue(), ^{
                ((void (*)(id, SEL, id, id))objc_msgSend)(del, @selector(locationManager:didUpdateLocations:), self, @[loc]);
            });
        }
    }
}

#pragma mark - [Upgrade 18] XPC & Mach IPC Sniffer / Fuzzer

static BOOL g_xpc_capture_active = NO;
static NSMutableArray<NSDictionary *> *g_xpc_messages = nil;
static void (*orig_xpc_connection_send_message)(void *conn, void *msg) = NULL;
static void (*orig_xpc_connection_send_message_with_reply)(void *conn, void *msg, dispatch_queue_t q, void *handler) = NULL;
static void *(*orig_xpc_connection_send_message_with_reply_sync)(void *conn, void *msg) = NULL;
static const char *(*fn_xpc_connection_get_name)(void *conn) = NULL;
static char *(*fn_xpc_copy_description)(void *obj) = NULL;

static void MERecordXPCMessage(const char *api, void *conn, void *msg, void *reply) {
    if (!g_xpc_capture_active) return;
    if (!fn_xpc_connection_get_name) fn_xpc_connection_get_name = dlsym(RTLD_DEFAULT, "xpc_connection_get_name");
    if (!fn_xpc_copy_description) fn_xpc_copy_description = dlsym(RTLD_DEFAULT, "xpc_copy_description");
    const char *svc = (conn && fn_xpc_connection_get_name) ? fn_xpc_connection_get_name(conn) : NULL;
    char *msgDesc = (msg && fn_xpc_copy_description) ? fn_xpc_copy_description(msg) : NULL;
    char *repDesc = (reply && fn_xpc_copy_description) ? fn_xpc_copy_description(reply) : NULL;
    NSString *svcStr = svc ? @(svc) : @"<anonymous>";
    NSString *msgStr = msgDesc ? @(msgDesc) : @"";
    NSString *repStr = repDesc ? @(repDesc) : @"";
    if (msgDesc) free(msgDesc);
    if (repDesc) free(repDesc);
    if (msgStr.length > 2048) msgStr = [msgStr substringToIndex:2048];
    if (repStr.length > 2048) repStr = [repStr substringToIndex:2048];
    @synchronized(MEMBLock()) {
        if (!g_xpc_messages) g_xpc_messages = [NSMutableArray array];
        if (g_xpc_messages.count >= 500) [g_xpc_messages removeObjectAtIndex:0];
        [g_xpc_messages addObject:@{
            @"api": @(api),
            @"service": svcStr,
            @"message": msgStr,
            @"reply": repStr,
            @"ts": @([[NSDate date] timeIntervalSince1970])
        }];
    }
}

static void hook_xpc_connection_send_message(void *conn, void *msg) {
    MERecordXPCMessage("xpc_connection_send_message", conn, msg, NULL);
    if (orig_xpc_connection_send_message) orig_xpc_connection_send_message(conn, msg);
}

static void hook_xpc_connection_send_message_with_reply(void *conn, void *msg, dispatch_queue_t q, void *handler) {
    MERecordXPCMessage("xpc_connection_send_message_with_reply", conn, msg, NULL);
    if (orig_xpc_connection_send_message_with_reply) orig_xpc_connection_send_message_with_reply(conn, msg, q, handler);
}

static void *hook_xpc_connection_send_message_with_reply_sync(void *conn, void *msg) {
    void *rep = orig_xpc_connection_send_message_with_reply_sync ? orig_xpc_connection_send_message_with_reply_sync(conn, msg) : NULL;
    MERecordXPCMessage("xpc_connection_send_message_with_reply_sync", conn, msg, rep);
    return rep;
}

#pragma mark - [Upgrade 21] Real-Time Sandbox File Watcher (Undelete Quarantine) & IOKit Tracer

static BOOL g_fs_tracer_active = NO;
static BOOL g_preserve_unlinked = YES;
static NSMutableArray<NSDictionary *> *g_fs_iokit_events = nil;
static NSMutableArray<NSString *> *g_quarantined_files = nil;

static int (*orig_mb_unlink)(const char *path) = NULL;
static int (*orig_mb_rename)(const char *oldp, const char *newp) = NULL;
static kern_return_t (*orig_IOConnectCallMethod)(mach_port_t connection,
                                                 uint32_t selector,
                                                 const uint64_t *input,
                                                 uint32_t inputCnt,
                                                 const void *inputStruct,
                                                 size_t inputStructCnt,
                                                 uint64_t *output,
                                                 uint32_t *outputCnt,
                                                 void *outputStruct,
                                                 size_t *outputStructCnt) = NULL;

static NSString *MEQuarantineDirectory(void) {
    NSString *dir = [NSTemporaryDirectory() stringByAppendingPathComponent:@".mcp_quarantine"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:NULL];
    return dir;
}

static int hook_mb_unlink(const char *path) {
    if (g_fs_tracer_active && path && *path && strstr(path, ".mcp_") == NULL && strstr(path, ".me_") == NULL) {
        NSString *pStr = @(path);
        NSString *quarantineDest = nil;
        if (g_preserve_unlinked) {
            NSString *base = pStr.lastPathComponent ?: @"file";
            NSString *qName = [NSString stringWithFormat:@"%llu_%@", (unsigned long long)([[NSDate date] timeIntervalSince1970] * 1000), base];
            quarantineDest = [MEQuarantineDirectory() stringByAppendingPathComponent:qName];
            if ([[NSFileManager defaultManager] copyItemAtPath:pStr toPath:quarantineDest error:NULL]) {
                @synchronized(MEMBLock()) {
                    if (!g_quarantined_files) g_quarantined_files = [NSMutableArray array];
                    [g_quarantined_files addObject:quarantineDest];
                }
            } else {
                quarantineDest = nil;
            }
        }
        @synchronized(MEMBLock()) {
            if (!g_fs_iokit_events) g_fs_iokit_events = [NSMutableArray array];
            if (g_fs_iokit_events.count >= 500) [g_fs_iokit_events removeObjectAtIndex:0];
            [g_fs_iokit_events addObject:@{
                @"type": @"fs.unlink",
                @"path": pStr,
                @"quarantined_to": quarantineDest ?: @"",
                @"ts": @([[NSDate date] timeIntervalSince1970])
            }];
        }
    }
    return orig_mb_unlink ? orig_mb_unlink(path) : unlink(path);
}

static int hook_mb_rename(const char *oldp, const char *newp) {
    if (g_fs_tracer_active && oldp && newp) {
        @synchronized(MEMBLock()) {
            if (!g_fs_iokit_events) g_fs_iokit_events = [NSMutableArray array];
            if (g_fs_iokit_events.count >= 500) [g_fs_iokit_events removeObjectAtIndex:0];
            [g_fs_iokit_events addObject:@{
                @"type": @"fs.rename",
                @"from": @(oldp),
                @"to": @(newp),
                @"ts": @([[NSDate date] timeIntervalSince1970])
            }];
        }
    }
    return orig_mb_rename ? orig_mb_rename(oldp, newp) : rename(oldp, newp);
}

static kern_return_t hook_IOConnectCallMethod(mach_port_t connection,
                                              uint32_t selector,
                                              const uint64_t *input,
                                              uint32_t inputCnt,
                                              const void *inputStruct,
                                              size_t inputStructCnt,
                                              uint64_t *output,
                                              uint32_t *outputCnt,
                                              void *outputStruct,
                                              size_t *outputStructCnt) {
    kern_return_t kr = orig_IOConnectCallMethod
        ? orig_IOConnectCallMethod(connection, selector, input, inputCnt, inputStruct, inputStructCnt, output, outputCnt, outputStruct, outputStructCnt)
        : KERN_FAILURE;
    if (g_fs_tracer_active) {
        @synchronized(MEMBLock()) {
            if (!g_fs_iokit_events) g_fs_iokit_events = [NSMutableArray array];
            if (g_fs_iokit_events.count >= 500) [g_fs_iokit_events removeObjectAtIndex:0];
            [g_fs_iokit_events addObject:@{
                @"type": @"iokit.IOConnectCallMethod",
                @"connection": @(connection),
                @"selector": @(selector),
                @"input_scalar_count": @(inputCnt),
                @"input_struct_size": @(inputStructCnt),
                @"kr": @(kr),
                @"ts": @([[NSDate date] timeIntervalSince1970])
            }];
        }
    }
    return kr;
}

#pragma mark - RPC Dispatcher

NSDictionary *MEMediaBio(NSString *op, NSDictionary *a) {
    if ([op isEqualToString:@"engine.camera_mic"]) {
        NSString *action = [a[@"action"] isKindOfClass:NSString.class] ? [a[@"action"] lowercaseString] : @"status";
        if ([action isEqualToString:@"stop"]) {
            g_virtual_cam_active = NO;
            g_virtual_mic_active = NO;
            return @{@"active": @NO, @"frames_fed": @(g_virtual_cam_frames_fed)};
        }

        if ([a[@"qr_text"] isKindOfClass:NSString.class] && [a[@"qr_text"] length]) {
            UIImage *qr = MEGenerateQRImage(a[@"qr_text"]);
            @synchronized(MEMBLock()) { g_virtual_camera_image = qr; }
            g_virtual_cam_active = (qr != nil);
        } else if ([a[@"image_path"] isKindOfClass:NSString.class] && [a[@"image_path"] length]) {
            UIImage *img = [UIImage imageWithContentsOfFile:a[@"image_path"]];
            @synchronized(MEMBLock()) { g_virtual_camera_image = img; }
            g_virtual_cam_active = (img != nil);
        } else if ([a[@"image_base64"] isKindOfClass:NSString.class] && [a[@"image_base64"] length]) {
            NSData *d = [[NSData alloc] initWithBase64EncodedString:a[@"image_base64"] options:NSDataBase64DecodingIgnoreUnknownCharacters];
            UIImage *img = d ? [UIImage imageWithData:d] : nil;
            @synchronized(MEMBLock()) { g_virtual_camera_image = img; }
            g_virtual_cam_active = (img != nil);
        }

        if ([a[@"wav_path"] isKindOfClass:NSString.class] && [a[@"wav_path"] length]) {
            NSData *wav = [NSData dataWithContentsOfFile:a[@"wav_path"]];
            if (wav.length > 44) {
                @synchronized(MEMBLock()) {
                    g_virtual_mic_pcm = [wav subdataWithRange:NSMakeRange(44, wav.length - 44)];
                    g_virtual_mic_offset = 0;
                }
                g_virtual_mic_active = YES;
            }
        }

        static dispatch_once_t camOnce;
        dispatch_once(&camOnce, ^{
            Class vdo = objc_getClass("AVCaptureVideoDataOutput");
            if (vdo) {
                Method m = class_getInstanceMethod(vdo, @selector(setSampleBufferDelegate:queue:));
                if (m) orig_setSampleBufferDelegate = (typeof(orig_setSampleBufferDelegate))method_setImplementation(m, (IMP)hook_setSampleBufferDelegate);
            }
        });

        if (!orig_AudioUnitRender) {
            orig_AudioUnitRender = dlsym(RTLD_DEFAULT, "AudioUnitRender");
        }
        struct mcp_rebinding binds[] = {
            {"AudioUnitRender", (void *)hook_AudioUnitRender, (void **)&orig_AudioUnitRender}
        };
        NSUInteger patched = 0;
        NSArray *pending = MEMBRebindAllImages(binds, 1, &patched);

        return @{
            @"camera_active": @(g_virtual_cam_active),
            @"microphone_active": @(g_virtual_mic_active),
            @"frames_fed": @(g_virtual_cam_frames_fed),
            @"patched_in_proc": @(patched),
            @"pending_slots": pending
        };
    }

    if ([op isEqualToString:@"engine.biometric_vault"]) {
        if ([a[@"mode"] isKindOfClass:NSString.class] && [a[@"mode"] length]) {
            g_biometric_mode = [a[@"mode"] lowercaseString];
        }
        if ([a[@"clear"] boolValue]) {
            @synchronized(MEMBLock()) { [g_biometric_events removeAllObjects]; }
        }
        static dispatch_once_t bioOnce;
        dispatch_once(&bioOnce, ^{
            Class laCls = objc_getClass("LAContext");
            if (laCls) {
                Method m1 = class_getInstanceMethod(laCls, @selector(canEvaluatePolicy:error:));
                if (m1) orig_LAContext_canEvaluatePolicy = (typeof(orig_LAContext_canEvaluatePolicy))method_setImplementation(m1, (IMP)hook_LAContext_canEvaluatePolicy);
                Method m2 = class_getInstanceMethod(laCls, @selector(evaluatePolicy:localizedReason:reply:));
                if (m2) orig_LAContext_evaluatePolicy = (typeof(orig_LAContext_evaluatePolicy))method_setImplementation(m2, (IMP)hook_LAContext_evaluatePolicy);
                Method m3 = class_getInstanceMethod(laCls, @selector(evaluateAccessControl:operation:localizedReason:reply:));
                if (m3) orig_LAContext_evaluateAccessControl = (typeof(orig_LAContext_evaluateAccessControl))method_setImplementation(m3, (IMP)hook_LAContext_evaluateAccessControl);
            }
            Class asCls = objc_getClass("ASAuthorizationController");
            if (asCls) {
                Method m4 = class_getInstanceMethod(asCls, @selector(performRequests));
                if (m4) orig_ASAuth_performRequests = (typeof(orig_ASAuth_performRequests))method_setImplementation(m4, (IMP)hook_ASAuth_performRequests);
            }
        });
        NSArray *evts = nil;
        @synchronized(MEMBLock()) { evts = [g_biometric_events copy] ?: @[]; }
        return @{
            @"active": @YES,
            @"mode": g_biometric_mode ?: @"auto_pass",
            @"event_count": @(evts.count),
            @"events": evts
        };
    }

    if ([op isEqualToString:@"engine.gps_teleporter"]) {
        NSString *action = [a[@"action"] isKindOfClass:NSString.class] ? [a[@"action"] lowercaseString] : @"teleport";
        if ([action isEqualToString:@"stop"]) {
            g_gps_spoof_active = NO;
            return @{@"active": @NO};
        }
        if (a[@"latitude"]) g_gps_lat = [a[@"latitude"] doubleValue];
        if (a[@"longitude"]) g_gps_lon = [a[@"longitude"] doubleValue];
        if (a[@"altitude"]) g_gps_alt = [a[@"altitude"] doubleValue];
        if (a[@"speed"]) g_gps_speed = [a[@"speed"] doubleValue];
        if (a[@"course"]) g_gps_course = [a[@"course"] doubleValue];
        if (a[@"accuracy"]) g_gps_accuracy = [a[@"accuracy"] doubleValue];
        g_gps_spoof_active = YES;

        static dispatch_once_t gpsOnce;
        dispatch_once(&gpsOnce, ^{
            Class clCls = objc_getClass("CLLocationManager");
            if (clCls) {
                Method m1 = class_getInstanceMethod(clCls, @selector(location));
                if (m1) orig_CLLocationManager_location = (typeof(orig_CLLocationManager_location))method_setImplementation(m1, (IMP)hook_CLLocationManager_location);
                Method m2 = class_getInstanceMethod(clCls, @selector(startUpdatingLocation));
                if (m2) orig_CLLocationManager_startUpdatingLocation = (typeof(orig_CLLocationManager_startUpdatingLocation))method_setImplementation(m2, (IMP)hook_CLLocationManager_startUpdatingLocation);
            }
        });

        return @{
            @"active": @(g_gps_spoof_active),
            @"latitude": @(g_gps_lat),
            @"longitude": @(g_gps_lon),
            @"altitude": @(g_gps_alt),
            @"speed": @(g_gps_speed),
            @"course": @(g_gps_course),
            @"accuracy": @(g_gps_accuracy)
        };
    }

    if ([op isEqualToString:@"engine.xpc_sniffer"]) {
        NSString *action = [a[@"action"] isKindOfClass:NSString.class] ? [a[@"action"] lowercaseString] : @"start";
        if ([action isEqualToString:@"stop"]) {
            g_xpc_capture_active = NO;
            return @{@"active": @NO};
        }
        if ([a[@"clear"] boolValue]) {
            @synchronized(MEMBLock()) { [g_xpc_messages removeAllObjects]; }
        }
        g_xpc_capture_active = YES;
        if (!orig_xpc_connection_send_message) {
            orig_xpc_connection_send_message = dlsym(RTLD_DEFAULT, "xpc_connection_send_message");
            orig_xpc_connection_send_message_with_reply = dlsym(RTLD_DEFAULT, "xpc_connection_send_message_with_reply");
            orig_xpc_connection_send_message_with_reply_sync = dlsym(RTLD_DEFAULT, "xpc_connection_send_message_with_reply_sync");
        }
        struct mcp_rebinding binds[] = {
            {"xpc_connection_send_message", (void *)hook_xpc_connection_send_message, (void **)&orig_xpc_connection_send_message},
            {"xpc_connection_send_message_with_reply", (void *)hook_xpc_connection_send_message_with_reply, (void **)&orig_xpc_connection_send_message_with_reply},
            {"xpc_connection_send_message_with_reply_sync", (void *)hook_xpc_connection_send_message_with_reply_sync, (void **)&orig_xpc_connection_send_message_with_reply_sync}
        };
        NSUInteger patched = 0;
        NSArray *pending = MEMBRebindAllImages(binds, 3, &patched);
        NSArray *msgs = nil;
        @synchronized(MEMBLock()) { msgs = [g_xpc_messages copy] ?: @[]; }
        return @{
            @"active": @(g_xpc_capture_active),
            @"message_count": @(msgs.count),
            @"messages": msgs,
            @"patched_in_proc": @(patched),
            @"pending_slots": pending
        };
    }

    if ([op isEqualToString:@"engine.fs_iokit_tracer"]) {
        NSString *action = [a[@"action"] isKindOfClass:NSString.class] ? [a[@"action"] lowercaseString] : @"start";
        if ([action isEqualToString:@"stop"]) {
            g_fs_tracer_active = NO;
            return @{@"active": @NO};
        }
        if (a[@"preserve_unlinked_files"] != nil) {
            g_preserve_unlinked = [a[@"preserve_unlinked_files"] boolValue];
        }
        if ([a[@"clear"] boolValue]) {
            @synchronized(MEMBLock()) { [g_fs_iokit_events removeAllObjects]; }
        }
        g_fs_tracer_active = YES;
        if (!orig_mb_unlink) {
            orig_mb_unlink = dlsym(RTLD_DEFAULT, "unlink");
            orig_mb_rename = dlsym(RTLD_DEFAULT, "rename");
            orig_IOConnectCallMethod = dlsym(RTLD_DEFAULT, "IOConnectCallMethod");
        }
        struct mcp_rebinding binds[] = {
            {"unlink", (void *)hook_mb_unlink, (void **)&orig_mb_unlink},
            {"rename", (void *)hook_mb_rename, (void **)&orig_mb_rename},
            {"IOConnectCallMethod", (void *)hook_IOConnectCallMethod, (void **)&orig_IOConnectCallMethod}
        };
        NSUInteger patched = 0;
        NSArray *pending = MEMBRebindAllImages(binds, 3, &patched);
        NSArray *evts = nil;
        NSArray *qFiles = nil;
        @synchronized(MEMBLock()) {
            evts = [g_fs_iokit_events copy] ?: @[];
            qFiles = [g_quarantined_files copy] ?: @[];
        }
        return @{
            @"active": @(g_fs_tracer_active),
            @"preserve_unlinked_files": @(g_preserve_unlinked),
            @"quarantine_directory": MEQuarantineDirectory(),
            @"quarantined_files": qFiles,
            @"event_count": @(evts.count),
            @"events": evts,
            @"patched_in_proc": @(patched),
            @"pending_slots": pending
        };
    }

    return nil;
}
