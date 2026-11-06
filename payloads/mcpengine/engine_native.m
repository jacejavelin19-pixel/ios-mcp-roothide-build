#import "engine_rpc.h"
#include "fishhook.h"
#include <mach-o/dyld.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <libkern/OSByteOrder.h>
#include <stdarg.h>
#include <string.h>
#include <ptrauth.h>

@implementation MEHook
@end
__thread unsigned MEDepth;
static MEHook *MESlots[ME_HOOK_SLOTS];
static NSObject *MEHookLock;
static unsigned MENextSlot;
static NSString *MEBundlePath;
static const struct mach_header *MESelf;

const struct mach_header *MESelfHeader(void) {
    return MESelf;
}

static void MEHookInit(void) {
    static dispatch_once_t once;
    dispatch_once(&once,^{ MEHookLock = [NSObject new]; });
}
MEHook *MENewHook(NSDictionary *a) {
    MEHookInit();
    @synchronized(MEHookLock) {
        if (MENextSlot >= ME_HOOK_SLOTS) MEFail(@"Hook slot budget exhausted; restart app");
        MEHook *h = [MEHook new]; h.slot = MENextSlot++;
        h.key = [NSString stringWithFormat:@"hook:%u",h.slot];
        h.maxEvents = MELimit(a,@"max_events",256,4096);
        h.events = [NSMutableArray array];
        h.boundSlots = [NSMutableArray array];
        h.record = a[@"record"] ? [a[@"record"] boolValue] : YES;
        h.overrideValue = a[@"override_return"];
        MESlots[h.slot] = h; return h;
    }
}
void MECheckObjCHook(Class owner, SEL selector) {
    MEHookInit();
    @synchronized(MEHookLock) {
        for (unsigned i=0;i<MENextSlot;i++) {
            MEHook *h=MESlots[i];
            if (h.active && h.objcHook && h.owner==owner && h.selector==selector) MEFail(@"Method already hooked");
        }
    }
}
static MEHook *MEFind(NSString *key) {
    MEHookInit();
    @synchronized(MEHookLock) {
        for (unsigned i=0;i<MENextSlot;i++) if ([MESlots[i].key isEqual:key]) return MESlots[i];
    }
    MEFail(@"Unknown hook key");
}
static NSArray *MERecordArgs(MEHook *h, const uintptr_t *args) {
    NSMutableArray *values = [NSMutableArray array];
    for (unsigned i=h.objcHook ? 2:0;i<h.argc;i++) {
        id boxed = h.objcHook ? MEBoxValue(h.types[i+1].UTF8String,&args[i]) : MEHex(args[i]);
        [values addObject:boxed];
    }
    return values;
}
void MERecord(MEHook *h, NSArray *values, uintptr_t ret) {
    @synchronized(h) {
        h.count++;
        if (!h.record || !h.maxEvents) return;
        id result = h.objcHook ? MEBoxValue(h.types[0].UTF8String,&ret) : MEHex(ret);
        if (h.events.count >= h.maxEvents) [h.events removeObjectAtIndex:0];
        [h.events addObject:@{@"ts":@([NSDate date].timeIntervalSince1970),@"args":values,@"ret":result}];
    }
}
// All calls use fixed prototypes. No variadic objc_msgSend cast is used.
uintptr_t MECall(void *fn, const uintptr_t *a, unsigned n) {
    if (!fn || n>8) MEFail(@"Invalid native call");
    switch (n) {
        case 0: return ((uintptr_t (*)(void))fn)();
        case 1: return ((uintptr_t (*)(uintptr_t))fn)(a[0]);
        case 2: return ((uintptr_t (*)(uintptr_t,uintptr_t))fn)(a[0],a[1]);
        case 3: return ((uintptr_t (*)(uintptr_t,uintptr_t,uintptr_t))fn)(a[0],a[1],a[2]);
        case 4: return ((uintptr_t (*)(uintptr_t,uintptr_t,uintptr_t,uintptr_t))fn)(a[0],a[1],a[2],a[3]);
        case 5: return ((uintptr_t (*)(uintptr_t,uintptr_t,uintptr_t,uintptr_t,uintptr_t))fn)(a[0],a[1],a[2],a[3],a[4]);
        case 6: return ((uintptr_t (*)(uintptr_t,uintptr_t,uintptr_t,uintptr_t,uintptr_t,uintptr_t))fn)(a[0],a[1],a[2],a[3],a[4],a[5]);
        case 7: return ((uintptr_t (*)(uintptr_t,uintptr_t,uintptr_t,uintptr_t,uintptr_t,uintptr_t,uintptr_t))fn)(a[0],a[1],a[2],a[3],a[4],a[5],a[6]);
        case 8: return ((uintptr_t (*)(uintptr_t,uintptr_t,uintptr_t,uintptr_t,uintptr_t,uintptr_t,uintptr_t,uintptr_t))fn)(a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7]);
    }
    __builtin_unreachable();
}
static uintptr_t MEIntercept(unsigned slot, uintptr_t *args) {
    MEHook *h = MESlots[slot];
    BOOL outer = MEDepth++ == 0; int savedErrno = errno;
    uintptr_t ret = 0; BOOL active; NSArray *recordedArgs = @[];
    @synchronized(h) { active = h.active; }
    @try {
        if (outer && active && h.record) {
            @try { recordedArgs = MERecordArgs(h,args); } @catch (NSException *e) { }
        }
        errno = savedErrno;
        if (active && h.overrideValue && (!h.objcHook || *METype(h.types[0].UTF8String) != 'v')) {
            ret = h.overrideBits;
        } else {
            if (h.objcHook) {
                // Casting IMP to a plain C pointer must re-sign on arm64e.
                uintptr_t (*fn)(void) = (uintptr_t (*)(void))h.originalIMP;
                ret = MECall((void *)fn,args,h.argc);
            } else ret = MECall(h.originalFunction,args,h.argc);
        }
        savedErrno = errno;
        if (outer && active) {
            // Diagnostics must never throw through an application's call frame.
            @try { MERecord(h,recordedArgs,ret); } @catch (NSException *e) { }
        }
    } @finally { MEDepth--; errno = savedErrno; }
    return ret;
}

// Static, compiler-generated adapters. No runtime executable allocation.
#define ME_WRAP(N) static uintptr_t MEW##N(uintptr_t a,uintptr_t b,uintptr_t c,uintptr_t d,uintptr_t e,uintptr_t f,uintptr_t g,uintptr_t h) { uintptr_t args[]={a,b,c,d,e,f,g,h}; return MEIntercept(N,args); }
ME_WRAP(0) ME_WRAP(1) ME_WRAP(2) ME_WRAP(3) ME_WRAP(4) ME_WRAP(5) ME_WRAP(6) ME_WRAP(7)
ME_WRAP(8) ME_WRAP(9) ME_WRAP(10) ME_WRAP(11) ME_WRAP(12) ME_WRAP(13) ME_WRAP(14) ME_WRAP(15)
ME_WRAP(16) ME_WRAP(17) ME_WRAP(18) ME_WRAP(19) ME_WRAP(20) ME_WRAP(21) ME_WRAP(22) ME_WRAP(23)
ME_WRAP(24) ME_WRAP(25) ME_WRAP(26) ME_WRAP(27) ME_WRAP(28) ME_WRAP(29) ME_WRAP(30) ME_WRAP(31)
ME_WRAP(32) ME_WRAP(33) ME_WRAP(34) ME_WRAP(35) ME_WRAP(36) ME_WRAP(37) ME_WRAP(38) ME_WRAP(39)
ME_WRAP(40) ME_WRAP(41) ME_WRAP(42) ME_WRAP(43) ME_WRAP(44) ME_WRAP(45) ME_WRAP(46) ME_WRAP(47)
ME_WRAP(48) ME_WRAP(49) ME_WRAP(50) ME_WRAP(51) ME_WRAP(52) ME_WRAP(53) ME_WRAP(54) ME_WRAP(55)
ME_WRAP(56) ME_WRAP(57) ME_WRAP(58) ME_WRAP(59) ME_WRAP(60) ME_WRAP(61) ME_WRAP(62) ME_WRAP(63)
#undef ME_WRAP
#define ME_ADDR(N) (void *)MEW##N
static void *const MEAdapters[] = {
    ME_ADDR(0),ME_ADDR(1),ME_ADDR(2),ME_ADDR(3),ME_ADDR(4),ME_ADDR(5),ME_ADDR(6),ME_ADDR(7),
    ME_ADDR(8),ME_ADDR(9),ME_ADDR(10),ME_ADDR(11),ME_ADDR(12),ME_ADDR(13),ME_ADDR(14),ME_ADDR(15),
    ME_ADDR(16),ME_ADDR(17),ME_ADDR(18),ME_ADDR(19),ME_ADDR(20),ME_ADDR(21),ME_ADDR(22),ME_ADDR(23),
    ME_ADDR(24),ME_ADDR(25),ME_ADDR(26),ME_ADDR(27),ME_ADDR(28),ME_ADDR(29),ME_ADDR(30),ME_ADDR(31),
    ME_ADDR(32),ME_ADDR(33),ME_ADDR(34),ME_ADDR(35),ME_ADDR(36),ME_ADDR(37),ME_ADDR(38),ME_ADDR(39),
    ME_ADDR(40),ME_ADDR(41),ME_ADDR(42),ME_ADDR(43),ME_ADDR(44),ME_ADDR(45),ME_ADDR(46),ME_ADDR(47),
    ME_ADDR(48),ME_ADDR(49),ME_ADDR(50),ME_ADDR(51),ME_ADDR(52),ME_ADDR(53),ME_ADDR(54),ME_ADDR(55),
    ME_ADDR(56),ME_ADDR(57),ME_ADDR(58),ME_ADDR(59),ME_ADDR(60),ME_ADDR(61),ME_ADDR(62),ME_ADDR(63)};
void *MEAdapter(unsigned slot) { if (slot >= ME_HOOK_SLOTS) MEFail(@"Invalid hook slot"); return MEAdapters[slot]; }

static MEHook *MEOpenHook;
static int MEOpen(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap,flags); mode = (mode_t)va_arg(ap,int); va_end(ap); }
    MEHook *h = MEOpenHook; BOOL outer = MEDepth++ == 0; int prior=errno; int result;
    uintptr_t words[]={(uintptr_t)path,(uintptr_t)flags,mode};
    NSArray *recordedArgs = @[];
    @try {
        BOOL active; @synchronized(h) { active=h.active; }
        if (outer && active && h.record) {
            @try { recordedArgs = MERecordArgs(h,words); } @catch (NSException *e) { }
        }
        errno=prior;
        if (active && h.overrideValue) result=(int)h.overrideBits;
        else {
            int (*original)(const char *,int,...) = h.originalFunction;
            result = flags & O_CREAT ? original(path,flags,mode) : original(path,flags);
        }
        prior=errno;
        if (outer && active) {
            @try { MERecord(h,recordedArgs,(uintptr_t)(intptr_t)result); } @catch (NSException *e) { }
        }
    } @finally { MEDepth--; errno=prior; }
    return result;
}

static BOOL MEIsCompanionPath(NSString *name) {
    NSString *base = name.lastPathComponent;
    if (!base.length) return NO;
    return ([base hasPrefix:@"libApple"] ||
            [base hasPrefix:@"00_libApple"] ||
            [base hasPrefix:@"01_libApple"] ||
            [base hasPrefix:@"libmcp"] ||
            [base hasPrefix:@"systemhook"] ||
            [base hasPrefix:@"TweakLoader"] ||
            [name containsString:@"/.jbroot-"] ||
            [name containsString:@"/usr/lib/TweakInject/"]);
}

static BOOL MEMatches(MEHook *h, const struct mach_header *image, const char *path) {
    if (image==MESelf || !path || !h.active || h.objcHook) return NO;
    if (!MEBundlePath.length) {
        MEBundlePath = NSBundle.mainBundle.bundlePath.stringByResolvingSymlinksInPath;
    }
    NSString *name=[@(path) stringByResolvingSymlinksInPath];
    if (MEIsCompanionPath(name)) return NO;
    if (h.module.length) return [h.module isEqual:name] || [h.module isEqual:name.lastPathComponent];
    return MEBundlePath.length ? [name hasPrefix:[MEBundlePath stringByAppendingString:@"/"]] : NO;
}

static NSDictionary *MESlotPatchToDict(const mcp_slot_patch_t *p, NSString *imageName) {
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

static void MERecordBoundSlotOnHook(MEHook *h, NSDictionary *slotDict) {
    if (!h || !slotDict) return;
    @synchronized(h) {
        if (!h.boundSlots) h.boundSlots = [NSMutableArray array];
        NSString *addr = slotDict[@"slot_address"];
        for (NSUInteger i = 0; i < h.boundSlots.count; i++) {
            if ([h.boundSlots[i][@"slot_address"] isEqualToString:addr]) {
                h.boundSlots[i] = slotDict;
                return;
            }
        }
        [h.boundSlots addObject:slotDict];
    }
}

static void MEApplyImage(const struct mach_header *image, intptr_t slide) {
    Dl_info info={0}; if (!dladdr(image,&info)) return;
    MEDepth++;
    @try {
        @synchronized(MEHookLock) {
            for (unsigned i=0;i<MENextSlot;i++) {
                MEHook *h=MESlots[i];
                if (!MEMatches(h,image,info.dli_fname)) continue;
                struct mcp_rebinding binding={h.symbol.UTF8String,h.replacement,NULL};
                mcp_slot_collector_t collector = {0};
                mcp_rebind_symbols_image_collect(image,slide,MESelf,&binding,1,&collector);
                NSString *imgName = info.dli_fname ? @(info.dli_fname) : @"";
                for (size_t k = 0; k < collector.count; k++) {
                    MERecordBoundSlotOnHook(h, MESlotPatchToDict(&collector.patches[k], imgName));
                }
                mcp_slot_collector_free(&collector);
            }
        }
    } @finally { MEDepth--; }
}

static void MECollectHookSlots(MEHook *h,
                               BOOL prepareOnly,
                               NSArray<NSDictionary *> **outAllSlots,
                               NSArray<NSDictionary *> **outPendingSlots,
                               NSUInteger *outPatchedInProc) {
    NSMutableArray<NSDictionary *> *allSlots = [NSMutableArray array];
    NSMutableArray<NSDictionary *> *pendingSlots = [NSMutableArray array];
    NSUInteger patchedInProc = 0;

    uint32_t count = _dyld_image_count();
    MEDepth++;
    @try {
        for (uint32_t i = 0; i < count; i++) {
            const struct mach_header *image = _dyld_get_image_header(i);
            const char *rawName = _dyld_get_image_name(i);
            if (!image || !rawName) continue;
            if (!MEMatches(h, image, rawName)) continue;
            intptr_t slide = _dyld_get_image_vmaddr_slide(i);
            struct mcp_rebinding binding = {h.symbol.UTF8String, h.replacement, NULL};
            mcp_slot_collector_t collector = {0};
            collector.prepare_only = prepareOnly ? 1 : 0;
            mcp_rebind_symbols_image_collect(image, slide, MESelf, &binding, 1, &collector);
            NSString *imgName = @(rawName);
            for (size_t k = 0; k < collector.count; k++) {
                NSDictionary *slotDict = MESlotPatchToDict(&collector.patches[k], imgName);
                MERecordBoundSlotOnHook(h, slotDict);
                [allSlots addObject:slotDict];
                if (collector.patches[k].written_in_proc) {
                    patchedInProc++;
                } else {
                    [pendingSlots addObject:slotDict];
                }
            }
            mcp_slot_collector_free(&collector);
        }
    } @finally {
        MEDepth--;
    }

    if (outAllSlots) *outAllSlots = allSlots;
    if (outPendingSlots) *outPendingSlots = pendingSlots;
    if (outPatchedInProc) *outPatchedInProc = patchedInProc;
}

void MEInitNative(void) {
    MEHookInit(); MEBundlePath=NSBundle.mainBundle.bundlePath.stringByResolvingSymlinksInPath;
    Dl_info info={0}; dladdr((void *)MEInitNative,&info); MESelf=info.dli_fbase;
    _dyld_register_func_for_add_image(MEApplyImage);
}

void MERestoreNative(MEHook *h) {
    @synchronized(h) {
        h.active = NO;
        for (NSDictionary *slotDict in h.boundSlots) {
            uintptr_t slotAddr = MEWord(slotDict[@"slot_address"]);
            uintptr_t origVal = MEWord(slotDict[@"original_value"]);
            if (slotAddr && origVal) {
                mcp_write_raw_slot_in_proc(slotAddr, origVal);
            }
        }
    }
}

NSDictionary *MEHooks(NSString *op, NSDictionary *a) {
    if (![op isEqual:@"engine.hook_events"] && ![op isEqual:@"engine.unhook"]) return nil;
    MEHook *h=MEFind(MEString(a,@"hook_key"));
    @synchronized(h) {
        if ([op isEqual:@"engine.hook_events"]) {
            NSUInteger max=MELimit(a,@"max_events",256,4096), n=MIN(max,h.events.count);
            return @{@"events":[h.events subarrayWithRange:NSMakeRange(h.events.count-n,n)],@"count":@(h.count),
                     @"active":@(h.active),@"dropped":@(h.count>h.events.count ? h.count-h.events.count:0)};
        }
        NSMutableArray<NSDictionary *> *restoreSlots = [NSMutableArray array];
        NSUInteger restoredInProc = 0;
        if (h.active && h.objcHook) {
            Method method=class_getInstanceMethod(h.owner,h.selector);
            if (method_getImplementation(method)!=(IMP)h.replacement) MEFail(@"Method changed by another hook; refusing to overwrite it");
            method_setImplementation(method,h.originalIMP);
            restoredInProc = 1;
        } else {
            for (NSDictionary *slotDict in h.boundSlots) {
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
        h.active=NO;
        return @{
            @"removed": @YES,
            @"restored_in_proc": @(restoredInProc),
            @"restore_slots": restoreSlots
        };
    }
}

NSDictionary *MENative(NSString *op, NSDictionary *a) {
    if ([op isEqual:@"engine.call"]) {
        NSArray *values=a[@"args"] ?: @[];
        if (![values isKindOfClass:NSArray.class] || values.count>8) MEFail(@"call requires up to eight integer/pointer arguments");
        uintptr_t args[8]={0}; for (NSUInteger i=0;i<values.count;i++) args[i]=MEWord(values[i]);
        void *fn=MEResolve(a);
#if __has_feature(ptrauth_calls)
        if (a[@"address"]) fn=ptrauth_sign_unauthenticated(ptrauth_strip(fn,ptrauth_key_function_pointer),ptrauth_key_function_pointer,0);
#endif
        return @{@"ret":MEHex(MECall(fn,args,(unsigned)values.count))};
    }
    BOOL isPrepare = [op isEqual:@"engine.prepare_native_hook"];
    BOOL isHook = [op isEqual:@"engine.hook_native"];
    if (!isPrepare && !isHook) return nil;

    NSString *symbol=a[@"symbol"];
    if (a[@"address"]) {
        Dl_info info={0}; void *addr=(void *)MEWord(a[@"address"]);
        if (!dladdr(addr,&info) || !info.dli_sname || info.dli_saddr!=addr) MEFail(@"Address must resolve exactly to an imported symbol; inline hooks are unsupported");
        symbol=@(info.dli_sname);
    }
    if (![symbol isKindOfClass:NSString.class] || !symbol.length) MEFail(@"symbol is required");
    // Avoid hooking allocation/locking/runtime primitives used by diagnostics.
    NSSet *forbidden=[NSSet setWithArray:@[@"malloc",@"calloc",@"realloc",@"free",@"objc_msgSend",@"objc_retain",@"objc_release",@"pthread_mutex_lock",@"pthread_mutex_unlock"]];
    if ([forbidden containsObject:symbol]) MEFail(@"Engine runtime primitive cannot be instrumented");
    NSDictionary *counts=@{
        @"open":@3,@"close":@1,@"read":@3,@"write":@3,
        @"stat":@2,@"lstat":@2,@"fstat":@2,@"access":@2,
        @"fopen":@2,@"dlopen":@2,@"SSL_read":@3,@"SSL_write":@3,
        @"send":@4,@"recv":@4,@"connect":@3,@"unlink":@1,@"getenv":@1
    };
    if (!a[@"arg_count"] && !counts[symbol]) MEFail(@"arg_count is required for a fixed integer/pointer native signature");
    unsigned argc=(unsigned)MELimit(a,@"arg_count",[counts[symbol] unsignedIntegerValue],8);
    if (counts[symbol] && argc != [counts[symbol] unsignedIntValue]) MEFail(@"arg_count does not match known symbol signature");
    void *original=MEResolve(@{@"symbol":symbol});
    uintptr_t overrideBits=a[@"override_return"] ? MEWord(a[@"override_return"]) : 0;

    MEHook *h = nil;
    @synchronized(MEHookLock) {
        for (unsigned i=0;i<MENextSlot;i++) {
            if (!MESlots[i].objcHook && [MESlots[i].symbol isEqual:symbol]) {
                if (MESlots[i].active && isHook && MESlots[i].boundSlots.count > 0 && !a[@"allow_reuse"]) {
                    // If it was prepared via prepare_native_hook (or unhooked), allow hook_native to apply/reuse it;
                    // only reject if already actively hooked with no pending slots unless prepare_native_hook was used.
                }
                h = MESlots[i];
                break;
            }
        }
    }
    if (h && h.active && isHook && !a[@"from_prepare"]) {
        // Check if any bound slot is actually active in memory; if already hooked, reject duplicate active hook
        BOOL anyActiveInMem = NO;
        for (NSDictionary *slotDict in h.boundSlots) {
            uintptr_t slotAddr = MEWord(slotDict[@"slot_address"]);
            uintptr_t replVal = MEWord(slotDict[@"replacement_value"]);
            if (slotAddr && *(uintptr_t *)slotAddr == replVal) {
                anyActiveInMem = YES;
                break;
            }
        }
        if (anyActiveInMem) {
            MEFail(@"Symbol already registered; native slots cannot be reused");
        }
    }

    if (!h) {
        h = MENewHook(a);
    } else {
        @synchronized(h) {
            h.maxEvents = MELimit(a,@"max_events",256,4096);
            h.record = a[@"record"] ? [a[@"record"] boolValue] : YES;
            h.overrideValue = a[@"override_return"];
            if (!h.boundSlots) h.boundSlots = [NSMutableArray array];
        }
    }

    h.symbol=symbol;
    h.module=a[@"module"];
    h.overrideBits=overrideBits;
    if (h.module && ![h.module isKindOfClass:NSString.class]) MEFail(@"module must be a string");
    h.argc=argc;
    h.originalFunction=original;
    h.replacement=[symbol isEqual:@"open"] ? (void *)MEOpen : MEAdapter(h.slot);
    if ([symbol isEqual:@"open"]) MEOpenHook=h;
    @synchronized(h) { h.active=YES; }

    BOOL prepareOnly = isPrepare || [a[@"prepare_only"] boolValue];
    NSArray<NSDictionary *> *allSlots = nil;
    NSArray<NSDictionary *> *pendingSlots = nil;
    NSUInteger patchedInProc = 0;
    MECollectHookSlots(h, prepareOnly, &allSlots, &pendingSlots, &patchedInProc);

    return @{
        @"hook_key": h.key,
        @"slot": @(h.slot),
        @"symbol": h.symbol,
        @"original_address": MEHex((uintptr_t)h.originalFunction),
        @"replacement_address": MEHex((uintptr_t)h.replacement),
        @"installed": @(!prepareOnly && (patchedInProc > 0 || pendingSlots.count == 0)),
        @"prepared": @YES,
        @"patched_in_proc": @(patchedInProc),
        @"slots": allSlots ?: @[],
        @"pending_slots": pendingSlots ?: @[],
        @"scope": @"app imports; direct/export calls unaffected"
    };
}
