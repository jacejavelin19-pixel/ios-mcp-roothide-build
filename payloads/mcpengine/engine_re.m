#import "engine_rpc.h"
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <objc/message.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint64_t bvr[16];
    uint64_t bcr[16];
    uint64_t wvr[16];
    uint64_t wcr[16];
    uint64_t mdscr_el1;
} MERawArmDebugState64;

typedef struct {
    uint64_t x[29];
    uint64_t fp;
    uint64_t lr;
    uint64_t sp;
    uint64_t pc;
    uint32_t cpsr;
    uint32_t pad;
} MERawArmThreadState64;

#ifndef ARM_DEBUG_STATE64
#define ARM_DEBUG_STATE64 15
#endif
#ifndef ARM_DEBUG_STATE64_COUNT
#define ARM_DEBUG_STATE64_COUNT ((mach_msg_type_number_t)(sizeof(MERawArmDebugState64) / sizeof(uint32_t)))
#endif
#ifndef ARM_THREAD_STATE64
#define ARM_THREAD_STATE64 6
#endif
#ifndef ARM_THREAD_STATE64_COUNT
#define ARM_THREAD_STATE64_COUNT ((mach_msg_type_number_t)(sizeof(MERawArmThreadState64) / sizeof(uint32_t)))
#endif

typedef struct {
    BOOL active;
    uint64_t address;
    uint64_t redirectPC;
    BOOL hasOverrideX0;
    uint64_t overrideX0;
    uint64_t hitCount;
    mach_port_t steppingThread;
} MEHWBreakpointSlot;

static pthread_mutex_t sHWMutex = PTHREAD_MUTEX_INITIALIZER;
static MEHWBreakpointSlot sHWSlots[16];
static NSMutableArray<NSDictionary *> *sHWEvents = nil;
static mach_port_t sHWExcPort = MACH_PORT_NULL;
static pthread_t sHWExcThread;
static mach_port_t sHWExcMachThread = MACH_PORT_NULL;
static BOOL sHWExcStarted = NO;

static uintptr_t MEStripPtr(uintptr_t p) {
    return (uintptr_t)((uint64_t)p & 0x00007fffffffffffULL);
}

static int64_t MESignExtend(uint64_t val, unsigned bits) {
    uint64_t shift = 64 - bits;
    return ((int64_t)(val << shift)) >> shift;
}

static void *MEHWExceptionLoop(void *unused) {
    (void)unused;
    sHWExcMachThread = mach_thread_self();

    typedef struct {
        mach_msg_header_t Head;
        mach_msg_body_t msgh_body;
        mach_msg_port_descriptor_t thread;
        mach_msg_port_descriptor_t task;
        NDR_record_t NDR;
        exception_type_t exception;
        mach_msg_type_number_t codeCnt;
        integer_t code[2];
        uint8_t tail[256];
    } MEExcRequest;

    typedef struct {
        mach_msg_header_t Head;
        NDR_record_t NDR;
        kern_return_t RetCode;
    } MEExcReply;

    for (;;) {
        MEExcRequest req;
        memset(&req, 0, sizeof(req));
        mach_msg_return_t mr = mach_msg(&req.Head,
                                        MACH_RCV_MSG,
                                        0,
                                        sizeof(req),
                                        sHWExcPort,
                                        MACH_MSG_TIMEOUT_NONE,
                                        MACH_PORT_NULL);
        if (mr != MACH_MSG_SUCCESS) continue;

        mach_port_t hitThread = req.thread.name;
        MERawArmThreadState64 ts;
        memset(&ts, 0, sizeof(ts));
        mach_msg_type_number_t tsCnt = ARM_THREAD_STATE64_COUNT;

        MERawArmDebugState64 dbg;
        memset(&dbg, 0, sizeof(dbg));
        mach_msg_type_number_t dbgCnt = ARM_DEBUG_STATE64_COUNT;

        if (thread_get_state(hitThread, ARM_THREAD_STATE64, (thread_state_t)&ts, &tsCnt) == KERN_SUCCESS &&
            thread_get_state(hitThread, ARM_DEBUG_STATE64, (thread_state_t)&dbg, &dbgCnt) == KERN_SUCCESS) {

            uint64_t cleanPC = (uint64_t)MEStripPtr((uintptr_t)ts.pc) & ~3ULL;
            pthread_mutex_lock(&sHWMutex);

            int matchedSlot = -1;
            int stepRestoreSlot = -1;
            for (int s = 0; s < 16; s++) {
                if (sHWSlots[s].active && sHWSlots[s].address == cleanPC) {
                    matchedSlot = s;
                    break;
                }
                if (sHWSlots[s].active && sHWSlots[s].steppingThread == hitThread) {
                    stepRestoreSlot = s;
                }
            }

            if (matchedSlot >= 0) {
                sHWSlots[matchedSlot].hitCount++;
                @autoreleasepool {
                    if (!sHWEvents) sHWEvents = [NSMutableArray array];
                    if (sHWEvents.count < 256) {
                        [sHWEvents addObject:@{
                            @"slot": @(matchedSlot),
                            @"pc": MEHex((uintptr_t)cleanPC),
                            @"lr": MEHex((uintptr_t)MEStripPtr((uintptr_t)ts.lr)),
                            @"sp": MEHex((uintptr_t)ts.sp),
                            @"x0": MEHex((uintptr_t)ts.x[0]),
                            @"x1": MEHex((uintptr_t)ts.x[1]),
                            @"x2": MEHex((uintptr_t)ts.x[2]),
                            @"x3": MEHex((uintptr_t)ts.x[3]),
                            @"hit_count": @(sHWSlots[matchedSlot].hitCount)
                        }];
                    }
                }

                if (sHWSlots[matchedSlot].redirectPC != 0) {
                    ts.pc = sHWSlots[matchedSlot].redirectPC;
                    thread_set_state(hitThread, ARM_THREAD_STATE64, (thread_state_t)&ts, ARM_THREAD_STATE64_COUNT);
                } else if (sHWSlots[matchedSlot].hasOverrideX0) {
                    ts.x[0] = sHWSlots[matchedSlot].overrideX0;
                    ts.pc = MEStripPtr((uintptr_t)ts.lr);
                    thread_set_state(hitThread, ARM_THREAD_STATE64, (thread_state_t)&ts, ARM_THREAD_STATE64_COUNT);
                } else {
                    // Single-step past current instruction using MDSCR_EL1.SS (bit 0)
                    dbg.bcr[matchedSlot] = 0;
                    dbg.mdscr_el1 |= 1ULL;
                    sHWSlots[matchedSlot].steppingThread = hitThread;
                    thread_set_state(hitThread, ARM_DEBUG_STATE64, (thread_state_t)&dbg, ARM_DEBUG_STATE64_COUNT);
                }
            } else if (stepRestoreSlot >= 0) {
                // Completed single-step: re-enable hardware breakpoint and clear MDSCR_EL1.SS
                dbg.bvr[stepRestoreSlot] = sHWSlots[stepRestoreSlot].address;
                dbg.bcr[stepRestoreSlot] = 0x1E5ULL;
                dbg.mdscr_el1 &= ~1ULL;
                sHWSlots[stepRestoreSlot].steppingThread = MACH_PORT_NULL;
                thread_set_state(hitThread, ARM_DEBUG_STATE64, (thread_state_t)&dbg, ARM_DEBUG_STATE64_COUNT);
            } else {
                dbg.mdscr_el1 &= ~1ULL;
                thread_set_state(hitThread, ARM_DEBUG_STATE64, (thread_state_t)&dbg, ARM_DEBUG_STATE64_COUNT);
            }

            pthread_mutex_unlock(&sHWMutex);
        }

        MEExcReply reply;
        memset(&reply, 0, sizeof(reply));
        reply.Head.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(req.Head.msgh_bits), 0);
        reply.Head.msgh_size = sizeof(reply);
        reply.Head.msgh_remote_port = req.Head.msgh_remote_port;
        reply.Head.msgh_local_port = MACH_PORT_NULL;
        reply.Head.msgh_id = req.Head.msgh_id + 100;
        reply.NDR = req.NDR;
        reply.RetCode = KERN_SUCCESS;
        mach_msg(&reply.Head, MACH_SEND_MSG, sizeof(reply), 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);

        if (hitThread != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), hitThread);
        if (req.task.name != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), req.task.name);
    }
    return NULL;
}

static void MEEnsureHWExceptionServer(void) {
    if (sHWExcStarted) return;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &sHWExcPort) != KERN_SUCCESS) return;
    if (mach_port_insert_right(mach_task_self(), sHWExcPort, sHWExcPort, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) return;
    if (task_set_exception_ports(mach_task_self(), EXC_MASK_BREAKPOINT, sHWExcPort, EXCEPTION_DEFAULT, ARM_THREAD_STATE64) != KERN_SUCCESS) return;
    if (pthread_create(&sHWExcThread, NULL, MEHWExceptionLoop, NULL) == 0) {
        pthread_detach(sHWExcThread);
        sHWExcStarted = YES;
        usleep(10 * 1000);
    }
}

static NSDictionary *MEHandleHWBreakpoint(NSDictionary *a) {
    NSString *action = [a[@"action"] isKindOfClass:[NSString class]] ? [a[@"action"] lowercaseString] : @"set";
    int reqSlot = a[@"slot"] ? [a[@"slot"] intValue] : -1;

    if ([action isEqualToString:@"events"]) {
        pthread_mutex_lock(&sHWMutex);
        NSArray *ev = sHWEvents ? [sHWEvents copy] : @[];
        if ([a[@"clear"] boolValue]) [sHWEvents removeAllObjects];
        pthread_mutex_unlock(&sHWMutex);
        return @{@"event_count": @(ev.count), @"events": ev};
    }

    pthread_mutex_lock(&sHWMutex);
    if (!sHWEvents) sHWEvents = [NSMutableArray array];

    int slot = reqSlot;
    if ([action isEqualToString:@"set"] || [action isEqualToString:@"install"]) {
        MEEnsureHWExceptionServer();
        uintptr_t targetAddr = a[@"address"] ? MEWord(a[@"address"]) : (uintptr_t)MEResolve(a);
        targetAddr = MEStripPtr(targetAddr) & ~(uintptr_t)3ULL;
        if (!targetAddr) {
            pthread_mutex_unlock(&sHWMutex);
            MEFail(@"Hardware breakpoint requires valid address or symbol");
        }
        if (slot < 0 || slot >= 16) {
            slot = 0;
            for (int s = 0; s < 16; s++) {
                if (!sHWSlots[s].active || sHWSlots[s].address == targetAddr) {
                    slot = s;
                    break;
                }
            }
        }
        sHWSlots[slot].active = YES;
        sHWSlots[slot].address = (uint64_t)targetAddr;
        sHWSlots[slot].redirectPC = a[@"redirect_address"] ? (uint64_t)(MEStripPtr(MEWord(a[@"redirect_address"])) & ~(uintptr_t)3ULL) : 0;
        sHWSlots[slot].hasOverrideX0 = (a[@"override_return"] != nil || a[@"override_x0"] != nil);
        sHWSlots[slot].overrideX0 = sHWSlots[slot].hasOverrideX0 ? (uint64_t)MEWord(a[@"override_return"] ?: a[@"override_x0"]) : 0;
        sHWSlots[slot].hitCount = 0;
        sHWSlots[slot].steppingThread = MACH_PORT_NULL;
    } else if ([action isEqualToString:@"clear"] || [action isEqualToString:@"remove"]) {
        if (slot < 0) {
            memset(sHWSlots, 0, sizeof(sHWSlots));
        } else if (slot < 16) {
            memset(&sHWSlots[slot], 0, sizeof(MEHWBreakpointSlot));
        }
    }

    thread_act_array_t threads = NULL;
    mach_msg_type_number_t threadCount = 0;
    NSUInteger updatedThreads = 0;
    if (task_threads(mach_task_self(), &threads, &threadCount) == KERN_SUCCESS) {
        mach_port_t selfThread = mach_thread_self();
        for (mach_msg_type_number_t i = 0; i < threadCount; i++) {
            if (threads[i] == sHWExcMachThread) continue;
            MERawArmDebugState64 dbg;
            memset(&dbg, 0, sizeof(dbg));
            mach_msg_type_number_t cnt = ARM_DEBUG_STATE64_COUNT;
            if (thread_get_state(threads[i], ARM_DEBUG_STATE64, (thread_state_t)&dbg, &cnt) == KERN_SUCCESS) {
                for (int s = 0; s < 16; s++) {
                    if (sHWSlots[s].active) {
                        dbg.bvr[s] = sHWSlots[s].address;
                        dbg.bcr[s] = 0x1E5ULL;
                    } else if ([action isEqualToString:@"clear"] || [action isEqualToString:@"remove"]) {
                        if (slot < 0 || slot == s) {
                            dbg.bvr[s] = 0;
                            dbg.bcr[s] = 0;
                        }
                    }
                }
                if (thread_set_state(threads[i], ARM_DEBUG_STATE64, (thread_state_t)&dbg, ARM_DEBUG_STATE64_COUNT) == KERN_SUCCESS) {
                    updatedThreads++;
                }
            }
        }
        mach_port_deallocate(mach_task_self(), selfThread);
        for (mach_msg_type_number_t i = 0; i < threadCount; i++) {
            mach_port_deallocate(mach_task_self(), threads[i]);
        }
        vm_deallocate(mach_task_self(), (vm_address_t)threads, threadCount * sizeof(thread_t));
    }

    NSMutableArray *slotList = [NSMutableArray array];
    for (int s = 0; s < 16; s++) {
        if (sHWSlots[s].active) {
            [slotList addObject:@{
                @"slot": @(s),
                @"address": MEHex((uintptr_t)sHWSlots[s].address),
                @"redirect_address": sHWSlots[s].redirectPC ? MEHex((uintptr_t)sHWSlots[s].redirectPC) : [NSNull null],
                @"has_override_x0": @(sHWSlots[s].hasOverrideX0),
                @"hit_count": @(sHWSlots[s].hitCount)
            }];
        }
    }
    NSArray *recentEvents = [sHWEvents copy];
    pthread_mutex_unlock(&sHWMutex);

    return @{
        @"action": action,
        @"slot": @(slot),
        @"updated_threads": @(updatedThreads),
        @"exception_server_active": @(sHWExcStarted),
        @"zero_memory_patch": @YES,
        @"active_slots": slotList,
        @"events": recentEvents ?: @[]
    };
}

#pragma mark - In-Process Live Disassembler & Decompiler (engine.decompile)

static NSDictionary *MEHandleDecompile(NSDictionary *a) {
    uintptr_t targetPtr = 0;
    NSString *fnLabel = nil;

    if ([a[@"class"] isKindOfClass:[NSString class]] && [a[@"selector"] isKindOfClass:[NSString class]]) {
        NSString *clsName = a[@"class"];
        NSString *selName = a[@"selector"];
        Class cls = objc_getClass(clsName.UTF8String);
        if (!cls) MEFail([@"Class not found: " stringByAppendingString:clsName]);
        SEL sel = sel_registerName(selName.UTF8String);
        Method m = class_getInstanceMethod(cls, sel);
        BOOL isClassMethod = NO;
        if (!m) {
            m = class_getClassMethod(cls, sel);
            isClassMethod = YES;
        }
        if (!m) MEFail([NSString stringWithFormat:@"Method %@ not found on %@", selName, clsName]);
        targetPtr = MEStripPtr((uintptr_t)method_getImplementation(m));
        fnLabel = [NSString stringWithFormat:@"%c[%@ %@]", isClassMethod ? '+' : '-', clsName, selName];
    } else if (a[@"address"]) {
        targetPtr = MEStripPtr(MEWord(a[@"address"]));
    } else {
        targetPtr = MEStripPtr((uintptr_t)MEResolve(a));
    }

    if (!targetPtr) MEFail(@"Could not resolve function address for decompilation");

    Dl_info dli;
    memset(&dli, 0, sizeof(dli));
    if (dladdr((const void *)targetPtr, &dli) && dli.dli_sname && !fnLabel.length) {
        fnLabel = [NSString stringWithUTF8String:dli.dli_sname];
    }
    if (!fnLabel.length) fnLabel = [NSString stringWithFormat:@"sub_%llx", (unsigned long long)targetPtr];

    NSUInteger maxInsns = MELimit(a, @"max_instructions", 128, 512);
    const uint32_t *words = (const uint32_t *)targetPtr;
    NSMutableArray<NSDictionary *> *disasm = [NSMutableArray arrayWithCapacity:maxInsns];
    NSMutableArray<NSString *> *pseudoC = [NSMutableArray array];
    [pseudoC addObject:[NSString stringWithFormat:@"// Live in-process decompilation of %@ @ 0x%llx", fnLabel, (unsigned long long)targetPtr]];
    [pseudoC addObject:[NSString stringWithFormat:@"uintptr_t %@(uintptr_t x0, uintptr_t x1, uintptr_t x2, uintptr_t x3) {", fnLabel]];

    uint64_t regPage[32] = {0};
    for (NSUInteger i = 0; i < maxInsns; i++) {
        uint64_t pc = (uint64_t)targetPtr + i * 4;
        uint32_t insn = words[i];
        NSString *mnem = @"dw";
        NSString *ops = [NSString stringWithFormat:@"0x%08x", insn];
        NSString *note = nil;

        if (insn == 0xD503237FU || insn == 0xD503233FU) { mnem = @"pacibsp"; ops = @""; note = @"PAC stripped"; }
        else if (insn == 0xD50323FFU || insn == 0xD50323BFU) { mnem = @"autibsp"; ops = @""; note = @"PAC stripped"; }
        else if (insn == 0xD65F03C0U || insn == 0xD65F0BFFU || insn == 0xD65F0FFFU) {
            mnem = (insn == 0xD65F03C0U) ? @"ret" : @"retaa";
            ops = @"";
            [pseudoC addObject:@"    return x0;"];
            [disasm addObject:@{@"address": MEHex((uintptr_t)pc), @"bytes": [NSString stringWithFormat:@"%08x", insn], @"mnemonic": mnem, @"operands": ops}];
            break;
        } else if ((insn & 0x7C000000U) == 0x14000000U) {
            BOOL isBL = (insn & 0x80000000U) != 0;
            int64_t off = MESignExtend(insn & 0x03FFFFFFU, 26) * 4;
            uint64_t target = (uint64_t)((int64_t)pc + off);
            mnem = isBL ? @"bl" : @"b";
            ops = MEHex((uintptr_t)target);
            Dl_info ti;
            if (dladdr((const void *)(uintptr_t)target, &ti) && ti.dli_sname) {
                note = [NSString stringWithUTF8String:ti.dli_sname];
                [pseudoC addObject:[NSString stringWithFormat:@"    x0 = %@(x0, x1);", note]];
            } else {
                [pseudoC addObject:[NSString stringWithFormat:@"    x0 = sub_%llx(x0, x1);", (unsigned long long)target]];
            }
        } else if ((insn & 0x9F000000U) == 0x90000000U) {
            unsigned rd = insn & 0x1F;
            int64_t immhi = (insn >> 5) & 0x7FFFFU;
            int64_t immlo = (insn >> 29) & 0x3U;
            int64_t imm = MESignExtend((uint64_t)((immhi << 2) | immlo), 21);
            uint64_t page = (pc & ~0xFFFULL) + (uint64_t)(imm << 12);
            regPage[rd] = page;
            mnem = @"adrp";
            ops = [NSString stringWithFormat:@"x%u, 0x%llx", rd, (unsigned long long)page];
        } else if ((insn & 0xFFC00000U) == 0xF9400000U) {
            uint64_t off = (uint64_t)((insn >> 10) & 0xFFFU) * 8;
            unsigned rn = (insn >> 5) & 0x1F;
            unsigned rt = insn & 0x1F;
            mnem = @"ldr";
            ops = [NSString stringWithFormat:@"x%u, [x%u, #0x%llx]", rt, rn, (unsigned long long)off];
            if (regPage[rn] != 0) {
                uint64_t ptrAddr = regPage[rn] + off;
                regPage[rt] = 0;
                Dl_info pi;
                if (dladdr((const void *)(uintptr_t)ptrAddr, &pi) && pi.dli_sname) {
                    note = [NSString stringWithUTF8String:pi.dli_sname];
                }
            }
        }

        NSMutableDictionary *d = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                                  MEHex((uintptr_t)pc), @"address",
                                  [NSString stringWithFormat:@"%08x", insn], @"bytes",
                                  mnem, @"mnemonic",
                                  ops, @"operands", nil];
        if (note.length) d[@"comment"] = note;
        [disasm addObject:d];
    }
    [pseudoC addObject:@"}"];

    return @{
        @"function_name": fnLabel,
        @"start_address": MEHex(targetPtr),
        @"module": dli.dli_fname ? [NSString stringWithUTF8String:dli.dli_fname] : @"",
        @"instruction_count": @(disasm.count),
        @"pseudo_c": [pseudoC componentsJoinedByString:@"\n"],
        @"disassembly": disasm
    };
}

#pragma mark - In-Process React Native / Hermes / JSC / WKWebView Evaluator (engine.eval_js)

static void MEFindWebViewsInView(id view, NSMutableArray *outWebViews) {
    if (!view) return;
    Class wkCls = objc_getClass("WKWebView");
    if (wkCls && [view isKindOfClass:wkCls]) {
        [outWebViews addObject:view];
    }
    SEL subSel = sel_registerName("subviews");
    if ([view respondsToSelector:subSel]) {
        NSArray *subviews = ((NSArray *(*)(id, SEL))objc_msgSend)(view, subSel);
        for (id child in subviews) {
            MEFindWebViewsInView(child, outWebViews);
        }
    }
}

static NSDictionary *MEHandleEvalJS(NSDictionary *a) {
    NSString *script = [a[@"script"] ?: (a[@"code"] ?: a[@"expression"]) isKindOfClass:[NSString class]]
        ? (a[@"script"] ?: (a[@"code"] ?: a[@"expression"]))
        : nil;
    if (!script.length) MEFail(@"Missing required string parameter: 'script' (or 'code' / 'expression')");

    // 1. Check React Native RCTBridge.currentBridge
    Class rctBridgeCls = objc_getClass("RCTBridge");
    if (rctBridgeCls) {
        SEL curSel = sel_registerName("currentBridge");
        if ([rctBridgeCls respondsToSelector:curSel]) {
            id bridge = ((id (*)(id, SEL))objc_msgSend)(rctBridgeCls, curSel);
            if (bridge) {
                SEL batchedSel = sel_registerName("batchedBridge");
                if ([bridge respondsToSelector:batchedSel]) {
                    id batched = ((id (*)(id, SEL))objc_msgSend)(bridge, batchedSel);
                    if (batched) bridge = batched;
                }
                @try {
                    id jsCtx = [bridge valueForKey:@"jsContext"];
                    if (jsCtx) {
                        SEL evalSel = sel_registerName("evaluateScript:");
                        if ([jsCtx respondsToSelector:evalSel]) {
                            id jsVal = ((id (*)(id, SEL, NSString *))objc_msgSend)(jsCtx, evalSel, script);
                            SEL toStrSel = sel_registerName("toString");
                            NSString *strVal = (jsVal && [jsVal respondsToSelector:toStrSel])
                                ? ((NSString *(*)(id, SEL))objc_msgSend)(jsVal, toStrSel)
                                : [jsVal description];
                            return @{
                                @"ok": @YES,
                                @"runtime": @"ReactNative_JSContext",
                                @"bridge": [bridge description] ?: @"",
                                @"result": strVal ?: @""
                            };
                        }
                    }
                } @catch (NSException *ignored) {}

                SEL execSel = sel_registerName("executeApplicationScript:url:onComplete:");
                if ([bridge respondsToSelector:execSel]) {
                    NSData *scriptData = [script dataUsingEncoding:NSUTF8StringEncoding];
                    NSURL *url = [NSURL URLWithString:@"mcp://eval.js"];
                    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
                    __block NSError *execErr = nil;
                    void (^completion)(NSError *) = ^(NSError *err) {
                        execErr = err;
                        dispatch_semaphore_signal(sem);
                    };
                    ((void (*)(id, SEL, NSData *, NSURL *, id))objc_msgSend)(bridge, execSel, scriptData, url, completion);
                    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC)));
                    return @{
                        @"ok": @(execErr == nil),
                        @"runtime": @"ReactNative_RCTBridge",
                        @"bridge": [bridge description] ?: @"",
                        @"error": execErr ? execErr.localizedDescription : [NSNull null]
                    };
                }
            }
        }
    }

    // 2. Check frontmost WKWebView in UIWindow hierarchy
    Class uiAppCls = objc_getClass("UIApplication");
    if (uiAppCls) {
        __block NSMutableArray *webViews = [NSMutableArray array];
        dispatch_sync(dispatch_get_main_queue(), ^{
            id app = ((id (*)(id, SEL))objc_msgSend)(uiAppCls, sel_registerName("sharedApplication"));
            if (app && [app respondsToSelector:sel_registerName("windows")]) {
                NSArray *windows = ((NSArray *(*)(id, SEL))objc_msgSend)(app, sel_registerName("windows"));
                for (id win in windows) {
                    MEFindWebViewsInView(win, webViews);
                }
            }
        });
        if (webViews.count > 0) {
            id targetWV = webViews.firstObject;
            dispatch_semaphore_t sem = dispatch_semaphore_create(0);
            __block id evalRes = nil;
            __block NSError *evalErr = nil;
            dispatch_async(dispatch_get_main_queue(), ^{
                SEL evalSel = sel_registerName("evaluateJavaScript:completionHandler:");
                void (^handler)(id, NSError *) = ^(id res, NSError *err) {
                    evalRes = res;
                    evalErr = err;
                    dispatch_semaphore_signal(sem);
                };
                ((void (*)(id, SEL, NSString *, id))objc_msgSend)(targetWV, evalSel, script, handler);
            });
            dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC)));
            if (!evalErr) {
                return @{
                    @"ok": @YES,
                    @"runtime": @"WKWebView",
                    @"webview_count": @(webViews.count),
                    @"result": [evalRes description] ?: @"undefined"
                };
            }
        }
    }

    // 3. Evaluate in JavaScriptCore JSContext
    dlopen("/System/Library/Frameworks/JavaScriptCore.framework/JavaScriptCore", RTLD_LAZY);
    Class jsCtxCls = objc_getClass("JSContext");
    if (jsCtxCls) {
        id ctx = nil;
        SEL curCtxSel = sel_registerName("currentContext");
        if ([jsCtxCls respondsToSelector:curCtxSel]) {
            ctx = ((id (*)(id, SEL))objc_msgSend)(jsCtxCls, curCtxSel);
        }
        if (!ctx) {
            ctx = [[jsCtxCls alloc] init];
        }
        if (ctx) {
            SEL evalSel = sel_registerName("evaluateScript:");
            id jsVal = ((id (*)(id, SEL, NSString *))objc_msgSend)(ctx, evalSel, script);
            SEL toStrSel = sel_registerName("toString");
            NSString *strVal = (jsVal && [jsVal respondsToSelector:toStrSel])
                ? ((NSString *(*)(id, SEL))objc_msgSend)(jsVal, toStrSel)
                : [jsVal description];
            return @{
                @"ok": @YES,
                @"runtime": @"JavaScriptCore_JSContext",
                @"result": strVal ?: @"undefined"
            };
        }
    }

    MEFail(@"No JavaScript runtime (ReactNative RCTBridge, WKWebView, or JavaScriptCore) available in process");
}

NSDictionary *MERE(NSString *op, NSDictionary *a) {
    if ([op isEqualToString:@"engine.hw_breakpoint"]) return MEHandleHWBreakpoint(a);
    if ([op isEqualToString:@"engine.decompile"]) return MEHandleDecompile(a);
    if ([op isEqualToString:@"engine.eval_js"]) return MEHandleEvalJS(a);
    return nil;
}
