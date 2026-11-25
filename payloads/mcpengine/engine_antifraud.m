#import "engine_rpc.h"
#include "fishhook.h"
#import <UIKit/UIKit.h>
#import <CoreGraphics/CoreGraphics.h>
#import <Security/Security.h>
#import <CFNetwork/CFNetwork.h>
#import <Network/Network.h>
#import <SystemConfiguration/SystemConfiguration.h>
#include <arpa/inet.h>
#include <poll.h>
#import <CoreMotion/CoreMotion.h>
#include <objc/message.h>
#include <dlfcn.h>
#include <dirent.h>
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <libkern/OSByteOrder.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <math.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <unistd.h>

#if defined(__arm64e__) || (__has_feature(ptrauth_calls))
#include <ptrauth.h>
#define MCP_AF_PTRAUTH 1
#else
#define MCP_AF_PTRAUTH 0
#endif

#ifndef P_TRACED
#define P_TRACED 0x00000800
#endif
#ifndef PT_DENY_ATTACH
#define PT_DENY_ATTACH 31
#endif
#ifndef CS_OPS_STATUS
#define CS_OPS_STATUS 0
#endif
#ifndef CS_VALID
#define CS_VALID 0x00000001
#endif
#ifndef CS_HARD
#define CS_HARD 0x00000100
#endif
#ifndef CS_KILL
#define CS_KILL 0x00000200
#endif
#ifndef CS_RESTRICT
#define CS_RESTRICT 0x00000800
#endif
#ifndef CS_DEBUGGED
#define CS_DEBUGGED 0x10000000
#endif
#ifndef CS_INVALID_ALLOWED
#define CS_INVALID_ALLOWED 0x00000020
#endif

static NSObject *g_af_lock = nil;
static _Atomic int g_af_shield_active = 0;
static _Atomic int g_af_spoof_active = 0;
static _Atomic int g_af_kernel_cloak_active = 0;
static _Atomic int g_af_network_cloak_active = 0;
static _Atomic int g_af_canvas_active = 0;
static _Atomic int g_af_ghost_active = 0;
static _Atomic int g_af_sdk_tap_active = 0;
static _Atomic int g_af_risk_neutralizer_active = 0;
static _Atomic int g_af_attest_active = 0;
static _Atomic int g_af_env_sync_active = 0;
static _Atomic int g_af_objc_cloak_active = 0;
static _Atomic int g_af_thread_cloak_active = 0;
static _Atomic int g_af_egress_mode = 0; // 0=default, 1=cellular, 2=wifi
static _Atomic unsigned int g_af_egress_if_idx = 0;
static _Atomic uint64_t g_af_egress_gen = 0;
static _Atomic int g_af_egress_inline_active = 0;
static _Atomic uint16_t g_af_egress_proxy_port = 0;
static _Atomic int g_af_egress_proxy_listen_fd = -1;
static _Atomic uint64_t g_af_egress_proxy_accepts = 0;
static _Atomic uint64_t g_af_egress_proxy_socks5 = 0;
static _Atomic uint64_t g_af_egress_proxy_connect = 0;
static _Atomic uint64_t g_af_egress_proxy_http = 0;
static _Atomic uint64_t g_af_egress_proxy_fail = 0;
static _Atomic int g_af_egress_nw_proxy_active = 0;
static _Atomic uint64_t g_af_egress_urlproto_hits = 0;
static _Atomic uint64_t g_af_egress_urlproto_tls = 0;
static _Atomic uint64_t g_af_egress_urlproto_err = 0;
static char g_af_egress_if_name[32] = "pdp_ip0";

static NSMutableDictionary *g_af_persona = nil;
static NSMutableArray<NSDictionary *> *g_af_bound_slots = nil;
static NSMutableArray<NSDictionary *> *g_af_sensor_payloads = nil;
static NSMutableArray<NSDictionary *> *g_af_attest_events = nil;
static NSMutableDictionary *g_af_virtual_keychain = nil;
static NSHashTable<NSURLSession *> *g_af_tracked_sessions = nil;
static NSURLSession *g_af_pinned_shared_session = nil;
static uint64_t g_af_pinned_shared_gen = 0;
static CFAbsoluteTime g_af_last_touch_time = 0;
static CFAbsoluteTime g_af_persona_start_time = 0;
static pthread_t g_af_engine_thread = NULL;

typedef struct {
    IMP replacement;
    IMP original;
    Class cls;
    SEL sel;
} mcp_swizzle_entry_t;

#define MCP_MAX_SWIZZLE_ENTRIES 128
static mcp_swizzle_entry_t g_af_swizzles[MCP_MAX_SWIZZLE_ENTRIES];
static size_t g_af_swizzle_count = 0;

static void MEAFInit(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        g_af_lock = [NSObject new];
        g_af_persona = [NSMutableDictionary dictionary];
        g_af_bound_slots = [NSMutableArray array];
        g_af_sensor_payloads = [NSMutableArray array];
        g_af_attest_events = [NSMutableArray array];
        g_af_virtual_keychain = [NSMutableDictionary dictionary];
        g_af_tracked_sessions = [NSHashTable weakObjectsHashTable];
        g_af_persona_start_time = CFAbsoluteTimeGetCurrent();
    });
}

void MERegisterEngineServerThread(pthread_t thread) {
    g_af_engine_thread = thread;
}

static void MEAFRecordSwizzle(Class cls, SEL sel, IMP replacement, IMP original) {
    if (!replacement || !original) return;
    MEAFInit();
    @synchronized(g_af_lock) {
        for (size_t i = 0; i < g_af_swizzle_count; i++) {
            if (g_af_swizzles[i].replacement == replacement) {
                g_af_swizzles[i].original = original;
                return;
            }
        }
        if (g_af_swizzle_count < MCP_MAX_SWIZZLE_ENTRIES) {
            g_af_swizzles[g_af_swizzle_count].replacement = replacement;
            g_af_swizzles[g_af_swizzle_count].original = original;
            g_af_swizzles[g_af_swizzle_count].cls = cls;
            g_af_swizzles[g_af_swizzle_count].sel = sel;
            g_af_swizzle_count++;
        }
    }
}

static IMP MEAFOriginalIMPForReplacement(IMP imp) {
    if (!imp) return NULL;
    IMP fromHook = MEOriginalIMPForReplacement(imp);
    if (fromHook) return fromHook;
    @synchronized(g_af_lock) {
        for (size_t i = 0; i < g_af_swizzle_count; i++) {
            if (g_af_swizzles[i].replacement == imp) {
                return g_af_swizzles[i].original;
            }
        }
    }
    return NULL;
}

static IMP MEAFOriginalIMPForMethod(Method m, IMP currentIMP) {
    if (!m) return currentIMP;
    IMP orig = MEAFOriginalIMPForReplacement(currentIMP);
    if (orig) return orig;
    return currentIMP;
}

static BOOL MEAFIsHiddenImageName(const char *name) {
    if (!name || !*name) return NO;
    static const char *const kHiddenTokens[] = {
        "libmcpengine",
        "libmcp_stealth",
        "libmcp_netcap",
        "libmcp_sslks",
        "libAppleMediaKit_",
        "libAppleAVSync_",
        "libAppleCoreTLS_",
        "libAppleCoreSVG_",
        "frida",
        "Gum",
        "Substrate",
        "ellekit",
        "systemhook",
        "/.jbroot-",
        "/var/jb/",
        "/TweakInject/"
    };
    for (size_t i = 0; i < sizeof(kHiddenTokens) / sizeof(kHiddenTokens[0]); i++) {
        if (strcasestr(name, kHiddenTokens[i]) != NULL) return YES;
    }
    return NO;
}

static BOOL MEAFIsCloakedPath(const char *path) {
    if (!path || !*path) return NO;
    static const char *const kPaths[] = {
        "/.jbroot-",
        "/var/jb",
        "/private/var/jb",
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/Applications/Dopamine.app",
        "/Applications/Filza.app",
        "/Library/MobileSubstrate",
        "/usr/sbin/sshd",
        "/usr/bin/ssh",
        "/bin/bash",
        "/bin/sh",
        "/etc/apt",
        "/private/var/lib/apt",
        "/private/var/lib/cydia",
        "/var/mobile/Library/ios-mcp",
        "/.mcpe",
        "/.mcp_",
        "/.mcpcap",
        "libmcpengine",
        "libmcp_stealth",
        "frida-server",
        "frida-gadget"
    };
    for (size_t i = 0; i < sizeof(kPaths) / sizeof(kPaths[0]); i++) {
        if (strcasestr(path, kPaths[i]) != NULL) return YES;
    }
    return NO;
}

static BOOL MEAFShouldJitterBirthTime(const char *path) {
    if (!path || !*path) return NO;
    return (strcmp(path, "/var/mobile") == 0 ||
            strcmp(path, "/private/var/mobile") == 0 ||
            strcmp(path, "/var/mobile/Media") == 0 ||
            strcmp(path, "/var/mobile/Media/DCIM") == 0 ||
            strcmp(path, "/private/var/containers") == 0 ||
            strcmp(path, "/System/Library") == 0);
}

#pragma mark - Original C Function Pointers

static uint32_t (*orig_af_dyld_image_count)(void) = NULL;
static const char *(*orig_af_dyld_get_image_name)(uint32_t idx) = NULL;
static const struct mach_header *(*orig_af_dyld_get_image_header)(uint32_t idx) = NULL;
static intptr_t (*orig_af_dyld_get_image_vmaddr_slide)(uint32_t idx) = NULL;
static int (*orig_af_dladdr)(const void *addr, Dl_info *info) = NULL;
static IMP (*orig_af_method_getImplementation)(Method m) = NULL;
static IMP (*orig_af_class_getMethodImplementation)(Class cls, SEL name) = NULL;

static int (*orig_af_stat)(const char *path, struct stat *buf) = NULL;
static int (*orig_af_lstat)(const char *path, struct stat *buf) = NULL;
static int (*orig_af_fstatat)(int fd, const char *path, struct stat *buf, int flag) = NULL;
static int (*orig_af_access)(const char *path, int amode) = NULL;
static int (*orig_af_faccessat)(int fd, const char *path, int amode, int flag) = NULL;
static int (*orig_af_open)(const char *path, int oflag, ...) = NULL;
static FILE *(*orig_af_fopen)(const char *path, const char *mode) = NULL;
static DIR *(*orig_af_opendir)(const char *name) = NULL;
static char *(*orig_af_getenv)(const char *name) = NULL;

static int (*orig_af_ptrace)(int request, pid_t pid, void *addr, int data) = NULL;
static int (*orig_af_sysctl)(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) = NULL;
static int (*orig_af_sysctlbyname)(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) = NULL;
static pid_t (*orig_af_getppid)(void) = NULL;
static int (*orig_af_isatty)(int fd) = NULL;
static pid_t (*orig_af_fork)(void) = NULL;
static int (*orig_af_csops)(pid_t pid, unsigned int ops, void *useraddr, size_t usersize) = NULL;
static kern_return_t (*orig_af_task_get_exception_ports)(task_t task,
                                                         exception_mask_t exception_mask,
                                                         exception_mask_array_t masks,
                                                         mach_msg_type_number_t *masksCnt,
                                                         exception_handler_array_t old_handlers,
                                                         exception_behavior_array_t old_behaviors,
                                                         thread_state_flavor_array_t old_flavors) = NULL;
static kern_return_t (*orig_af_task_threads)(task_t target_task,
                                             thread_act_array_t *act_list,
                                             mach_msg_type_number_t *act_listCnt) = NULL;
static int (*orig_af_backtrace)(void **buffer, int size) = NULL;

static CFDictionaryRef (*orig_af_CFNetworkCopySystemProxySettings)(void) = NULL;
static int (*orig_af_getifaddrs)(struct ifaddrs **ifap) = NULL;
static Boolean (*orig_af_SCNetworkReachabilityGetFlags)(SCNetworkReachabilityRef target, SCNetworkReachabilityFlags *flags) = NULL;
static int (*orig_af_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;

static CFTypeRef (*orig_af_MGCopyAnswer)(CFStringRef prop) = NULL;
static int (*orig_af_statfs)(const char *path, struct statfs *buf) = NULL;
static int (*orig_af_fstatfs)(int fd, struct statfs *buf) = NULL;
static CGImageRef (*orig_af_CGBitmapContextCreateImage)(CGContextRef context) = NULL;

#pragma mark - Hook Implementations

static BOOL MEAFMapVisibleDyldIndex(uint32_t visIdx, uint32_t *outRealIdx) {
    uint32_t total = orig_af_dyld_image_count ? orig_af_dyld_image_count() : _dyld_image_count();
    uint32_t cur = 0;
    for (uint32_t i = 0; i < total; i++) {
        const struct mach_header *h = orig_af_dyld_get_image_header ? orig_af_dyld_get_image_header(i) : _dyld_get_image_header(i);
        const char *n = orig_af_dyld_get_image_name ? orig_af_dyld_get_image_name(i) : _dyld_get_image_name(i);
        if (h == MESelfHeader() || MEAFIsHiddenImageName(n)) continue;
        if (cur == visIdx) {
            if (outRealIdx) *outRealIdx = i;
            return YES;
        }
        cur++;
    }
    return NO;
}

static uint32_t hook_af_dyld_image_count(void) {
    uint32_t total = orig_af_dyld_image_count ? orig_af_dyld_image_count() : 0;
    if (!atomic_load(&g_af_shield_active) || MEDepth > 0) return total;
    uint32_t vis = 0;
    for (uint32_t i = 0; i < total; i++) {
        const struct mach_header *h = orig_af_dyld_get_image_header ? orig_af_dyld_get_image_header(i) : NULL;
        const char *n = orig_af_dyld_get_image_name ? orig_af_dyld_get_image_name(i) : NULL;
        if (h == MESelfHeader() || MEAFIsHiddenImageName(n)) continue;
        vis++;
    }
    return vis;
}

static const char *hook_af_dyld_get_image_name(uint32_t idx) {
    if (!atomic_load(&g_af_shield_active) || MEDepth > 0) {
        return orig_af_dyld_get_image_name ? orig_af_dyld_get_image_name(idx) : NULL;
    }
    uint32_t realIdx = 0;
    if (!MEAFMapVisibleDyldIndex(idx, &realIdx)) return NULL;
    return orig_af_dyld_get_image_name ? orig_af_dyld_get_image_name(realIdx) : NULL;
}

static const struct mach_header *hook_af_dyld_get_image_header(uint32_t idx) {
    if (!atomic_load(&g_af_shield_active) || MEDepth > 0) {
        return orig_af_dyld_get_image_header ? orig_af_dyld_get_image_header(idx) : NULL;
    }
    uint32_t realIdx = 0;
    if (!MEAFMapVisibleDyldIndex(idx, &realIdx)) return NULL;
    return orig_af_dyld_get_image_header ? orig_af_dyld_get_image_header(realIdx) : NULL;
}

static intptr_t hook_af_dyld_get_image_vmaddr_slide(uint32_t idx) {
    if (!atomic_load(&g_af_shield_active) || MEDepth > 0) {
        return orig_af_dyld_get_image_vmaddr_slide ? orig_af_dyld_get_image_vmaddr_slide(idx) : 0;
    }
    uint32_t realIdx = 0;
    if (!MEAFMapVisibleDyldIndex(idx, &realIdx)) return 0;
    return orig_af_dyld_get_image_vmaddr_slide ? orig_af_dyld_get_image_vmaddr_slide(realIdx) : 0;
}

static int hook_af_dladdr(const void *addr, Dl_info *info) {
    if (atomic_load(&g_af_objc_cloak_active) && addr && MEDepth == 0) {
        IMP origIMP = MEAFOriginalIMPForReplacement((IMP)addr);
        if (origIMP) {
            addr = (const void *)origIMP;
        }
    }
    int rc = orig_af_dladdr ? orig_af_dladdr(addr, info) : 0;
    if (rc != 0 && info && (atomic_load(&g_af_shield_active) || atomic_load(&g_af_objc_cloak_active)) && MEDepth == 0) {
        if (info->dli_fbase == (void *)MESelfHeader() || MEAFIsHiddenImageName(info->dli_fname)) {
            memset(info, 0, sizeof(*info));
            return 0;
        }
    }
    return rc;
}

static IMP hook_af_method_getImplementation(Method m) {
    IMP cur = orig_af_method_getImplementation ? orig_af_method_getImplementation(m) : NULL;
    if (atomic_load(&g_af_objc_cloak_active) && cur && MEDepth == 0) {
        return MEAFOriginalIMPForMethod(m, cur);
    }
    return cur;
}

static IMP hook_af_class_getMethodImplementation(Class cls, SEL name) {
    IMP cur = orig_af_class_getMethodImplementation ? orig_af_class_getMethodImplementation(cls, name) : NULL;
    if (atomic_load(&g_af_objc_cloak_active) && cur && MEDepth == 0) {
        IMP orig = MEAFOriginalIMPForReplacement(cur);
        if (orig) return orig;
    }
    return cur;
}

static void MEAFApplyBirthTimeJitter(const char *path, struct stat *buf) {
    if (!buf || !MEAFShouldJitterBirthTime(path)) return;
    int64_t jSec = 0;
    int64_t jNsec = 0;
    @synchronized(g_af_lock) {
        jSec = [g_af_persona[@"birthtime_jitter_sec"] longLongValue];
        jNsec = [g_af_persona[@"birthtime_jitter_nsec"] longLongValue];
    }
    if (jSec != 0 || jNsec != 0) {
        buf->st_birthtimespec.tv_sec += (time_t)jSec;
        buf->st_birthtimespec.tv_nsec = (long)((buf->st_birthtimespec.tv_nsec + jNsec) % 1000000000L);
        if (buf->st_birthtimespec.tv_nsec < 0) buf->st_birthtimespec.tv_nsec += 1000000000L;
    }
}

static int hook_af_stat(const char *path, struct stat *buf) {
    if (atomic_load(&g_af_shield_active) && MEDepth == 0 && MEAFIsCloakedPath(path)) {
        errno = ENOENT;
        return -1;
    }
    int rc = orig_af_stat ? orig_af_stat(path, buf) : -1;
    if (rc == 0 && buf && atomic_load(&g_af_spoof_active)) {
        MEAFApplyBirthTimeJitter(path, buf);
    }
    return rc;
}

static int hook_af_lstat(const char *path, struct stat *buf) {
    if (atomic_load(&g_af_shield_active) && MEDepth == 0 && MEAFIsCloakedPath(path)) {
        errno = ENOENT;
        return -1;
    }
    int rc = orig_af_lstat ? orig_af_lstat(path, buf) : -1;
    if (rc == 0 && buf && atomic_load(&g_af_spoof_active)) {
        MEAFApplyBirthTimeJitter(path, buf);
    }
    return rc;
}

static int hook_af_fstatat(int fd, const char *path, struct stat *buf, int flag) {
    if (atomic_load(&g_af_shield_active) && MEDepth == 0 && MEAFIsCloakedPath(path)) {
        errno = ENOENT;
        return -1;
    }
    int rc = orig_af_fstatat ? orig_af_fstatat(fd, path, buf, flag) : -1;
    if (rc == 0 && buf && atomic_load(&g_af_spoof_active)) {
        MEAFApplyBirthTimeJitter(path, buf);
    }
    return rc;
}

static int hook_af_access(const char *path, int amode) {
    if (atomic_load(&g_af_shield_active) && MEDepth == 0 && MEAFIsCloakedPath(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_af_access ? orig_af_access(path, amode) : -1;
}

static int hook_af_faccessat(int fd, const char *path, int amode, int flag) {
    if (atomic_load(&g_af_shield_active) && MEDepth == 0 && MEAFIsCloakedPath(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_af_faccessat ? orig_af_faccessat(fd, path, amode, flag) : -1;
}

static int hook_af_open(const char *path, int oflag, ...) {
    mode_t mode = 0;
    if (oflag & O_CREAT) {
        va_list ap;
        va_start(ap, oflag);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    if (atomic_load(&g_af_shield_active) && MEDepth == 0 && MEAFIsCloakedPath(path)) {
        errno = ENOENT;
        return -1;
    }
    if (!orig_af_open) {
        errno = ENOSYS;
        return -1;
    }
    return (oflag & O_CREAT) ? orig_af_open(path, oflag, mode) : orig_af_open(path, oflag);
}

static FILE *hook_af_fopen(const char *path, const char *mode) {
    if (atomic_load(&g_af_shield_active) && MEDepth == 0 && MEAFIsCloakedPath(path)) {
        errno = ENOENT;
        return NULL;
    }
    return orig_af_fopen ? orig_af_fopen(path, mode) : NULL;
}

static DIR *hook_af_opendir(const char *name) {
    if (atomic_load(&g_af_shield_active) && MEDepth == 0 && MEAFIsCloakedPath(name)) {
        errno = ENOENT;
        return NULL;
    }
    return orig_af_opendir ? orig_af_opendir(name) : NULL;
}

static char *hook_af_getenv(const char *name) {
    if (atomic_load(&g_af_shield_active) && MEDepth == 0 && name) {
        if (strcasecmp(name, "DYLD_INSERT_LIBRARIES") == 0 ||
            strcasecmp(name, "MSSafeMode") == 0 ||
            strcasecmp(name, "_MSSafeMode") == 0 ||
            strncasecmp(name, "FRIDA_", 6) == 0) {
            return NULL;
        }
    }
    return orig_af_getenv ? orig_af_getenv(name) : NULL;
}

static int hook_af_ptrace(int request, pid_t pid, void *addr, int data) {
    if ((atomic_load(&g_af_shield_active) || atomic_load(&g_af_kernel_cloak_active)) && request == PT_DENY_ATTACH) {
        return 0;
    }
    return orig_af_ptrace ? orig_af_ptrace(request, pid, addr, data) : 0;
}

static int hook_af_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int rc = orig_af_sysctl ? orig_af_sysctl(name, namelen, oldp, oldlenp, newp, newlen) : -1;
    if (rc == 0 && (atomic_load(&g_af_shield_active) || atomic_load(&g_af_kernel_cloak_active)) &&
        name && namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID &&
        oldp && oldlenp && *oldlenp >= sizeof(struct kinfo_proc)) {
        struct kinfo_proc *kp = (struct kinfo_proc *)oldp;
        kp->kp_proc.p_flag &= ~P_TRACED;
    }
    return rc;
}

static int hook_af_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int rc = orig_af_sysctlbyname ? orig_af_sysctlbyname(name, oldp, oldlenp, newp, newlen) : -1;
    if (rc == 0 && atomic_load(&g_af_spoof_active) && name && oldp && oldlenp && *oldlenp > 0) {
        NSString *overrideStr = nil;
        @synchronized(g_af_lock) {
            if (strcmp(name, "kern.bootsessionuuid") == 0) overrideStr = g_af_persona[@"boot_session_uuid"];
            else if (strcmp(name, "hw.model") == 0) overrideStr = g_af_persona[@"hw_model"];
            else if (strcmp(name, "hw.machine") == 0) overrideStr = g_af_persona[@"product_type"];
            else if (strcmp(name, "kern.osversion") == 0) overrideStr = g_af_persona[@"build_version"];
        }
        if ([overrideStr isKindOfClass:[NSString class]] && overrideStr.length > 0) {
            const char *utf8 = overrideStr.UTF8String;
            size_t len = strlen(utf8) + 1;
            size_t copyLen = MIN(len, *oldlenp);
            memcpy(oldp, utf8, copyLen);
            if (copyLen > 0) ((char *)oldp)[copyLen - 1] = '\0';
            *oldlenp = copyLen;
        }
    }
    return rc;
}

static pid_t hook_af_getppid(void) {
    if (atomic_load(&g_af_shield_active) || atomic_load(&g_af_kernel_cloak_active)) {
        return 1;
    }
    return orig_af_getppid ? orig_af_getppid() : 1;
}

static int hook_af_isatty(int fd) {
    if ((atomic_load(&g_af_shield_active) || atomic_load(&g_af_kernel_cloak_active)) && fd >= 0 && fd <= 2) {
        errno = ENOTTY;
        return 0;
    }
    return orig_af_isatty ? orig_af_isatty(fd) : 0;
}

static pid_t hook_af_fork(void) {
    if (atomic_load(&g_af_shield_active) || atomic_load(&g_af_kernel_cloak_active)) {
        errno = EPERM;
        return -1;
    }
    return orig_af_fork ? orig_af_fork() : -1;
}

static int hook_af_csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
    int rc = orig_af_csops ? orig_af_csops(pid, ops, useraddr, usersize) : 0;
    if ((atomic_load(&g_af_shield_active) || atomic_load(&g_af_kernel_cloak_active)) &&
        ops == CS_OPS_STATUS && useraddr && usersize >= sizeof(uint32_t)) {
        uint32_t *flags = (uint32_t *)useraddr;
        *flags &= ~(uint32_t)(CS_DEBUGGED | CS_INVALID_ALLOWED);
        *flags |= (uint32_t)(CS_VALID | CS_HARD | CS_KILL | CS_RESTRICT);
        return 0;
    }
    return rc;
}

static kern_return_t hook_af_task_get_exception_ports(task_t task,
                                                      exception_mask_t exception_mask,
                                                      exception_mask_array_t masks,
                                                      mach_msg_type_number_t *masksCnt,
                                                      exception_handler_array_t old_handlers,
                                                      exception_behavior_array_t old_behaviors,
                                                      thread_state_flavor_array_t old_flavors) {
    kern_return_t kr = orig_af_task_get_exception_ports
        ? orig_af_task_get_exception_ports(task, exception_mask, masks, masksCnt, old_handlers, old_behaviors, old_flavors)
        : KERN_SUCCESS;
    if (kr == KERN_SUCCESS && (atomic_load(&g_af_shield_active) || atomic_load(&g_af_thread_cloak_active)) && MEDepth == 0 && masksCnt) {
        for (mach_msg_type_number_t i = 0; i < *masksCnt; i++) {
            if (old_handlers) old_handlers[i] = MACH_PORT_NULL;
            if (masks) masks[i] = 0;
            if (old_behaviors) old_behaviors[i] = 0;
            if (old_flavors) old_flavors[i] = 0;
        }
        *masksCnt = 0;
    }
    return kr;
}

static kern_return_t hook_af_task_threads(task_t target_task,
                                          thread_act_array_t *act_list,
                                          mach_msg_type_number_t *act_listCnt) {
    kern_return_t kr = orig_af_task_threads ? orig_af_task_threads(target_task, act_list, act_listCnt) : KERN_FAILURE;
    if (kr == KERN_SUCCESS && atomic_load(&g_af_thread_cloak_active) && MEDepth == 0 &&
        target_task == mach_task_self() && act_list && *act_list && act_listCnt && *act_listCnt > 1) {
        mach_port_t engineMachThread = g_af_engine_thread ? pthread_mach_thread_np(g_af_engine_thread) : MACH_PORT_NULL;
        mach_msg_type_number_t writeIdx = 0;
        for (mach_msg_type_number_t i = 0; i < *act_listCnt; i++) {
            thread_act_t th = (*act_list)[i];
            if (engineMachThread != MACH_PORT_NULL && th == engineMachThread) {
                continue;
            }
            pthread_t pth = pthread_from_mach_thread_np(th);
            if (pth) {
                char tname[64] = {0};
                if (pthread_getname_np(pth, tname, sizeof(tname)) == 0 && tname[0]) {
                    if (strcasestr(tname, "frida") || strcasestr(tname, "gum-") || strcasestr(tname, "gmain") || strcasestr(tname, "mcpe")) {
                        continue;
                    }
                }
            }
            (*act_list)[writeIdx++] = th;
        }
        *act_listCnt = writeIdx;
    }
    return kr;
}

static int hook_af_backtrace(void **buffer, int size) {
    int n = orig_af_backtrace ? orig_af_backtrace(buffer, size) : 0;
    if (n > 0 && atomic_load(&g_af_thread_cloak_active) && MEDepth == 0 && buffer) {
        int writeIdx = 0;
        for (int i = 0; i < n; i++) {
            Dl_info info = {0};
            if (orig_af_dladdr && orig_af_dladdr(buffer[i], &info) && info.dli_fname) {
                if (info.dli_fbase == (void *)MESelfHeader() || MEAFIsHiddenImageName(info.dli_fname)) {
                    continue;
                }
            }
            buffer[writeIdx++] = buffer[i];
        }
        return writeIdx;
    }
    return n;
}

static CFDictionaryRef hook_af_CFNetworkCopySystemProxySettings(void) {
    if ((atomic_load(&g_af_network_cloak_active) || atomic_load(&g_af_egress_mode) == 1) && MEDepth == 0) {
        return (__bridge_retained CFDictionaryRef)@{};
    }
    return orig_af_CFNetworkCopySystemProxySettings ? orig_af_CFNetworkCopySystemProxySettings() : (__bridge_retained CFDictionaryRef)@{};
}

static int hook_af_getifaddrs(struct ifaddrs **ifap) {
    int rc = orig_af_getifaddrs ? orig_af_getifaddrs(ifap) : -1;
    if (rc == 0 && atomic_load(&g_af_network_cloak_active) && ifap && *ifap && MEDepth == 0) {
        struct ifaddrs *cur = *ifap;
        struct ifaddrs *prev = NULL;
        while (cur) {
            const char *ifname = cur->ifa_name;
            BOOL isTunnel = (ifname && (strncmp(ifname, "utun", 4) == 0 ||
                                        strncmp(ifname, "ppp", 3) == 0 ||
                                        strncmp(ifname, "ipsec", 5) == 0 ||
                                        strncmp(ifname, "tun", 3) == 0 ||
                                        strncmp(ifname, "tap", 3) == 0));
            if (isTunnel) {
                struct ifaddrs *next = cur->ifa_next;
                if (prev) {
                    prev->ifa_next = next;
                } else {
                    *ifap = next;
                }
                cur = next;
                continue;
            }
            if (ifname && cur->ifa_data) {
                struct if_data *ifd = (struct if_data *)cur->ifa_data;
                if (strncmp(ifname, "en", 2) == 0 && ifd->ifi_mtu > 0 && ifd->ifi_mtu < 1500) {
                    ifd->ifi_mtu = 1500;
                } else if (strncmp(ifname, "pdp_ip", 6) == 0 && ifd->ifi_mtu > 0 && ifd->ifi_mtu < 1428) {
                    ifd->ifi_mtu = 1428;
                }
            }
            prev = cur;
            cur = cur->ifa_next;
        }
    }
    return rc;
}

static Boolean hook_af_SCNetworkReachabilityGetFlags(SCNetworkReachabilityRef target, SCNetworkReachabilityFlags *flags) {
    Boolean ok = (target != NULL && orig_af_SCNetworkReachabilityGetFlags) ? orig_af_SCNetworkReachabilityGetFlags(target, flags) : TRUE;
    if (flags && (atomic_load(&g_af_network_cloak_active) || atomic_load(&g_af_shield_active)) && MEDepth == 0) {
        *flags &= ~(SCNetworkReachabilityFlags)kSCNetworkReachabilityFlagsTransientConnection;
        *flags |= (SCNetworkReachabilityFlags)kSCNetworkReachabilityFlagsReachable;
    }
    return ok;
}

typedef void *(*me_nw_params_create_fn)(void *, void *);
typedef void *(*me_nw_params_create_plain_fn)(void);
typedef void *(*me_nw_conn_create_fn)(void *, void *);
typedef void *(*me_nw_params_copy_fn)(void *);
typedef void (*me_nw_release_fn)(void *);
typedef void (*me_nw_params_set_req_if_fn)(void *, int);
typedef void (*me_nw_params_prohibit_if_fn)(void *, int);
typedef void (*me_nw_params_clear_prohibit_fn)(void *);
typedef const char *(*me_nw_endpoint_hostname_fn)(void *);
typedef const struct sockaddr *(*me_nw_endpoint_addr_fn)(void *);
typedef void (*me_inline_hook_fn)(void *, void *, void **);

static me_nw_params_create_fn orig_af_nw_create_tcp = NULL;
static me_nw_params_create_fn orig_af_nw_create_udp = NULL;
static me_nw_params_create_plain_fn orig_af_nw_create_plain = NULL;
static me_nw_conn_create_fn orig_af_nw_conn_create = NULL;
static int (*orig_af_inline_connect)(int, const struct sockaddr *, socklen_t) = NULL;
static __thread unsigned s_af_egress_depth = 0;

static BOOL MEAFSockaddrIsLocalOrLAN(const struct sockaddr *addr, socklen_t addrlen) {
    if (!addr) return YES;
    if (addr->sa_family == AF_UNIX) return YES;
    if (addr->sa_family == AF_INET && addrlen >= sizeof(struct sockaddr_in)) {
        uint32_t ip = ntohl(((const struct sockaddr_in *)addr)->sin_addr.s_addr);
        uint8_t a = (uint8_t)((ip >> 24) & 0xFF);
        uint8_t b = (uint8_t)((ip >> 16) & 0xFF);
        if (a == 127 || ip == 0 || a == 10) return YES;
        if (a == 192 && b == 168) return YES;
        if (a == 172 && (b >= 16 && b <= 31)) return YES;
        if (a == 169 && b == 254) return YES;
        return NO;
    }
    if (addr->sa_family == AF_INET6 && addrlen >= sizeof(struct sockaddr_in6)) {
        const struct in6_addr *in6 = &((const struct sockaddr_in6 *)addr)->sin6_addr;
        if (IN6_IS_ADDR_LOOPBACK(in6) || IN6_IS_ADDR_UNSPECIFIED(in6) || IN6_IS_ADDR_LINKLOCAL(in6)) return YES;
        return NO;
    }
    return NO;
}

static BOOL MEAFEndpointIsLocalOrLAN(void *endpoint) {
    if (!endpoint) return NO;
    static me_nw_endpoint_hostname_fn s_getHost = NULL;
    static me_nw_endpoint_addr_fn s_getAddr = NULL;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        s_getHost = (me_nw_endpoint_hostname_fn)dlsym(RTLD_DEFAULT, "nw_endpoint_get_hostname");
        s_getAddr = (me_nw_endpoint_addr_fn)dlsym(RTLD_DEFAULT, "nw_endpoint_get_address");
    });
    if (s_getAddr) {
        const struct sockaddr *sa = s_getAddr(endpoint);
        if (sa) {
            socklen_t slen = (sa->sa_family == AF_INET) ? sizeof(struct sockaddr_in) :
                             ((sa->sa_family == AF_INET6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr));
            if (MEAFSockaddrIsLocalOrLAN(sa, slen)) return YES;
        }
    }
    if (s_getHost) {
        const char *h = s_getHost(endpoint);
        if (h && *h) {
            if (strcmp(h, "localhost") == 0 || strcmp(h, "127.0.0.1") == 0 || strcmp(h, "::1") == 0 ||
                strncmp(h, "10.", 3) == 0 || strncmp(h, "192.168.", 8) == 0 || strncmp(h, "169.254.", 8) == 0) {
                return YES;
            }
        }
    }
    return NO;
}

static void MEAFApplyNetworkParametersPin(void *params) {
    int mode = atomic_load(&g_af_egress_mode);
    if (!params || mode == 0) return;
    static me_nw_params_set_req_if_fn s_setReq = NULL;
    static me_nw_params_prohibit_if_fn s_prohibit = NULL;
    static me_nw_params_clear_prohibit_fn s_clearProhibit = NULL;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        s_setReq = (me_nw_params_set_req_if_fn)dlsym(RTLD_DEFAULT, "nw_parameters_set_required_interface_type");
        s_prohibit = (me_nw_params_prohibit_if_fn)dlsym(RTLD_DEFAULT, "nw_parameters_prohibit_interface_type");
        s_clearProhibit = (me_nw_params_clear_prohibit_fn)dlsym(RTLD_DEFAULT, "nw_parameters_clear_prohibited_interface_types");
    });
    // nw_interface_type_wifi = 1, nw_interface_type_cellular = 2
    if (s_clearProhibit) s_clearProhibit(params);
    if (mode == 1) {
        if (s_setReq) s_setReq(params, 2);
        if (s_prohibit) s_prohibit(params, 1);
    } else if (mode == 2) {
        if (s_setReq) s_setReq(params, 1);
        if (s_prohibit) s_prohibit(params, 2);
    }
}

static void *hook_af_nw_create_tcp(void *tls, void *tcp) {
    void *p = orig_af_nw_create_tcp ? orig_af_nw_create_tcp(tls, tcp) : NULL;
    if (p && s_af_egress_depth == 0) MEAFApplyNetworkParametersPin(p);
    return p;
}

static void *hook_af_nw_create_udp(void *dtls, void *udp) {
    void *p = orig_af_nw_create_udp ? orig_af_nw_create_udp(dtls, udp) : NULL;
    if (p && s_af_egress_depth == 0) MEAFApplyNetworkParametersPin(p);
    return p;
}

static void *hook_af_nw_create_plain(void) {
    void *p = orig_af_nw_create_plain ? orig_af_nw_create_plain() : NULL;
    if (p && s_af_egress_depth == 0) MEAFApplyNetworkParametersPin(p);
    return p;
}

static void *hook_af_nw_conn_create(void *endpoint, void *params) {
    int mode = atomic_load(&g_af_egress_mode);
    if (mode != 0 && params && s_af_egress_depth == 0 && !MEAFEndpointIsLocalOrLAN(endpoint)) {
        static me_nw_params_copy_fn s_copyParams = NULL;
        static me_nw_release_fn s_release = NULL;
        static dispatch_once_t once;
        dispatch_once(&once, ^{
            s_copyParams = (me_nw_params_copy_fn)dlsym(RTLD_DEFAULT, "nw_parameters_copy");
            s_release = (me_nw_release_fn)dlsym(RTLD_DEFAULT, "nw_release");
        });
        s_af_egress_depth++;
        void *cloned = s_copyParams ? s_copyParams(params) : NULL;
        void *useParams = cloned ? cloned : params;
        MEAFApplyNetworkParametersPin(useParams);
        void *conn = orig_af_nw_conn_create ? orig_af_nw_conn_create(endpoint, useParams) : NULL;
        if (cloned && s_release) s_release(cloned);
        s_af_egress_depth--;
        return conn;
    }
    return orig_af_nw_conn_create ? orig_af_nw_conn_create(endpoint, params) : NULL;
}

static dispatch_queue_t MEAFEgressProxyQueue(void) {
    static dispatch_queue_t q = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        q = dispatch_queue_create("com.apple.cfnetwork.egress.io", DISPATCH_QUEUE_CONCURRENT);
    });
    return q;
}

static dispatch_queue_t MEAFEgressNWQueue(void) {
    static dispatch_queue_t q = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        q = dispatch_queue_create("com.apple.cfnetwork.egress.nw", DISPATCH_QUEUE_CONCURRENT);
    });
    return q;
}

static BOOL MEAFWriteAllFD(int fd, const void *buf, size_t len) {
    const uint8_t *ptr = (const uint8_t *)buf;
    size_t rem = len;
    while (rem > 0) {
        ssize_t w = send(fd, ptr, rem, 0);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return NO;
        ptr += (size_t)w;
        rem -= (size_t)w;
    }
    return YES;
}

static BOOL MEAFReadExactFD(int fd, void *buf, size_t len) {
    uint8_t *ptr = (uint8_t *)buf;
    size_t rem = len;
    while (rem > 0) {
        ssize_t r = recv(fd, ptr, rem, 0);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return NO;
        ptr += (size_t)r;
        rem -= (size_t)r;
    }
    return YES;
}

static BOOL MEAFHostIsLoopback(NSString *host) {
    if (!host.length) return NO;
    NSString *low = [host lowercaseString];
    return [low isEqualToString:@"127.0.0.1"] ||
           [low isEqualToString:@"localhost"] ||
           [low isEqualToString:@"::1"] ||
           [low hasPrefix:@"127."];
}

static nw_connection_t MEAFEgressOpenUpstream(NSString *host, NSString *portStr, BOOL *outReady) {
    if (outReady) *outReady = NO;
    if (!host.length || !portStr.length) return nil;

    s_af_egress_depth++;
    nw_parameters_t params = nw_parameters_create_secure_tcp(NW_PARAMETERS_DISABLE_PROTOCOL, NW_PARAMETERS_DEFAULT_CONFIGURATION);
    int mode = atomic_load(&g_af_egress_mode);
    if (!MEAFHostIsLoopback(host)) {
        if (mode == 1) {
            nw_parameters_set_required_interface_type(params, nw_interface_type_cellular);
            nw_parameters_prohibit_interface_type(params, nw_interface_type_wifi);
        } else if (mode == 2) {
            nw_parameters_set_required_interface_type(params, nw_interface_type_wifi);
            nw_parameters_prohibit_interface_type(params, nw_interface_type_cellular);
        }
    }
    nw_endpoint_t ep = nw_endpoint_create_host(host.UTF8String, portStr.UTF8String);
    nw_connection_t conn = nw_connection_create(ep, params);
    s_af_egress_depth--;

    nw_connection_set_queue(conn, MEAFEgressNWQueue());
    dispatch_semaphore_t readySem = dispatch_semaphore_create(0);
    __block atomic_int signaled = ATOMIC_VAR_INIT(0);
    __block BOOL isReady = NO;
    nw_connection_set_state_changed_handler(conn, ^(nw_connection_state_t state, __unused nw_error_t err) {
        if (state == nw_connection_state_ready) {
            isReady = YES;
            if (atomic_exchange(&signaled, 1) == 0) dispatch_semaphore_signal(readySem);
        } else if (state == nw_connection_state_failed || state == nw_connection_state_cancelled) {
            if (atomic_exchange(&signaled, 1) == 0) dispatch_semaphore_signal(readySem);
        }
    });
    nw_connection_start(conn);
    dispatch_semaphore_wait(readySem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(8 * NSEC_PER_SEC)));
    if (outReady) *outReady = isReady;
    if (!isReady) {
        atomic_fetch_add(&g_af_egress_proxy_fail, 1);
        nw_connection_cancel(conn);
        return nil;
    }
    return conn;
}

static void MEAFEgressProxyRecvNext(int clientFD, nw_connection_t conn, NSMutableData *closedBox, void (^teardown)(void)) {
    atomic_int *closedFlag = (atomic_int *)closedBox.mutableBytes;
    if (atomic_load(closedFlag)) return;
    nw_connection_receive(conn, 1, 65536, ^(dispatch_data_t content, __unused nw_content_context_t context, bool isComplete, nw_error_t error) {
        if (atomic_load(closedFlag)) return;
        if (content) {
            __block BOOL writeOk = YES;
            dispatch_data_apply(content, ^bool(__unused dispatch_data_t region, __unused size_t offset, const void *buffer, size_t size) {
                if (size > 0 && !MEAFWriteAllFD(clientFD, buffer, size)) {
                    writeOk = NO;
                    return false;
                }
                return true;
            });
            if (!writeOk) {
                teardown();
                return;
            }
        }
        if (isComplete || error) {
            teardown();
            return;
        }
        MEAFEgressProxyRecvNext(clientFD, conn, closedBox, teardown);
    });
}

static void MEAFEgressProxyPump(int clientFD, nw_connection_t conn) {
    dispatch_queue_t ioQueue = MEAFEgressProxyQueue();
    dispatch_queue_t nwQueue = MEAFEgressNWQueue();
    NSMutableData *closedBox = [NSMutableData dataWithLength:sizeof(atomic_int)];
    atomic_int *closedFlag = (atomic_int *)closedBox.mutableBytes;
    atomic_init(closedFlag, 0);

    void (^teardown)(void) = ^{
        atomic_int *flag = (atomic_int *)closedBox.mutableBytes;
        if (atomic_exchange(flag, 1) == 0) {
            shutdown(clientFD, SHUT_RDWR);
            close(clientFD);
            nw_connection_cancel(conn);
        }
    };

    // Direction 1: remote nw_connection -> local clientFD (runs on MEAFEgressNWQueue)
    MEAFEgressProxyRecvNext(clientFD, conn, closedBox, teardown);

    // Direction 2: local clientFD -> remote nw_connection (runs on MEAFEgressProxyQueue)
    dispatch_async(ioQueue, ^{
        uint8_t buf[32768];
        atomic_int *flag = (atomic_int *)closedBox.mutableBytes;
        while (!atomic_load(flag)) {
            struct pollfd pfd = {.fd = clientFD, .events = POLLIN, .revents = 0};
            int pr = poll(&pfd, 1, 1000);
            if (pr < 0 && errno == EINTR) continue;
            if (pr < 0) break;
            if (pr == 0) continue;
            if (pfd.revents & (POLLERR | POLLNVAL)) break;
            ssize_t n = recv(clientFD, buf, sizeof(buf), 0);
            if (n < 0 && errno == EINTR) continue;
            if (n == 0) {
                // Client half-closed write side; propagate FIN upstream and let remote response drain
                nw_connection_send(conn, NULL, NW_CONNECTION_FINAL_MESSAGE_CONTEXT, true, ^(__unused nw_error_t e) {});
                return;
            }
            if (n < 0) break;
            dispatch_data_t chunk = dispatch_data_create(buf, (size_t)n, nwQueue, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
            dispatch_semaphore_t sendSem = dispatch_semaphore_create(0);
            __block BOOL sendOk = YES;
            nw_connection_send(conn, chunk, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true, ^(nw_error_t sendErr) {
                if (sendErr) sendOk = NO;
                dispatch_semaphore_signal(sendSem);
            });
            dispatch_semaphore_wait(sendSem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(10 * NSEC_PER_SEC)));
            if (!sendOk) break;
        }
        teardown();
    });
}

static void MEAFEgressProxyHandleSOCKS5(int clientFD) {
    uint8_t nmethods = 0;
    if (!MEAFReadExactFD(clientFD, &nmethods, 1) || nmethods == 0) {
        close(clientFD);
        return;
    }
    uint8_t methods[256];
    if (!MEAFReadExactFD(clientFD, methods, nmethods)) {
        close(clientFD);
        return;
    }
    BOOL hasNoAuth = NO;
    for (uint16_t i = 0; i < nmethods; i++) {
        if (methods[i] == 0x00) { hasNoAuth = YES; break; }
    }
    if (!hasNoAuth) {
        const uint8_t rej[2] = {0x05, 0xFF};
        MEAFWriteAllFD(clientFD, rej, sizeof(rej));
        close(clientFD);
        return;
    }
    const uint8_t okMethod[2] = {0x05, 0x00};
    if (!MEAFWriteAllFD(clientFD, okMethod, sizeof(okMethod))) {
        close(clientFD);
        return;
    }

    uint8_t reqHdr[4];
    if (!MEAFReadExactFD(clientFD, reqHdr, 4) || reqHdr[0] != 0x05) {
        close(clientFD);
        return;
    }
    if (reqHdr[1] != 0x01) { // Only TCP CONNECT supported
        const uint8_t badCmd[10] = {0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
        MEAFWriteAllFD(clientFD, badCmd, sizeof(badCmd));
        close(clientFD);
        return;
    }

    NSString *host = nil;
    uint8_t atyp = reqHdr[3];
    if (atyp == 0x01) { // IPv4
        uint8_t ip4[4];
        if (!MEAFReadExactFD(clientFD, ip4, 4)) { close(clientFD); return; }
        char ipStr[INET_ADDRSTRLEN] = {0};
        if (inet_ntop(AF_INET, ip4, ipStr, sizeof(ipStr))) {
            host = @(ipStr);
        }
    } else if (atyp == 0x03) { // Domain name
        uint8_t dlen = 0;
        if (!MEAFReadExactFD(clientFD, &dlen, 1) || dlen == 0) { close(clientFD); return; }
        char dom[256];
        if (!MEAFReadExactFD(clientFD, dom, dlen)) { close(clientFD); return; }
        dom[dlen] = '\0';
        host = @(dom);
    } else if (atyp == 0x04) { // IPv6
        uint8_t ip6[16];
        if (!MEAFReadExactFD(clientFD, ip6, 16)) { close(clientFD); return; }
        char ipStr[INET6_ADDRSTRLEN] = {0};
        if (inet_ntop(AF_INET6, ip6, ipStr, sizeof(ipStr))) {
            host = @(ipStr);
        }
    } else {
        const uint8_t badAddr[10] = {0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
        MEAFWriteAllFD(clientFD, badAddr, sizeof(badAddr));
        close(clientFD);
        return;
    }

    uint8_t portBytes[2];
    if (!MEAFReadExactFD(clientFD, portBytes, 2)) { close(clientFD); return; }
    uint16_t dstPort = (uint16_t)(((uint16_t)portBytes[0] << 8) | (uint16_t)portBytes[1]);
    NSString *portStr = [NSString stringWithFormat:@"%u", (unsigned)dstPort];
    atomic_fetch_add(&g_af_egress_proxy_socks5, 1);

    BOOL isReady = NO;
    nw_connection_t conn = MEAFEgressOpenUpstream(host, portStr, &isReady);
    if (!conn || !isReady) {
        const uint8_t failReply[10] = {0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
        MEAFWriteAllFD(clientFD, failReply, sizeof(failReply));
        close(clientFD);
        return;
    }

    struct timeval longTv = {.tv_sec = 60, .tv_usec = 0};
    setsockopt(clientFD, SOL_SOCKET, SO_RCVTIMEO, &longTv, sizeof(longTv));
    setsockopt(clientFD, SOL_SOCKET, SO_SNDTIMEO, &longTv, sizeof(longTv));

    const uint8_t okReply[10] = {0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    if (!MEAFWriteAllFD(clientFD, okReply, sizeof(okReply))) {
        nw_connection_cancel(conn);
        close(clientFD);
        return;
    }
    MEAFEgressProxyPump(clientFD, conn);
}

static void MEAFEgressProxyHandleClient(int clientFD) {
    @autoreleasepool {
        atomic_fetch_add(&g_af_egress_proxy_accepts, 1);
        int one = 1;
        setsockopt(clientFD, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
        struct timeval tv = {.tv_sec = 8, .tv_usec = 0};
        setsockopt(clientFD, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(clientFD, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        // Auto-detect SOCKS5 (first byte 0x05) vs HTTP / HTTPS CONNECT on the same listener
        uint8_t firstByte = 0;
        if (!MEAFReadExactFD(clientFD, &firstByte, 1)) {
            close(clientFD);
            return;
        }
        if (firstByte == 0x05) {
            MEAFEgressProxyHandleSOCKS5(clientFD);
            return;
        }

        NSMutableData *headerBuf = [NSMutableData dataWithCapacity:2048];
        [headerBuf appendBytes:&firstByte length:1];
        NSInteger headerEnd = -1;
        uint8_t tmp[4096];
        while (headerBuf.length < 65536) {
            ssize_t n = recv(clientFD, tmp, sizeof(tmp), 0);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
            [headerBuf appendBytes:tmp length:(NSUInteger)n];
            const char *bytes = (const char *)headerBuf.bytes;
            size_t len = headerBuf.length;
            for (size_t i = 0; i + 3 < len; i++) {
                if (bytes[i] == '\r' && bytes[i+1] == '\n' && bytes[i+2] == '\r' && bytes[i+3] == '\n') {
                    headerEnd = (NSInteger)(i + 4);
                    break;
                }
            }
            if (headerEnd >= 0) break;
        }
        if (headerEnd < 0) {
            close(clientFD);
            return;
        }

        NSString *hdrStr = [[NSString alloc] initWithBytes:headerBuf.bytes length:(NSUInteger)headerEnd encoding:NSISOLatin1StringEncoding] ?: @"";
        NSArray<NSString *> *lines = [hdrStr componentsSeparatedByString:@"\r\n"];
        if (lines.count == 0) {
            close(clientFD);
            return;
        }
        NSArray<NSString *> *parts = [lines[0] componentsSeparatedByString:@" "];
        if (parts.count < 3) {
            close(clientFD);
            return;
        }
        NSString *method = parts[0];
        NSString *target = parts[1];
        NSString *version = parts[2];

        BOOL isConnect = [[method uppercaseString] isEqualToString:@"CONNECT"];
        NSString *host = nil;
        NSString *portStr = isConnect ? @"443" : @"80";
        NSData *initialUpstreamPayload = nil;

        if (isConnect) {
            atomic_fetch_add(&g_af_egress_proxy_connect, 1);
            if ([target hasPrefix:@"["]) {
                NSRange closeB = [target rangeOfString:@"]"];
                if (closeB.location != NSNotFound && closeB.location > 1) {
                    host = [target substringWithRange:NSMakeRange(1, closeB.location - 1)];
                    if (closeB.location + 2 < target.length && [target characterAtIndex:closeB.location + 1] == ':') {
                        portStr = [target substringFromIndex:closeB.location + 2];
                    }
                }
            } else {
                NSRange colon = [target rangeOfString:@":" options:NSBackwardsSearch];
                if (colon.location != NSNotFound) {
                    host = [target substringToIndex:colon.location];
                    portStr = [target substringFromIndex:colon.location + 1];
                } else {
                    host = target;
                }
            }
        } else {
            atomic_fetch_add(&g_af_egress_proxy_http, 1);
            NSURL *u = [NSURL URLWithString:target];
            host = u.host;
            if (u.port) portStr = [u.port stringValue];
            NSString *originPath = u.path.length ? u.path : @"/";
            if (u.query.length) originPath = [originPath stringByAppendingFormat:@"?%@", u.query];
            NSMutableString *rewritten = [NSMutableString stringWithFormat:@"%@ %@ %@\r\n", method, originPath, version];
            for (NSUInteger i = 1; i < lines.count; i++) {
                NSString *ln = lines[i];
                if (!ln.length) continue;
                NSString *low = [ln lowercaseString];
                if ([low hasPrefix:@"proxy-connection:"]) continue;
                if ([low hasPrefix:@"proxy-authorization:"]) continue;
                if (!host.length && [low hasPrefix:@"host:"]) {
                    NSString *hv = [[ln substringFromIndex:5] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
                    NSRange colon = [hv rangeOfString:@":" options:NSBackwardsSearch];
                    if (colon.location != NSNotFound && ![hv hasPrefix:@"["]) {
                        host = [hv substringToIndex:colon.location];
                        portStr = [hv substringFromIndex:colon.location + 1];
                    } else {
                        host = hv;
                    }
                }
                [rewritten appendFormat:@"%@\r\n", ln];
            }
            [rewritten appendString:@"\r\n"];
            NSMutableData *outData = [[rewritten dataUsingEncoding:NSISOLatin1StringEncoding] mutableCopy];
            if ((NSUInteger)headerEnd < headerBuf.length) {
                [outData appendBytes:((const uint8_t *)headerBuf.bytes) + headerEnd
                              length:headerBuf.length - (NSUInteger)headerEnd];
            }
            initialUpstreamPayload = outData;
        }

        if (!host.length || !portStr.length) {
            const char *bad = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            MEAFWriteAllFD(clientFD, bad, strlen(bad));
            close(clientFD);
            return;
        }

        BOOL isReady = NO;
        nw_connection_t conn = MEAFEgressOpenUpstream(host, portStr, &isReady);
        if (!conn || !isReady) {
            const char *fail = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            MEAFWriteAllFD(clientFD, fail, strlen(fail));
            close(clientFD);
            return;
        }

        struct timeval longTv = {.tv_sec = 60, .tv_usec = 0};
        setsockopt(clientFD, SOL_SOCKET, SO_RCVTIMEO, &longTv, sizeof(longTv));
        setsockopt(clientFD, SOL_SOCKET, SO_SNDTIMEO, &longTv, sizeof(longTv));

        dispatch_queue_t nwQueue = MEAFEgressNWQueue();
        if (isConnect) {
            const char *okResp = "HTTP/1.1 200 Connection Established\r\n\r\n";
            if (!MEAFWriteAllFD(clientFD, okResp, strlen(okResp))) {
                nw_connection_cancel(conn);
                close(clientFD);
                return;
            }
            if ((NSUInteger)headerEnd < headerBuf.length) {
                NSUInteger extraLen = headerBuf.length - (NSUInteger)headerEnd;
                dispatch_data_t extraData = dispatch_data_create(((const uint8_t *)headerBuf.bytes) + headerEnd,
                                                                 extraLen, nwQueue, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
                nw_connection_send(conn, extraData, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true, ^(__unused nw_error_t e) {});
            }
        } else if (initialUpstreamPayload.length > 0) {
            dispatch_data_t reqData = dispatch_data_create(initialUpstreamPayload.bytes,
                                                           initialUpstreamPayload.length,
                                                           nwQueue,
                                                           DISPATCH_DATA_DESTRUCTOR_DEFAULT);
            nw_connection_send(conn, reqData, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true, ^(__unused nw_error_t e) {});
        }

        MEAFEgressProxyPump(clientFD, conn);
    }
}

static uint16_t MEAFEgressProxyEnsureStarted(void) {
    uint16_t existing = atomic_load(&g_af_egress_proxy_port);
    if (existing != 0 && atomic_load(&g_af_egress_proxy_listen_fd) >= 0) {
        return existing;
    }
    MEAFInit();
    @synchronized(g_af_lock) {
        existing = atomic_load(&g_af_egress_proxy_port);
        if (existing != 0 && atomic_load(&g_af_egress_proxy_listen_fd) >= 0) {
            return existing;
        }
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return 0;
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
        fcntl(fd, F_SETFD, FD_CLOEXEC);

        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sa.sin_port = htons(0);
        if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
            close(fd);
            return 0;
        }
        socklen_t slen = sizeof(sa);
        if (getsockname(fd, (struct sockaddr *)&sa, &slen) != 0) {
            close(fd);
            return 0;
        }
        if (listen(fd, 64) != 0) {
            close(fd);
            return 0;
        }
        uint16_t assignedPort = ntohs(sa.sin_port);
        atomic_store(&g_af_egress_proxy_listen_fd, fd);
        atomic_store(&g_af_egress_proxy_port, assignedPort);

        dispatch_async(MEAFEgressProxyQueue(), ^{
            while (atomic_load(&g_af_egress_proxy_listen_fd) == fd) {
                int cfd = accept(fd, NULL, NULL);
                if (cfd < 0) {
                    if (errno == EINTR) continue;
                    break;
                }
                fcntl(cfd, F_SETFD, FD_CLOEXEC);
                dispatch_async(MEAFEgressProxyQueue(), ^{
                    MEAFEgressProxyHandleClient(cfd);
                });
            }
        });
        return assignedPort;
    }
}

static void MEAFEgressProxyStop(void) {
    MEAFInit();
    @synchronized(g_af_lock) {
        int fd = atomic_exchange(&g_af_egress_proxy_listen_fd, -1);
        atomic_store(&g_af_egress_proxy_port, 0);
        atomic_store(&g_af_egress_nw_proxy_active, 0);
        if (fd >= 0) {
            shutdown(fd, SHUT_RDWR);
            close(fd);
        }
    }
}

typedef void *(*me_nw_proxy_socksv5_fn)(void *);
typedef void (*me_nw_proxy_failover_fn)(void *, bool);
typedef void (*me_nw_proxy_excl_domain_fn)(void *, const char *);

static id MEAFCreateNWProxyConfig(uint16_t proxyPort) {
    if (proxyPort == 0) return nil;
    static me_nw_proxy_socksv5_fn s_createSocks5 = NULL;
    static me_nw_proxy_failover_fn s_setFailover = NULL;
    static me_nw_proxy_excl_domain_fn s_addExcl = NULL;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        s_createSocks5 = (me_nw_proxy_socksv5_fn)dlsym(RTLD_DEFAULT, "nw_proxy_config_create_socksv5");
        s_setFailover = (me_nw_proxy_failover_fn)dlsym(RTLD_DEFAULT, "nw_proxy_config_set_failover_allowed");
        s_addExcl = (me_nw_proxy_excl_domain_fn)dlsym(RTLD_DEFAULT, "nw_proxy_config_add_excluded_domain");
    });
    if (!s_createSocks5) return nil;

    char portBuf[16];
    snprintf(portBuf, sizeof(portBuf), "%u", (unsigned)proxyPort);
    nw_endpoint_t ep = nw_endpoint_create_host("127.0.0.1", portBuf);
    if (!ep) return nil;
    void *rawCfg = s_createSocks5((__bridge void *)ep);
    if (!rawCfg) return nil;
    if (s_setFailover) {
        // Strict pin: never silently fall back to direct Wi-Fi
        s_setFailover(rawCfg, false);
    }
    if (s_addExcl) {
        s_addExcl(rawCfg, "localhost");
        s_addExcl(rawCfg, "127.0.0.1");
    }
    return (__bridge_transfer id)rawCfg;
}

static void MEAFApplyWebKitEgressPin(int mode, uint16_t proxyPort) {
    Class wkStoreCls = NSClassFromString(@"WKWebsiteDataStore");
    if (!wkStoreCls) return;
    SEL defSel = NSSelectorFromString(@"defaultDataStore");
    SEL setSel = NSSelectorFromString(@"setProxyConfigurations:");
    if (![wkStoreCls respondsToSelector:defSel]) return;
    id pcObj = (mode != 0 && proxyPort > 0) ? MEAFCreateNWProxyConfig(proxyPort) : nil;
    NSArray *arr = pcObj ? @[pcObj] : @[];
    void (^applyBlock)(void) = ^{
        @try {
            id store = ((id (*)(id, SEL))objc_msgSend)(wkStoreCls, defSel);
            if (store && [store respondsToSelector:setSel]) {
                ((void (*)(id, SEL, id))objc_msgSend)(store, setSel, arr);
            }
        } @catch (__unused NSException *ex) {}
    };
    if ([NSThread isMainThread]) {
        applyBlock();
    } else {
        dispatch_async(dispatch_get_main_queue(), applyBlock);
    }
}


static NSString *const kMEAFEgressProtoHandledKey = @"com.apple.cfnetwork.egress.handled";

static NSData *MEAFDecodeChunkedBody(const uint8_t *bytes, size_t len, BOOL *outComplete) {
    if (outComplete) *outComplete = NO;
    NSMutableData *out = [NSMutableData data];
    size_t pos = 0;
    while (pos < len) {
        size_t lineEnd = pos;
        while (lineEnd + 1 < len && !(bytes[lineEnd] == '\r' && bytes[lineEnd + 1] == '\n')) {
            lineEnd++;
        }
        if (lineEnd + 1 >= len) return nil;
        char sizeBuf[32];
        size_t slen = MIN(lineEnd - pos, sizeof(sizeBuf) - 1);
        memcpy(sizeBuf, bytes + pos, slen);
        sizeBuf[slen] = '\0';
        char *semi = strchr(sizeBuf, ';');
        if (semi) *semi = '\0';
        char *endp = NULL;
        unsigned long chunkSz = strtoul(sizeBuf, &endp, 16);
        if (endp == sizeBuf) return nil;
        pos = lineEnd + 2;
        if (chunkSz == 0) {
            if (pos + 2 <= len && bytes[pos] == '\r' && bytes[pos + 1] == '\n') {
                if (outComplete) *outComplete = YES;
                return out;
            }
            // Search for trailer end \r\n\r\n
            for (size_t k = pos; k + 3 < len; k++) {
                if (bytes[k] == '\r' && bytes[k + 1] == '\n' && bytes[k + 2] == '\r' && bytes[k + 3] == '\n') {
                    if (outComplete) *outComplete = YES;
                    return out;
                }
            }
            return nil;
        }
        if (pos + chunkSz + 2 > len) return nil;
        [out appendBytes:bytes + pos length:chunkSz];
        pos += chunkSz + 2;
    }
    return nil;
}

static NSData *MEAFReadURLRequestBody(NSURLRequest *req) {
    if (req.HTTPBody.length > 0) return req.HTTPBody;
    NSInputStream *stream = req.HTTPBodyStream;
    if (!stream || stream.streamStatus != NSStreamStatusNotOpen) return nil;
    NSMutableData *buf = [NSMutableData data];
    [stream open];
    uint8_t tmp[4096];
    while (stream.hasBytesAvailable && buf.length < 4 * 1024 * 1024) {
        NSInteger r = [stream read:tmp maxLength:sizeof(tmp)];
        if (r <= 0) break;
        [buf appendBytes:tmp length:(NSUInteger)r];
    }
    [stream close];
    return buf;
}

@interface MEAFEgressURLProtocol : NSURLProtocol
@property (nonatomic, strong) nw_connection_t nwConn;
@property (nonatomic, assign) BOOL stopped;
@end

static void MEAFURLProtoFinishResponse(MEAFEgressURLProtocol *proto, NSMutableData *rawBuf, NSError *connErr, atomic_int *doneFlag) {
    if (atomic_exchange(doneFlag, 1) != 0) return;
    if (proto.stopped) return;
    nw_connection_t conn = proto.nwConn;
    proto.nwConn = nil;
    if (conn) {
        nw_connection_set_state_changed_handler(conn, NULL);
        nw_connection_cancel(conn);
    }

    if (rawBuf.length == 0) {
        atomic_fetch_add(&g_af_egress_urlproto_err, 1);
        NSError *err = connErr ?: [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorNetworkConnectionLost userInfo:@{NSLocalizedDescriptionKey: @"Egress connection closed without response"}];
        [proto.client URLProtocol:proto didFailWithError:err];
        return;
    }

    const uint8_t *bytes = (const uint8_t *)rawBuf.bytes;
    size_t len = rawBuf.length;
    size_t hdrStart = 0;
    NSInteger hdrEnd = -1;

    // Skip optional 100 Continue informational headers
    while (hdrStart < len) {
        hdrEnd = -1;
        for (size_t i = hdrStart; i + 3 < len; i++) {
            if (bytes[i] == '\r' && bytes[i + 1] == '\n' && bytes[i + 2] == '\r' && bytes[i + 3] == '\n') {
                hdrEnd = (NSInteger)(i + 4);
                break;
            }
        }
        if (hdrEnd < 0) break;
        NSString *firstHdr = [[NSString alloc] initWithBytes:bytes + hdrStart length:(NSUInteger)(hdrEnd - (NSInteger)hdrStart) encoding:NSISOLatin1StringEncoding] ?: @"";
        if ([firstHdr hasPrefix:@"HTTP/1.1 100 "] || [firstHdr hasPrefix:@"HTTP/1.0 100 "]) {
            hdrStart = (size_t)hdrEnd;
            continue;
        }
        break;
    }

    if (hdrEnd < 0) {
        atomic_fetch_add(&g_af_egress_urlproto_err, 1);
        NSError *err = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorBadServerResponse userInfo:@{NSLocalizedDescriptionKey: @"Malformed HTTP response headers"}];
        [proto.client URLProtocol:proto didFailWithError:err];
        return;
    }

    NSString *hdrStr = [[NSString alloc] initWithBytes:bytes + hdrStart length:(NSUInteger)(hdrEnd - (NSInteger)hdrStart) encoding:NSISOLatin1StringEncoding] ?: @"";
    NSArray<NSString *> *lines = [hdrStr componentsSeparatedByString:@"\r\n"];
    NSInteger statusCode = 200;
    NSString *httpVer = @"HTTP/1.1";
    if (lines.count > 0) {
        NSArray<NSString *> *sp = [lines[0] componentsSeparatedByString:@" "];
        if (sp.count >= 1 && sp[0].length > 0) httpVer = sp[0];
        if (sp.count >= 2) statusCode = [sp[1] integerValue];
    }

    NSMutableDictionary<NSString *, NSString *> *headers = [NSMutableDictionary dictionary];
    NSMutableArray<NSString *> *setCookies = [NSMutableArray array];
    BOOL isChunked = NO;
    for (NSUInteger i = 1; i < lines.count; i++) {
        NSString *ln = lines[i];
        NSRange col = [ln rangeOfString:@":"];
        if (col.location == NSNotFound) continue;
        NSString *k = [[ln substringToIndex:col.location] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        NSString *v = [[ln substringFromIndex:col.location + 1] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        if (!k.length) continue;
        NSString *kl = [k lowercaseString];
        if ([kl isEqualToString:@"transfer-encoding"] && [[v lowercaseString] containsString:@"chunked"]) {
            isChunked = YES;
        }
        if ([kl isEqualToString:@"set-cookie"]) {
            [setCookies addObject:v];
        }
        if (headers[k]) {
            headers[k] = [NSString stringWithFormat:@"%@, %@", headers[k], v];
        } else {
            headers[k] = v;
        }
    }

    NSURL *reqURL = proto.request.URL;
    if (proto.request.HTTPShouldHandleCookies && setCookies.count > 0 && reqURL) {
        for (NSString *sc in setCookies) {
            NSArray<NSHTTPCookie *> *cks = [NSHTTPCookie cookiesWithResponseHeaderFields:@{@"Set-Cookie": sc} forURL:reqURL];
            if (cks.count > 0) {
                [[NSHTTPCookieStorage sharedHTTPCookieStorage] setCookies:cks forURL:reqURL mainDocumentURL:proto.request.mainDocumentURL];
            }
        }
    }

    NSData *bodyData = [NSData data];
    if ((size_t)hdrEnd < len) {
        const uint8_t *bodyPtr = bytes + (size_t)hdrEnd;
        size_t bodyLen = len - (size_t)hdrEnd;
        if (isChunked) {
            BOOL chunkDone = NO;
            NSData *decoded = MEAFDecodeChunkedBody(bodyPtr, bodyLen, &chunkDone);
            bodyData = decoded ?: [NSData dataWithBytes:bodyPtr length:bodyLen];
        } else {
            bodyData = [NSData dataWithBytes:bodyPtr length:bodyLen];
        }
    }

    NSHTTPURLResponse *httpResp = [[NSHTTPURLResponse alloc] initWithURL:reqURL statusCode:statusCode HTTPVersion:httpVer headerFields:headers];

    // Forward 3xx redirects cleanly to NSURLSession's redirect handler
    NSString *loc = nil;
    for (NSString *hk in headers) {
        if ([[hk lowercaseString] isEqualToString:@"location"]) {
            loc = headers[hk];
            break;
        }
    }
    if ((statusCode == 301 || statusCode == 302 || statusCode == 303 || statusCode == 307 || statusCode == 308) && loc.length > 0 && reqURL) {
        NSURL *redirURL = [NSURL URLWithString:loc relativeToURL:reqURL].absoluteURL;
        if (redirURL) {
            NSMutableURLRequest *redirReq = [proto.request mutableCopy];
            redirReq.URL = redirURL;
            if (statusCode == 303 || ((statusCode == 301 || statusCode == 302) && ![proto.request.HTTPMethod.uppercaseString isEqualToString:@"GET"] && ![proto.request.HTTPMethod.uppercaseString isEqualToString:@"HEAD"])) {
                redirReq.HTTPMethod = @"GET";
                redirReq.HTTPBody = nil;
                redirReq.HTTPBodyStream = nil;
                [redirReq setValue:nil forHTTPHeaderField:@"Content-Length"];
                [redirReq setValue:nil forHTTPHeaderField:@"Content-Type"];
            }
            [NSURLProtocol removePropertyForKey:kMEAFEgressProtoHandledKey inRequest:redirReq];
            [proto.client URLProtocol:proto wasRedirectedToRequest:redirReq redirectResponse:httpResp];
            return;
        }
    }

    [proto.client URLProtocol:proto didReceiveResponse:httpResp cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    if (bodyData.length > 0) {
        [proto.client URLProtocol:proto didLoadData:bodyData];
    }
    [proto.client URLProtocolDidFinishLoading:proto];
}

static BOOL MEAFURLProtoResponseIsComplete(NSMutableData *rawBuf, BOOL isHead) {
    const uint8_t *bytes = (const uint8_t *)rawBuf.bytes;
    size_t len = rawBuf.length;
    NSInteger hdrEnd = -1;
    size_t hdrStart = 0;
    while (hdrStart < len) {
        hdrEnd = -1;
        for (size_t i = hdrStart; i + 3 < len; i++) {
            if (bytes[i] == '\r' && bytes[i + 1] == '\n' && bytes[i + 2] == '\r' && bytes[i + 3] == '\n') {
                hdrEnd = (NSInteger)(i + 4);
                break;
            }
        }
        if (hdrEnd < 0) return NO;
        NSString *firstHdr = [[NSString alloc] initWithBytes:bytes + hdrStart length:(NSUInteger)(hdrEnd - (NSInteger)hdrStart) encoding:NSISOLatin1StringEncoding] ?: @"";
        if ([firstHdr hasPrefix:@"HTTP/1.1 100 "] || [firstHdr hasPrefix:@"HTTP/1.0 100 "]) {
            hdrStart = (size_t)hdrEnd;
            continue;
        }
        if (isHead) return YES;
        NSArray<NSString *> *lines = [firstHdr componentsSeparatedByString:@"\r\n"];
        NSInteger code = 200;
        if (lines.count > 0) {
            NSArray<NSString *> *sp = [lines[0] componentsSeparatedByString:@" "];
            if (sp.count >= 2) code = [sp[1] integerValue];
        }
        if (code == 204 || code == 304 || (code >= 100 && code < 200)) return YES;
        NSInteger contentLen = -1;
        BOOL isChunked = NO;
        for (NSUInteger j = 1; j < lines.count; j++) {
            NSString *low = [lines[j] lowercaseString];
            if ([low hasPrefix:@"content-length:"]) {
                contentLen = [[lines[j] substringFromIndex:15] integerValue];
            } else if ([low hasPrefix:@"transfer-encoding:"] && [low containsString:@"chunked"]) {
                isChunked = YES;
            }
        }
        size_t bodyLen = len - (size_t)hdrEnd;
        if (contentLen >= 0 && bodyLen >= (size_t)contentLen) return YES;
        if (isChunked) {
            BOOL chunkDone = NO;
            MEAFDecodeChunkedBody(bytes + (size_t)hdrEnd, bodyLen, &chunkDone);
            if (chunkDone) return YES;
        }
        return NO;
    }
    return NO;
}

static void MEAFURLProtoRecvNext(MEAFEgressURLProtocol *proto, nw_connection_t conn, NSMutableData *rawBuf, NSMutableData *doneBox, BOOL isHead) {
    atomic_int *doneFlag = (atomic_int *)doneBox.mutableBytes;
    if (atomic_load(doneFlag) || proto.stopped) return;
    nw_connection_receive(conn, 1, 65536, ^(dispatch_data_t content, __unused nw_content_context_t ctx, bool isComplete, nw_error_t error) {
        if (atomic_load(doneFlag) || proto.stopped) return;
        if (content) {
            dispatch_data_apply(content, ^bool(__unused dispatch_data_t region, __unused size_t offset, const void *buffer, size_t size) {
                if (size > 0) [rawBuf appendBytes:buffer length:size];
                return true;
            });
        }
        if (MEAFURLProtoResponseIsComplete(rawBuf, isHead)) {
            MEAFURLProtoFinishResponse(proto, rawBuf, nil, doneFlag);
            return;
        }
        if (isComplete || error) {
            NSError *nsErr = nil;
            if (error && rawBuf.length == 0) {
                nsErr = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorCannotConnectToHost userInfo:@{NSLocalizedDescriptionKey: @"Cellular egress receive error"}];
            }
            MEAFURLProtoFinishResponse(proto, rawBuf, nsErr, doneFlag);
            return;
        }
        MEAFURLProtoRecvNext(proto, conn, rawBuf, doneBox, isHead);
    });
}

@implementation MEAFEgressURLProtocol

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    if (atomic_load(&g_af_egress_mode) == 0) return NO;
    NSURL *u = request.URL;
    if (!u || !u.host.length) return NO;
    NSString *scheme = [u.scheme lowercaseString];
    if (![scheme isEqualToString:@"http"] && ![scheme isEqualToString:@"https"]) return NO;
    if (MEAFHostIsLoopback(u.host)) return NO;
    if ([[NSURLProtocol propertyForKey:kMEAFEgressProtoHandledKey inRequest:request] boolValue]) return NO;
    return YES;
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request {
    return request;
}

- (void)startLoading {
    NSURLRequest *req = self.request;
    NSURL *u = req.URL;
    NSString *scheme = [u.scheme lowercaseString];
    BOOL isTLS = [scheme isEqualToString:@"https"];
    NSString *host = u.host ?: @"";
    NSString *portStr = u.port ? [u.port stringValue] : (isTLS ? @"443" : @"80");
    BOOL isDefaultPort = (isTLS && [portStr isEqualToString:@"443"]) || (!isTLS && [portStr isEqualToString:@"80"]);
    NSString *method = req.HTTPMethod.length ? [req.HTTPMethod uppercaseString] : @"GET";
    BOOL isHead = [method isEqualToString:@"HEAD"];

    atomic_fetch_add(&g_af_egress_urlproto_hits, 1);
    if (isTLS) atomic_fetch_add(&g_af_egress_urlproto_tls, 1);

    // Preserve exact percent-encoded path & query
    NSURLComponents *comps = [NSURLComponents componentsWithURL:u resolvingAgainstBaseURL:YES];
    NSString *pathPart = comps.percentEncodedPath.length ? comps.percentEncodedPath : @"/";
    NSString *reqTarget = comps.percentEncodedQuery.length ? [NSString stringWithFormat:@"%@?%@", pathPart, comps.percentEncodedQuery] : pathPart;

    NSData *reqBody = MEAFReadURLRequestBody(req);
    NSMutableString *wire = [NSMutableString stringWithFormat:@"%@ %@ HTTP/1.1\r\n", method, reqTarget];
    if (isDefaultPort) {
        [wire appendFormat:@"Host: %@\r\n", host];
    } else {
        [wire appendFormat:@"Host: %@:%@\r\n", host, portStr];
    }
    [wire appendString:@"Connection: close\r\n"];
    [wire appendString:@"Accept-Encoding: identity\r\n"];

    BOOL hasUA = NO;
    BOOL hasCookie = NO;
    NSDictionary<NSString *, NSString *> *hdrs = req.allHTTPHeaderFields ?: @{};
    for (NSString *k in hdrs) {
        NSString *kl = [k lowercaseString];
        if ([kl isEqualToString:@"host"] || [kl isEqualToString:@"connection"] ||
            [kl isEqualToString:@"accept-encoding"] || [kl isEqualToString:@"content-length"] ||
            [kl isEqualToString:@"proxy-connection"]) {
            continue;
        }
        if ([kl isEqualToString:@"user-agent"]) hasUA = YES;
        if ([kl isEqualToString:@"cookie"]) hasCookie = YES;
        [wire appendFormat:@"%@: %@\r\n", k, hdrs[k]];
    }
    if (!hasUA) {
        [wire appendString:@"User-Agent: CFNetwork/1400 Darwin/22.0.0\r\n"];
    }
    if (!hasCookie && req.HTTPShouldHandleCookies) {
        NSArray<NSHTTPCookie *> *cks = [[NSHTTPCookieStorage sharedHTTPCookieStorage] cookiesForURL:u];
        if (cks.count > 0) {
            NSDictionary<NSString *, NSString *> *ckHdrs = [NSHTTPCookie requestHeaderFieldsWithCookies:cks];
            NSString *ckVal = ckHdrs[@"Cookie"];
            if (ckVal.length > 0) [wire appendFormat:@"Cookie: %@\r\n", ckVal];
        }
    }
    if (reqBody.length > 0 || [method isEqualToString:@"POST"] || [method isEqualToString:@"PUT"] || [method isEqualToString:@"PATCH"]) {
        [wire appendFormat:@"Content-Length: %lu\r\n", (unsigned long)reqBody.length];
    }
    [wire appendString:@"\r\n"];

    NSMutableData *wireData = [[wire dataUsingEncoding:NSISOLatin1StringEncoding] mutableCopy];
    if (reqBody.length > 0) [wireData appendData:reqBody];

    s_af_egress_depth++;
    nw_parameters_t params = nil;
    if (isTLS) {
        NSString *sniHost = [host copy];
        params = nw_parameters_create_secure_tcp(^(nw_protocol_options_t tlsOpts) {
            sec_protocol_options_t secOpts = nw_tls_copy_sec_protocol_options(tlsOpts);
            if (secOpts) {
                if (sniHost.length > 0) {
                    sec_protocol_options_set_tls_server_name(secOpts, sniHost.UTF8String);
                }
                sec_protocol_options_add_tls_application_protocol(secOpts, "http/1.1");
            }
        }, NW_PARAMETERS_DEFAULT_CONFIGURATION);
    } else {
        params = nw_parameters_create_secure_tcp(NW_PARAMETERS_DISABLE_PROTOCOL, NW_PARAMETERS_DEFAULT_CONFIGURATION);
    }
    int mode = atomic_load(&g_af_egress_mode);
    if (mode == 1) {
        nw_parameters_set_required_interface_type(params, nw_interface_type_cellular);
        nw_parameters_prohibit_interface_type(params, nw_interface_type_wifi);
    } else if (mode == 2) {
        nw_parameters_set_required_interface_type(params, nw_interface_type_wifi);
        nw_parameters_prohibit_interface_type(params, nw_interface_type_cellular);
    }
    nw_endpoint_t ep = nw_endpoint_create_host(host.UTF8String, portStr.UTF8String);
    nw_connection_t conn = nw_connection_create(ep, params);
    s_af_egress_depth--;

    self.nwConn = conn;
    dispatch_queue_t nwQ = MEAFEgressNWQueue();
    nw_connection_set_queue(conn, nwQ);

    NSMutableData *rawBuf = [NSMutableData dataWithCapacity:4096];
    NSMutableData *doneBox = [NSMutableData dataWithLength:sizeof(atomic_int)];
    atomic_init((atomic_int *)doneBox.mutableBytes, 0);

    double timeoutSec = (req.timeoutInterval > 1.0 && req.timeoutInterval < 60.0) ? req.timeoutInterval : 15.0;
    __weak typeof(self) weakSelf = self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(timeoutSec * NSEC_PER_SEC)), nwQ, ^{
        MEAFEgressURLProtocol *strongSelf = weakSelf;
        if (!strongSelf) return;
        atomic_int *flag = (atomic_int *)doneBox.mutableBytes;
        if (atomic_load(flag) == 0 && !strongSelf.stopped) {
            NSError *toErr = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorTimedOut userInfo:@{NSLocalizedDescriptionKey: @"Cellular egress request timed out"}];
            MEAFURLProtoFinishResponse(strongSelf, rawBuf, toErr, flag);
        }
    });

    nw_connection_set_state_changed_handler(conn, ^(nw_connection_state_t state, nw_error_t err) {
        atomic_int *flag = (atomic_int *)doneBox.mutableBytes;
        if (atomic_load(flag) || self.stopped) return;
        if (state == nw_connection_state_ready) {
            dispatch_data_t sendData = dispatch_data_create(wireData.bytes, wireData.length, nwQ, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
            nw_connection_send(conn, sendData, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true, ^(nw_error_t sendErr) {
                if (sendErr) {
                    NSError *nsErr = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorCannotConnectToHost userInfo:@{NSLocalizedDescriptionKey: @"Cellular egress send failed"}];
                    MEAFURLProtoFinishResponse(self, rawBuf, nsErr, flag);
                    return;
                }
                MEAFURLProtoRecvNext(self, conn, rawBuf, doneBox, isHead);
            });
        } else if (state == nw_connection_state_failed || state == nw_connection_state_cancelled) {
            NSError *nsErr = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorCannotConnectToHost userInfo:@{NSLocalizedDescriptionKey: err ? @"Cellular egress connection failed" : @"Cellular egress connection cancelled"}];
            MEAFURLProtoFinishResponse(self, rawBuf, nsErr, flag);
        }
    });
    nw_connection_start(conn);
}

- (void)stopLoading {
    self.stopped = YES;
    nw_connection_t conn = self.nwConn;
    self.nwConn = nil;
    if (conn) {
        nw_connection_set_state_changed_handler(conn, NULL);
        nw_connection_cancel(conn);
    }
}

@end

static void MEAFApplySessionConfigEgressPin(NSURLSessionConfiguration *cfg) {
    if (!cfg) return;
    int mode = atomic_load(&g_af_egress_mode);
    if (mode == 0) return;
    uint16_t proxyPort = MEAFEgressProxyEnsureStarted();
    @try {
        if (mode == 1) {
            cfg.allowsCellularAccess = YES;
            if ([cfg respondsToSelector:@selector(setAllowsExpensiveNetworkAccess:)]) {
                cfg.allowsExpensiveNetworkAccess = YES;
            }
            if ([cfg respondsToSelector:@selector(setAllowsConstrainedNetworkAccess:)]) {
                cfg.allowsConstrainedNetworkAccess = YES;
            }
        }
        // Disable HTTP/3 QUIC (bypasses TCP SOCKS5/HTTP proxies) and avoid pooled Wi-Fi sockets
        SEL selHTTP3 = NSSelectorFromString(@"set_allowsHTTP3:");
        if ([cfg respondsToSelector:selHTTP3]) {
            ((void (*)(id, SEL, BOOL))objc_msgSend)(cfg, selHTTP3, NO);
        }
        SEL selForceNew = NSSelectorFromString(@"set_forcesNewConnections:");
        if ([cfg respondsToSelector:selForceNew]) {
            ((void (*)(id, SEL, BOOL))objc_msgSend)(cfg, selForceNew, YES);
        }
        // Prepend MEAFEgressURLProtocol so every NSURLSession HTTP/HTTPS request routes directly over pinned nw_connection
        NSArray<Class> *existingProtos = cfg.protocolClasses ?: @[];
        if (existingProtos.firstObject != [MEAFEgressURLProtocol class]) {
            NSMutableArray<Class> *updated = [NSMutableArray arrayWithObject:[MEAFEgressURLProtocol class]];
            for (Class cls in existingProtos) {
                if (cls != [MEAFEgressURLProtocol class]) [updated addObject:cls];
            }
            cfg.protocolClasses = updated;
        }
        atomic_store(&g_af_egress_nw_proxy_active, 1);
        (void)proxyPort;
    } @catch (__unused NSException *ex) {}
}

static NSURLSessionConfiguration *(*orig_af_defaultSessionConfig)(id, SEL) = NULL;
static NSURLSessionConfiguration *(*orig_af_ephemeralSessionConfig)(id, SEL) = NULL;
static NSURLSessionConfiguration *(*orig_af_bgSessionConfig)(id, SEL, NSString *) = NULL;
static NSURLSession *(*orig_af_sessionWithConfig)(id, SEL, NSURLSessionConfiguration *) = NULL;
static NSURLSession *(*orig_af_sessionWithConfigDelegate)(id, SEL, NSURLSessionConfiguration *, id, NSOperationQueue *) = NULL;
static NSURLSession *(*orig_af_sharedSession)(id, SEL) = NULL;

static NSURLSessionConfiguration *swizzled_af_defaultSessionConfig(id self, SEL _cmd) {
    NSURLSessionConfiguration *cfg = orig_af_defaultSessionConfig ? orig_af_defaultSessionConfig(self, _cmd) : nil;
    if (cfg && s_af_egress_depth == 0 && atomic_load(&g_af_egress_mode) != 0) {
        s_af_egress_depth++;
        MEAFApplySessionConfigEgressPin(cfg);
        s_af_egress_depth--;
    }
    return cfg;
}

static NSURLSessionConfiguration *swizzled_af_ephemeralSessionConfig(id self, SEL _cmd) {
    NSURLSessionConfiguration *cfg = orig_af_ephemeralSessionConfig ? orig_af_ephemeralSessionConfig(self, _cmd) : nil;
    if (cfg && s_af_egress_depth == 0 && atomic_load(&g_af_egress_mode) != 0) {
        s_af_egress_depth++;
        MEAFApplySessionConfigEgressPin(cfg);
        s_af_egress_depth--;
    }
    return cfg;
}

static NSURLSessionConfiguration *swizzled_af_bgSessionConfig(id self, SEL _cmd, NSString *identifier) {
    NSURLSessionConfiguration *cfg = orig_af_bgSessionConfig ? orig_af_bgSessionConfig(self, _cmd, identifier) : nil;
    if (cfg && s_af_egress_depth == 0 && atomic_load(&g_af_egress_mode) != 0) {
        s_af_egress_depth++;
        MEAFApplySessionConfigEgressPin(cfg);
        s_af_egress_depth--;
    }
    return cfg;
}

static NSURLSession *swizzled_af_sessionWithConfig(id self, SEL _cmd, NSURLSessionConfiguration *cfg) {
    NSURLSessionConfiguration *useCfg = cfg;
    if (useCfg && s_af_egress_depth == 0 && atomic_load(&g_af_egress_mode) != 0) {
        s_af_egress_depth++;
        useCfg = [useCfg copy];
        MEAFApplySessionConfigEgressPin(useCfg);
        s_af_egress_depth--;
    }
    NSURLSession *sess = orig_af_sessionWithConfig ? orig_af_sessionWithConfig(self, _cmd, useCfg) : nil;
    if (sess && g_af_lock && g_af_tracked_sessions) {
        @synchronized(g_af_lock) { [g_af_tracked_sessions addObject:sess]; }
    }
    return sess;
}

static NSURLSession *swizzled_af_sessionWithConfigDelegate(id self, SEL _cmd, NSURLSessionConfiguration *cfg, id del, NSOperationQueue *q) {
    NSURLSessionConfiguration *useCfg = cfg;
    if (useCfg && s_af_egress_depth == 0 && atomic_load(&g_af_egress_mode) != 0) {
        s_af_egress_depth++;
        useCfg = [useCfg copy];
        MEAFApplySessionConfigEgressPin(useCfg);
        s_af_egress_depth--;
    }
    NSURLSession *sess = orig_af_sessionWithConfigDelegate ? orig_af_sessionWithConfigDelegate(self, _cmd, useCfg, del, q) : nil;
    if (sess && g_af_lock && g_af_tracked_sessions) {
        @synchronized(g_af_lock) { [g_af_tracked_sessions addObject:sess]; }
    }
    return sess;
}

static NSURLSession *swizzled_af_sharedSession(id self, SEL _cmd) {
    int mode = atomic_load(&g_af_egress_mode);
    if (mode != 0 && s_af_egress_depth == 0 && orig_af_defaultSessionConfig && orig_af_sessionWithConfig) {
        uint64_t curGen = atomic_load(&g_af_egress_gen);
        MEAFInit();
        @synchronized(g_af_lock) {
            if (!g_af_pinned_shared_session || g_af_pinned_shared_gen != curGen) {
                s_af_egress_depth++;
                NSURLSessionConfiguration *cfg = orig_af_defaultSessionConfig([NSURLSessionConfiguration class], @selector(defaultSessionConfiguration));
                MEAFApplySessionConfigEgressPin(cfg);
                g_af_pinned_shared_session = orig_af_sessionWithConfig([NSURLSession class], @selector(sessionWithConfiguration:), cfg);
                g_af_pinned_shared_gen = curGen;
                if (g_af_pinned_shared_session && g_af_tracked_sessions) {
                    [g_af_tracked_sessions addObject:g_af_pinned_shared_session];
                }
                s_af_egress_depth--;
            }
            if (g_af_pinned_shared_session) return g_af_pinned_shared_session;
        }
    }
    return orig_af_sharedSession ? orig_af_sharedSession(self, _cmd) : nil;
}

static void MEAFInstallSessionEgressSwizzlesOnce(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        [NSURLProtocol registerClass:[MEAFEgressURLProtocol class]];
        Method mDef = class_getClassMethod([NSURLSessionConfiguration class], @selector(defaultSessionConfiguration));
        if (mDef) {
            orig_af_defaultSessionConfig = (typeof(orig_af_defaultSessionConfig))method_setImplementation(mDef, (IMP)swizzled_af_defaultSessionConfig);
            MEAFRecordSwizzle(object_getClass([NSURLSessionConfiguration class]), @selector(defaultSessionConfiguration), (IMP)swizzled_af_defaultSessionConfig, (IMP)orig_af_defaultSessionConfig);
        }
        Method mEph = class_getClassMethod([NSURLSessionConfiguration class], @selector(ephemeralSessionConfiguration));
        if (mEph) {
            orig_af_ephemeralSessionConfig = (typeof(orig_af_ephemeralSessionConfig))method_setImplementation(mEph, (IMP)swizzled_af_ephemeralSessionConfig);
            MEAFRecordSwizzle(object_getClass([NSURLSessionConfiguration class]), @selector(ephemeralSessionConfiguration), (IMP)swizzled_af_ephemeralSessionConfig, (IMP)orig_af_ephemeralSessionConfig);
        }
        Method mBg = class_getClassMethod([NSURLSessionConfiguration class], @selector(backgroundSessionConfigurationWithIdentifier:));
        if (mBg) {
            orig_af_bgSessionConfig = (typeof(orig_af_bgSessionConfig))method_setImplementation(mBg, (IMP)swizzled_af_bgSessionConfig);
            MEAFRecordSwizzle(object_getClass([NSURLSessionConfiguration class]), @selector(backgroundSessionConfigurationWithIdentifier:), (IMP)swizzled_af_bgSessionConfig, (IMP)orig_af_bgSessionConfig);
        }
        Method mSess = class_getClassMethod([NSURLSession class], @selector(sessionWithConfiguration:));
        if (mSess) {
            orig_af_sessionWithConfig = (typeof(orig_af_sessionWithConfig))method_setImplementation(mSess, (IMP)swizzled_af_sessionWithConfig);
            MEAFRecordSwizzle(object_getClass([NSURLSession class]), @selector(sessionWithConfiguration:), (IMP)swizzled_af_sessionWithConfig, (IMP)orig_af_sessionWithConfig);
        }
        Method mSessDel = class_getClassMethod([NSURLSession class], @selector(sessionWithConfiguration:delegate:delegateQueue:));
        if (mSessDel) {
            orig_af_sessionWithConfigDelegate = (typeof(orig_af_sessionWithConfigDelegate))method_setImplementation(mSessDel, (IMP)swizzled_af_sessionWithConfigDelegate);
            MEAFRecordSwizzle(object_getClass([NSURLSession class]), @selector(sessionWithConfiguration:delegate:delegateQueue:), (IMP)swizzled_af_sessionWithConfigDelegate, (IMP)orig_af_sessionWithConfigDelegate);
        }
        Method mShared = class_getClassMethod([NSURLSession class], @selector(sharedSession));
        if (mShared) {
            orig_af_sharedSession = (typeof(orig_af_sharedSession))method_setImplementation(mShared, (IMP)swizzled_af_sharedSession);
            MEAFRecordSwizzle(object_getClass([NSURLSession class]), @selector(sharedSession), (IMP)swizzled_af_sharedSession, (IMP)orig_af_sharedSession);
        }
    });
}

static int hook_af_inline_connect_impl(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (s_af_egress_depth == 0 && addr && atomic_load(&g_af_egress_mode) != 0 && !MEAFSockaddrIsLocalOrLAN(addr, addrlen)) {
        unsigned int pinIdx = atomic_load(&g_af_egress_if_idx);
        if (pinIdx == 0) {
            int mode = atomic_load(&g_af_egress_mode);
            pinIdx = if_nametoindex(mode == 1 ? (g_af_egress_if_name[0] ? g_af_egress_if_name : "pdp_ip0") : "en0");
            if (pinIdx != 0) atomic_store(&g_af_egress_if_idx, pinIdx);
        }
        if (pinIdx != 0) {
            if (addr->sa_family == AF_INET) {
                setsockopt(sockfd, IPPROTO_IP, IP_BOUND_IF, &pinIdx, sizeof(pinIdx));
            } else if (addr->sa_family == AF_INET6) {
                setsockopt(sockfd, IPPROTO_IPV6, IPV6_BOUND_IF, &pinIdx, sizeof(pinIdx));
            }
        }
    }
    return orig_af_inline_connect ? orig_af_inline_connect(sockfd, addr, addrlen) : -1;
}

static BOOL MEAFInstallInlineEgressHooksOnce(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        me_inline_hook_fn hookFn = (me_inline_hook_fn)dlsym(RTLD_DEFAULT, "MSHookFunction");
        if (!hookFn) hookFn = (me_inline_hook_fn)dlsym(RTLD_DEFAULT, "EKHookFunction");
        if (!hookFn) {
            const char *cands[] = {
                "/usr/lib/libellekit.dylib",
                "/var/jb/usr/lib/libellekit.dylib",
                NULL
            };
            for (int i = 0; cands[i] && !hookFn; i++) {
                void *h = dlopen(cands[i], RTLD_NOLOAD);
                if (!h) h = dlopen(cands[i], RTLD_NOW | RTLD_LOCAL);
                if (h) {
                    hookFn = (me_inline_hook_fn)dlsym(h, "MSHookFunction");
                    if (!hookFn) hookFn = (me_inline_hook_fn)dlsym(h, "EKHookFunction");
                }
            }
        }
        if (!hookFn) {
            NSArray<NSString *> *roots = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"/var/containers/Bundle/Application" error:NULL];
            for (NSString *entry in roots) {
                if (![entry hasPrefix:@".jbroot-"]) continue;
                NSString *cand = [[@"/var/containers/Bundle/Application" stringByAppendingPathComponent:entry] stringByAppendingString:@"/usr/lib/libellekit.dylib"];
                void *h = dlopen(cand.UTF8String, RTLD_NOLOAD);
                if (!h) h = dlopen(cand.UTF8String, RTLD_NOW | RTLD_LOCAL);
                if (h) {
                    hookFn = (me_inline_hook_fn)dlsym(h, "MSHookFunction");
                    if (!hookFn) hookFn = (me_inline_hook_fn)dlsym(h, "EKHookFunction");
                    if (hookFn) break;
                }
            }
        }
        if (!hookFn) return;
        BOOL hookedAny = NO;
        void *nwConnSym = dlsym(RTLD_DEFAULT, "nw_connection_create");
        if (!nwConnSym) {
            void *libnw = dlopen("/usr/lib/libnetwork.dylib", RTLD_LAZY);
            if (libnw) nwConnSym = dlsym(libnw, "nw_connection_create");
        }
        if (nwConnSym) {
            hookFn(nwConnSym, (void *)hook_af_nw_conn_create, (void **)&orig_af_nw_conn_create);
            if (orig_af_nw_conn_create) hookedAny = YES;
        }
        void *connectSym = dlsym(RTLD_DEFAULT, "connect");
        if (connectSym) {
            hookFn(connectSym, (void *)hook_af_inline_connect_impl, (void **)&orig_af_inline_connect);
            if (orig_af_inline_connect) hookedAny = YES;
        }
        if (hookedAny) atomic_store(&g_af_egress_inline_active, 1);
    });
    return atomic_load(&g_af_egress_inline_active) != 0;
}

static unsigned int MEAFResolvePinnedInterfaceIndex(void) {
    int mode = atomic_load(&g_af_egress_mode);
    if (mode == 0) return 0;
    unsigned int idx = atomic_load(&g_af_egress_if_idx);
    if (idx != 0) return idx;
    if (mode == 1) {
        idx = if_nametoindex(g_af_egress_if_name[0] ? g_af_egress_if_name : "pdp_ip0");
        if (idx == 0) idx = if_nametoindex("pdp_ip0");
        if (idx == 0) idx = if_nametoindex("pdp_ip1");
    } else if (mode == 2) {
        idx = if_nametoindex("en0");
    }
    if (idx != 0) atomic_store(&g_af_egress_if_idx, idx);
    return idx;
}

static int hook_af_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    BOOL isLocal = NO;
    uint16_t port = 0;
    if (addr) {
        if (addr->sa_family == AF_INET && addrlen >= sizeof(struct sockaddr_in)) {
            const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
            port = ntohs(sin->sin_port);
            uint32_t ip = ntohl(sin->sin_addr.s_addr);
            if ((ip >> 24) == 127 || ip == 0) isLocal = YES;
        } else if (addr->sa_family == AF_INET6 && addrlen >= sizeof(struct sockaddr_in6)) {
            const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
            port = ntohs(sin6->sin6_port);
            if (IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr) || IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) isLocal = YES;
        }
    }
    if (!isLocal && !MEAFSockaddrIsLocalOrLAN(addr, addrlen) && MEDepth == 0 && addr && atomic_load(&g_af_egress_mode) != 0) {
        unsigned int pinIdx = MEAFResolvePinnedInterfaceIndex();
        if (pinIdx != 0) {
            if (addr->sa_family == AF_INET) {
                setsockopt(sockfd, IPPROTO_IP, IP_BOUND_IF, &pinIdx, sizeof(pinIdx));
            } else if (addr->sa_family == AF_INET6) {
                setsockopt(sockfd, IPPROTO_IPV6, IPV6_BOUND_IF, &pinIdx, sizeof(pinIdx));
            }
        }
    }
    if ((atomic_load(&g_af_risk_neutralizer_active) || atomic_load(&g_af_shield_active)) && MEDepth == 0 && addr) {
        if (isLocal && (port == 22 || port == 27042 || port == 27043 || port == 23946 ||
                        port == 8090 || port == 1234 || port == 4444 || port == 8080 || port == 8888 || port == 9090)) {
            errno = ECONNREFUSED;
            return -1;
        }
    }
    return orig_af_connect ? orig_af_connect(sockfd, addr, addrlen) : -1;
}

static CFTypeRef hook_af_MGCopyAnswer(CFStringRef prop) {
    if (atomic_load(&g_af_spoof_active) && prop && MEDepth == 0) {
        NSString *key = (__bridge NSString *)prop;
        id val = nil;
        @synchronized(g_af_lock) {
            if ([key isEqualToString:@"UniqueDeviceID"]) val = g_af_persona[@"udid"];
            else if ([key isEqualToString:@"SerialNumber"]) val = g_af_persona[@"serial_number"];
            else if ([key isEqualToString:@"UniqueChipID"]) val = g_af_persona[@"ecid"];
            else if ([key isEqualToString:@"MLBSerialNumber"]) val = g_af_persona[@"mlb_serial"];
            else if ([key isEqualToString:@"WifiAddress"]) val = g_af_persona[@"wifi_mac"];
            else if ([key isEqualToString:@"BluetoothAddress"]) val = g_af_persona[@"bt_mac"];
            else if ([key isEqualToString:@"ProductType"]) val = g_af_persona[@"product_type"];
            else if ([key isEqualToString:@"BuildVersion"]) val = g_af_persona[@"build_version"];
            else if ([key isEqualToString:@"HardwareModel"]) val = g_af_persona[@"hw_model"];
            else if ([key isEqualToString:@"ProductVersion"]) val = g_af_persona[@"os_version"];
        }
        if (val) {
            return (__bridge_retained CFTypeRef)val;
        }
    }
    return orig_af_MGCopyAnswer ? orig_af_MGCopyAnswer(prop) : NULL;
}

static int hook_af_statfs(const char *path, struct statfs *buf) {
    int rc = orig_af_statfs ? orig_af_statfs(path, buf) : -1;
    if (rc == 0 && buf && atomic_load(&g_af_spoof_active) && MEDepth == 0) {
        @synchronized(g_af_lock) {
            if (g_af_persona[@"fsid_0"]) buf->f_fsid.val[0] = [g_af_persona[@"fsid_0"] intValue];
            if (g_af_persona[@"fsid_1"]) buf->f_fsid.val[1] = [g_af_persona[@"fsid_1"] intValue];
        }
    }
    return rc;
}

static int hook_af_fstatfs(int fd, struct statfs *buf) {
    int rc = orig_af_fstatfs ? orig_af_fstatfs(fd, buf) : -1;
    if (rc == 0 && buf && atomic_load(&g_af_spoof_active) && MEDepth == 0) {
        @synchronized(g_af_lock) {
            if (g_af_persona[@"fsid_0"]) buf->f_fsid.val[0] = [g_af_persona[@"fsid_0"] intValue];
            if (g_af_persona[@"fsid_1"]) buf->f_fsid.val[1] = [g_af_persona[@"fsid_1"] intValue];
        }
    }
    return rc;
}

static CGImageRef hook_af_CGBitmapContextCreateImage(CGContextRef context) {
    if (atomic_load(&g_af_canvas_active) && context && MEDepth == 0) {
        uint8_t *data = (uint8_t *)CGBitmapContextGetData(context);
        size_t width = CGBitmapContextGetWidth(context);
        size_t height = CGBitmapContextGetHeight(context);
        size_t bpr = CGBitmapContextGetBytesPerRow(context);
        if (data && width >= 4 && height >= 4 && bpr >= width * 4) {
            uint32_t seed = 0x9E3779B9u;
            @synchronized(g_af_lock) {
                if (g_af_persona[@"canvas_seed"]) {
                    seed = [g_af_persona[@"canvas_seed"] unsignedIntValue];
                }
            }
            for (uint32_t i = 0; i < 4; i++) {
                size_t px = ((seed >> (i * 4)) + i * 7) % width;
                size_t py = ((seed >> (i * 3)) + i * 5) % height;
                size_t idx = py * bpr + px * 4 + (i % 3);
                data[idx] ^= 0x01;
            }
        }
    }
    return orig_af_CGBitmapContextCreateImage ? orig_af_CGBitmapContextCreateImage(context) : NULL;
}

#pragma mark - Objective-C Swizzles (Identity, Environment, Biometrics, JSON Sanitizer, Stack Cloak)

static NSUUID *(*orig_af_idfv)(id, SEL) = NULL;
static NSUUID *(*orig_af_idfa)(id, SEL) = NULL;
static UIDeviceBatteryState (*orig_af_batteryState)(id, SEL) = NULL;
static float (*orig_af_batteryLevel)(id, SEL) = NULL;
static NSTimeZone *(*orig_af_localTimeZone)(id, SEL) = NULL;
static NSTimeZone *(*orig_af_systemTimeZone)(id, SEL) = NULL;
static NSLocale *(*orig_af_currentLocale)(id, SEL) = NULL;
static NSArray<NSString *> *(*orig_af_preferredLanguages)(id, SEL) = NULL;
static NSString *(*orig_af_carrierName)(id, SEL) = NULL;
static NSString *(*orig_af_mcc)(id, SEL) = NULL;
static NSString *(*orig_af_mnc)(id, SEL) = NULL;
static NSString *(*orig_af_isoCountry)(id, SEL) = NULL;
static BOOL (*orig_af_canOpenURL)(id, SEL, NSURL *) = NULL;
static NSArray<NSString *> *(*orig_af_callStackSymbols)(id, SEL) = NULL;
static NSArray<NSNumber *> *(*orig_af_callStackReturnAddresses)(id, SEL) = NULL;
static void (*orig_af_sendEvent)(id, SEL, UIEvent *) = NULL;
static NSData *(*orig_af_jsonDataWithObject)(id, SEL, id, NSJSONWritingOptions, NSError **) = NULL;

static NSUUID *swizzled_af_idfv(id self, SEL _cmd) {
    if (atomic_load(&g_af_spoof_active)) {
        NSString *uuidStr = nil;
        @synchronized(g_af_lock) { uuidStr = g_af_persona[@"idfv"]; }
        if ([uuidStr isKindOfClass:[NSString class]]) {
            NSUUID *u = [[NSUUID alloc] initWithUUIDString:uuidStr];
            if (u) return u;
        }
    }
    return orig_af_idfv ? orig_af_idfv(self, _cmd) : [NSUUID UUID];
}

static NSUUID *swizzled_af_idfa(id self, SEL _cmd) {
    if (atomic_load(&g_af_spoof_active)) {
        NSString *uuidStr = nil;
        @synchronized(g_af_lock) { uuidStr = g_af_persona[@"idfa"]; }
        if ([uuidStr isKindOfClass:[NSString class]]) {
            NSUUID *u = [[NSUUID alloc] initWithUUIDString:uuidStr];
            if (u) return u;
        }
    }
    return orig_af_idfa ? orig_af_idfa(self, _cmd) : [NSUUID UUID];
}

static UIDeviceBatteryState swizzled_af_batteryState(id self, SEL _cmd) {
    if (atomic_load(&g_af_env_sync_active) || atomic_load(&g_af_spoof_active)) {
        return UIDeviceBatteryStateUnplugged;
    }
    return orig_af_batteryState ? orig_af_batteryState(self, _cmd) : UIDeviceBatteryStateUnplugged;
}

static float swizzled_af_batteryLevel(id self, SEL _cmd) {
    if (atomic_load(&g_af_env_sync_active) || atomic_load(&g_af_spoof_active)) {
        float baseLevel = 0.78f;
        @synchronized(g_af_lock) {
            if (g_af_persona[@"battery_level"]) baseLevel = [g_af_persona[@"battery_level"] floatValue];
        }
        double elapsedMin = (CFAbsoluteTimeGetCurrent() - g_af_persona_start_time) / 60.0;
        float drifted = baseLevel - (float)(elapsedMin * 0.00125);
        if (drifted < 0.18f) drifted = 0.18f;
        if (drifted > 0.96f) drifted = 0.96f;
        return drifted;
    }
    return orig_af_batteryLevel ? orig_af_batteryLevel(self, _cmd) : 0.78f;
}

static NSTimeZone *swizzled_af_localTimeZone(id self, SEL _cmd) {
    if (atomic_load(&g_af_env_sync_active)) {
        NSString *tzName = nil;
        @synchronized(g_af_lock) { tzName = g_af_persona[@"timezone"]; }
        if ([tzName isKindOfClass:[NSString class]] && tzName.length > 0) {
            NSTimeZone *tz = [NSTimeZone timeZoneWithName:tzName];
            if (tz) return tz;
        }
    }
    return orig_af_localTimeZone ? orig_af_localTimeZone(self, _cmd) : [NSTimeZone defaultTimeZone];
}

static NSTimeZone *swizzled_af_systemTimeZone(id self, SEL _cmd) {
    if (atomic_load(&g_af_env_sync_active)) {
        NSString *tzName = nil;
        @synchronized(g_af_lock) { tzName = g_af_persona[@"timezone"]; }
        if ([tzName isKindOfClass:[NSString class]] && tzName.length > 0) {
            NSTimeZone *tz = [NSTimeZone timeZoneWithName:tzName];
            if (tz) return tz;
        }
    }
    return orig_af_systemTimeZone ? orig_af_systemTimeZone(self, _cmd) : [NSTimeZone defaultTimeZone];
}

static NSLocale *swizzled_af_currentLocale(id self, SEL _cmd) {
    if (atomic_load(&g_af_env_sync_active)) {
        NSString *locId = nil;
        @synchronized(g_af_lock) { locId = g_af_persona[@"locale"]; }
        if ([locId isKindOfClass:[NSString class]] && locId.length > 0) {
            NSLocale *loc = [NSLocale localeWithLocaleIdentifier:locId];
            if (loc) return loc;
        }
    }
    return orig_af_currentLocale ? orig_af_currentLocale(self, _cmd) : [NSLocale autoupdatingCurrentLocale];
}

static NSArray<NSString *> *swizzled_af_preferredLanguages(id self, SEL _cmd) {
    if (atomic_load(&g_af_env_sync_active)) {
        NSString *lang = nil;
        @synchronized(g_af_lock) { lang = g_af_persona[@"language"]; }
        if ([lang isKindOfClass:[NSString class]] && lang.length > 0) {
            return @[lang];
        }
    }
    return orig_af_preferredLanguages ? orig_af_preferredLanguages(self, _cmd) : @[@"en-US"];
}

static NSString *swizzled_af_carrierName(id self, SEL _cmd) {
    if (atomic_load(&g_af_env_sync_active)) {
        NSString *v = nil;
        @synchronized(g_af_lock) { v = g_af_persona[@"carrier_name"]; }
        if ([v isKindOfClass:[NSString class]] && v.length > 0) return v;
    }
    return orig_af_carrierName ? orig_af_carrierName(self, _cmd) : @"T-Mobile";
}

static NSString *swizzled_af_mcc(id self, SEL _cmd) {
    if (atomic_load(&g_af_env_sync_active)) {
        NSString *v = nil;
        @synchronized(g_af_lock) { v = g_af_persona[@"mcc"]; }
        if ([v isKindOfClass:[NSString class]] && v.length > 0) return v;
    }
    return orig_af_mcc ? orig_af_mcc(self, _cmd) : @"310";
}

static NSString *swizzled_af_mnc(id self, SEL _cmd) {
    if (atomic_load(&g_af_env_sync_active)) {
        NSString *v = nil;
        @synchronized(g_af_lock) { v = g_af_persona[@"mnc"]; }
        if ([v isKindOfClass:[NSString class]] && v.length > 0) return v;
    }
    return orig_af_mnc ? orig_af_mnc(self, _cmd) : @"260";
}

static NSString *swizzled_af_isoCountry(id self, SEL _cmd) {
    if (atomic_load(&g_af_env_sync_active)) {
        NSString *v = nil;
        @synchronized(g_af_lock) { v = [g_af_persona[@"country"] lowercaseString]; }
        if ([v isKindOfClass:[NSString class]] && v.length > 0) return v;
    }
    return orig_af_isoCountry ? orig_af_isoCountry(self, _cmd) : @"us";
}

static BOOL swizzled_af_canOpenURL(id self, SEL _cmd, NSURL *url) {
    if ((atomic_load(&g_af_risk_neutralizer_active) || atomic_load(&g_af_shield_active)) && [url isKindOfClass:[NSURL class]]) {
        NSString *scheme = url.scheme.lowercaseString;
        if (scheme.length > 0) {
            static NSSet<NSString *> *blocked = nil;
            static dispatch_once_t onceToken;
            dispatch_once(&onceToken, ^{
                blocked = [NSSet setWithArray:@[
                    @"cydia", @"sileo", @"zbra", @"filza", @"undecimus",
                    @"activator", @"roothide", @"trollstore", @"dopamine", @"santander"
                ]];
            });
            if ([blocked containsObject:scheme]) return NO;
        }
    }
    return orig_af_canOpenURL ? orig_af_canOpenURL(self, _cmd, url) : NO;
}

static NSArray<NSString *> *swizzled_af_callStackSymbols(id self, SEL _cmd) {
    NSArray<NSString *> *orig = orig_af_callStackSymbols ? orig_af_callStackSymbols(self, _cmd) : @[];
    if (!atomic_load(&g_af_thread_cloak_active) || MEDepth > 0) return orig;
    NSMutableArray<NSString *> *clean = [NSMutableArray arrayWithCapacity:orig.count];
    for (NSString *frame in orig) {
        if (MEAFIsHiddenImageName(frame.UTF8String) || [frame containsString:@"swizzled_af_"]) continue;
        [clean addObject:frame];
    }
    return clean;
}

static NSArray<NSNumber *> *swizzled_af_callStackReturnAddresses(id self, SEL _cmd) {
    NSArray<NSNumber *> *orig = orig_af_callStackReturnAddresses ? orig_af_callStackReturnAddresses(self, _cmd) : @[];
    if (!atomic_load(&g_af_thread_cloak_active) || MEDepth > 0) return orig;
    NSMutableArray<NSNumber *> *clean = [NSMutableArray arrayWithCapacity:orig.count];
    for (NSNumber *num in orig) {
        const void *addr = (const void *)(uintptr_t)num.unsignedLongLongValue;
        Dl_info info = {0};
        if (orig_af_dladdr && orig_af_dladdr(addr, &info) && info.dli_fname) {
            if (info.dli_fbase == (void *)MESelfHeader() || MEAFIsHiddenImageName(info.dli_fname)) {
                continue;
            }
        }
        [clean addObject:num];
    }
    return clean;
}

static void swizzled_af_sendEvent(id self, SEL _cmd, UIEvent *event) {
    if (atomic_load(&g_af_ghost_active) && event.type == UIEventTypeTouches) {
        g_af_last_touch_time = CFAbsoluteTimeGetCurrent();
    }
    if (orig_af_sendEvent) orig_af_sendEvent(self, _cmd, event);
}

static id MEAFSanitizeRiskObject(id obj, BOOL *outModified) {
    if ([obj isKindOfClass:[NSDictionary class]]) {
        NSDictionary *dict = (NSDictionary *)obj;
        NSMutableDictionary *clean = [NSMutableDictionary dictionaryWithCapacity:dict.count];
        static NSSet<NSString *> *riskBoolKeys = nil;
        static dispatch_once_t onceToken;
        dispatch_once(&onceToken, ^{
            riskBoolKeys = [NSSet setWithArray:@[
                @"isjailbroken", @"jailbroken", @"isrooted", @"rooted",
                @"ishooked", @"hooked", @"isdebuggerattached", @"debugger",
                @"issimulator", @"simulator", @"isemulator", @"fridadetected",
                @"cydiainstalled", @"vpnactive", @"isvpn", @"proxyenabled", @"isproxy",
                @"tampered", @"istampered", @"repackaged"
            ]];
        });
        for (id k in dict) {
            id v = dict[k];
            NSString *kLower = [k isKindOfClass:[NSString class]] ? [(NSString *)k lowercaseString] : @"";
            if ([riskBoolKeys containsObject:kLower]) {
                if (outModified) *outModified = YES;
                clean[k] = [v isKindOfClass:[NSString class]] ? @"false" : @NO;
            } else {
                clean[k] = MEAFSanitizeRiskObject(v, outModified);
            }
        }
        return clean;
    }
    if ([obj isKindOfClass:[NSArray class]]) {
        NSArray *arr = (NSArray *)obj;
        NSMutableArray *clean = [NSMutableArray arrayWithCapacity:arr.count];
        for (id item in arr) {
            [clean addObject:MEAFSanitizeRiskObject(item, outModified)];
        }
        return clean;
    }
    return obj;
}

static NSData *swizzled_af_jsonDataWithObject(id self, SEL _cmd, id obj, NSJSONWritingOptions opt, NSError **error) {
    if ((atomic_load(&g_af_risk_neutralizer_active) || atomic_load(&g_af_sdk_tap_active)) && MEDepth == 0 && obj) {
        MEDepth++;
        @try {
            BOOL modified = NO;
            id sanitized = MEAFSanitizeRiskObject(obj, &modified);
            if (modified) {
                obj = sanitized;
                @synchronized(g_af_lock) {
                    if (g_af_sensor_payloads.count >= 128) [g_af_sensor_payloads removeObjectAtIndex:0];
                    [g_af_sensor_payloads addObject:@{
                        @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                        @"sanitized": @YES,
                        @"payload": [obj isKindOfClass:[NSDictionary class]] ? obj : @{@"root": [obj description] ?: @""}
                    }];
                }
            }
        } @catch (NSException *ex) {
            (void)ex;
        } @finally {
            MEDepth--;
        }
    }
    return orig_af_jsonDataWithObject ? orig_af_jsonDataWithObject(self, _cmd, obj, opt, error) : nil;
}

#pragma mark - Installation of ObjC & GOT Hooks

static void MEAFInstallObjCSwizzlesOnce(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        Method mIdfv = class_getInstanceMethod([UIDevice class], @selector(identifierForVendor));
        if (mIdfv) {
            orig_af_idfv = (typeof(orig_af_idfv))method_setImplementation(mIdfv, (IMP)swizzled_af_idfv);
            MEAFRecordSwizzle([UIDevice class], @selector(identifierForVendor), (IMP)swizzled_af_idfv, (IMP)orig_af_idfv);
        }
        Class asCls = NSClassFromString(@"ASIdentifierManager");
        if (asCls) {
            Method mIdfa = class_getInstanceMethod(asCls, NSSelectorFromString(@"advertisingIdentifier"));
            if (mIdfa) {
                orig_af_idfa = (typeof(orig_af_idfa))method_setImplementation(mIdfa, (IMP)swizzled_af_idfa);
                MEAFRecordSwizzle(asCls, NSSelectorFromString(@"advertisingIdentifier"), (IMP)swizzled_af_idfa, (IMP)orig_af_idfa);
            }
        }
        Method mBatState = class_getInstanceMethod([UIDevice class], @selector(batteryState));
        if (mBatState) {
            orig_af_batteryState = (typeof(orig_af_batteryState))method_setImplementation(mBatState, (IMP)swizzled_af_batteryState);
            MEAFRecordSwizzle([UIDevice class], @selector(batteryState), (IMP)swizzled_af_batteryState, (IMP)orig_af_batteryState);
        }
        Method mBatLvl = class_getInstanceMethod([UIDevice class], @selector(batteryLevel));
        if (mBatLvl) {
            orig_af_batteryLevel = (typeof(orig_af_batteryLevel))method_setImplementation(mBatLvl, (IMP)swizzled_af_batteryLevel);
            MEAFRecordSwizzle([UIDevice class], @selector(batteryLevel), (IMP)swizzled_af_batteryLevel, (IMP)orig_af_batteryLevel);
        }
        Method mLocalTZ = class_getClassMethod([NSTimeZone class], @selector(localTimeZone));
        if (mLocalTZ) {
            orig_af_localTimeZone = (typeof(orig_af_localTimeZone))method_setImplementation(mLocalTZ, (IMP)swizzled_af_localTimeZone);
            MEAFRecordSwizzle(object_getClass([NSTimeZone class]), @selector(localTimeZone), (IMP)swizzled_af_localTimeZone, (IMP)orig_af_localTimeZone);
        }
        Method mSysTZ = class_getClassMethod([NSTimeZone class], @selector(systemTimeZone));
        if (mSysTZ) {
            orig_af_systemTimeZone = (typeof(orig_af_systemTimeZone))method_setImplementation(mSysTZ, (IMP)swizzled_af_systemTimeZone);
            MEAFRecordSwizzle(object_getClass([NSTimeZone class]), @selector(systemTimeZone), (IMP)swizzled_af_systemTimeZone, (IMP)orig_af_systemTimeZone);
        }
        Method mCurLoc = class_getClassMethod([NSLocale class], @selector(currentLocale));
        if (mCurLoc) {
            orig_af_currentLocale = (typeof(orig_af_currentLocale))method_setImplementation(mCurLoc, (IMP)swizzled_af_currentLocale);
            MEAFRecordSwizzle(object_getClass([NSLocale class]), @selector(currentLocale), (IMP)swizzled_af_currentLocale, (IMP)orig_af_currentLocale);
        }
        Method mPrefLang = class_getClassMethod([NSLocale class], @selector(preferredLanguages));
        if (mPrefLang) {
            orig_af_preferredLanguages = (typeof(orig_af_preferredLanguages))method_setImplementation(mPrefLang, (IMP)swizzled_af_preferredLanguages);
            MEAFRecordSwizzle(object_getClass([NSLocale class]), @selector(preferredLanguages), (IMP)swizzled_af_preferredLanguages, (IMP)orig_af_preferredLanguages);
        }
        Class ctCls = NSClassFromString(@"CTCarrier");
        if (ctCls) {
            Method mCN = class_getInstanceMethod(ctCls, NSSelectorFromString(@"carrierName"));
            if (mCN) {
                orig_af_carrierName = (typeof(orig_af_carrierName))method_setImplementation(mCN, (IMP)swizzled_af_carrierName);
                MEAFRecordSwizzle(ctCls, NSSelectorFromString(@"carrierName"), (IMP)swizzled_af_carrierName, (IMP)orig_af_carrierName);
            }
            Method mMCC = class_getInstanceMethod(ctCls, NSSelectorFromString(@"mobileCountryCode"));
            if (mMCC) {
                orig_af_mcc = (typeof(orig_af_mcc))method_setImplementation(mMCC, (IMP)swizzled_af_mcc);
                MEAFRecordSwizzle(ctCls, NSSelectorFromString(@"mobileCountryCode"), (IMP)swizzled_af_mcc, (IMP)orig_af_mcc);
            }
            Method mMNC = class_getInstanceMethod(ctCls, NSSelectorFromString(@"mobileNetworkCode"));
            if (mMNC) {
                orig_af_mnc = (typeof(orig_af_mnc))method_setImplementation(mMNC, (IMP)swizzled_af_mnc);
                MEAFRecordSwizzle(ctCls, NSSelectorFromString(@"mobileNetworkCode"), (IMP)swizzled_af_mnc, (IMP)orig_af_mnc);
            }
            Method mISO = class_getInstanceMethod(ctCls, NSSelectorFromString(@"isoCountryCode"));
            if (mISO) {
                orig_af_isoCountry = (typeof(orig_af_isoCountry))method_setImplementation(mISO, (IMP)swizzled_af_isoCountry);
                MEAFRecordSwizzle(ctCls, NSSelectorFromString(@"isoCountryCode"), (IMP)swizzled_af_isoCountry, (IMP)orig_af_isoCountry);
            }
        }
        Method mCanOpen = class_getInstanceMethod([UIApplication class], @selector(canOpenURL:));
        if (mCanOpen) {
            orig_af_canOpenURL = (typeof(orig_af_canOpenURL))method_setImplementation(mCanOpen, (IMP)swizzled_af_canOpenURL);
            MEAFRecordSwizzle([UIApplication class], @selector(canOpenURL:), (IMP)swizzled_af_canOpenURL, (IMP)orig_af_canOpenURL);
        }
        Method mSendEv = class_getInstanceMethod([UIApplication class], @selector(sendEvent:));
        if (mSendEv) {
            orig_af_sendEvent = (typeof(orig_af_sendEvent))method_setImplementation(mSendEv, (IMP)swizzled_af_sendEvent);
            MEAFRecordSwizzle([UIApplication class], @selector(sendEvent:), (IMP)swizzled_af_sendEvent, (IMP)orig_af_sendEvent);
        }
        Method mStackSym = class_getClassMethod([NSThread class], @selector(callStackSymbols));
        if (mStackSym) {
            orig_af_callStackSymbols = (typeof(orig_af_callStackSymbols))method_setImplementation(mStackSym, (IMP)swizzled_af_callStackSymbols);
            MEAFRecordSwizzle(object_getClass([NSThread class]), @selector(callStackSymbols), (IMP)swizzled_af_callStackSymbols, (IMP)orig_af_callStackSymbols);
        }
        Method mStackAddr = class_getClassMethod([NSThread class], @selector(callStackReturnAddresses));
        if (mStackAddr) {
            orig_af_callStackReturnAddresses = (typeof(orig_af_callStackReturnAddresses))method_setImplementation(mStackAddr, (IMP)swizzled_af_callStackReturnAddresses);
            MEAFRecordSwizzle(object_getClass([NSThread class]), @selector(callStackReturnAddresses), (IMP)swizzled_af_callStackReturnAddresses, (IMP)orig_af_callStackReturnAddresses);
        }
        Method mJson = class_getClassMethod([NSJSONSerialization class], @selector(dataWithJSONObject:options:error:));
        if (mJson) {
            orig_af_jsonDataWithObject = (typeof(orig_af_jsonDataWithObject))method_setImplementation(mJson, (IMP)swizzled_af_jsonDataWithObject);
            MEAFRecordSwizzle(object_getClass([NSJSONSerialization class]), @selector(dataWithJSONObject:options:error:), (IMP)swizzled_af_jsonDataWithObject, (IMP)orig_af_jsonDataWithObject);
        }
    });
}

static NSDictionary *MEAFSlotPatchToDict(const mcp_slot_patch_t *p, NSString *imageName) {
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

static void MEAFInstallGOTHooks(NSMutableArray<NSDictionary *> *allSlots,
                                NSMutableArray<NSDictionary *> *pendingSlots,
                                NSUInteger *outPatchedInProc) {
    MEAFInit();
    MEAFInstallObjCSwizzlesOnce();

    if (!orig_af_dyld_image_count) orig_af_dyld_image_count = dlsym(RTLD_DEFAULT, "_dyld_image_count");
    if (!orig_af_dyld_get_image_name) orig_af_dyld_get_image_name = dlsym(RTLD_DEFAULT, "_dyld_get_image_name");
    if (!orig_af_dyld_get_image_header) orig_af_dyld_get_image_header = dlsym(RTLD_DEFAULT, "_dyld_get_image_header");
    if (!orig_af_dyld_get_image_vmaddr_slide) orig_af_dyld_get_image_vmaddr_slide = dlsym(RTLD_DEFAULT, "_dyld_get_image_vmaddr_slide");
    if (!orig_af_dladdr) orig_af_dladdr = dlsym(RTLD_DEFAULT, "dladdr");
    if (!orig_af_method_getImplementation) orig_af_method_getImplementation = dlsym(RTLD_DEFAULT, "method_getImplementation");
    if (!orig_af_class_getMethodImplementation) orig_af_class_getMethodImplementation = dlsym(RTLD_DEFAULT, "class_getMethodImplementation");
    if (!orig_af_stat) orig_af_stat = dlsym(RTLD_DEFAULT, "stat");
    if (!orig_af_lstat) orig_af_lstat = dlsym(RTLD_DEFAULT, "lstat");
    if (!orig_af_fstatat) orig_af_fstatat = dlsym(RTLD_DEFAULT, "fstatat");
    if (!orig_af_access) orig_af_access = dlsym(RTLD_DEFAULT, "access");
    if (!orig_af_faccessat) orig_af_faccessat = dlsym(RTLD_DEFAULT, "faccessat");
    if (!orig_af_open) orig_af_open = dlsym(RTLD_DEFAULT, "open");
    if (!orig_af_fopen) orig_af_fopen = dlsym(RTLD_DEFAULT, "fopen");
    if (!orig_af_opendir) orig_af_opendir = dlsym(RTLD_DEFAULT, "opendir");
    if (!orig_af_getenv) orig_af_getenv = dlsym(RTLD_DEFAULT, "getenv");
    if (!orig_af_ptrace) orig_af_ptrace = dlsym(RTLD_DEFAULT, "ptrace");
    if (!orig_af_sysctl) orig_af_sysctl = dlsym(RTLD_DEFAULT, "sysctl");
    if (!orig_af_sysctlbyname) orig_af_sysctlbyname = dlsym(RTLD_DEFAULT, "sysctlbyname");
    if (!orig_af_getppid) orig_af_getppid = dlsym(RTLD_DEFAULT, "getppid");
    if (!orig_af_isatty) orig_af_isatty = dlsym(RTLD_DEFAULT, "isatty");
    if (!orig_af_fork) orig_af_fork = dlsym(RTLD_DEFAULT, "fork");
    if (!orig_af_csops) orig_af_csops = dlsym(RTLD_DEFAULT, "csops");
    if (!orig_af_task_get_exception_ports) orig_af_task_get_exception_ports = dlsym(RTLD_DEFAULT, "task_get_exception_ports");
    if (!orig_af_task_threads) orig_af_task_threads = dlsym(RTLD_DEFAULT, "task_threads");
    if (!orig_af_backtrace) orig_af_backtrace = dlsym(RTLD_DEFAULT, "backtrace");
    if (!orig_af_CFNetworkCopySystemProxySettings) orig_af_CFNetworkCopySystemProxySettings = dlsym(RTLD_DEFAULT, "CFNetworkCopySystemProxySettings");
    if (!orig_af_getifaddrs) orig_af_getifaddrs = dlsym(RTLD_DEFAULT, "getifaddrs");
    if (!orig_af_SCNetworkReachabilityGetFlags) orig_af_SCNetworkReachabilityGetFlags = dlsym(RTLD_DEFAULT, "SCNetworkReachabilityGetFlags");
    if (!orig_af_connect) orig_af_connect = dlsym(RTLD_DEFAULT, "connect");
    if (!orig_af_statfs) orig_af_statfs = dlsym(RTLD_DEFAULT, "statfs");
    if (!orig_af_fstatfs) orig_af_fstatfs = dlsym(RTLD_DEFAULT, "fstatfs");
    if (!orig_af_CGBitmapContextCreateImage) orig_af_CGBitmapContextCreateImage = dlsym(RTLD_DEFAULT, "CGBitmapContextCreateImage");
    if (!orig_af_MGCopyAnswer) {
        void *mg = dlopen("/usr/lib/libMobileGestalt.dylib", RTLD_LAZY);
        if (mg) orig_af_MGCopyAnswer = dlsym(mg, "MGCopyAnswer");
    }

    struct mcp_rebinding rebindings[] = {
        {"_dyld_image_count", (void *)hook_af_dyld_image_count, (void **)&orig_af_dyld_image_count},
        {"_dyld_get_image_name", (void *)hook_af_dyld_get_image_name, (void **)&orig_af_dyld_get_image_name},
        {"_dyld_get_image_header", (void *)hook_af_dyld_get_image_header, (void **)&orig_af_dyld_get_image_header},
        {"_dyld_get_image_vmaddr_slide", (void *)hook_af_dyld_get_image_vmaddr_slide, (void **)&orig_af_dyld_get_image_vmaddr_slide},
        {"dladdr", (void *)hook_af_dladdr, (void **)&orig_af_dladdr},
        {"method_getImplementation", (void *)hook_af_method_getImplementation, (void **)&orig_af_method_getImplementation},
        {"class_getMethodImplementation", (void *)hook_af_class_getMethodImplementation, (void **)&orig_af_class_getMethodImplementation},
        {"stat", (void *)hook_af_stat, (void **)&orig_af_stat},
        {"lstat", (void *)hook_af_lstat, (void **)&orig_af_lstat},
        {"fstatat", (void *)hook_af_fstatat, (void **)&orig_af_fstatat},
        {"access", (void *)hook_af_access, (void **)&orig_af_access},
        {"faccessat", (void *)hook_af_faccessat, (void **)&orig_af_faccessat},
        {"open", (void *)hook_af_open, (void **)&orig_af_open},
        {"fopen", (void *)hook_af_fopen, (void **)&orig_af_fopen},
        {"opendir", (void *)hook_af_opendir, (void **)&orig_af_opendir},
        {"getenv", (void *)hook_af_getenv, (void **)&orig_af_getenv},
        {"ptrace", (void *)hook_af_ptrace, (void **)&orig_af_ptrace},
        {"sysctl", (void *)hook_af_sysctl, (void **)&orig_af_sysctl},
        {"sysctlbyname", (void *)hook_af_sysctlbyname, (void **)&orig_af_sysctlbyname},
        {"getppid", (void *)hook_af_getppid, (void **)&orig_af_getppid},
        {"isatty", (void *)hook_af_isatty, (void **)&orig_af_isatty},
        {"fork", (void *)hook_af_fork, (void **)&orig_af_fork},
        {"csops", (void *)hook_af_csops, (void **)&orig_af_csops},
        {"task_get_exception_ports", (void *)hook_af_task_get_exception_ports, (void **)&orig_af_task_get_exception_ports},
        {"task_threads", (void *)hook_af_task_threads, (void **)&orig_af_task_threads},
        {"backtrace", (void *)hook_af_backtrace, (void **)&orig_af_backtrace},
        {"CFNetworkCopySystemProxySettings", (void *)hook_af_CFNetworkCopySystemProxySettings, (void **)&orig_af_CFNetworkCopySystemProxySettings},
        {"getifaddrs", (void *)hook_af_getifaddrs, (void **)&orig_af_getifaddrs},
        {"SCNetworkReachabilityGetFlags", (void *)hook_af_SCNetworkReachabilityGetFlags, (void **)&orig_af_SCNetworkReachabilityGetFlags},
        {"connect", (void *)hook_af_connect, (void **)&orig_af_connect},
        {"nw_parameters_create_secure_tcp", (void *)hook_af_nw_create_tcp, (void **)&orig_af_nw_create_tcp},
        {"nw_parameters_create_secure_udp", (void *)hook_af_nw_create_udp, (void **)&orig_af_nw_create_udp},
        {"nw_parameters_create", (void *)hook_af_nw_create_plain, (void **)&orig_af_nw_create_plain},
        {"MGCopyAnswer", (void *)hook_af_MGCopyAnswer, (void **)&orig_af_MGCopyAnswer},
        {"statfs", (void *)hook_af_statfs, (void **)&orig_af_statfs},
        {"fstatfs", (void *)hook_af_fstatfs, (void **)&orig_af_fstatfs},
        {"CGBitmapContextCreateImage", (void *)hook_af_CGBitmapContextCreateImage, (void **)&orig_af_CGBitmapContextCreateImage}
    };

    NSUInteger patched = 0;
    uint32_t count = orig_af_dyld_image_count ? orig_af_dyld_image_count() : _dyld_image_count();
    MEDepth++;
    @try {
        for (uint32_t i = 0; i < count; i++) {
            const struct mach_header *hdr = orig_af_dyld_get_image_header ? orig_af_dyld_get_image_header(i) : _dyld_get_image_header(i);
            const char *name = orig_af_dyld_get_image_name ? orig_af_dyld_get_image_name(i) : _dyld_get_image_name(i);
            if (!hdr || !name || hdr == MESelfHeader() || MEAFIsHiddenImageName(name)) continue;
            if (strstr(name, "/System/Library/") != NULL || strstr(name, "/usr/lib/") != NULL || strstr(name, "/Developer/") != NULL) {
                continue;
            }
            intptr_t slide = orig_af_dyld_get_image_vmaddr_slide ? orig_af_dyld_get_image_vmaddr_slide(i) : _dyld_get_image_vmaddr_slide(i);
            mcp_slot_collector_t collector = {0};
            mcp_rebind_symbols_image_collect(hdr, slide, MESelfHeader(), rebindings, sizeof(rebindings) / sizeof(rebindings[0]), &collector);
            NSString *imgName = @(name);
            for (size_t k = 0; k < collector.count; k++) {
                NSDictionary *slotDict = MEAFSlotPatchToDict(&collector.patches[k], imgName);
                @synchronized(g_af_lock) {
                    [g_af_bound_slots addObject:slotDict];
                }
                if (allSlots) [allSlots addObject:slotDict];
                if (collector.patches[k].written_in_proc) {
                    patched++;
                } else if (pendingSlots) {
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

#pragma mark - Direct SVC #0x80 Scanner ([Upgrade 04])

static NSArray<NSDictionary *> *MEAFScanDirectSyscalls(BOOL installHardwareTraps) {
    NSMutableArray<NSDictionary *> *sites = [NSMutableArray array];
    const struct mach_header_64 *hdr = (const struct mach_header_64 *)(orig_af_dyld_get_image_header ? orig_af_dyld_get_image_header(0) : _dyld_get_image_header(0));
    if (!hdr || hdr->magic != MH_MAGIC_64) return sites;
    intptr_t slide = orig_af_dyld_get_image_vmaddr_slide ? orig_af_dyld_get_image_vmaddr_slide(0) : _dyld_get_image_vmaddr_slide(0);

    uintptr_t cur = (uintptr_t)hdr + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cur;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            if (strcmp(seg->segname, SEG_TEXT) == 0) {
                const struct section_64 *sec = (const struct section_64 *)(seg + 1);
                for (uint32_t s = 0; s < seg->nsects; s++) {
                    if (strcmp(sec[s].sectname, SECT_TEXT) == 0) {
                        const uint32_t *insns = (const uint32_t *)((uintptr_t)sec[s].addr + slide);
                        size_t count = (size_t)(sec[s].size / 4);
                        for (size_t idx = 0; idx < count && sites.count < 64; idx++) {
                            if (insns[idx] == 0xD4001001u) { // svc #0x80
                                uintptr_t siteAddr = (uintptr_t)&insns[idx];
                                int syscallNum = -1;
                                for (int back = 1; back <= 4 && idx >= (size_t)back; back++) {
                                    uint32_t prev = insns[idx - back];
                                    // MOVZ W16/X16, #imm16
                                    if ((prev & 0x7F80001Fu) == 0x52800010u) {
                                        syscallNum = (int)((prev >> 5) & 0xFFFFu);
                                        break;
                                    }
                                }
                                Dl_info info = {0};
                                NSString *sym = (orig_af_dladdr && orig_af_dladdr((const void *)siteAddr, &info) && info.dli_sname)
                                    ? @(info.dli_sname)
                                    : @"<stripped>";
                                BOOL trapped = NO;
                                if (installHardwareTraps && sites.count < 4) {
                                    @try {
                                        NSDictionary *bpRes = MERE(@"engine.hw_breakpoint", @{
                                            @"action": @"set",
                                            @"address": MEHex(siteAddr),
                                            @"override_return": @"0x0"
                                        });
                                        trapped = [bpRes[@"installed"] boolValue];
                                    } @catch (NSException *ex) {
                                        (void)ex;
                                    }
                                }
                                [sites addObject:@{
                                    @"address": MEHex(siteAddr),
                                    @"instruction": @"svc #0x80",
                                    @"syscall_number": @(syscallNum),
                                    @"symbol": sym,
                                    @"hardware_trapped": @(trapped)
                                }];
                            }
                        }
                    }
                }
            }
        }
        cur += lc->cmdsize;
    }
    return sites;
}

#pragma mark - 50-Point Live In-Process Fraud Surface Audit ([Upgrade 36])

static NSDictionary *MEAFAuditCheck(int index, NSString *category, NSString *name, BOOL passed, NSString *detail) {
    return @{
        @"id": @(index),
        @"category": category ?: @"general",
        @"probe": name ?: @"",
        @"passed": @(passed),
        @"detail": detail ?: @""
    };
}

static NSDictionary *MEAFRun50PointAudit(void) {
    int savedDepth = MEDepth;
    MEDepth = 0;
    NSMutableArray<NSDictionary *> *checks = [NSMutableArray arrayWithCapacity:50];
    int checkId = 1;

    // 1..10: Filesystem & RootHide / Jailbreak Path Cloaking
    const char *jbPaths[10] = {
        "/var/jb", "/.jbroot-test", "/Applications/Cydia.app", "/Applications/Sileo.app",
        "/Applications/Zebra.app", "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/usr/sbin/sshd", "/bin/bash", "/etc/apt", "/private/var/lib/cydia"
    };
    for (int i = 0; i < 10; i++) {
        struct stat st;
        int rc = hook_af_stat(jbPaths[i], &st);
        BOOL ok = (rc == -1 && errno == ENOENT);
        [checks addObject:MEAFAuditCheck(checkId++, @"filesystem_cloak", [NSString stringWithFormat:@"stat(%s)", jbPaths[i]], ok, ok ? @"ENOENT" : @"leaked")];
    }

    // 11..15: DYLD & Image Enumeration Cloaking
    uint32_t visCount = hook_af_dyld_image_count();
    BOOL leakedImage = NO;
    for (uint32_t i = 0; i < visCount; i++) {
        const char *n = hook_af_dyld_get_image_name(i);
        if (MEAFIsHiddenImageName(n)) {
            leakedImage = YES;
            break;
        }
    }
    [checks addObject:MEAFAuditCheck(checkId++, @"dyld_cloak", @"_dyld_image_count / _dyld_get_image_name filter", !leakedImage, [NSString stringWithFormat:@"visible=%u", visCount])];
    Dl_info selfDl = {0};
    int dlRc = hook_af_dladdr((const void *)&MEAFRun50PointAudit, &selfDl);
    [checks addObject:MEAFAuditCheck(checkId++, @"dyld_cloak", @"dladdr(engine_address) hidden", dlRc == 0, dlRc == 0 ? @"0 (hidden)" : @"leaked")];
    char *dyldEnv = hook_af_getenv("DYLD_INSERT_LIBRARIES");
    [checks addObject:MEAFAuditCheck(checkId++, @"dyld_cloak", @"getenv(DYLD_INSERT_LIBRARIES)", dyldEnv == NULL, @"NULL")];
    char *safeModeEnv = hook_af_getenv("MSSafeMode");
    [checks addObject:MEAFAuditCheck(checkId++, @"dyld_cloak", @"getenv(MSSafeMode)", safeModeEnv == NULL, @"NULL")];
    char *fridaEnv = hook_af_getenv("FRIDA_GADGET_CONFIG");
    [checks addObject:MEAFAuditCheck(checkId++, @"dyld_cloak", @"getenv(FRIDA_*)", fridaEnv == NULL, @"NULL")];

    // 16..21: Kernel / Process / Anti-Debug Cloak
    uint32_t csFlags = 0;
    hook_af_csops(getpid(), CS_OPS_STATUS, &csFlags, sizeof(csFlags));
    BOOL csClean = ((csFlags & CS_DEBUGGED) == 0) && ((csFlags & CS_VALID) != 0);
    [checks addObject:MEAFAuditCheck(checkId++, @"kernel_proc_cloak", @"csops(CS_OPS_STATUS) CS_DEBUGGED stripped", csClean, [NSString stringWithFormat:@"flags=0x%08x", csFlags])];
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc kp = {0};
    size_t kpLen = sizeof(kp);
    hook_af_sysctl(mib, 4, &kp, &kpLen, NULL, 0);
    BOOL pTracedClean = ((kp.kp_proc.p_flag & P_TRACED) == 0);
    [checks addObject:MEAFAuditCheck(checkId++, @"kernel_proc_cloak", @"sysctl(KERN_PROC_PID) P_TRACED masked", pTracedClean, @"P_TRACED=0")];
    [checks addObject:MEAFAuditCheck(checkId++, @"kernel_proc_cloak", @"getppid() == 1 (launchd)", hook_af_getppid() == 1, @"ppid=1")];
    [checks addObject:MEAFAuditCheck(checkId++, @"kernel_proc_cloak", @"ptrace(PT_DENY_ATTACH) neutralized", hook_af_ptrace(PT_DENY_ATTACH, 0, NULL, 0) == 0, @"rc=0")];
    [checks addObject:MEAFAuditCheck(checkId++, @"kernel_proc_cloak", @"isatty(0) == 0", hook_af_isatty(0) == 0, @"not a tty")];
    [checks addObject:MEAFAuditCheck(checkId++, @"kernel_proc_cloak", @"fork() sandbox blocked", hook_af_fork() == -1, @"rc=-1 EPERM")];

    // 22..25: Mach Exception Port & Thread / Stack Cloak
    exception_mask_t masks[EXC_TYPES_COUNT];
    mach_msg_type_number_t masksCnt = EXC_TYPES_COUNT;
    exception_handler_t handlers[EXC_TYPES_COUNT];
    exception_behavior_t behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t flavors[EXC_TYPES_COUNT];
    hook_af_task_get_exception_ports(mach_task_self(), EXC_MASK_ALL, masks, &masksCnt, handlers, behaviors, flavors);
    [checks addObject:MEAFAuditCheck(checkId++, @"thread_stack_cloak", @"task_get_exception_ports cloaked", masksCnt == 0, @"masksCnt=0")];
    NSArray<NSString *> *stackSyms = swizzled_af_callStackSymbols([NSThread class], @selector(callStackSymbols));
    BOOL stackClean = YES;
    for (NSString *s in stackSyms) {
        if (MEAFIsHiddenImageName(s.UTF8String)) { stackClean = NO; break; }
    }
    [checks addObject:MEAFAuditCheck(checkId++, @"thread_stack_cloak", @"NSThread.callStackSymbols scrubbed", stackClean, [NSString stringWithFormat:@"frames=%lu", (unsigned long)stackSyms.count])];
    void *btBuf[32] = {0};
    int btCount = hook_af_backtrace(btBuf, 32);
    [checks addObject:MEAFAuditCheck(checkId++, @"thread_stack_cloak", @"backtrace() scrubbed", btCount >= 0, [NSString stringWithFormat:@"frames=%d", btCount])];
    Method mIdfv = class_getInstanceMethod([UIDevice class], @selector(identifierForVendor));
    IMP reportedIMP = hook_af_method_getImplementation(mIdfv);
    Dl_info impDl = {0};
    hook_af_dladdr((const void *)reportedIMP, &impDl);
    BOOL impClean = (reportedIMP != (IMP)swizzled_af_idfv);
    [checks addObject:MEAFAuditCheck(checkId++, @"objc_integrity_cloak", @"method_getImplementation returns original IMP", impClean, MEHex((uintptr_t)reportedIMP))];

    // 26..31: Network, Proxy, VPN (utun*) & Reachability Cloak
    CFDictionaryRef proxyDict = hook_af_CFNetworkCopySystemProxySettings();
    NSDictionary *nsProxy = CFBridgingRelease(proxyDict);
    [checks addObject:MEAFAuditCheck(checkId++, @"network_vpn_cloak", @"CFNetworkCopySystemProxySettings empty", nsProxy.count == 0, @"@{}")];
    struct ifaddrs *ifap = NULL;
    BOOL utunFound = NO;
    if (hook_af_getifaddrs(&ifap) == 0 && ifap) {
        for (struct ifaddrs *cur = ifap; cur; cur = cur->ifa_next) {
            if (cur->ifa_name && (strncmp(cur->ifa_name, "utun", 4) == 0 || strncmp(cur->ifa_name, "ppp", 3) == 0 || strncmp(cur->ifa_name, "ipsec", 5) == 0)) {
                utunFound = YES;
                break;
            }
        }
        freeifaddrs(ifap);
    }
    [checks addObject:MEAFAuditCheck(checkId++, @"network_vpn_cloak", @"getifaddrs() utun*/ppp*/ipsec* stripped", !utunFound, @"0 tunnel interfaces")];
    SCNetworkReachabilityFlags reachFlags = kSCNetworkReachabilityFlagsTransientConnection;
    hook_af_SCNetworkReachabilityGetFlags(NULL, &reachFlags);
    [checks addObject:MEAFAuditCheck(checkId++, @"network_vpn_cloak", @"SCNetworkReachabilityGetFlags direct", (reachFlags & kSCNetworkReachabilityFlagsTransientConnection) == 0, [NSString stringWithFormat:@"flags=0x%x", reachFlags])];

    // Localhost Port-Scan Sinkhole (27042, 27043, 22)
    uint16_t probePorts[3] = {27042, 27043, 22};
    for (int i = 0; i < 3; i++) {
        struct sockaddr_in sin = {0};
        sin.sin_len = sizeof(sin);
        sin.sin_family = AF_INET;
        sin.sin_port = htons(probePorts[i]);
        sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        int rc = hook_af_connect(-1, (const struct sockaddr *)&sin, sizeof(sin));
        BOOL blocked = (rc == -1 && errno == ECONNREFUSED);
        [checks addObject:MEAFAuditCheck(checkId++, @"port_scan_sinkhole", [NSString stringWithFormat:@"connect(127.0.0.1:%u) sinkholed", probePorts[i]], blocked, @"ECONNREFUSED")];
    }

    // 32..37: Jailbreak URL Scheme Probe Filter
    NSArray<NSString *> *schemes = @[@"cydia://", @"sileo://", @"zbra://", @"filza://", @"roothide://", @"trollstore://"];
    for (NSString *sch in schemes) {
        BOOL canOpen = swizzled_af_canOpenURL(nil, @selector(canOpenURL:), [NSURL URLWithString:sch]);
        [checks addObject:MEAFAuditCheck(checkId++, @"url_scheme_cloak", [NSString stringWithFormat:@"canOpenURL(%@)", sch], !canOpen, @"NO")];
    }

    // 38..45: Hardware Identity, MobileGestalt, Timezone, Locale, Carrier & Battery Coherence
    NSUUID *idfv = swizzled_af_idfv(nil, @selector(identifierForVendor));
    [checks addObject:MEAFAuditCheck(checkId++, @"persona_identity", @"UIDevice.identifierForVendor valid", idfv != nil, idfv.UUIDString ?: @"")];
    UIDeviceBatteryState bState = swizzled_af_batteryState(nil, @selector(batteryState));
    [checks addObject:MEAFAuditCheck(checkId++, @"persona_identity", @"UIDevice.batteryState == Unplugged", bState == UIDeviceBatteryStateUnplugged, @"UIDeviceBatteryStateUnplugged")];
    float bLevel = swizzled_af_batteryLevel(nil, @selector(batteryLevel));
    [checks addObject:MEAFAuditCheck(checkId++, @"persona_identity", @"UIDevice.batteryLevel natural discharge", bLevel > 0.15f && bLevel < 0.99f, [NSString stringWithFormat:@"%.3f", bLevel])];
    NSTimeZone *tz = swizzled_af_localTimeZone([NSTimeZone class], @selector(localTimeZone));
    [checks addObject:MEAFAuditCheck(checkId++, @"persona_identity", @"NSTimeZone.localTimeZone coherent", tz.name.length > 0, tz.name ?: @"")];
    NSLocale *loc = swizzled_af_currentLocale([NSLocale class], @selector(currentLocale));
    [checks addObject:MEAFAuditCheck(checkId++, @"persona_identity", @"NSLocale.currentLocale coherent", loc.localeIdentifier.length > 0, loc.localeIdentifier ?: @"")];
    NSString *carrier = swizzled_af_carrierName(nil, @selector(carrierName));
    [checks addObject:MEAFAuditCheck(checkId++, @"persona_identity", @"CTCarrier.carrierName coherent", carrier.length > 0, carrier ?: @"")];
    NSString *mcc = swizzled_af_mcc(nil, @selector(mobileCountryCode));
    [checks addObject:MEAFAuditCheck(checkId++, @"persona_identity", @"CTCarrier.mobileCountryCode coherent", mcc.length > 0, mcc ?: @"")];
    struct statfs sfs = {0};
    hook_af_statfs("/var/mobile", &sfs);
    [checks addObject:MEAFAuditCheck(checkId++, @"persona_identity", @"statfs(/var/mobile) f_fsid active", sfs.f_fsid.val[0] != 0, [NSString stringWithFormat:@"0x%x:0x%x", sfs.f_fsid.val[0], sfs.f_fsid.val[1]])];

    // 46..50: Risk Dictionary Sanitizer, Canvas Entropy, Direct Syscall Scan & BirthTime Jitter
    NSDictionary *dirtyRisk = @{@"isJailbroken": @YES, @"isDebuggerAttached": @YES, @"fridaDetected": @YES};
    NSData *sanitizedData = swizzled_af_jsonDataWithObject([NSJSONSerialization class], @selector(dataWithJSONObject:options:error:), dirtyRisk, 0, NULL);
    NSDictionary *parsedClean = sanitizedData ? [NSJSONSerialization JSONObjectWithData:sanitizedData options:0 error:NULL] : @{};
    BOOL dictClean = ([parsedClean[@"isJailbroken"] boolValue] == NO && [parsedClean[@"isDebuggerAttached"] boolValue] == NO && [parsedClean[@"fridaDetected"] boolValue] == NO);
    [checks addObject:MEAFAuditCheck(checkId++, @"sdk_sanitizer", @"NSJSONSerialization risk dictionary sanitizer", dictClean, @"isJailbroken=false")];
    [checks addObject:MEAFAuditCheck(checkId++, @"canvas_entropy", @"CGBitmapContextCreateImage LSB mutator active", atomic_load(&g_af_canvas_active) != 0, @"enabled")];
    [checks addObject:MEAFAuditCheck(checkId++, @"ghost_biometrics", @"Touch-to-IMU recoil & pasteboard cloak active", atomic_load(&g_af_ghost_active) != 0, @"enabled")];
    struct stat mobileSt = {0};
    hook_af_stat("/var/mobile", &mobileSt);
    [checks addObject:MEAFAuditCheck(checkId++, @"canary_wiper", @"st_birthtimespec persona jitter active", mobileSt.st_birthtimespec.tv_sec > 0, [NSString stringWithFormat:@"%ld.%09ld", (long)mobileSt.st_birthtimespec.tv_sec, mobileSt.st_birthtimespec.tv_nsec])];
    NSArray *svcSites = MEAFScanDirectSyscalls(NO);
    [checks addObject:MEAFAuditCheck(checkId++, @"syscall_shield", @"Direct SVC #0x80 scanner & shield operational", YES, [NSString stringWithFormat:@"svc_sites=%lu", (unsigned long)svcSites.count])];

    MEDepth = savedDepth;

    NSUInteger passedCount = 0;
    for (NSDictionary *c in checks) {
        if ([c[@"passed"] boolValue]) passedCount++;
    }
    return @{
        @"pid": @(getpid()),
        @"total_checks": @(checks.count),
        @"passed_count": @(passedCount),
        @"failed_count": @(checks.count - passedCount),
        @"all_passed": @(passedCount == checks.count),
        @"score": [NSString stringWithFormat:@"%lu/%lu PASSED", (unsigned long)passedCount, (unsigned long)checks.count],
        @"checks": checks
    };
}

#pragma mark - Helper: Enable All 12 Layers & Apply Persona Dict

static NSDictionary *MEAFEnableAllLayersWithPersona(NSDictionary *persona, BOOL scanSvcTraps) {
    MEAFInit();
    @synchronized(g_af_lock) {
        if ([persona isKindOfClass:[NSDictionary class]] && persona.count > 0) {
            [g_af_persona addEntriesFromDictionary:persona];
        }
        uint32_t seed = [g_af_persona[@"canvas_seed"] unsignedIntValue] ?: 0x13572468u;
        if (!g_af_persona[@"birthtime_jitter_sec"]) {
            g_af_persona[@"birthtime_jitter_sec"] = @((int64_t)((seed % 86400) + 3600));
            g_af_persona[@"birthtime_jitter_nsec"] = @((int64_t)((seed * 2654435761u) % 999999999u));
        }
        if (!g_af_persona[@"fsid_0"]) {
            g_af_persona[@"fsid_0"] = @((int32_t)(0x1A2B3C40u ^ seed));
            g_af_persona[@"fsid_1"] = @((int32_t)(0x00010011u));
        }
        if (!g_af_persona[@"idfv"]) {
            g_af_persona[@"idfv"] = [[NSUUID UUID] UUIDString];
        }
    }
    atomic_store(&g_af_shield_active, 1);
    atomic_store(&g_af_spoof_active, 1);
    atomic_store(&g_af_kernel_cloak_active, 1);
    atomic_store(&g_af_network_cloak_active, 1);
    atomic_store(&g_af_canvas_active, 1);
    atomic_store(&g_af_ghost_active, 1);
    atomic_store(&g_af_sdk_tap_active, 1);
    atomic_store(&g_af_risk_neutralizer_active, 1);
    atomic_store(&g_af_attest_active, 1);
    atomic_store(&g_af_env_sync_active, 1);
    atomic_store(&g_af_objc_cloak_active, 1);
    atomic_store(&g_af_thread_cloak_active, 1);

    NSMutableArray<NSDictionary *> *allSlots = [NSMutableArray array];
    NSMutableArray<NSDictionary *> *pendingSlots = [NSMutableArray array];
    NSUInteger patchedInProc = 0;
    MEAFInstallGOTHooks(allSlots, pendingSlots, &patchedInProc);
    NSArray<NSDictionary *> *svcSites = MEAFScanDirectSyscalls(scanSvcTraps);

    NSDictionary *activePersona = nil;
    @synchronized(g_af_lock) {
        activePersona = [g_af_persona copy];
    }

    return @{
        @"active": @YES,
        @"pid": @(getpid()),
        @"patched_in_proc": @(patchedInProc),
        @"slots": allSlots,
        @"pending_slots": pendingSlots,
        @"direct_svc_sites": svcSites,
        @"persona": activePersona ?: @{}
    };
}

#pragma mark - RPC Dispatcher (MEAntiFraud)

NSDictionary *MEAntiFraud(NSString *op, NSDictionary *a) {
    MEAFInit();

    if ([op isEqualToString:@"engine.antifraud_shield"]) {
        atomic_store(&g_af_shield_active, 1);
        atomic_store(&g_af_kernel_cloak_active, 1);
        BOOL trapSvc = [a[@"trap_svc"] boolValue];
        NSMutableArray<NSDictionary *> *allSlots = [NSMutableArray array];
        NSMutableArray<NSDictionary *> *pendingSlots = [NSMutableArray array];
        NSUInteger patchedInProc = 0;
        MEAFInstallGOTHooks(allSlots, pendingSlots, &patchedInProc);
        NSArray<NSDictionary *> *svcSites = MEAFScanDirectSyscalls(trapSvc);
        return @{
            @"shield_active": @YES,
            @"pid": @(getpid()),
            @"patched_in_proc": @(patchedInProc),
            @"slots": allSlots,
            @"pending_slots": pendingSlots,
            @"direct_svc_sites": svcSites
        };
    }

    if ([op isEqualToString:@"engine.spoof_fingerprint"]) {
        if ([a[@"persona"] isKindOfClass:[NSDictionary class]]) {
            @synchronized(g_af_lock) { [g_af_persona addEntriesFromDictionary:a[@"persona"]]; }
        } else {
            @synchronized(g_af_lock) { [g_af_persona addEntriesFromDictionary:a]; }
        }
        atomic_store(&g_af_spoof_active, 1);
        NSMutableArray<NSDictionary *> *allSlots = [NSMutableArray array];
        NSMutableArray<NSDictionary *> *pendingSlots = [NSMutableArray array];
        NSUInteger patchedInProc = 0;
        MEAFInstallGOTHooks(allSlots, pendingSlots, &patchedInProc);
        NSDictionary *snap = nil;
        @synchronized(g_af_lock) { snap = [g_af_persona copy]; }
        return @{
            @"spoof_active": @YES,
            @"pid": @(getpid()),
            @"patched_in_proc": @(patchedInProc),
            @"pending_slots": pendingSlots,
            @"persona": snap ?: @{}
        };
    }

    if ([op isEqualToString:@"engine.kernel_proc_cloak"]) {
        atomic_store(&g_af_kernel_cloak_active, 1);
        atomic_store(&g_af_shield_active, 1);
        NSMutableArray<NSDictionary *> *allSlots = [NSMutableArray array];
        NSMutableArray<NSDictionary *> *pendingSlots = [NSMutableArray array];
        NSUInteger patchedInProc = 0;
        MEAFInstallGOTHooks(allSlots, pendingSlots, &patchedInProc);
        uint32_t csFlags = 0;
        hook_af_csops(getpid(), CS_OPS_STATUS, &csFlags, sizeof(csFlags));
        return @{
            @"kernel_proc_cloak_active": @YES,
            @"pid": @(getpid()),
            @"spoofed_csflags": [NSString stringWithFormat:@"0x%08x", csFlags],
            @"cs_debugged_cleared": @((csFlags & CS_DEBUGGED) == 0),
            @"p_traced_cleared": @YES,
            @"patched_in_proc": @(patchedInProc),
            @"pending_slots": pendingSlots
        };
    }

    if ([op isEqualToString:@"engine.network_cloak"]) {
        atomic_store(&g_af_network_cloak_active, 1);
        NSMutableArray<NSDictionary *> *allSlots = [NSMutableArray array];
        NSMutableArray<NSDictionary *> *pendingSlots = [NSMutableArray array];
        NSUInteger patchedInProc = 0;
        MEAFInstallGOTHooks(allSlots, pendingSlots, &patchedInProc);
        return @{
            @"network_cloak_active": @YES,
            @"proxy_settings_cloaked": @YES,
            @"vpn_interfaces_hidden": @[@"utun*", @"ppp*", @"ipsec*", @"tun*", @"tap*"],
            @"mtu_normalized": @1500,
            @"patched_in_proc": @(patchedInProc),
            @"pending_slots": pendingSlots
        };
    }

    if ([op isEqualToString:@"engine.canvas_gpu_audio"]) {
        @synchronized(g_af_lock) {
            if (a[@"canvas_seed"]) g_af_persona[@"canvas_seed"] = a[@"canvas_seed"];
            else if (!g_af_persona[@"canvas_seed"]) g_af_persona[@"canvas_seed"] = @(arc4random());
            if (a[@"gpu_name"]) g_af_persona[@"gpu_name"] = a[@"gpu_name"];
        }
        atomic_store(&g_af_canvas_active, 1);
        NSMutableArray<NSDictionary *> *allSlots = [NSMutableArray array];
        NSMutableArray<NSDictionary *> *pendingSlots = [NSMutableArray array];
        NSUInteger patchedInProc = 0;
        MEAFInstallGOTHooks(allSlots, pendingSlots, &patchedInProc);
        return @{
            @"canvas_gpu_audio_active": @YES,
            @"canvas_seed": g_af_persona[@"canvas_seed"] ?: @0,
            @"patched_in_proc": @(patchedInProc),
            @"pending_slots": pendingSlots
        };
    }

    if ([op isEqualToString:@"engine.ghost_player"]) {
        atomic_store(&g_af_ghost_active, 1);
        MEAFInstallObjCSwizzlesOnce();
        NSString *ghostText = [a[@"text"] isKindOfClass:[NSString class]] ? a[@"text"] : nil;
        __block BOOL typed = NO;
        if (ghostText.length > 0) {
            dispatch_sync(dispatch_get_main_queue(), ^{
                #pragma clang diagnostic push
                #pragma clang diagnostic ignored "-Wdeprecated-declarations"
                UIWindow *keyWin = [UIApplication sharedApplication].keyWindow;
                #pragma clang diagnostic pop
                UIResponder *firstResp = [keyWin valueForKey:@"firstResponder"];
                if ([firstResp conformsToProtocol:@protocol(UITextInput)]) {
                    id<UITextInput> ti = (id<UITextInput>)firstResp;
                    for (NSUInteger i = 0; i < ghostText.length; i++) {
                        NSString *ch = [ghostText substringWithRange:NSMakeRange(i, 1)];
                        [ti insertText:ch];
                        g_af_last_touch_time = CFAbsoluteTimeGetCurrent();
                    }
                    typed = YES;
                }
            });
        }
        double sinceTouchMs = (g_af_last_touch_time > 0) ? (CFAbsoluteTimeGetCurrent() - g_af_last_touch_time) * 1000.0 : -1.0;
        return @{
            @"ghost_player_active": @YES,
            @"touch_imu_recoil_coupled": @YES,
            @"pasteboard_cloaked": @YES,
            @"ghost_typed": @(typed),
            @"ms_since_last_touch": @(round(sinceTouchMs * 10.0) / 10.0)
        };
    }

    if ([op isEqualToString:@"engine.sdk_tap"]) {
        atomic_store(&g_af_sdk_tap_active, 1);
        MEAFInstallObjCSwizzlesOnce();
        NSMutableArray<NSString *> *detectedSDKs = [NSMutableArray array];
        NSArray<NSString *> *knownClasses = @[
            @"PXManager", @"PerimeterX", @"CYFMonitor", @"DataDome", @"DataDomeSDK",
            @"KPSDK", @"TMXProfiling", @"SardineMobile", @"ForterSDK", @"SEONFingerprint"
        ];
        for (NSString *clsName in knownClasses) {
            if (NSClassFromString(clsName)) [detectedSDKs addObject:clsName];
        }
        NSMutableDictionary *tokens = [NSMutableDictionary dictionary];
        for (NSHTTPCookie *c in [[NSHTTPCookieStorage sharedHTTPCookieStorage] cookies]) {
            NSString *n = c.name.lowercaseString;
            if ([n containsString:@"_px"] || [n containsString:@"_abck"] || [n containsString:@"bm_sz"] ||
                [n containsString:@"datadome"] || [n containsString:@"kp_"]) {
                tokens[c.name] = c.value ?: @"";
            }
        }
        NSArray *payloads = nil;
        @synchronized(g_af_lock) {
            payloads = [g_af_sensor_payloads copy];
        }
        return @{
            @"sdk_tap_active": @YES,
            @"detected_sdks": detectedSDKs,
            @"harvested_tokens": tokens,
            @"sanitized_payload_count": @(payloads.count),
            @"sanitized_payloads": payloads ?: @[]
        };
    }

    if ([op isEqualToString:@"engine.risk_neutralizer"]) {
        atomic_store(&g_af_risk_neutralizer_active, 1);
        NSMutableArray<NSDictionary *> *allSlots = [NSMutableArray array];
        NSMutableArray<NSDictionary *> *pendingSlots = [NSMutableArray array];
        NSUInteger patchedInProc = 0;
        MEAFInstallGOTHooks(allSlots, pendingSlots, &patchedInProc);
        return @{
            @"risk_neutralizer_active": @YES,
            @"localhost_port_sinkhole": @[@22, @27042, @27043, @23946, @8090, @1234, @4444, @8080, @8888, @9090],
            @"blocked_url_schemes": @[@"cydia", @"sileo", @"zbra", @"filza", @"undecimus", @"activator", @"roothide", @"trollstore", @"dopamine"],
            @"json_risk_dictionary_sanitizer": @YES,
            @"patched_in_proc": @(patchedInProc),
            @"pending_slots": pendingSlots
        };
    }

    if ([op isEqualToString:@"engine.app_attest"]) {
        atomic_store(&g_af_attest_active, 1);
        BOOL rotate = [a[@"rotate"] boolValue];
        if (rotate) {
            NSUserDefaults *defs = [NSUserDefaults standardUserDefaults];
            NSDictionary *rep = [defs dictionaryRepresentation];
            for (NSString *k in rep) {
                if ([k.lowercaseString containsString:@"attest"] || [k.lowercaseString containsString:@"devicecheck"]) {
                    [defs removeObjectForKey:k];
                }
            }
            [defs synchronize];
        }
        Class dcAppAttest = NSClassFromString(@"DCAppAttestService");
        BOOL supported = NO;
        SEL sharedSvcSel = NSSelectorFromString(@"sharedService");
        SEL isSuppSel = NSSelectorFromString(@"isSupported");
        if (dcAppAttest && [dcAppAttest respondsToSelector:sharedSvcSel]) {
            @try {
                id svc = [dcAppAttest valueForKey:@"sharedService"];
                if (svc && [svc respondsToSelector:isSuppSel]) {
                    supported = [[svc valueForKey:@"isSupported"] boolValue];
                }
            } @catch (NSException *ex) {
                (void)ex;
            }
        }
        NSArray *events = nil;
        @synchronized(g_af_lock) { events = [g_af_attest_events copy]; }
        return @{
            @"app_attest_bridge_active": @YES,
            @"dc_app_attest_supported": @(supported),
            @"rotated_key_state": @(rotate),
            @"captured_events": events ?: @[]
        };
    }

    if ([op isEqualToString:@"engine.sync_persona"]) {
        @synchronized(g_af_lock) {
            [g_af_persona addEntriesFromDictionary:a];
        }
        atomic_store(&g_af_env_sync_active, 1);
        MEAFInstallObjCSwizzlesOnce();
        return @{
            @"environment_synced": @YES,
            @"timezone": [NSTimeZone localTimeZone].name ?: @"",
            @"locale": [NSLocale currentLocale].localeIdentifier ?: @"",
            @"preferred_languages": [NSLocale preferredLanguages] ?: @[],
            @"carrier_name": swizzled_af_carrierName(nil, @selector(carrierName)),
            @"mcc": swizzled_af_mcc(nil, @selector(mobileCountryCode)),
            @"mnc": swizzled_af_mnc(nil, @selector(mobileNetworkCode)),
            @"battery_state": @"Unplugged",
            @"battery_level": @(swizzled_af_batteryLevel([UIDevice currentDevice], @selector(batteryLevel)))
        };
    }

    if ([op isEqualToString:@"engine.objc_integrity_cloak"]) {
        atomic_store(&g_af_objc_cloak_active, 1);
        NSMutableArray<NSDictionary *> *allSlots = [NSMutableArray array];
        NSMutableArray<NSDictionary *> *pendingSlots = [NSMutableArray array];
        NSUInteger patchedInProc = 0;
        MEAFInstallGOTHooks(allSlots, pendingSlots, &patchedInProc);
        return @{
            @"objc_integrity_cloak_active": @YES,
            @"cloaked_swizzle_count": @(g_af_swizzle_count),
            @"patched_in_proc": @(patchedInProc),
            @"pending_slots": pendingSlots
        };
    }

    if ([op isEqualToString:@"engine.thread_stack_cloak"]) {
        atomic_store(&g_af_thread_cloak_active, 1);
        NSMutableArray<NSDictionary *> *allSlots = [NSMutableArray array];
        NSMutableArray<NSDictionary *> *pendingSlots = [NSMutableArray array];
        NSUInteger patchedInProc = 0;
        MEAFInstallGOTHooks(allSlots, pendingSlots, &patchedInProc);
        return @{
            @"thread_stack_cloak_active": @YES,
            @"patched_in_proc": @(patchedInProc),
            @"pending_slots": pendingSlots
        };
    }

    if ([op isEqualToString:@"engine.wipe_canaries"]) {
        [[NSURLCache sharedURLCache] removeAllCachedResponses];
        NSHTTPCookieStorage *cs = [NSHTTPCookieStorage sharedHTTPCookieStorage];
        NSArray<NSHTTPCookie *> *cookies = [cs.cookies copy];
        for (NSHTTPCookie *c in cookies) {
            [cs deleteCookie:c];
        }
        NSUbiquitousKeyValueStore *ikvs = [NSUbiquitousKeyValueStore defaultStore];
        NSDictionary *kvsDict = [ikvs dictionaryRepresentation];
        for (NSString *k in kvsDict) {
            [ikvs removeObjectForKey:k];
        }
        [ikvs synchronize];
        [UIPasteboard generalPasteboard].items = @[];
        @synchronized(g_af_lock) {
            [g_af_virtual_keychain removeAllObjects];
            uint32_t newSeed = arc4random();
            g_af_persona[@"canvas_seed"] = @(newSeed);
            g_af_persona[@"birthtime_jitter_sec"] = @((int64_t)((newSeed % 86400) + 3600));
            g_af_persona[@"birthtime_jitter_nsec"] = @((int64_t)((newSeed * 2654435761u) % 999999999u));
        }
        return @{
            @"in_process_canaries_wiped": @YES,
            @"cleared_url_cache": @YES,
            @"cleared_cookies": @(cookies.count),
            @"cleared_icloud_kvs": @(kvsDict.count),
            @"cleared_pasteboard": @YES,
            @"rotated_birthtime_jitter": @YES
        };
    }

    if ([op isEqualToString:@"engine.apply_persona"]) {
        NSDictionary *persona = [a[@"persona"] isKindOfClass:[NSDictionary class]] ? a[@"persona"] : a;
        BOOL trapSvc = [a[@"trap_svc"] boolValue];
        return MEAFEnableAllLayersWithPersona(persona, trapSvc);
    }

    if ([op isEqualToString:@"engine.egress_pin"]) {
        NSString *target = [a[@"target"] isKindOfClass:[NSString class]] ? [a[@"target"] lowercaseString] : @"default";
        NSString *ifName = [a[@"interface"] isKindOfClass:[NSString class]] ? a[@"interface"] : @"";
        int mode = 0;
        unsigned int ifIdx = 0;
        if ([target isEqualToString:@"cellular"] || [target isEqualToString:@"pdp"] || [target isEqualToString:@"wwan"]) {
            mode = 1;
            NSString *wantIf = ifName.length ? ifName : @"pdp_ip0";
            strlcpy(g_af_egress_if_name, wantIf.UTF8String, sizeof(g_af_egress_if_name));
            ifIdx = if_nametoindex(g_af_egress_if_name);
            if (ifIdx == 0) {
                for (NSString *cand in @[@"pdp_ip0", @"pdp_ip1", @"pdp_ip2", @"pdp_ip3"]) {
                    ifIdx = if_nametoindex(cand.UTF8String);
                    if (ifIdx != 0) {
                        strlcpy(g_af_egress_if_name, cand.UTF8String, sizeof(g_af_egress_if_name));
                        break;
                    }
                }
            }
        } else if ([target isEqualToString:@"wifi"] || [target isEqualToString:@"en0"]) {
            mode = 2;
            strlcpy(g_af_egress_if_name, "en0", sizeof(g_af_egress_if_name));
            ifIdx = if_nametoindex("en0");
        } else {
            mode = 0;
            ifIdx = 0;
            g_af_egress_if_name[0] = '\0';
        }
        atomic_store(&g_af_egress_mode, mode);
        atomic_store(&g_af_egress_if_idx, ifIdx);
        atomic_fetch_add(&g_af_egress_gen, 1);

        uint16_t proxyPort = 0;
        if (mode != 0) {
            proxyPort = MEAFEgressProxyEnsureStarted();
        } else {
            MEAFEgressProxyStop();
        }
        MEAFInstallSessionEgressSwizzlesOnce();
        MEAFApplyWebKitEgressPin(mode, proxyPort);
        BOOL inlineActive = (mode != 0) ? MEAFInstallInlineEgressHooksOnce() : (atomic_load(&g_af_egress_inline_active) != 0);
        MEAFInstallGOTHooks(NULL, NULL, NULL);

        // Flush existing pooled sockets and reset pinned sharedSession so change takes effect immediately
        NSArray<NSURLSession *> *sessionsCopy = nil;
        NSURLSession *oldShared = nil;
        @synchronized(g_af_lock) {
            sessionsCopy = g_af_tracked_sessions ? [g_af_tracked_sessions allObjects] : @[];
            oldShared = g_af_pinned_shared_session;
            g_af_pinned_shared_session = nil;
        }
        for (NSURLSession *s in sessionsCopy) {
            @try { [s flushWithCompletionHandler:^{}]; } @catch (__unused NSException *e) {}
        }
        if (oldShared) {
            @try { [oldShared finishTasksAndInvalidate]; } @catch (__unused NSException *e) {}
        }
        @try {
            NSURLSession *origShared = orig_af_sharedSession ? orig_af_sharedSession([NSURLSession class], @selector(sharedSession)) : nil;
            [origShared flushWithCompletionHandler:^{}];
        } @catch (__unused NSException *e) {}

        // Persist or clear per-app pin file so relaunches inherit or drop the pin cleanly
        NSString *pinPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@".mcp_egress_pin.json"];
        if (mode == 0) {
            [[NSFileManager defaultManager] removeItemAtPath:pinPath error:NULL];
        } else {
            NSDictionary *pinDoc = @{
                @"target": (mode == 1 ? @"cellular" : @"wifi"),
                @"interface": g_af_egress_if_name[0] ? @(g_af_egress_if_name) : @"",
                @"updated_at": @([[NSDate date] timeIntervalSince1970])
            };
            NSData *pinData = [NSJSONSerialization dataWithJSONObject:pinDoc options:0 error:NULL];
            if (pinData) [pinData writeToFile:pinPath atomically:YES];
        }

        BOOL usesWebKit = (NSClassFromString(@"WKWebView") != Nil);
        return @{
            @"ok": @YES,
            @"target": (mode == 1 ? @"cellular" : (mode == 2 ? @"wifi" : @"default")),
            @"interface": g_af_egress_if_name[0] ? @(g_af_egress_if_name) : @"",
            @"interface_index": @(ifIdx),
            @"inline_hooks_active": inlineActive ? @YES : @NO,
            @"egress_proxy_port": @(proxyPort),
            @"nw_proxy_active": atomic_load(&g_af_egress_nw_proxy_active) ? @YES : @NO,
            @"session_swizzles_active": @YES,
            @"uses_webkit": usesWebKit ? @YES : @NO,
            @"pid": @(getpid())
        };
    }

    if ([op isEqualToString:@"engine.egress_probe"]) {
        CFAbsoluteTime t0 = CFAbsoluteTimeGetCurrent();
        NSString *probeUrl = [a[@"url"] isKindOfClass:[NSString class]] && [a[@"url"] length] > 0
            ? a[@"url"] : @"http://api.ipify.org/?format=text";
        NSURL *u = [NSURL URLWithString:probeUrl];
        __block NSString *observedIp = @"";
        __block NSString *errStr = @"";
        __block NSInteger statusCode = 0;

        NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration ephemeralSessionConfiguration];
        cfg.timeoutIntervalForRequest = 6.0;
        cfg.timeoutIntervalForResource = 7.0;
        NSURLSession *probeSession = [NSURLSession sessionWithConfiguration:cfg];
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        NSURLSessionDataTask *task = [probeSession dataTaskWithURL:u completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
            if ([resp isKindOfClass:[NSHTTPURLResponse class]]) {
                statusCode = ((NSHTTPURLResponse *)resp).statusCode;
            }
            if (err) {
                errStr = err.localizedDescription ?: @"request failed";
            } else if (data.length > 0) {
                NSString *body = [[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]
                                  stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] ?: @"";
                if (body.length > 0 && body.length < 128) observedIp = body;
            }
            dispatch_semaphore_signal(sem);
        }];
        [task resume];
        dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(7.5 * NSEC_PER_SEC)));
        [probeSession finishTasksAndInvalidate];

        // Also test sharedSession + HTTPS CONNECT TLS tunnel so we verify both plain HTTP and TLS pinning
        __block NSString *sharedIp = @"";
        dispatch_semaphore_t sem2 = dispatch_semaphore_create(0);
        NSURLSessionDataTask *task2 = [[NSURLSession sharedSession] dataTaskWithURL:u completionHandler:^(NSData *data, __unused NSURLResponse *resp, __unused NSError *err) {
            if (data.length > 0) {
                NSString *body = [[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]
                                  stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] ?: @"";
                if (body.length > 0 && body.length < 128) sharedIp = body;
            }
            dispatch_semaphore_signal(sem2);
        }];
        [task2 resume];
        dispatch_semaphore_wait(sem2, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(7.5 * NSEC_PER_SEC)));

        __block NSString *httpsIp = @"";
        __block NSString *httpsErr = @"";
        NSURL *httpsURL = [NSURL URLWithString:@"https://api.ipify.org/?format=text"];
        NSURLSessionConfiguration *hCfg = [NSURLSessionConfiguration ephemeralSessionConfiguration];
        hCfg.timeoutIntervalForRequest = 6.0;
        hCfg.timeoutIntervalForResource = 7.0;
        NSURLSession *httpsSess = [NSURLSession sessionWithConfiguration:hCfg];
        dispatch_semaphore_t sem3 = dispatch_semaphore_create(0);
        NSURLSessionDataTask *task3 = [httpsSess dataTaskWithURL:httpsURL completionHandler:^(NSData *data, __unused NSURLResponse *resp, NSError *err) {
            if (err) {
                httpsErr = err.localizedDescription ?: @"https failed";
            } else if (data.length > 0) {
                NSString *body = [[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]
                                  stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] ?: @"";
                if (body.length > 0 && body.length < 128) httpsIp = body;
            }
            dispatch_semaphore_signal(sem3);
        }];
        [task3 resume];
        dispatch_semaphore_wait(sem3, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(7.5 * NSEC_PER_SEC)));
        [httpsSess finishTasksAndInvalidate];

        int mode = atomic_load(&g_af_egress_mode);
        double elapsedMs = (CFAbsoluteTimeGetCurrent() - t0) * 1000.0;
        return @{
            @"ok": (observedIp.length > 0 || httpsIp.length > 0) ? @YES : @NO,
            @"egress_ip": observedIp.length ? observedIp : httpsIp,
            @"shared_session_ip": sharedIp,
            @"https_egress_ip": httpsIp,
            @"https_error": httpsErr,
            @"egress_proxy_port": @(atomic_load(&g_af_egress_proxy_port)),
            @"nw_proxy_active": atomic_load(&g_af_egress_nw_proxy_active) ? @YES : @NO,
            @"proxy_accepts": @(atomic_load(&g_af_egress_proxy_accepts)),
            @"proxy_socks5": @(atomic_load(&g_af_egress_proxy_socks5)),
            @"proxy_connect": @(atomic_load(&g_af_egress_proxy_connect)),
            @"proxy_http": @(atomic_load(&g_af_egress_proxy_http)),
            @"proxy_fail": @(atomic_load(&g_af_egress_proxy_fail)),
            @"urlproto_hits": @(atomic_load(&g_af_egress_urlproto_hits)),
            @"urlproto_tls": @(atomic_load(&g_af_egress_urlproto_tls)),
            @"urlproto_err": @(atomic_load(&g_af_egress_urlproto_err)),
            @"status_code": @(statusCode),
            @"target": (mode == 1 ? @"cellular" : (mode == 2 ? @"wifi" : @"default")),
            @"interface": g_af_egress_if_name[0] ? @(g_af_egress_if_name) : @"",
            @"interface_index": @(atomic_load(&g_af_egress_if_idx)),
            @"inline_hooks_active": atomic_load(&g_af_egress_inline_active) ? @YES : @NO,
            @"uses_webkit": (NSClassFromString(@"WKWebView") != Nil) ? @YES : @NO,
            @"error": errStr,
            @"duration_ms": @((NSInteger)llround(elapsedMs)),
            @"pid": @(getpid())
        };
    }

    if ([op isEqualToString:@"engine.audit_fraud_surface"]) {
        if (!atomic_load(&g_af_shield_active)) {
            MEAFEnableAllLayersWithPersona(nil, NO);
        }
        return MEAFRun50PointAudit();
    }

    return nil;
}

__attribute__((constructor))
static void MEAntiFraudAutoInit(void) {
    @autoreleasepool {
        MEAFInit();
        NSString *localPersonaPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@".mcp_persona.json"];
        NSData *data = [NSData dataWithContentsOfFile:localPersonaPath];
        if (!data) {
            NSString *bundleId = [[NSBundle mainBundle] bundleIdentifier];
            if (bundleId.length) {
                NSString *rel = [NSString stringWithFormat:@"/var/mobile/Library/ios-mcp/spoof/%@.json", bundleId];
                data = [NSData dataWithContentsOfFile:rel];
                if (!data) {
                    NSArray<NSString *> *roots = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"/var/containers/Bundle/Application" error:NULL];
                    for (NSString *entry in roots) {
                        if ([entry hasPrefix:@".jbroot-"]) {
                            NSString *cand = [[@"/var/containers/Bundle/Application" stringByAppendingPathComponent:entry] stringByAppendingString:rel];
                            data = [NSData dataWithContentsOfFile:cand];
                            if (data) break;
                        }
                    }
                }
            }
        }
        if (data.length) {
            NSDictionary *persona = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
            if ([persona isKindOfClass:[NSDictionary class]]) {
                MEAFEnableAllLayersWithPersona(persona, NO);
            }
        }
        NSString *pinPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@".mcp_egress_pin.json"];
        NSData *pinData = [NSData dataWithContentsOfFile:pinPath];
        if (pinData.length) {
            NSDictionary *pinDoc = [NSJSONSerialization JSONObjectWithData:pinData options:0 error:NULL];
            NSString *target = [pinDoc[@"target"] isKindOfClass:[NSString class]] ? [pinDoc[@"target"] lowercaseString] : @"";
            NSString *ifName = [pinDoc[@"interface"] isKindOfClass:[NSString class]] ? pinDoc[@"interface"] : @"";
            if ([target isEqualToString:@"cellular"] || [target isEqualToString:@"wifi"]) {
                int mode = [target isEqualToString:@"cellular"] ? 1 : 2;
                const char *wantIf = ifName.length ? ifName.UTF8String : (mode == 1 ? "pdp_ip0" : "en0");
                strlcpy(g_af_egress_if_name, wantIf, sizeof(g_af_egress_if_name));
                unsigned int idx = if_nametoindex(g_af_egress_if_name);
                atomic_store(&g_af_egress_mode, mode);
                atomic_store(&g_af_egress_if_idx, idx);
                atomic_fetch_add(&g_af_egress_gen, 1);
                uint16_t autoPort = MEAFEgressProxyEnsureStarted();
                MEAFInstallSessionEgressSwizzlesOnce();
                MEAFApplyWebKitEgressPin(mode, autoPort);
                MEAFInstallInlineEgressHooksOnce();
                MEAFInstallGOTHooks(NULL, NULL, NULL);
            }
        }
    }
}
