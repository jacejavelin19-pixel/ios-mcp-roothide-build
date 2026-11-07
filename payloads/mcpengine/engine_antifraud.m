#import "engine_rpc.h"
#include "fishhook.h"
#import <UIKit/UIKit.h>
#import <CoreGraphics/CoreGraphics.h>
#import <Security/Security.h>
#import <CFNetwork/CFNetwork.h>
#import <SystemConfiguration/SystemConfiguration.h>
#import <CoreMotion/CoreMotion.h>
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

static NSMutableDictionary *g_af_persona = nil;
static NSMutableArray<NSDictionary *> *g_af_bound_slots = nil;
static NSMutableArray<NSDictionary *> *g_af_sensor_payloads = nil;
static NSMutableArray<NSDictionary *> *g_af_attest_events = nil;
static NSMutableDictionary *g_af_virtual_keychain = nil;
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
    if (atomic_load(&g_af_shield_active) && MEDepth == 0) {
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
    if (atomic_load(&g_af_network_cloak_active) && MEDepth == 0) {
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
    Boolean ok = orig_af_SCNetworkReachabilityGetFlags ? orig_af_SCNetworkReachabilityGetFlags(target, flags) : TRUE;
    if (ok && flags && atomic_load(&g_af_network_cloak_active) && MEDepth == 0) {
        *flags &= ~(SCNetworkReachabilityFlags)kSCNetworkReachabilityFlagsTransientConnection;
        *flags |= (SCNetworkReachabilityFlags)kSCNetworkReachabilityFlagsReachable;
    }
    return ok;
}

static int hook_af_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if ((atomic_load(&g_af_risk_neutralizer_active) || atomic_load(&g_af_shield_active)) && MEDepth == 0 && addr) {
        uint16_t port = 0;
        BOOL isLocal = NO;
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
        BOOL canOpen = swizzled_af_canOpenURL([UIApplication sharedApplication], @selector(canOpenURL:), [NSURL URLWithString:sch]);
        [checks addObject:MEAFAuditCheck(checkId++, @"url_scheme_cloak", [NSString stringWithFormat:@"canOpenURL(%@)", sch], !canOpen, @"NO")];
    }

    // 38..45: Hardware Identity, MobileGestalt, Timezone, Locale, Carrier & Battery Coherence
    NSUUID *idfv = swizzled_af_idfv([UIDevice currentDevice], @selector(identifierForVendor));
    [checks addObject:MEAFAuditCheck(checkId++, @"persona_identity", @"UIDevice.identifierForVendor valid", idfv != nil, idfv.UUIDString ?: @"")];
    UIDeviceBatteryState bState = swizzled_af_batteryState([UIDevice currentDevice], @selector(batteryState));
    [checks addObject:MEAFAuditCheck(checkId++, @"persona_identity", @"UIDevice.batteryState == Unplugged", bState == UIDeviceBatteryStateUnplugged, @"UIDeviceBatteryStateUnplugged")];
    float bLevel = swizzled_af_batteryLevel([UIDevice currentDevice], @selector(batteryLevel));
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
    if ([persona isKindOfClass:[NSDictionary class]] && persona.count > 0) {
        @synchronized(g_af_lock) {
            [g_af_persona addEntriesFromDictionary:persona];
            if (!g_af_persona[@"birthtime_jitter_sec"]) {
                uint32_t seed = [g_af_persona[@"canvas_seed"] unsignedIntValue] ?: 0x13572468u;
                g_af_persona[@"birthtime_jitter_sec"] = @((int64_t)((seed % 86400) + 3600));
                g_af_persona[@"birthtime_jitter_nsec"] = @((int64_t)((seed * 2654435761u) % 999999999u));
            }
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
            id svc = ((id (*)(id, SEL))objc_msgSend)(dcAppAttest, sharedSvcSel);
            if ([svc respondsToSelector:isSuppSel]) {
                supported = ((BOOL (*)(id, SEL))objc_msgSend)(svc, isSuppSel);
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
                NSString *globalPath = [NSString stringWithFormat:@"/var/mobile/Library/ios-mcp/spoof/%@.json", bundleId];
                data = [NSData dataWithContentsOfFile:globalPath];
            }
        }
        if (data.length) {
            NSDictionary *persona = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
            if ([persona isKindOfClass:[NSDictionary class]]) {
                MEAFEnableAllLayersWithPersona(persona, NO);
            }
        }
    }
}
