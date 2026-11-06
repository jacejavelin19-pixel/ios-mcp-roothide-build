#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#import <dirent.h>
#import <errno.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <netinet/in.h>
#import <pthread.h>
#import <stdarg.h>
#import <stdatomic.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import <sys/socket.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <unistd.h>
#import "fishhook.h"

#if defined(__arm64e__) || (__has_feature(ptrauth_calls))
#include <ptrauth.h>
#define MCP_STEALTH_PTRAUTH 1
#else
#define MCP_STEALTH_PTRAUTH 0
#endif

#ifndef P_TRACED
#define P_TRACED 0x00000800
#endif

#ifndef PT_DENY_ATTACH
#define PT_DENY_ATTACH 31
#endif

extern kern_return_t mach_vm_region(vm_map_t target_task,
                                    mach_vm_address_t *address,
                                    mach_vm_size_t *size,
                                    vm_region_flavor_t flavor,
                                    vm_region_info_t info,
                                    mach_msg_type_number_t *infoCnt,
                                    mach_port_t *object_name);

typedef struct {
    uintptr_t start;
    uintptr_t end;
} mcp_addr_range_t;

static const struct mach_header *g_stealth_header = NULL;
static const struct mach_header *g_gadget_header = NULL;
static mcp_addr_range_t g_stealth_text = {0, 0};
static mcp_addr_range_t g_gadget_text = {0, 0};
#define MCP_MAX_COMPANION_RANGES 16
static mcp_addr_range_t g_companion_text[MCP_MAX_COMPANION_RANGES];
static size_t g_companion_text_count = 0;

static pthread_mutex_t g_stealth_lock = PTHREAD_MUTEX_INITIALIZER;
static time_t g_cfg_last_mtime = 0;

// Feature flags (configurable via .mcp_stealth_cfg.json)
static int g_enable_thread_cloak = 1;
static int g_enable_dyld_cloak = 1;
static int g_enable_anti_debug = 1;
static int g_enable_exception_cloak = 1;
static int g_enable_fs_cloak = 1;
static int g_enable_port_cloak = 1;
static int g_enable_env_scheme_cloak = 1;
static int g_enable_vm_integrity_cloak = 1;

// Dynamic hidden names & scrubbed tokens loaded from .mcp_stealth_cfg.json
#define MCP_MAX_HIDDEN_TOKENS 32
static char g_hidden_dylib_names[MCP_MAX_HIDDEN_TOKENS][128];
static size_t g_hidden_dylib_count = 0;
static char g_scrubbed_tokens[MCP_MAX_HIDDEN_TOKENS][64];
static size_t g_scrubbed_token_count = 0;

// Laundered thread telemetry
#define MCP_MAX_LAUNDERED_THREADS 32
typedef struct {
    char original[64];
    char laundered[64];
    uint64_t tid;
    int from_gadget_text;
} mcp_thread_record_t;
static mcp_thread_record_t g_laundered_threads[MCP_MAX_LAUNDERED_THREADS];
static size_t g_laundered_thread_count = 0;

// Telemetry counters
static _Atomic uint64_t g_cnt_thread_cloak = 0;
static _Atomic uint64_t g_cnt_dyld_cloak = 0;
static _Atomic uint64_t g_cnt_anti_debug = 0;
static _Atomic uint64_t g_cnt_exception_cloak = 0;
static _Atomic uint64_t g_cnt_fs_cloak = 0;
static _Atomic uint64_t g_cnt_port_cloak = 0;
static _Atomic uint64_t g_cnt_env_scheme_cloak = 0;
static _Atomic uint64_t g_cnt_vm_cloak = 0;

// Original function pointers
static int (*orig_pthread_setname_np)(const char *name) = NULL;
static uint32_t (*orig__dyld_image_count)(void) = NULL;
static const char *(*orig__dyld_get_image_name)(uint32_t idx) = NULL;
static const struct mach_header *(*orig__dyld_get_image_header)(uint32_t idx) = NULL;
static intptr_t (*orig__dyld_get_image_vmaddr_slide)(uint32_t idx) = NULL;
static void (*orig__dyld_register_func_for_add_image)(void (*func)(const struct mach_header *, intptr_t)) = NULL;
static int (*orig_dladdr)(const void *addr, Dl_info *info) = NULL;

static int (*orig_ptrace)(int request, pid_t pid, void *addr, int data) = NULL;
static int (*orig_sysctl)(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) = NULL;
static pid_t (*orig_getppid)(void) = NULL;
static int (*orig_isatty)(int fd) = NULL;

static kern_return_t (*orig_task_get_exception_ports)(task_t task,
                                                      exception_mask_t exception_mask,
                                                      exception_mask_array_t masks,
                                                      mach_msg_type_number_t *masksCnt,
                                                      exception_handler_array_t old_handlers,
                                                      exception_behavior_array_t old_behaviors,
                                                      thread_state_flavor_array_t old_flavors) = NULL;
static kern_return_t (*orig_thread_get_exception_ports)(thread_act_t thread,
                                                        exception_mask_t exception_mask,
                                                        exception_mask_array_t masks,
                                                        mach_msg_type_number_t *masksCnt,
                                                        exception_handler_array_t old_handlers,
                                                        exception_behavior_array_t old_behaviors,
                                                        thread_state_flavor_array_t old_flavors) = NULL;

static int (*orig_stat)(const char *path, struct stat *buf) = NULL;
static int (*orig_lstat)(const char *path, struct stat *buf) = NULL;
static int (*orig_access)(const char *path, int amode) = NULL;
static int (*orig_faccessat)(int fd, const char *path, int amode, int flag) = NULL;
static int (*orig_open)(const char *path, int oflag, ...) = NULL;
static FILE *(*orig_fopen)(const char *path, const char *mode) = NULL;
static DIR *(*orig_opendir)(const char *name) = NULL;

static int (*orig_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;
static char *(*orig_getenv)(const char *name) = NULL;
static BOOL (*orig_canOpenURL)(id self, SEL _cmd, NSURL *url) = NULL;

static kern_return_t (*orig_vm_region_64)(vm_map_t target_task,
                                          vm_address_t *address,
                                          vm_size_t *size,
                                          vm_region_flavor_t flavor,
                                          vm_region_info_t info,
                                          mach_msg_type_number_t *infoCnt,
                                          mach_port_t *object_name) = NULL;
static kern_return_t (*orig_mach_vm_region)(vm_map_t target_task,
                                            mach_vm_address_t *address,
                                            mach_vm_size_t *size,
                                            vm_region_flavor_t flavor,
                                            vm_region_info_t info,
                                            mach_msg_type_number_t *infoCnt,
                                            mach_port_t *object_name) = NULL;

static uintptr_t mcp_strip_return_addr(const void *ret) {
    if (!ret) return 0;
#if MCP_STEALTH_PTRAUTH
    return (uintptr_t)ptrauth_strip((void *)ret, ptrauth_key_return_address);
#else
    return ((uintptr_t)ret) & 0x00007fffffffffffULL;
#endif
}

static mcp_addr_range_t mcp_compute_text_range(const struct mach_header *hdr) {
    mcp_addr_range_t r = {0, 0};
    if (!hdr || hdr->magic != MH_MAGIC_64) return r;
    const struct mach_header_64 *h64 = (const struct mach_header_64 *)hdr;
    uintptr_t cur = (uintptr_t)h64 + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < h64->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cur;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            if (strcmp(seg->segname, SEG_TEXT) == 0) {
                r.start = (uintptr_t)h64;
                r.end = (uintptr_t)h64 + (uintptr_t)seg->vmsize;
                return r;
            }
        }
        cur += lc->cmdsize;
    }
    return r;
}

static inline int mcp_addr_in_range(uintptr_t addr, mcp_addr_range_t r) {
    return (r.start != 0 && addr >= r.start && addr < r.end) ? 1 : 0;
}

static void mcp_register_companion_text_unlocked(const struct mach_header *hdr) {
    if (!hdr || hdr == g_stealth_header) return;
    mcp_addr_range_t r = mcp_compute_text_range(hdr);
    if (r.start == 0 || r.end <= r.start) return;
    for (size_t i = 0; i < g_companion_text_count; i++) {
        if (g_companion_text[i].start == r.start) return;
    }
    if (g_companion_text_count < MCP_MAX_COMPANION_RANGES) {
        g_companion_text[g_companion_text_count++] = r;
    }
}

static inline int mcp_is_gadget_caller(const void *raw_ret) {
    uintptr_t a = mcp_strip_return_addr(raw_ret);
    return mcp_addr_in_range(a, g_gadget_text);
}

static inline int mcp_is_internal_caller(const void *raw_ret) {
    uintptr_t a = mcp_strip_return_addr(raw_ret);
    if (mcp_addr_in_range(a, g_stealth_text) || mcp_addr_in_range(a, g_gadget_text)) {
        return 1;
    }
    for (size_t i = 0; i < g_companion_text_count; i++) {
        if (mcp_addr_in_range(a, g_companion_text[i])) return 1;
    }
    return 0;
}

static int mcp_ci_contains(const char *haystack, const char *needle) {
    if (!haystack || !needle || !*needle) return 0;
    size_t nlen = strlen(needle);
    for (const char *p = haystack; *p; p++) {
        if (strncasecmp(p, needle, nlen) == 0) return 1;
    }
    return 0;
}

static NSString *mcp_stealth_cfg_path(void) {
    return [NSTemporaryDirectory() stringByAppendingPathComponent:@".mcp_stealth_cfg.json"];
}

static NSString *mcp_stealth_status_path(void) {
    return [NSTemporaryDirectory() stringByAppendingPathComponent:@".mcp_stealth_status.json"];
}

static void mcp_reload_config_if_needed(int force) {
    const char *cfgCStr = mcp_stealth_cfg_path().fileSystemRepresentation;
    if (!cfgCStr) return;
    struct stat st;
    int rc = orig_stat ? orig_stat(cfgCStr, &st) : stat(cfgCStr, &st);
    if (rc != 0) return;
    if (!force && st.st_mtimespec.tv_sec == g_cfg_last_mtime) return;

    int fd = orig_open ? orig_open(cfgCStr, O_RDONLY | O_CLOEXEC, 0) : open(cfgCStr, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    char buf[8192];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return;
    buf[n] = '\0';

    NSData *data = [NSData dataWithBytes:buf length:(NSUInteger)n];
    NSDictionary *cfg = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
    if (![cfg isKindOfClass:[NSDictionary class]]) return;

    pthread_mutex_lock(&g_stealth_lock);
    g_cfg_last_mtime = st.st_mtimespec.tv_sec;
    if (cfg[@"thread_cloak"]) g_enable_thread_cloak = [cfg[@"thread_cloak"] boolValue] ? 1 : 0;
    if (cfg[@"dyld_cloak"]) g_enable_dyld_cloak = [cfg[@"dyld_cloak"] boolValue] ? 1 : 0;
    if (cfg[@"anti_debug"]) g_enable_anti_debug = [cfg[@"anti_debug"] boolValue] ? 1 : 0;
    if (cfg[@"exception_cloak"]) g_enable_exception_cloak = [cfg[@"exception_cloak"] boolValue] ? 1 : 0;
    if (cfg[@"fs_cloak"]) g_enable_fs_cloak = [cfg[@"fs_cloak"] boolValue] ? 1 : 0;
    if (cfg[@"port_cloak"]) g_enable_port_cloak = [cfg[@"port_cloak"] boolValue] ? 1 : 0;
    if (cfg[@"env_scheme_cloak"]) g_enable_env_scheme_cloak = [cfg[@"env_scheme_cloak"] boolValue] ? 1 : 0;
    if (cfg[@"vm_integrity_cloak"]) g_enable_vm_integrity_cloak = [cfg[@"vm_integrity_cloak"] boolValue] ? 1 : 0;

    if ([cfg[@"hidden_dylib_names"] isKindOfClass:[NSArray class]]) {
        g_hidden_dylib_count = 0;
        for (id item in (NSArray *)cfg[@"hidden_dylib_names"]) {
            if (![item isKindOfClass:[NSString class]]) continue;
            if (g_hidden_dylib_count >= MCP_MAX_HIDDEN_TOKENS) break;
            const char *s = [(NSString *)item UTF8String];
            if (s && *s) {
                strncpy(g_hidden_dylib_names[g_hidden_dylib_count], s, sizeof(g_hidden_dylib_names[0]) - 1);
                g_hidden_dylib_names[g_hidden_dylib_count][sizeof(g_hidden_dylib_names[0]) - 1] = '\0';
                g_hidden_dylib_count++;
            }
        }
    }

    if ([cfg[@"scrubbed_tokens"] isKindOfClass:[NSArray class]]) {
        g_scrubbed_token_count = 0;
        for (id item in (NSArray *)cfg[@"scrubbed_tokens"]) {
            if (![item isKindOfClass:[NSString class]]) continue;
            if (g_scrubbed_token_count >= MCP_MAX_HIDDEN_TOKENS) break;
            const char *s = [(NSString *)item UTF8String];
            if (s && *s) {
                strncpy(g_scrubbed_tokens[g_scrubbed_token_count], s, sizeof(g_scrubbed_tokens[0]) - 1);
                g_scrubbed_tokens[g_scrubbed_token_count][sizeof(g_scrubbed_tokens[0]) - 1] = '\0';
                g_scrubbed_token_count++;
            }
        }
    }
    pthread_mutex_unlock(&g_stealth_lock);
}

static int mcp_is_hidden_image_unlocked(const struct mach_header *hdr, const char *name) {
    if (hdr && (hdr == g_stealth_header || hdr == g_gadget_header)) {
        return 1;
    }
    if (!name || !*name) return 0;
    const char *base = strrchr(name, '/');
    base = base ? (base + 1) : name;
    for (size_t i = 0; i < g_hidden_dylib_count; i++) {
        if (g_hidden_dylib_names[i][0] &&
            (strcasecmp(base, g_hidden_dylib_names[i]) == 0 ||
             mcp_ci_contains(base, g_hidden_dylib_names[i]))) {
            mcp_register_companion_text_unlocked(hdr);
            return 1;
        }
    }
    if (mcp_ci_contains(base, "libAppleMediaKit_") ||
        mcp_ci_contains(base, "libAppleAVSync_") ||
        mcp_ci_contains(base, "libAppleCoreTLS_") ||
        mcp_ci_contains(base, "libAppleCoreSVG_") ||
        mcp_ci_contains(base, "libmcpengine") ||
        mcp_ci_contains(base, "libnetcap") ||
        mcp_ci_contains(base, "libsslkillswitch")) {
        mcp_register_companion_text_unlocked(hdr);
        return 1;
    }
    if (mcp_ci_contains(name, "libmcp_stealth") ||
        mcp_ci_contains(name, "frida") ||
        mcp_ci_contains(name, "/.jbroot-") ||
        mcp_ci_contains(name, "/var/jb/") ||
        mcp_ci_contains(name, "MobileSubstrate") ||
        mcp_ci_contains(name, "systemhook") ||
        mcp_ci_contains(name, "roothide")) {
        return 1;
    }
    // Heuristic: staged Gadget in <App>.app/Frameworks/<stem>.dylib always has <stem>.config next to it
    if (strstr(name, "/Frameworks/") != NULL) {
        size_t len = strlen(name);
        if (len > 6 && len < 900 && strcmp(name + len - 6, ".dylib") == 0) {
            char cfgPath[1024];
            memcpy(cfgPath, name, len - 6);
            memcpy(cfgPath + len - 6, ".config", 8);
            int acc = orig_access ? orig_access(cfgPath, F_OK) : access(cfgPath, F_OK);
            if (acc == 0) {
                if (hdr && !g_gadget_header && hdr != g_stealth_header) {
                    g_gadget_header = hdr;
                    g_gadget_text = mcp_compute_text_range(hdr);
                }
                return 1;
            }
        }
    }
    return 0;
}

static int mcp_is_hidden_image(const struct mach_header *hdr, const char *name) {
    pthread_mutex_lock(&g_stealth_lock);
    int res = mcp_is_hidden_image_unlocked(hdr, name);
    pthread_mutex_unlock(&g_stealth_lock);
    return res;
}

static void mcp_flush_stealth_status(void) {
    uint32_t realCount = orig__dyld_image_count ? orig__dyld_image_count() : _dyld_image_count();
    uint32_t visibleCount = 0;
    NSMutableArray<NSString *> *hiddenList = [NSMutableArray array];

    for (uint32_t i = 0; i < realCount; i++) {
        const struct mach_header *h = orig__dyld_get_image_header ? orig__dyld_get_image_header(i) : _dyld_get_image_header(i);
        const char *n = orig__dyld_get_image_name ? orig__dyld_get_image_name(i) : _dyld_get_image_name(i);
        if (mcp_is_hidden_image(h, n)) {
            if (n) [hiddenList addObject:[NSString stringWithUTF8String:n] ?: @""];
        } else {
            visibleCount++;
        }
    }

    NSMutableArray<NSDictionary *> *threadArr = [NSMutableArray array];
    pthread_mutex_lock(&g_stealth_lock);
    for (size_t i = 0; i < g_laundered_thread_count; i++) {
        [threadArr addObject:@{
            @"original": [NSString stringWithUTF8String:g_laundered_threads[i].original] ?: @"",
            @"laundered": [NSString stringWithUTF8String:g_laundered_threads[i].laundered] ?: @"",
            @"tid": @(g_laundered_threads[i].tid),
            @"from_gadget_text": @(g_laundered_threads[i].from_gadget_text ? YES : NO)
        }];
    }
    NSDictionary *features = @{
        @"thread_cloak": @(g_enable_thread_cloak ? YES : NO),
        @"dyld_cloak": @(g_enable_dyld_cloak ? YES : NO),
        @"anti_debug": @(g_enable_anti_debug ? YES : NO),
        @"exception_cloak": @(g_enable_exception_cloak ? YES : NO),
        @"fs_cloak": @(g_enable_fs_cloak ? YES : NO),
        @"port_cloak": @(g_enable_port_cloak ? YES : NO),
        @"env_scheme_cloak": @(g_enable_env_scheme_cloak ? YES : NO),
        @"vm_integrity_cloak": @(g_enable_vm_integrity_cloak ? YES : NO)
    };
    pthread_mutex_unlock(&g_stealth_lock);

    NSDictionary *doc = @{
        @"active": @YES,
        @"pid": @(getpid()),
        @"stealth_text_start": [NSString stringWithFormat:@"0x%llx", (unsigned long long)g_stealth_text.start],
        @"gadget_detected": @(g_gadget_header != NULL),
        @"gadget_text_start": [NSString stringWithFormat:@"0x%llx", (unsigned long long)g_gadget_text.start],
        @"real_dyld_image_count": @(realCount),
        @"visible_dyld_image_count": @(visibleCount),
        @"hidden_dyld_image_count": @(hiddenList.count),
        @"hidden_dyld_images": hiddenList,
        @"laundered_threads": threadArr,
        @"features": features,
        @"intercept_counts": @{
            @"thread_cloak": @(atomic_load(&g_cnt_thread_cloak)),
            @"dyld_cloak": @(atomic_load(&g_cnt_dyld_cloak)),
            @"anti_debug": @(atomic_load(&g_cnt_anti_debug)),
            @"exception_cloak": @(atomic_load(&g_cnt_exception_cloak)),
            @"fs_cloak": @(atomic_load(&g_cnt_fs_cloak)),
            @"port_cloak": @(atomic_load(&g_cnt_port_cloak)),
            @"env_scheme_cloak": @(atomic_load(&g_cnt_env_scheme_cloak)),
            @"vm_integrity_cloak": @(atomic_load(&g_cnt_vm_cloak))
        },
        @"timestamp": @([[NSDate date] timeIntervalSince1970])
    };

    NSData *json = [NSJSONSerialization dataWithJSONObject:doc options:0 error:NULL];
    if (!json.length) return;
    const char *path = mcp_stealth_status_path().fileSystemRepresentation;
    int fd = orig_open
        ? orig_open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644)
        : open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd >= 0) {
        write(fd, json.bytes, json.length);
        close(fd);
    }
}

#pragma mark - #14 Thread-Name Laundering

static const char *const kAppleThreadNamePool[] = {
    "com.apple.CFNetwork.Connection",
    "com.apple.NSURLConnectionLoader",
    "com.apple.uikit.eventfetch-thread",
    "com.apple.CoreAnalytics.event",
    "com.apple.xpc.q",
    "AVAudioSession Notify Thread"
};

static int mcp_should_launder_thread_name(const char *name, int from_gadget) {
    if (from_gadget) return 1;
    if (!name || !*name) return 0;
    if (mcp_ci_contains(name, "gum-js-loop") ||
        mcp_ci_contains(name, "gmain") ||
        mcp_ci_contains(name, "gdbus") ||
        mcp_ci_contains(name, "pool-spawner") ||
        mcp_ci_contains(name, "pool-spin") ||
        mcp_ci_contains(name, "frida") ||
        mcp_ci_contains(name, "gadget") ||
        strncmp(name, "gum-", 4) == 0) {
        return 1;
    }
    pthread_mutex_lock(&g_stealth_lock);
    int matched = 0;
    for (size_t i = 0; i < g_scrubbed_token_count; i++) {
        if (g_scrubbed_tokens[i][0] && mcp_ci_contains(name, g_scrubbed_tokens[i])) {
            matched = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_stealth_lock);
    return matched;
}

static int hook_pthread_setname_np(const char *name) {
    const void *ret = __builtin_return_address(0);
    if (!g_enable_thread_cloak) {
        return orig_pthread_setname_np ? orig_pthread_setname_np(name) : 0;
    }
    int from_gadget = mcp_is_gadget_caller(ret);
    if (mcp_should_launder_thread_name(name, from_gadget)) {
        uint64_t idx = atomic_fetch_add(&g_cnt_thread_cloak, 1);
        const char *clean = kAppleThreadNamePool[idx % (sizeof(kAppleThreadNamePool) / sizeof(kAppleThreadNamePool[0]))];
        uint64_t tid = 0;
        pthread_threadid_np(NULL, &tid);

        pthread_mutex_lock(&g_stealth_lock);
        if (g_laundered_thread_count < MCP_MAX_LAUNDERED_THREADS) {
            mcp_thread_record_t *rec = &g_laundered_threads[g_laundered_thread_count++];
            strncpy(rec->original, name ? name : "<null>", sizeof(rec->original) - 1);
            rec->original[sizeof(rec->original) - 1] = '\0';
            strncpy(rec->laundered, clean, sizeof(rec->laundered) - 1);
            rec->laundered[sizeof(rec->laundered) - 1] = '\0';
            rec->tid = tid;
            rec->from_gadget_text = from_gadget;
        }
        pthread_mutex_unlock(&g_stealth_lock);

        int rc = orig_pthread_setname_np ? orig_pthread_setname_np(clean) : 0;
        mcp_flush_stealth_status();
        return rc;
    }
    return orig_pthread_setname_np ? orig_pthread_setname_np(name) : 0;
}

#pragma mark - #15 dyld Image Hiding

static int mcp_map_visible_dyld_index(uint32_t visible_idx, uint32_t *out_real_idx) {
    uint32_t real_total = orig__dyld_image_count ? orig__dyld_image_count() : 0;
    uint32_t cur_vis = 0;
    for (uint32_t r = 0; r < real_total; r++) {
        const struct mach_header *h = orig__dyld_get_image_header ? orig__dyld_get_image_header(r) : NULL;
        const char *n = orig__dyld_get_image_name ? orig__dyld_get_image_name(r) : NULL;
        if (mcp_is_hidden_image(h, n)) continue;
        if (cur_vis == visible_idx) {
            if (out_real_idx) *out_real_idx = r;
            return 1;
        }
        cur_vis++;
    }
    return 0;
}

static uint32_t hook__dyld_image_count(void) {
    const void *ret = __builtin_return_address(0);
    mcp_reload_config_if_needed(0);
    if (!g_enable_dyld_cloak || mcp_is_internal_caller(ret)) {
        return orig__dyld_image_count ? orig__dyld_image_count() : 0;
    }
    atomic_fetch_add(&g_cnt_dyld_cloak, 1);
    uint32_t real_total = orig__dyld_image_count ? orig__dyld_image_count() : 0;
    uint32_t vis = 0;
    for (uint32_t r = 0; r < real_total; r++) {
        const struct mach_header *h = orig__dyld_get_image_header ? orig__dyld_get_image_header(r) : NULL;
        const char *n = orig__dyld_get_image_name ? orig__dyld_get_image_name(r) : NULL;
        if (!mcp_is_hidden_image(h, n)) vis++;
    }
    return vis;
}

static const char *hook__dyld_get_image_name(uint32_t image_index) {
    const void *ret = __builtin_return_address(0);
    if (!g_enable_dyld_cloak || mcp_is_internal_caller(ret)) {
        return orig__dyld_get_image_name ? orig__dyld_get_image_name(image_index) : NULL;
    }
    uint32_t real_idx = 0;
    if (!mcp_map_visible_dyld_index(image_index, &real_idx)) return NULL;
    return orig__dyld_get_image_name ? orig__dyld_get_image_name(real_idx) : NULL;
}

static const struct mach_header *hook__dyld_get_image_header(uint32_t image_index) {
    const void *ret = __builtin_return_address(0);
    if (!g_enable_dyld_cloak || mcp_is_internal_caller(ret)) {
        return orig__dyld_get_image_header ? orig__dyld_get_image_header(image_index) : NULL;
    }
    uint32_t real_idx = 0;
    if (!mcp_map_visible_dyld_index(image_index, &real_idx)) return NULL;
    return orig__dyld_get_image_header ? orig__dyld_get_image_header(real_idx) : NULL;
}

static intptr_t hook__dyld_get_image_vmaddr_slide(uint32_t image_index) {
    const void *ret = __builtin_return_address(0);
    if (!g_enable_dyld_cloak || mcp_is_internal_caller(ret)) {
        return orig__dyld_get_image_vmaddr_slide ? orig__dyld_get_image_vmaddr_slide(image_index) : 0;
    }
    uint32_t real_idx = 0;
    if (!mcp_map_visible_dyld_index(image_index, &real_idx)) return 0;
    return orig__dyld_get_image_vmaddr_slide ? orig__dyld_get_image_vmaddr_slide(real_idx) : 0;
}

#define MCP_MAX_ADD_IMAGE_CBS 16
static void (*g_external_add_image_cbs[MCP_MAX_ADD_IMAGE_CBS])(const struct mach_header *, intptr_t);
static _Atomic uint32_t g_external_add_image_cb_count = 0;
static int g_dispatcher_registered = 0;

static void mcp_filtered_add_image_dispatcher(const struct mach_header *hdr, intptr_t slide) {
    Dl_info info;
    const char *name = (orig_dladdr && orig_dladdr(hdr, &info) && info.dli_fname) ? info.dli_fname : NULL;
    if (g_enable_dyld_cloak && mcp_is_hidden_image(hdr, name)) {
        atomic_fetch_add(&g_cnt_dyld_cloak, 1);
        return;
    }
    uint32_t count = atomic_load(&g_external_add_image_cb_count);
    for (uint32_t i = 0; i < count; i++) {
        if (g_external_add_image_cbs[i]) {
            g_external_add_image_cbs[i](hdr, slide);
        }
    }
}

static void hook__dyld_register_func_for_add_image(void (*func)(const struct mach_header *, intptr_t)) {
    const void *ret = __builtin_return_address(0);
    if (!func) return;
    if (!g_enable_dyld_cloak || mcp_is_internal_caller(ret)) {
        if (orig__dyld_register_func_for_add_image) orig__dyld_register_func_for_add_image(func);
        return;
    }
    // Deliver existing visible images immediately (matching dyld contract) and register future ones on dispatcher
    uint32_t real_total = orig__dyld_image_count ? orig__dyld_image_count() : 0;
    for (uint32_t r = 0; r < real_total; r++) {
        const struct mach_header *h = orig__dyld_get_image_header ? orig__dyld_get_image_header(r) : NULL;
        const char *n = orig__dyld_get_image_name ? orig__dyld_get_image_name(r) : NULL;
        intptr_t s = orig__dyld_get_image_vmaddr_slide ? orig__dyld_get_image_vmaddr_slide(r) : 0;
        if (!mcp_is_hidden_image(h, n) && h) {
            func(h, s);
        } else {
            atomic_fetch_add(&g_cnt_dyld_cloak, 1);
        }
    }
    pthread_mutex_lock(&g_stealth_lock);
    uint32_t slot = atomic_load(&g_external_add_image_cb_count);
    if (slot < MCP_MAX_ADD_IMAGE_CBS) {
        g_external_add_image_cbs[slot] = func;
        atomic_store(&g_external_add_image_cb_count, slot + 1);
    }
    int need_reg = !g_dispatcher_registered;
    g_dispatcher_registered = 1;
    pthread_mutex_unlock(&g_stealth_lock);
    if (need_reg && orig__dyld_register_func_for_add_image) {
        orig__dyld_register_func_for_add_image(mcp_filtered_add_image_dispatcher);
    }
}

static int hook_dladdr(const void *addr, Dl_info *info) {
    const void *ret = __builtin_return_address(0);
    int rc = orig_dladdr ? orig_dladdr(addr, info) : 0;
    if (rc == 0 || !info) return rc;
    if (!g_enable_dyld_cloak || mcp_is_internal_caller(ret)) return rc;
    if (mcp_is_hidden_image((const struct mach_header *)info->dli_fbase, info->dli_fname)) {
        atomic_fetch_add(&g_cnt_dyld_cloak, 1);
        memset(info, 0, sizeof(*info));
        return 0;
    }
    return rc;
}

#pragma mark - Bypass 1: Anti-Debug (ptrace PT_DENY_ATTACH + sysctl P_TRACED + getppid + isatty)

static int hook_ptrace(int request, pid_t pid, void *addr, int data) {
    const void *ret = __builtin_return_address(0);
    if (g_enable_anti_debug && !mcp_is_internal_caller(ret) && request == PT_DENY_ATTACH) {
        atomic_fetch_add(&g_cnt_anti_debug, 1);
        mcp_flush_stealth_status();
        return 0;
    }
    return orig_ptrace ? orig_ptrace(request, pid, addr, data) : 0;
}

static int hook_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    const void *ret = __builtin_return_address(0);
    int rc = orig_sysctl ? orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen) : -1;
    if (rc == 0 && g_enable_anti_debug && !mcp_is_internal_caller(ret) &&
        name && namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID &&
        oldp && oldlenp && *oldlenp >= sizeof(struct kinfo_proc)) {
        struct kinfo_proc *kp = (struct kinfo_proc *)oldp;
        atomic_fetch_add(&g_cnt_anti_debug, 1);
        kp->kp_proc.p_flag &= ~P_TRACED;
    }
    return rc;
}

static pid_t hook_getppid(void) {
    const void *ret = __builtin_return_address(0);
    pid_t ppid = orig_getppid ? orig_getppid() : 1;
    if (g_enable_anti_debug && !mcp_is_internal_caller(ret) && ppid != 1) {
        atomic_fetch_add(&g_cnt_anti_debug, 1);
        return 1;
    }
    return ppid;
}

static int hook_isatty(int fd) {
    const void *ret = __builtin_return_address(0);
    if (g_enable_anti_debug && !mcp_is_internal_caller(ret) && (fd >= 0 && fd <= 2)) {
        atomic_fetch_add(&g_cnt_anti_debug, 1);
        errno = ENOTTY;
        return 0;
    }
    return orig_isatty ? orig_isatty(fd) : 0;
}

#pragma mark - Bypass 2: Mach Exception Port Cloak (Gum Exception Handler Hiding)

static kern_return_t hook_task_get_exception_ports(task_t task,
                                                   exception_mask_t exception_mask,
                                                   exception_mask_array_t masks,
                                                   mach_msg_type_number_t *masksCnt,
                                                   exception_handler_array_t old_handlers,
                                                   exception_behavior_array_t old_behaviors,
                                                   thread_state_flavor_array_t old_flavors) {
    const void *ret = __builtin_return_address(0);
    kern_return_t kr = orig_task_get_exception_ports
        ? orig_task_get_exception_ports(task, exception_mask, masks, masksCnt, old_handlers, old_behaviors, old_flavors)
        : KERN_FAILURE;
    if (kr == KERN_SUCCESS && g_enable_exception_cloak && !mcp_is_internal_caller(ret) && masksCnt) {
        atomic_fetch_add(&g_cnt_exception_cloak, 1);
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

static kern_return_t hook_thread_get_exception_ports(thread_act_t thread,
                                                     exception_mask_t exception_mask,
                                                     exception_mask_array_t masks,
                                                     mach_msg_type_number_t *masksCnt,
                                                     exception_handler_array_t old_handlers,
                                                     exception_behavior_array_t old_behaviors,
                                                     thread_state_flavor_array_t old_flavors) {
    const void *ret = __builtin_return_address(0);
    kern_return_t kr = orig_thread_get_exception_ports
        ? orig_thread_get_exception_ports(thread, exception_mask, masks, masksCnt, old_handlers, old_behaviors, old_flavors)
        : KERN_FAILURE;
    if (kr == KERN_SUCCESS && g_enable_exception_cloak && !mcp_is_internal_caller(ret) && masksCnt) {
        atomic_fetch_add(&g_cnt_exception_cloak, 1);
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

#pragma mark - Bypass 3: Filesystem / RootHide / Gadget Artifact Cloak

static int mcp_is_cloaked_path(const char *path) {
    if (!path || !*path) return 0;
    static const char *const kCloakedPatterns[] = {
        "/.jbroot-",
        "/var/jb",
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/Applications/Dopamine.app",
        "/Library/MobileSubstrate",
        "/usr/sbin/sshd",
        "/usr/bin/ssh",
        "/bin/bash",
        "/bin/sh",
        "/etc/apt",
        "/private/var/lib/apt",
        "/private/var/lib/cydia",
        "/var/mobile/Library/ios-mcp/frida",
        "/.fc_",
        "/.mcp_stealth",
        "libmcp_stealth",
        "frida-server",
        "frida-gadget"
    };
    for (size_t i = 0; i < sizeof(kCloakedPatterns) / sizeof(kCloakedPatterns[0]); i++) {
        if (mcp_ci_contains(path, kCloakedPatterns[i])) return 1;
    }
    const char *base = strrchr(path, '/');
    base = base ? (base + 1) : path;
    pthread_mutex_lock(&g_stealth_lock);
    int matched = 0;
    for (size_t i = 0; i < g_hidden_dylib_count; i++) {
        const char *h = g_hidden_dylib_names[i];
        if (!h[0]) continue;
        if (strcasecmp(base, h) == 0) {
            matched = 1;
            break;
        }
        size_t hlen = strlen(h);
        if (hlen > 6 && strcmp(h + hlen - 6, ".dylib") == 0) {
            if (strncasecmp(base, h, hlen - 6) == 0) {
                const char *ext = base + (hlen - 6);
                if (strcasecmp(ext, ".config") == 0 || strcasecmp(ext, ".js") == 0) {
                    matched = 1;
                    break;
                }
            }
        }
    }
    pthread_mutex_unlock(&g_stealth_lock);
    return matched;
}

static int hook_stat(const char *path, struct stat *buf) {
    const void *ret = __builtin_return_address(0);
    if (g_enable_fs_cloak && !mcp_is_internal_caller(ret) && mcp_is_cloaked_path(path)) {
        atomic_fetch_add(&g_cnt_fs_cloak, 1);
        errno = ENOENT;
        return -1;
    }
    return orig_stat ? orig_stat(path, buf) : -1;
}

static int hook_lstat(const char *path, struct stat *buf) {
    const void *ret = __builtin_return_address(0);
    if (g_enable_fs_cloak && !mcp_is_internal_caller(ret) && mcp_is_cloaked_path(path)) {
        atomic_fetch_add(&g_cnt_fs_cloak, 1);
        errno = ENOENT;
        return -1;
    }
    return orig_lstat ? orig_lstat(path, buf) : -1;
}

static int hook_access(const char *path, int amode) {
    const void *ret = __builtin_return_address(0);
    if (g_enable_fs_cloak && !mcp_is_internal_caller(ret) && mcp_is_cloaked_path(path)) {
        atomic_fetch_add(&g_cnt_fs_cloak, 1);
        errno = ENOENT;
        return -1;
    }
    return orig_access ? orig_access(path, amode) : -1;
}

static int hook_faccessat(int fd, const char *path, int amode, int flag) {
    const void *ret = __builtin_return_address(0);
    if (g_enable_fs_cloak && !mcp_is_internal_caller(ret) && mcp_is_cloaked_path(path)) {
        atomic_fetch_add(&g_cnt_fs_cloak, 1);
        errno = ENOENT;
        return -1;
    }
    return orig_faccessat ? orig_faccessat(fd, path, amode, flag) : -1;
}

static int hook_open(const char *path, int oflag, ...) {
    const void *ret = __builtin_return_address(0);
    mode_t mode = 0;
    if (oflag & O_CREAT) {
        va_list ap;
        va_start(ap, oflag);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    if (g_enable_fs_cloak && !mcp_is_internal_caller(ret) && mcp_is_cloaked_path(path)) {
        atomic_fetch_add(&g_cnt_fs_cloak, 1);
        errno = ENOENT;
        return -1;
    }
    if (!orig_open) {
        errno = ENOSYS;
        return -1;
    }
    if (oflag & O_CREAT) {
        return orig_open(path, oflag, mode);
    }
    return orig_open(path, oflag);
}

static FILE *hook_fopen(const char *path, const char *mode) {
    const void *ret = __builtin_return_address(0);
    if (g_enable_fs_cloak && !mcp_is_internal_caller(ret) && mcp_is_cloaked_path(path)) {
        atomic_fetch_add(&g_cnt_fs_cloak, 1);
        errno = ENOENT;
        return NULL;
    }
    return orig_fopen ? orig_fopen(path, mode) : NULL;
}

static DIR *hook_opendir(const char *name) {
    const void *ret = __builtin_return_address(0);
    if (g_enable_fs_cloak && !mcp_is_internal_caller(ret) && mcp_is_cloaked_path(name)) {
        atomic_fetch_add(&g_cnt_fs_cloak, 1);
        errno = ENOENT;
        return NULL;
    }
    return orig_opendir ? orig_opendir(name) : NULL;
}

#pragma mark - Bypass 4: Localhost Anti-Frida Port Probe Blocker

static int hook_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    const void *ret = __builtin_return_address(0);
    if (g_enable_port_cloak && !mcp_is_internal_caller(ret) && addr) {
        uint16_t port = 0;
        int is_local = 0;
        if (addr->sa_family == AF_INET && addrlen >= sizeof(struct sockaddr_in)) {
            const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
            port = ntohs(sin->sin_port);
            uint32_t ip = ntohl(sin->sin_addr.s_addr);
            if ((ip >> 24) == 127 || ip == 0) is_local = 1;
        } else if (addr->sa_family == AF_INET6 && addrlen >= sizeof(struct sockaddr_in6)) {
            const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
            port = ntohs(sin6->sin6_port);
            if (IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr) || IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
                is_local = 1;
            }
        }
        if (is_local && (port == 27042 || port == 27043 || port == 23946)) {
            atomic_fetch_add(&g_cnt_port_cloak, 1);
            errno = ECONNREFUSED;
            return -1;
        }
    }
    return orig_connect ? orig_connect(sockfd, addr, addrlen) : -1;
}

#pragma mark - Bypass 5: Environment & Jailbreak URL Scheme Sanitizer

static char *hook_getenv(const char *name) {
    const void *ret = __builtin_return_address(0);
    if (g_enable_env_scheme_cloak && !mcp_is_internal_caller(ret) && name) {
        if (strcasecmp(name, "DYLD_INSERT_LIBRARIES") == 0 ||
            strcasecmp(name, "MSSafeMode") == 0 ||
            strcasecmp(name, "_MSSafeMode") == 0 ||
            strncasecmp(name, "FRIDA_", 6) == 0) {
            atomic_fetch_add(&g_cnt_env_scheme_cloak, 1);
            return NULL;
        }
    }
    return orig_getenv ? orig_getenv(name) : NULL;
}

static BOOL swizzled_canOpenURL(id self, SEL _cmd, NSURL *url) {
    if (g_enable_env_scheme_cloak && [url isKindOfClass:[NSURL class]]) {
        NSString *scheme = url.scheme.lowercaseString;
        if (scheme.length > 0) {
            static NSSet<NSString *> *blocked = nil;
            static dispatch_once_t onceToken;
            dispatch_once(&onceToken, ^{
                blocked = [NSSet setWithArray:@[
                    @"cydia", @"sileo", @"zbra", @"filza", @"undecimus",
                    @"activator", @"roothide", @"trollstore", @"dopamine"
                ]];
            });
            if ([blocked containsObject:scheme]) {
                atomic_fetch_add(&g_cnt_env_scheme_cloak, 1);
                return NO;
            }
        }
    }
    return orig_canOpenURL ? orig_canOpenURL(self, _cmd, url) : NO;
}

#pragma mark - Bypass 6: VM Region RWX / Gum Trampoline Integrity Cloak

static kern_return_t hook_vm_region_64(vm_map_t target_task,
                                       vm_address_t *address,
                                       vm_size_t *size,
                                       vm_region_flavor_t flavor,
                                       vm_region_info_t info,
                                       mach_msg_type_number_t *infoCnt,
                                       mach_port_t *object_name) {
    const void *ret = __builtin_return_address(0);
    kern_return_t kr = orig_vm_region_64
        ? orig_vm_region_64(target_task, address, size, flavor, info, infoCnt, object_name)
        : KERN_FAILURE;
    if (kr == KERN_SUCCESS && g_enable_vm_integrity_cloak && !mcp_is_internal_caller(ret) &&
        info && flavor == VM_REGION_BASIC_INFO_64) {
        vm_region_basic_info_64_t b = (vm_region_basic_info_64_t)info;
        if ((b->protection & (VM_PROT_WRITE | VM_PROT_EXECUTE)) == (VM_PROT_WRITE | VM_PROT_EXECUTE)) {
            atomic_fetch_add(&g_cnt_vm_cloak, 1);
            b->protection &= ~VM_PROT_WRITE;
            b->max_protection &= ~VM_PROT_WRITE;
        }
    }
    return kr;
}

static kern_return_t hook_mach_vm_region(vm_map_t target_task,
                                         mach_vm_address_t *address,
                                         mach_vm_size_t *size,
                                         vm_region_flavor_t flavor,
                                         vm_region_info_t info,
                                         mach_msg_type_number_t *infoCnt,
                                         mach_port_t *object_name) {
    const void *ret = __builtin_return_address(0);
    kern_return_t kr = orig_mach_vm_region
        ? orig_mach_vm_region(target_task, address, size, flavor, info, infoCnt, object_name)
        : KERN_FAILURE;
    if (kr == KERN_SUCCESS && g_enable_vm_integrity_cloak && !mcp_is_internal_caller(ret) &&
        info && flavor == VM_REGION_BASIC_INFO_64) {
        vm_region_basic_info_64_t b = (vm_region_basic_info_64_t)info;
        if ((b->protection & (VM_PROT_WRITE | VM_PROT_EXECUTE)) == (VM_PROT_WRITE | VM_PROT_EXECUTE)) {
            atomic_fetch_add(&g_cnt_vm_cloak, 1);
            b->protection &= ~VM_PROT_WRITE;
            b->max_protection &= ~VM_PROT_WRITE;
        }
    }
    return kr;
}

#pragma mark - Image Registration & Rebinding

static void mcp_stealth_apply_hooks_to_image(const struct mach_header *hdr, intptr_t slide) {
    if (!hdr || hdr == g_stealth_header) return;
    Dl_info info;
    const char *name = (orig_dladdr ? orig_dladdr(hdr, &info) : dladdr(hdr, &info)) && info.dli_fname
        ? info.dli_fname
        : NULL;

    // Detect if this newly mapped image is the scrubbed Frida Gadget dylib
    int newly_detected_gadget = 0;
    if (hdr != g_stealth_header && mcp_is_hidden_image(hdr, name)) {
        if (name && strstr(name, "/Frameworks/") != NULL && !mcp_ci_contains(name, "libmcp_stealth")) {
            g_gadget_header = hdr;
            g_gadget_text = mcp_compute_text_range(hdr);
            newly_detected_gadget = 1;
        }
    }

    // Hook main executable + all non-system dylibs (including Gadget so pthread_setname_np is laundered!)
    int should_hook = 0;
    if (hdr->filetype == MH_EXECUTE) {
        should_hook = 1;
    } else if (name && strstr(name, "/System/") == NULL && strstr(name, "/usr/lib/") == NULL) {
        should_hook = 1;
    }
    if (!should_hook) return;

    struct mcp_rebinding rebindings[] = {
        {"pthread_setname_np", (void *)hook_pthread_setname_np, (void **)&orig_pthread_setname_np},
        {"_dyld_image_count", (void *)hook__dyld_image_count, (void **)&orig__dyld_image_count},
        {"_dyld_get_image_name", (void *)hook__dyld_get_image_name, (void **)&orig__dyld_get_image_name},
        {"_dyld_get_image_header", (void *)hook__dyld_get_image_header, (void **)&orig__dyld_get_image_header},
        {"_dyld_get_image_vmaddr_slide", (void *)hook__dyld_get_image_vmaddr_slide, (void **)&orig__dyld_get_image_vmaddr_slide},
        {"_dyld_register_func_for_add_image", (void *)hook__dyld_register_func_for_add_image, (void **)&orig__dyld_register_func_for_add_image},
        {"dladdr", (void *)hook_dladdr, (void **)&orig_dladdr},
        {"ptrace", (void *)hook_ptrace, (void **)&orig_ptrace},
        {"sysctl", (void *)hook_sysctl, (void **)&orig_sysctl},
        {"getppid", (void *)hook_getppid, (void **)&orig_getppid},
        {"isatty", (void *)hook_isatty, (void **)&orig_isatty},
        {"task_get_exception_ports", (void *)hook_task_get_exception_ports, (void **)&orig_task_get_exception_ports},
        {"thread_get_exception_ports", (void *)hook_thread_get_exception_ports, (void **)&orig_thread_get_exception_ports},
        {"stat", (void *)hook_stat, (void **)&orig_stat},
        {"lstat", (void *)hook_lstat, (void **)&orig_lstat},
        {"access", (void *)hook_access, (void **)&orig_access},
        {"faccessat", (void *)hook_faccessat, (void **)&orig_faccessat},
        {"open", (void *)hook_open, (void **)&orig_open},
        {"fopen", (void *)hook_fopen, (void **)&orig_fopen},
        {"opendir", (void *)hook_opendir, (void **)&orig_opendir},
        {"connect", (void *)hook_connect, (void **)&orig_connect},
        {"getenv", (void *)hook_getenv, (void **)&orig_getenv},
        {"vm_region_64", (void *)hook_vm_region_64, (void **)&orig_vm_region_64},
        {"mach_vm_region", (void *)hook_mach_vm_region, (void **)&orig_mach_vm_region},
    };
    mcp_rebind_symbols_image(hdr, slide, g_stealth_header, rebindings, sizeof(rebindings) / sizeof(rebindings[0]));
    if (newly_detected_gadget) {
        mcp_flush_stealth_status();
    }
}

__attribute__((constructor(101)))
static void mcp_stealth_init(void) {
    @autoreleasepool {
        // Seed true OS pointers before rebinding any GOTs
        orig_pthread_setname_np = (typeof(orig_pthread_setname_np))dlsym(RTLD_DEFAULT, "pthread_setname_np");
        orig__dyld_image_count = (typeof(orig__dyld_image_count))dlsym(RTLD_DEFAULT, "_dyld_image_count");
        orig__dyld_get_image_name = (typeof(orig__dyld_get_image_name))dlsym(RTLD_DEFAULT, "_dyld_get_image_name");
        orig__dyld_get_image_header = (typeof(orig__dyld_get_image_header))dlsym(RTLD_DEFAULT, "_dyld_get_image_header");
        orig__dyld_get_image_vmaddr_slide = (typeof(orig__dyld_get_image_vmaddr_slide))dlsym(RTLD_DEFAULT, "_dyld_get_image_vmaddr_slide");
        orig__dyld_register_func_for_add_image = (typeof(orig__dyld_register_func_for_add_image))dlsym(RTLD_DEFAULT, "_dyld_register_func_for_add_image");
        orig_dladdr = (typeof(orig_dladdr))dlsym(RTLD_DEFAULT, "dladdr");
        orig_ptrace = (typeof(orig_ptrace))dlsym(RTLD_DEFAULT, "ptrace");
        orig_sysctl = (typeof(orig_sysctl))dlsym(RTLD_DEFAULT, "sysctl");
        orig_getppid = (typeof(orig_getppid))dlsym(RTLD_DEFAULT, "getppid");
        orig_isatty = (typeof(orig_isatty))dlsym(RTLD_DEFAULT, "isatty");
        orig_task_get_exception_ports = (typeof(orig_task_get_exception_ports))dlsym(RTLD_DEFAULT, "task_get_exception_ports");
        orig_thread_get_exception_ports = (typeof(orig_thread_get_exception_ports))dlsym(RTLD_DEFAULT, "thread_get_exception_ports");
        orig_stat = (typeof(orig_stat))dlsym(RTLD_DEFAULT, "stat");
        orig_lstat = (typeof(orig_lstat))dlsym(RTLD_DEFAULT, "lstat");
        orig_access = (typeof(orig_access))dlsym(RTLD_DEFAULT, "access");
        orig_faccessat = (typeof(orig_faccessat))dlsym(RTLD_DEFAULT, "faccessat");
        orig_open = (typeof(orig_open))dlsym(RTLD_DEFAULT, "open");
        orig_fopen = (typeof(orig_fopen))dlsym(RTLD_DEFAULT, "fopen");
        orig_opendir = (typeof(orig_opendir))dlsym(RTLD_DEFAULT, "opendir");
        orig_connect = (typeof(orig_connect))dlsym(RTLD_DEFAULT, "connect");
        orig_getenv = (typeof(orig_getenv))dlsym(RTLD_DEFAULT, "getenv");
        orig_vm_region_64 = (typeof(orig_vm_region_64))dlsym(RTLD_DEFAULT, "vm_region_64");
        orig_mach_vm_region = (typeof(orig_mach_vm_region))dlsym(RTLD_DEFAULT, "mach_vm_region");

        Dl_info selfInfo;
        if (orig_dladdr((const void *)&mcp_stealth_init, &selfInfo) && selfInfo.dli_fbase) {
            g_stealth_header = (const struct mach_header *)selfInfo.dli_fbase;
            g_stealth_text = mcp_compute_text_range(g_stealth_header);
            if (selfInfo.dli_fname) {
                const char *base = strrchr(selfInfo.dli_fname, '/');
                base = base ? (base + 1) : selfInfo.dli_fname;
                strncpy(g_hidden_dylib_names[0], base, sizeof(g_hidden_dylib_names[0]) - 1);
                g_hidden_dylib_count = 1;
            }
        }

        mcp_reload_config_if_needed(1);

        Class uiApp = objc_getClass("UIApplication");
        if (uiApp) {
            Method m = class_getInstanceMethod(uiApp, @selector(canOpenURL:));
            if (m) {
                orig_canOpenURL = (typeof(orig_canOpenURL))method_setImplementation(m, (IMP)swizzled_canOpenURL);
            }
        }

        // Register our internal add-image hook via real dyld BEFORE rebinding _dyld_register_func_for_add_image
        if (orig__dyld_register_func_for_add_image) {
            orig__dyld_register_func_for_add_image(mcp_stealth_apply_hooks_to_image);
        }

        mcp_flush_stealth_status();
    }
}
