#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <sqlite3.h>
#import <dlfcn.h>
#import <errno.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <mach-o/dyld.h>
#import <arpa/inet.h>
#import <netinet/in.h>
#import <pthread.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import <sys/socket.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <sys/types.h>
#import <unistd.h>

#ifndef P_TRACED
#define P_TRACED 0x00000800
#endif

#ifndef PT_DENY_ATTACH
#define PT_DENY_ATTACH 31
#endif

extern int ptrace(int request, pid_t pid, caddr_t addr, int data);

static const uint8_t kMCPSelfSignedCertDER[336] = {
    0x30, 0x82, 0x01, 0x4c, 0x30, 0x81, 0xf3, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x04, 0x01, 0x29,
    0x23, 0x59, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x1d,
    0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x12, 0x70, 0x69, 0x6e, 0x2e, 0x69,
    0x6f, 0x73, 0x6d, 0x63, 0x70, 0x2e, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x30, 0x1e, 0x17,
    0x0d, 0x32, 0x35, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x17, 0x0d,
    0x33, 0x35, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x1d, 0x31,
    0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x12, 0x70, 0x69, 0x6e, 0x2e, 0x69, 0x6f,
    0x73, 0x6d, 0x63, 0x70, 0x2e, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x30, 0x59, 0x30, 0x13,
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xa0, 0x51, 0xa2, 0x3d, 0x63, 0x25, 0x6a, 0x3d, 0x11,
    0x43, 0xf2, 0x70, 0xbd, 0xa9, 0x33, 0x46, 0x55, 0x91, 0x2d, 0x7c, 0x49, 0x36, 0x6a, 0xc0, 0x7a,
    0x9c, 0x63, 0xd0, 0xa4, 0x13, 0x9f, 0xe9, 0x5a, 0x73, 0x5f, 0xcd, 0xd5, 0xa9, 0xaf, 0x52, 0x81,
    0x81, 0x26, 0x67, 0x47, 0x45, 0x48, 0x37, 0x50, 0x06, 0xae, 0x62, 0x3d, 0x86, 0xbb, 0x05, 0x27,
    0x8a, 0xc7, 0x83, 0xa7, 0xdc, 0xd3, 0x87, 0xa3, 0x21, 0x30, 0x1f, 0x30, 0x1d, 0x06, 0x03, 0x55,
    0x1d, 0x11, 0x04, 0x16, 0x30, 0x14, 0x82, 0x12, 0x70, 0x69, 0x6e, 0x2e, 0x69, 0x6f, 0x73, 0x6d,
    0x63, 0x70, 0x2e, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x34, 0xdc, 0x98,
    0xf0, 0x36, 0xbd, 0x93, 0x14, 0x18, 0x5c, 0xf7, 0x9b, 0xf8, 0x3f, 0x5d, 0x54, 0xfb, 0x85, 0x0d,
    0x74, 0xd0, 0xb0, 0xe3, 0xff, 0x0b, 0x64, 0xe2, 0x97, 0xbe, 0xa8, 0x5a, 0x10, 0x02, 0x21, 0x00,
    0xe6, 0x37, 0x3f, 0x07, 0x16, 0x5f, 0x5f, 0x51, 0xf1, 0xb4, 0xf9, 0x7a, 0x29, 0x98, 0x48, 0x08,
    0x35, 0x84, 0xed, 0x76, 0x1b, 0x8b, 0x4a, 0xe7, 0xfd, 0x3f, 0xe5, 0x95, 0xd9, 0x42, 0xdc, 0xea
};

@interface MCPTestVault : NSObject {
    NSString *_secretToken;
    NSInteger _magicCounter;
    char *_heapMarkerBuffer;
    uint16_t _localEchoPort;
    int _localServerFD;
}

+ (instancetype)sharedVault;
+ (NSString *)vaultVersion;
+ (NSString *)runAntiDetectionAuditJSON;
- (NSInteger)verifyPinCode:(NSInteger)pin;
- (NSString *)computeVaultDigest:(NSString *)seed;
- (NSString *)currentHeapMarkerString;
- (NSDictionary *)evaluatePinnedSelfSignedTLS;
- (void)startLocalEchoServer;
- (void)triggerLocalHTTPFetch;
- (void)seedSQLiteFixture;
- (void)writeRuntimeStateSnapshot;
- (uintptr_t)engineScratchAddress;
- (NSInteger)runEngineProbe;

@end

@implementation MCPTestVault

+ (instancetype)sharedVault {
    static MCPTestVault *vault = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        vault = [[MCPTestVault alloc] init];
    });
    return vault;
}

+ (NSString *)vaultVersion {
    return @"1.2.9-roothide";
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _secretToken = @"MCP_VAULT_SECRET_129";
        _magicCounter = 0x1337BEEF;
        _localEchoPort = 0;
        _localServerFD = -1;
        _heapMarkerBuffer = (char *)calloc(1, 64);
        if (_heapMarkerBuffer) {
            strcpy(_heapMarkerBuffer, "MCP_HEAP_MARKER_ORIGINAL_129");
        }
    }
    return self;
}

- (NSInteger)verifyPinCode:(NSInteger)pin {
    return (pin == 2359) ? 1 : 0;
}

- (uintptr_t)engineScratchAddress {
    // Dedicated, writable 64-byte fixture allocation; never use code pages.
    return (uintptr_t)_heapMarkerBuffer;
}

- (NSInteger)runEngineProbe {
    NSInteger pinResult = [self verifyPinCode:0];
    NSString *path = [NSTemporaryDirectory() stringByAppendingPathComponent:@"engine_probe.txt"];
    int fd = open(path.fileSystemRepresentation, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) {
        const char marker[] = "MCPTest engine native hook probe\n";
        (void)write(fd, marker, sizeof(marker)-1);
        close(fd);
    }
    NSDictionary *result = @{@"pid":@(getpid()), @"pin_result":@(pinResult),
                              @"file_opened":@(fd >= 0), @"foreground":@([UIApplication sharedApplication].applicationState == UIApplicationStateActive)};
    [[NSJSONSerialization dataWithJSONObject:result options:0 error:NULL]
        writeToFile:[NSTemporaryDirectory() stringByAppendingPathComponent:@"engine_probe.json"] atomically:YES];
    return pinResult;
}

- (NSString *)computeVaultDigest:(NSString *)seed {
    return [NSString stringWithFormat:@"DIGEST[%@:%@:%ld]", seed ?: @"none", _secretToken, (long)_magicCounter];
}

- (NSString *)currentHeapMarkerString {
    if (!_heapMarkerBuffer) return @"";
    _heapMarkerBuffer[63] = '\0';
    return [NSString stringWithUTF8String:_heapMarkerBuffer] ?: @"";
}

- (NSDictionary *)evaluatePinnedSelfSignedTLS {
    CFDataRef derData = CFDataCreate(kCFAllocatorDefault, kMCPSelfSignedCertDER, sizeof(kMCPSelfSignedCertDER));
    SecCertificateRef cert = derData ? SecCertificateCreateWithData(kCFAllocatorDefault, derData) : NULL;
    if (derData) CFRelease(derData);
    if (!cert) {
        return @{@"ok": @NO, @"error": @"SecCertificateCreateWithData failed"};
    }

    SecPolicyRef policy = SecPolicyCreateSSL(true, CFSTR("pin.iosmcp.invalid"));
    CFArrayRef certs = CFArrayCreate(kCFAllocatorDefault, (const void **)&cert, 1, &kCFTypeArrayCallBacks);
    SecTrustRef trust = NULL;
    OSStatus createStatus = SecTrustCreateWithCertificates(certs, policy, &trust);
    if (certs) CFRelease(certs);
    if (policy) CFRelease(policy);
    CFRelease(cert);

    if (createStatus != errSecSuccess || !trust) {
        return @{@"ok": @NO, @"osstatus": @(createStatus)};
    }

    CFErrorRef cfErr = NULL;
    bool trustedWithError = SecTrustEvaluateWithError(trust, &cfErr);
    NSString *errDesc = @"";
    if (cfErr) {
        CFStringRef desc = CFErrorCopyDescription(cfErr);
        if (desc) {
            errDesc = [(__bridge NSString *)desc copy];
            CFRelease(desc);
        }
        CFRelease(cfErr);
    }

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    SecTrustResultType legacyResult = kSecTrustResultInvalid;
    OSStatus legacyStatus = SecTrustEvaluate(trust, &legacyResult);
#pragma clang diagnostic pop

    CFRelease(trust);

    NSDictionary *res = @{
        @"pid": @(getpid()),
        @"sec_trust_with_error_trusted": @(trustedWithError ? YES : NO),
        @"sec_trust_evaluate_osstatus": @(legacyStatus),
        @"sec_trust_evaluate_result": @((int)legacyResult),
        @"error_description": errDesc ?: @"",
        @"timestamp": @([[NSDate date] timeIntervalSince1970])
    };
    NSString *outPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"tls_pin_result.json"];
    NSData *json = [NSJSONSerialization dataWithJSONObject:res options:NSJSONWritingPrettyPrinted error:NULL];
    [json writeToFile:outPath options:NSDataWritingAtomic error:NULL];
    return res;
}

- (void)startLocalEchoServer {
    if (_localServerFD >= 0) return;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return;
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_len = sizeof(sin);
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = 0;

    if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) != 0 || listen(fd, 8) != 0) {
        close(fd);
        return;
    }

    socklen_t slen = sizeof(sin);
    if (getsockname(fd, (struct sockaddr *)&sin, &slen) == 0) {
        _localEchoPort = ntohs(sin.sin_port);
    }
    _localServerFD = fd;

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        while (1) {
            struct sockaddr_in clientAddr;
            socklen_t clen = sizeof(clientAddr);
            int cfd = accept(fd, (struct sockaddr *)&clientAddr, &clen);
            if (cfd < 0) break;
            char reqBuf[2048];
            (void)recv(cfd, reqBuf, sizeof(reqBuf) - 1, 0);
            static const char body[] = "{\"ok\":true,\"service\":\"mcp-local-echo\",\"version\":\"1.2.9\"}";
            char resp[512];
            int n = snprintf(resp, sizeof(resp),
                             "HTTP/1.1 200 OK\r\n"
                             "Content-Type: application/json\r\n"
                             "X-MCP-Echo: active\r\n"
                             "Content-Length: %zu\r\n"
                             "Connection: close\r\n\r\n%s",
                             sizeof(body) - 1, body);
            if (n > 0) {
                (void)send(cfd, resp, (size_t)n, 0);
            }
            close(cfd);
        }
    });
}

- (void)triggerLocalHTTPFetch {
    if (_localEchoPort == 0) [self startLocalEchoServer];
    if (_localEchoPort == 0) return;

    NSString *urlStr = [NSString stringWithFormat:@"http://127.0.0.1:%u/api/v1/vault/ping?client=MCPTestTarget", (unsigned)_localEchoPort];
    NSURL *url = [NSURL URLWithString:urlStr];
    if (!url) return;

    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.HTTPMethod = @"POST";
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    [req setValue:@"129-roothide" forHTTPHeaderField:@"X-Vault-Probe"];
    req.HTTPBody = [@"{\"ping\":\"ios-mcp-1.2.9\",\"op\":\"vault_sync\"}" dataUsingEncoding:NSUTF8StringEncoding];

    NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithRequest:req
                                                                 completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        NSHTTPURLResponse *http = [response isKindOfClass:[NSHTTPURLResponse class]] ? (NSHTTPURLResponse *)response : nil;
        NSDictionary *fetchInfo = @{
            @"url": urlStr,
            @"status": @(http ? http.statusCode : 0),
            @"bytes": @(data ? data.length : 0),
            @"error": error ? (error.localizedDescription ?: @"error") : @""
        };
        NSString *p = [NSTemporaryDirectory() stringByAppendingPathComponent:@"last_http_fetch.json"];
        NSData *j = [NSJSONSerialization dataWithJSONObject:fetchInfo options:NSJSONWritingPrettyPrinted error:NULL];
        [j writeToFile:p options:NSDataWritingAtomic error:NULL];
    }];
    [task resume];
}

- (void)seedSQLiteFixture {
    NSString *dbPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"vault_fixture.sqlite"];
    sqlite3 *db = NULL;
    if (sqlite3_open(dbPath.fileSystemRepresentation, &db) != SQLITE_OK || !db) {
        if (db) sqlite3_close(db);
        return;
    }
    const char *sql =
        "CREATE TABLE IF NOT EXISTS vault_records (id INTEGER PRIMARY KEY, label TEXT NOT NULL, clearance INTEGER NOT NULL);"
        "DELETE FROM vault_records;"
        "INSERT INTO vault_records (id, label, clearance) VALUES (1, 'alpha_sector', 10), (2, 'bravo_key', 20), (3, 'charlie_root', 30);";
    sqlite3_exec(db, sql, NULL, NULL, NULL);
    sqlite3_close(db);
}

- (void)writeRuntimeStateSnapshot {
    uintptr_t mainBase = 0;
    uint32_t imgCount = _dyld_image_count();
    for (uint32_t i = 0; i < imgCount; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, "MCPTestTarget") != NULL) {
            mainBase = (uintptr_t)_dyld_get_image_header(i);
            break;
        }
    }
    NSDictionary *state = @{
        @"pid": @(getpid()),
        @"bundle_id": [[NSBundle mainBundle] bundleIdentifier] ?: @"com.iosmcp.testtarget",
        @"main_image_base": [NSString stringWithFormat:@"0x%llx", (unsigned long long)mainBase],
        @"heap_marker_address": [NSString stringWithFormat:@"0x%llx", (unsigned long long)(uintptr_t)_heapMarkerBuffer],
        @"heap_marker_capacity": @(64),
        @"heap_marker_value": [self currentHeapMarkerString],
        @"local_echo_port": @(_localEchoPort),
        @"sqlite_fixture_path": [NSTemporaryDirectory() stringByAppendingPathComponent:@"vault_fixture.sqlite"],
        @"tls_result_path": [NSTemporaryDirectory() stringByAppendingPathComponent:@"tls_pin_result.json"]
    };
    NSString *statePath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"test_state.json"];
    NSData *json = [NSJSONSerialization dataWithJSONObject:state options:NSJSONWritingPrettyPrinted error:NULL];
    [json writeToFile:statePath options:NSDataWritingAtomic error:NULL];
}

+ (NSString *)runAntiDetectionAuditJSON {
    // 1. Dyld image enumeration from app's own __TEXT caller
    uint32_t dyldCount = _dyld_image_count();
    NSMutableArray<NSString *> *suspiciousImages = [NSMutableArray array];
    for (uint32_t i = 0; i < dyldCount; i++) {
        const char *raw = _dyld_get_image_name(i);
        if (!raw) continue;
        NSString *s = [NSString stringWithUTF8String:raw] ?: @"";
        NSString *low = s.lowercaseString;
        if ([low containsString:@"frida"] ||
            [low containsString:@"gadget"] ||
            [low containsString:@"libmcp_stealth"] ||
            [low containsString:@"applecoresvg_"] ||
            [low containsString:@"appleaudiodsp_"] ||
            [low containsString:@".jbroot-"] ||
            [low containsString:@"/var/jb"] ||
            [low containsString:@"mobilesubstrate"]) {
            [suspiciousImages addObject:s];
        }
    }

    // 2. Thread-name enumeration via task_threads + pthread_getname_np
    thread_act_array_t threadList = NULL;
    mach_msg_type_number_t threadCount = 0;
    NSMutableArray<NSString *> *threadNames = [NSMutableArray array];
    NSMutableArray<NSString *> *suspiciousThreads = [NSMutableArray array];
    if (task_threads(mach_task_self(), &threadList, &threadCount) == KERN_SUCCESS && threadList) {
        for (mach_msg_type_number_t i = 0; i < threadCount; i++) {
            pthread_t pt = pthread_from_mach_thread_np(threadList[i]);
            char tname[128] = {0};
            if (pt) pthread_getname_np(pt, tname, sizeof(tname));
            NSString *ns = [NSString stringWithUTF8String:tname] ?: @"";
            [threadNames addObject:ns];
            NSString *low = ns.lowercaseString;
            if ([low containsString:@"frida"] ||
                [low containsString:@"gum-js-loop"] ||
                [low containsString:@"gmain"] ||
                [low containsString:@"gdbus"] ||
                [low containsString:@"pool-spawner"] ||
                [low containsString:@"gadget"]) {
                [suspiciousThreads addObject:ns];
            }
            mach_port_deallocate(mach_task_self(), threadList[i]);
        }
        vm_deallocate(mach_task_self(), (vm_address_t)threadList, sizeof(thread_act_t) * threadCount);
    }

    // 3. Anti-debug: ptrace(PT_DENY_ATTACH), sysctl P_TRACED, getppid, isatty
    int ptraceRet = ptrace(PT_DENY_ATTACH, 0, 0, 0);
    struct kinfo_proc kp;
    memset(&kp, 0, sizeof(kp));
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    size_t kpSize = sizeof(kp);
    int sysctlRet = sysctl(mib, 4, &kp, &kpSize, NULL, 0);
    BOOL pTraced = (sysctlRet == 0 && (kp.kp_proc.p_flag & P_TRACED) != 0);
    pid_t ppid = getppid();
    int tty0 = isatty(STDIN_FILENO);

    // 4. Mach exception ports cloak
    exception_mask_t masks[EXC_TYPES_COUNT];
    mach_msg_type_number_t masksCnt = EXC_TYPES_COUNT;
    exception_handler_t handlers[EXC_TYPES_COUNT];
    exception_behavior_t behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t flavors[EXC_TYPES_COUNT];
    memset(handlers, 0, sizeof(handlers));
    kern_return_t excKr = task_get_exception_ports(mach_task_self(),
                                                   EXC_MASK_BAD_ACCESS | EXC_MASK_BREAKPOINT,
                                                   masks,
                                                   &masksCnt,
                                                   handlers,
                                                   behaviors,
                                                   flavors);
    NSUInteger activeExcHandlers = 0;
    if (excKr == KERN_SUCCESS) {
        for (mach_msg_type_number_t i = 0; i < masksCnt; i++) {
            if (handlers[i] != MACH_PORT_NULL) {
                activeExcHandlers++;
                mach_port_deallocate(mach_task_self(), handlers[i]);
            }
        }
    }

    // 5. Filesystem jailbreak & Frida path probes
    struct stat st;
    BOOL statVarJbExists = (stat("/var/jb", &st) == 0);
    BOOL accessFridaServerExists = (access("/usr/sbin/frida-server", F_OK) == 0);
    FILE *fpSub = fopen("/Library/MobileSubstrate/MobileSubstrate.dylib", "rb");
    BOOL fopenSubstrateExists = (fpSub != NULL);
    if (fpSub) fclose(fpSub);

    // 6. Localhost Frida port probe (127.0.0.1:27042)
    BOOL fridaPort27042Open = NO;
    int probeSock = socket(AF_INET, SOCK_STREAM, 0);
    if (probeSock >= 0) {
        fcntl(probeSock, F_SETFL, O_NONBLOCK);
        struct sockaddr_in fsin;
        memset(&fsin, 0, sizeof(fsin));
        fsin.sin_len = sizeof(fsin);
        fsin.sin_family = AF_INET;
        fsin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        fsin.sin_port = htons(27042);
        int crc = connect(probeSock, (struct sockaddr *)&fsin, sizeof(fsin));
        if (crc == 0) {
            fridaPort27042Open = YES;
        }
        close(probeSock);
    }

    // 7. Environment & URL scheme cloak
    const char *dyldInsert = getenv("DYLD_INSERT_LIBRARIES");
    __block BOOL canOpenCydia = NO;
    void (^schemeBlock)(void) = ^{
        canOpenCydia = [[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"cydia://package/com.example"]];
    };
    if ([NSThread isMainThread]) {
        schemeBlock();
    } else {
        dispatch_sync(dispatch_get_main_queue(), schemeBlock);
    }

    // 8. VM RWX page integrity scan via vm_region_64
    vm_address_t addr = 0;
    vm_size_t regionSize = 0;
    NSUInteger rwxRegions = 0;
    for (int iter = 0; iter < 4096; iter++) {
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t infoCnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t objName = MACH_PORT_NULL;
        kern_return_t kr = vm_region_64(mach_task_self(), &addr, &regionSize, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &infoCnt, &objName);
        if (objName != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), objName);
        if (kr != KERN_SUCCESS) break;
        if ((info.protection & (VM_PROT_WRITE | VM_PROT_EXECUTE)) == (VM_PROT_WRITE | VM_PROT_EXECUTE)) {
            rwxRegions++;
        }
        if (regionSize == 0) break;
        addr += regionSize;
    }

    NSDictionary *audit = @{
        @"visible_dyld_image_count": @(dyldCount),
        @"suspicious_dyld_images": suspiciousImages,
        @"dyld_clean": @(suspiciousImages.count == 0),
        @"thread_count": @(threadNames.count),
        @"thread_names": threadNames,
        @"suspicious_threads": suspiciousThreads,
        @"threads_clean": @(suspiciousThreads.count == 0),
        @"ptrace_deny_attach_ret": @(ptraceRet),
        @"sysctl_p_traced": @(pTraced),
        @"getppid": @(ppid),
        @"stdin_isatty": @(tty0),
        @"anti_debug_clean": @(ptraceRet == 0 && !pTraced && ppid == 1 && tty0 == 0),
        @"active_exception_handlers": @(activeExcHandlers),
        @"exception_ports_clean": @(activeExcHandlers == 0),
        @"stat_var_jb_exists": @(statVarJbExists),
        @"access_frida_server_exists": @(accessFridaServerExists),
        @"fopen_substrate_exists": @(fopenSubstrateExists),
        @"fs_clean": @(!statVarJbExists && !accessFridaServerExists && !fopenSubstrateExists),
        @"frida_port_27042_open": @(fridaPort27042Open),
        @"dyld_insert_libraries_present": @(dyldInsert != NULL && dyldInsert[0] != '\0'),
        @"can_open_cydia_scheme": @(canOpenCydia),
        @"env_scheme_clean": @((dyldInsert == NULL || dyldInsert[0] == '\0') && !canOpenCydia),
        @"rwx_region_count": @(rwxRegions),
        @"vm_rwx_clean": @(rwxRegions == 0)
    };

    NSString *auditPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"anti_detection_audit.json"];
    NSData *json = [NSJSONSerialization dataWithJSONObject:audit options:NSJSONWritingPrettyPrinted error:NULL];
    [json writeToFile:auditPath options:NSDataWritingAtomic error:NULL];
    return json ? ([[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding] ?: @"{}") : @"{}";
}

@end

@interface MCPTestViewController : UIViewController
@property (nonatomic, strong) UILabel *statusLabel;
@end

@implementation MCPTestViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor colorWithRed:0.08 green:0.10 blue:0.14 alpha:1.0];

    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(20, 56, self.view.bounds.size.width - 40, 32)];
    title.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    title.text = @"MCPTestTarget 1.2.9";
    title.font = [UIFont boldSystemFontOfSize:22];
    title.textColor = [UIColor whiteColor];
    [self.view addSubview:title];

    self.statusLabel = [[UILabel alloc] initWithFrame:CGRectMake(20, 96, self.view.bounds.size.width - 40, 140)];
    self.statusLabel.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    self.statusLabel.numberOfLines = 0;
    self.statusLabel.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightRegular];
    self.statusLabel.textColor = [UIColor colorWithRed:0.72 green:0.92 blue:0.80 alpha:1.0];
    self.statusLabel.text = [NSString stringWithFormat:@"PID: %d\nVault: %@\nMarker: %@",
                             getpid(),
                             [MCPTestVault vaultVersion],
                             [[MCPTestVault sharedVault] currentHeapMarkerString]];
    [self.view addSubview:self.statusLabel];

    NSArray<NSArray *> *buttons = @[
        @[@"Run TLS Pin Test", NSStringFromSelector(@selector(onRunTLS))],
        @[@"Run HTTP Fetch", NSStringFromSelector(@selector(onRunHTTP))],
        @[@"Run Anti-Detection Audit", NSStringFromSelector(@selector(onRunAudit))],
        @[@"Refresh Vault State", NSStringFromSelector(@selector(onRefreshState))],
        @[@"Run Engine Probe", NSStringFromSelector(@selector(onEngineProbe))]
    ];

    CGFloat y = 250.0;
    for (NSArray *spec in buttons) {
        UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
        btn.frame = CGRectMake(20, y, self.view.bounds.size.width - 40, 44);
        btn.autoresizingMask = UIViewAutoresizingFlexibleWidth;
        btn.backgroundColor = [UIColor colorWithRed:0.16 green:0.24 blue:0.36 alpha:1.0];
        btn.layer.cornerRadius = 8.0;
        [btn setTitle:spec[0] forState:UIControlStateNormal];
        [btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        btn.accessibilityLabel = spec[0];
        [btn addTarget:self action:NSSelectorFromString(spec[1]) forControlEvents:UIControlEventTouchUpInside];
        [self.view addSubview:btn];
        y += 54.0;
    }
}

- (void)onRunTLS {
    NSDictionary *r = [[MCPTestVault sharedVault] evaluatePinnedSelfSignedTLS];
    self.statusLabel.text = [NSString stringWithFormat:@"PID: %d\nTLS Trusted: %@",
                             getpid(), r[@"sec_trust_with_error_trusted"]];
}

- (void)onRunHTTP {
    [[MCPTestVault sharedVault] triggerLocalHTTPFetch];
    self.statusLabel.text = [NSString stringWithFormat:@"PID: %d\nHTTP Fetch Triggered", getpid()];
}

- (void)onEngineProbe {
    NSInteger result = [[MCPTestVault sharedVault] runEngineProbe];
    self.statusLabel.text = [NSString stringWithFormat:@"PID: %d\nEngine PIN(0): %ld\nNative open/write probe complete", getpid(), (long)result];
}

- (void)onRunAudit {
    (void)[MCPTestVault runAntiDetectionAuditJSON];
    self.statusLabel.text = [NSString stringWithFormat:@"PID: %d\nAnti-Detection Audit Written", getpid()];
}

- (void)onRefreshState {
    [[MCPTestVault sharedVault] writeRuntimeStateSnapshot];
    self.statusLabel.text = [NSString stringWithFormat:@"PID: %d\nMarker: %@",
                             getpid(), [[MCPTestVault sharedVault] currentHeapMarkerString]];
}

@end

@interface MCPTestAppDelegate : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@end

@implementation MCPTestAppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    MCPTestVault *vault = [MCPTestVault sharedVault];
    [vault startLocalEchoServer];
    [vault seedSQLiteFixture];
    [vault evaluatePinnedSelfSignedTLS];
    [vault writeRuntimeStateSnapshot];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(250 * NSEC_PER_MSEC)), dispatch_get_main_queue(), ^{
        [vault triggerLocalHTTPFetch];
    });

    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    self.window.rootViewController = [[MCPTestViewController alloc] init];
    [self.window makeKeyAndVisible];
    // UIKit owns the main run loop. Keep the display awake during an explicit
    // engine test session; iOS still controls background suspension normally.
    BOOL engineMode = [[[NSProcessInfo processInfo] arguments] containsObject:@"--engine-test"] ||
        [[NSFileManager defaultManager] fileExistsAtPath:[NSTemporaryDirectory() stringByAppendingPathComponent:@".mcpe_cfg.json"]];
    application.idleTimerDisabled = engineMode;
    return YES;
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([MCPTestAppDelegate class]));
    }
}
