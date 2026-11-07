#import "MemoryManager.h"
#import <ctype.h>
#import <dlfcn.h>
#import <glob.h>
#import <libkern/OSByteOrder.h>
#import <mach/mach.h>
#import <mach-o/dyld.h>
#import <mach-o/fat.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <spawn.h>
#import <stdbool.h>
#import <stdlib.h>
#import <string.h>
#import <sys/stat.h>
#import <sys/wait.h>
#import <unistd.h>

extern char **environ;

// The iOS SDK intentionally omits the mach_vm MIG declarations.
extern kern_return_t mach_vm_read_overwrite(vm_map_t, mach_vm_address_t, mach_vm_size_t, mach_vm_address_t, mach_vm_size_t *);
extern kern_return_t mach_vm_write(vm_map_t, mach_vm_address_t, vm_offset_t, mach_msg_type_number_t);
extern kern_return_t mach_vm_protect(vm_map_t, mach_vm_address_t, mach_vm_size_t, boolean_t, vm_prot_t);
extern kern_return_t mach_vm_region(vm_map_t, mach_vm_address_t *, mach_vm_size_t *, vm_region_flavor_t, vm_region_info_t, mach_msg_type_number_t *, mach_port_t *);

typedef int (*mcp_jb_set_debugged_fn)(uint64_t pid, bool fully_debugged);
typedef kern_return_t (*mcp_hookd_vm_protect_fn)(pid_t pid, mach_vm_address_t address, mach_vm_size_t size, bool set_max, vm_prot_t new_prot);

static void *MCPLoadLibJailbreak(void) {
    static void *sHandle = NULL;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sHandle = dlopen("/basebin/libjailbreak.dylib", RTLD_LAZY);
        if (!sHandle) {
            glob_t g = {0};
            if (glob("/var/containers/Bundle/Application/.jbroot-*/basebin/libjailbreak.dylib", 0, NULL, &g) == 0 && g.gl_pathc > 0) {
                sHandle = dlopen(g.gl_pathv[0], RTLD_LAZY);
            }
            globfree(&g);
        }
    });
    return sHandle;
}

static void MCPTryEnsureProcessDebugged(pid_t pid) {
    void *h = MCPLoadLibJailbreak();
    if (!h) return;
    mcp_jb_set_debugged_fn fn = (mcp_jb_set_debugged_fn)dlsym(h, "jbclient_platform_set_process_debugged");
    if (fn) {
        fn((uint64_t)pid, false);
    }
}

static NSString *MCPMemoryEnsureWorkDir(void) {
    NSString *dir = @"/var/mobile/Library/Caches/ios-mcp-work";
    glob_t g = {0};
    if (glob("/var/containers/Bundle/Application/.jbroot-*/var/mobile/Library/Caches", 0, NULL, &g) == 0 && g.gl_pathc > 0) {
        dir = [[NSString stringWithUTF8String:g.gl_pathv[0]] stringByAppendingPathComponent:@"ios-mcp-work"];
    }
    globfree(&g);
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    chmod(dir.UTF8String, 0777);
    chown(dir.UTF8String, 501, 501);
    return dir;
}

static kern_return_t MCPTryHookdVmProtect(pid_t pid, mach_vm_address_t addr, mach_vm_size_t size, vm_prot_t prot) {
    void *h = MCPLoadLibJailbreak();
    if (!h) return KERN_FAILURE;
    mcp_hookd_vm_protect_fn fn = (mcp_hookd_vm_protect_fn)dlsym(h, "hookd_vm_protect");
    if (!fn) fn = (mcp_hookd_vm_protect_fn)dlsym(h, "_hookd_vm_protect");
    if (!fn) return KERN_FAILURE;
    return fn(pid, addr, size, false, prot);
}

typedef struct {
    uint32_t version;
    uint32_t infoArrayCount;
    uint64_t infoArray;
} MCPRemoteDyldAllImageInfos;

typedef struct {
    uint64_t imageLoadAddress;
    uint64_t imageFilePath;
    uint64_t imageFileModDate;
} MCPRemoteDyldImageInfo;

static NSString *MCPMachError(kern_return_t result) {
    return [NSString stringWithFormat:@"%s (%d)", mach_error_string(result), result];
}

static NSString *MCPVMProtString(vm_prot_t prot) {
    return [NSString stringWithFormat:@"%c%c%c",
            (prot & VM_PROT_READ) ? 'r' : '-',
            (prot & VM_PROT_WRITE) ? 'w' : '-',
            (prot & VM_PROT_EXECUTE) ? 'x' : '-'];
}

static uint64_t MCPComputeRemoteVAMask(mach_port_t task) {
    mach_vm_address_t addr = 0;
    uint64_t highest = 0;
    for (NSUInteger i = 0; i < 8192; i++) {
        mach_vm_size_t size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj = MACH_PORT_NULL;
        kern_return_t kr = mach_vm_region(task, &addr, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &obj);
        if (obj != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), obj);
        if (kr != KERN_SUCCESS || size == 0) break;
        uint64_t end = addr + size;
        if (end > highest) highest = end;
        if (addr > UINT64_MAX - size) break;
        addr += size;
    }
    unsigned bits = 36;
    while (bits < 48 && highest > (1ULL << bits)) {
        bits++;
    }
    return (1ULL << bits) - 1ULL;
}

static uint64_t MCPStripPAC(uint64_t ptr, uint64_t vaMask) {
    return ptr & vaMask;
}

static uint64_t MCPStripRemotePointer(uint64_t ptr, uint64_t vaMask) {
    return MCPStripPAC(ptr, vaMask);
}

static BOOL MCPRemoteReadExact(mach_port_t task, uint64_t addr, void *buf, size_t len, uint64_t vaMask) {
    if (!addr || !buf || !len) return NO;
    uint64_t clean = MCPStripPAC(addr, vaMask);
    if (!clean) return NO;
    mach_vm_size_t actual = 0;
    kern_return_t kr = mach_vm_read_overwrite(task, clean, len, (mach_vm_address_t)buf, &actual);
    if (kr == KERN_SUCCESS && actual == len) return YES;

    // Fallback masks in case kernel shared region sits slightly above normal user VA bits
    const uint64_t fallbacks[] = {0x0000000FFFFFFFFFULL, 0x0000007FFFFFFFFFULL, 0x00007FFFFFFFFFFFULL};
    for (size_t i = 0; i < sizeof(fallbacks) / sizeof(fallbacks[0]); i++) {
        uint64_t alt = addr & fallbacks[i];
        if (alt == clean || alt == 0) continue;
        actual = 0;
        kr = mach_vm_read_overwrite(task, alt, len, (mach_vm_address_t)buf, &actual);
        if (kr == KERN_SUCCESS && actual == len) return YES;
    }
    return NO;
}

static NSString *MCPRemoteReadCString(mach_port_t task, uint64_t addr, size_t maxLen, uint64_t vaMask) {
    if (!addr || maxLen == 0) return nil;
    uint64_t clean = MCPStripPAC(addr, vaMask);
    if (!clean) return nil;
    if (maxLen > 1024) maxLen = 1024;
    char buf[1025] = {0};

    // Read in 64-byte chunks to avoid crossing into an unmapped guard page
    size_t offset = 0;
    while (offset < maxLen) {
        size_t chunk = MIN((size_t)64, maxLen - offset);
        if (!MCPRemoteReadExact(task, clean + offset, buf + offset, chunk, vaMask)) {
            if (offset == 0) return nil;
            break;
        }
        for (size_t i = 0; i < chunk; i++) {
            if (buf[offset + i] == '\0') {
                if (offset + i == 0) return @"";
                return [[NSString alloc] initWithBytes:buf length:offset + i encoding:NSUTF8StringEncoding];
            }
        }
        offset += chunk;
    }
    buf[offset] = '\0';
    size_t slen = strlen(buf);
    if (slen == 0) return nil;
    return [[NSString alloc] initWithBytes:buf length:slen encoding:NSUTF8StringEncoding];
}

static NSArray<NSDictionary *> *MCPRemoteEnumerateDyldImages(mach_port_t task, uint64_t *outVaMask) {
    uint64_t vaMask = MCPComputeRemoteVAMask(task);
    if (outVaMask) *outVaMask = vaMask;
    NSMutableArray<NSDictionary *> *images = [NSMutableArray array];
    task_dyld_info_data_t dyldInfo = {0};
    mach_msg_type_number_t dyldCount = TASK_DYLD_INFO_COUNT;
    if (task_info(task, TASK_DYLD_INFO, (task_info_t)&dyldInfo, &dyldCount) == KERN_SUCCESS &&
        dyldInfo.all_image_info_addr != 0) {
        MCPRemoteDyldAllImageInfos allInfos = {0};
        if (MCPRemoteReadExact(task, dyldInfo.all_image_info_addr, &allInfos, sizeof(allInfos), vaMask) &&
            allInfos.infoArray != 0 && allInfos.infoArrayCount > 0) {
            uint32_t imgCount = MIN(allInfos.infoArrayCount, 2048U);
            NSMutableData *arrData = [NSMutableData dataWithLength:imgCount * sizeof(MCPRemoteDyldImageInfo)];
            if (MCPRemoteReadExact(task, allInfos.infoArray, arrData.mutableBytes, arrData.length, vaMask)) {
                const MCPRemoteDyldImageInfo *entries = arrData.bytes;
                for (uint32_t i = 0; i < imgCount; i++) {
                    uint64_t base = MCPStripPAC(entries[i].imageLoadAddress, vaMask);
                    NSString *path = MCPRemoteReadCString(task, entries[i].imageFilePath, 512, vaMask) ?: @"";
                    if (base) [images addObject:@{@"address": @(base), @"base": @(base), @"path": path}];
                }
            }
        }
    }
    return images;
}

static BOOL MCPLooksLikeObjCIdentifier(NSString *str, BOOL allowColons) {
    if (!str.length || str.length > 256) return NO;
    const char *s = str.UTF8String;
    if (!s || !*s) return NO;
    unsigned char first = (unsigned char)s[0];
    if (!(isalpha(first) || first == '_' || first == '$')) return NO;
    for (const char *p = s + 1; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (isalnum(c) || c == '_' || c == '$' || c == '.') continue;
        if (allowColons && c == ':') continue;
        return NO;
    }
    return YES;
}

static BOOL MCPRemoteResolveClassRO(mach_port_t task,
                                    uint64_t clsAddr,
                                    uint64_t vaMask,
                                    uint64_t *outROAddr,
                                    uint64_t *outIsaAddr,
                                    uint64_t *outSuperAddr) {
    uint64_t clsHeader[5] = {0}; // isa, superclass, cache[0], cache[1], bits
    if (!MCPRemoteReadExact(task, clsAddr, clsHeader, sizeof(clsHeader), vaMask)) return NO;

    if (outIsaAddr) *outIsaAddr = MCPStripPAC(clsHeader[0], vaMask) & ~7ULL;
    if (outSuperAddr) *outSuperAddr = MCPStripPAC(clsHeader[1], vaMask) & ~7ULL;

    uint64_t dataPtr = MCPStripPAC(clsHeader[4], vaMask) & ~7ULL;
    if (!dataPtr) return NO;

    uint8_t rwProbe[32] = {0};
    if (!MCPRemoteReadExact(task, dataPtr, rwProbe, sizeof(rwProbe), vaMask)) return NO;
    uint32_t flags = *(const uint32_t *)(rwProbe + 0);

    uint64_t roPtr = dataPtr;
    if ((flags & (1U << 31)) != 0) {
        // Realized class_rw_t: +8 holds ro_or_rw_ext
        uint64_t roOrExt = *(const uint64_t *)(rwProbe + 8);
        if ((roOrExt & 1ULL) != 0) {
            uint64_t extAddr = MCPStripPAC(roOrExt & ~1ULL, vaMask);
            uint64_t extRO = 0;
            if (!MCPRemoteReadExact(task, extAddr, &extRO, sizeof(extRO), vaMask)) return NO;
            roPtr = MCPStripPAC(extRO, vaMask) & ~7ULL;
        } else {
            roPtr = MCPStripPAC(roOrExt, vaMask) & ~7ULL;
        }
    }

    if (!roPtr) return NO;
    if (outROAddr) *outROAddr = roPtr;
    return YES;
}

static NSArray<NSDictionary *> *MCPRemoteReadMethodList(mach_port_t task,
                                                        uint64_t methodListAddr,
                                                        BOOL isClassMethod,
                                                        uint64_t vaMask) {
    uint64_t cleanList = MCPStripPAC(methodListAddr, vaMask) & ~3ULL;
    if (!cleanList) return @[];

    uint32_t header[2] = {0}; // entsizeAndFlags, count
    if (!MCPRemoteReadExact(task, cleanList, header, sizeof(header), vaMask)) return @[];

    uint32_t entsizeAndFlags = header[0];
    uint32_t count = header[1];
    if (count == 0 || count > 4096) return @[];

    BOOL isRelative = (entsizeAndFlags & 0x80000000U) != 0;
    BOOL directSel = (entsizeAndFlags & 0x40000000U) != 0;
    uint32_t entsize = entsizeAndFlags & 0x0000FFFCU;
    if (entsize == 0) entsize = isRelative ? 12 : 24;

    NSMutableArray<NSDictionary *> *methods = [NSMutableArray arrayWithCapacity:MIN(count, 256U)];
    uint64_t entryAddr = cleanList + 8;
    NSString *kindPrefix = isClassMethod ? @"+" : @"-";

    for (uint32_t i = 0; i < count && methods.count < 512; i++, entryAddr += entsize) {
        NSString *selName = nil;
        NSString *typeEnc = nil;
        uint64_t impAddr = 0;

        if (isRelative && entsize >= 12) {
            int32_t rel[3] = {0};
            if (!MCPRemoteReadExact(task, entryAddr, rel, sizeof(rel), vaMask)) break;
            uint64_t nameTarget = (uint64_t)((int64_t)entryAddr + (int64_t)rel[0]);
            uint64_t typesTarget = (uint64_t)((int64_t)(entryAddr + 4) + (int64_t)rel[1]);
            impAddr = MCPStripPAC((uint64_t)((int64_t)(entryAddr + 8) + (int64_t)rel[2]), vaMask);

            if (directSel) {
                selName = MCPRemoteReadCString(task, nameTarget, 256, vaMask);
            }
            if (!MCPLooksLikeObjCIdentifier(selName, YES)) {
                uint64_t selPtr = 0;
                if (MCPRemoteReadExact(task, nameTarget, &selPtr, sizeof(selPtr), vaMask) && selPtr != 0) {
                    NSString *deref = MCPRemoteReadCString(task, selPtr, 256, vaMask);
                    if (MCPLooksLikeObjCIdentifier(deref, YES)) {
                        selName = deref;
                    }
                }
                if (!MCPLooksLikeObjCIdentifier(selName, YES)) {
                    NSString *direct = MCPRemoteReadCString(task, nameTarget, 256, vaMask);
                    if (MCPLooksLikeObjCIdentifier(direct, YES)) selName = direct;
                }
            }
            if (rel[1] != 0) {
                typeEnc = MCPRemoteReadCString(task, typesTarget, 128, vaMask);
            }
        } else if (!isRelative && entsize >= 24) {
            uint64_t raw[3] = {0};
            if (!MCPRemoteReadExact(task, entryAddr, raw, sizeof(raw), vaMask)) break;
            selName = MCPRemoteReadCString(task, raw[0], 256, vaMask);
            typeEnc = MCPRemoteReadCString(task, raw[1], 128, vaMask);
            impAddr = MCPStripPAC(raw[2], vaMask);
        }

        if (MCPLooksLikeObjCIdentifier(selName, YES)) {
            [methods addObject:@{
                @"name": [NSString stringWithFormat:@"%@%@", kindPrefix, selName],
                @"selector": selName,
                @"is_class_method": @(isClassMethod),
                @"types": typeEnc ?: @"",
                @"imp": [NSString stringWithFormat:@"0x%llx", (unsigned long long)impAddr]
            }];
        }
    }
    return methods;
}

static NSArray<NSDictionary *> *MCPRemoteReadIvarList(mach_port_t task, uint64_t ivarListAddr, uint64_t vaMask) {
    uint64_t cleanList = MCPStripPAC(ivarListAddr, vaMask) & ~3ULL;
    if (!cleanList) return @[];

    uint32_t header[2] = {0}; // entsize, count
    if (!MCPRemoteReadExact(task, cleanList, header, sizeof(header), vaMask)) return @[];
    uint32_t entsize = header[0] ?: 32;
    uint32_t count = header[1];
    if (entsize < 24 || count == 0 || count > 2048) return @[];

    NSMutableArray<NSDictionary *> *ivars = [NSMutableArray arrayWithCapacity:MIN(count, 128U)];
    uint64_t entryAddr = cleanList + 8;

    for (uint32_t i = 0; i < count && ivars.count < 256; i++, entryAddr += entsize) {
        // 64-bit ivar_t: +0 int32_t *offset, +8 const char *name, +16 const char *type, +24 uint32_t align, +28 uint32_t size
        uint8_t raw[32] = {0};
        size_t toRead = MIN((size_t)entsize, sizeof(raw));
        if (!MCPRemoteReadExact(task, entryAddr, raw, toRead, vaMask)) break;

        uint64_t offsetPtr = *(const uint64_t *)(raw + 0);
        uint64_t namePtr = *(const uint64_t *)(raw + 8);
        uint64_t typePtr = *(const uint64_t *)(raw + 16);
        uint32_t ivarSize = (toRead >= 32) ? *(const uint32_t *)(raw + 28) : 0;

        NSString *name = MCPRemoteReadCString(task, namePtr, 256, vaMask);
        if (!MCPLooksLikeObjCIdentifier(name, NO)) continue;
        NSString *typeEnc = MCPRemoteReadCString(task, typePtr, 128, vaMask) ?: @"";

        int32_t byteOffset = 0;
        if (offsetPtr) {
            MCPRemoteReadExact(task, offsetPtr, &byteOffset, sizeof(byteOffset), vaMask);
        }
        [ivars addObject:@{
            @"name": name,
            @"type": typeEnc,
            @"offset": @(byteOffset),
            @"size": @(ivarSize)
        }];
    }
    return ivars;
}

@implementation MemoryManager

+ (instancetype)sharedInstance {
    static MemoryManager *instance;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ instance = [self new]; });
    return instance;
}

- (mach_port_t)taskForPID:(pid_t)pid error:(NSString **)error {
    if (pid <= 0) {
        if (error) *error = @"pid must be positive";
        return MACH_PORT_NULL;
    }
    if (pid == getpid()) {
        mach_port_t task = mach_task_self();
        kern_return_t result = mach_port_mod_refs(task, task, MACH_PORT_RIGHT_SEND, 1);
        if (result != KERN_SUCCESS) {
            if (error) *error = MCPMachError(result);
            return MACH_PORT_NULL;
        }
        return task;
    }
    MCPTryEnsureProcessDebugged(pid);
    mach_port_t task = MACH_PORT_NULL;
    kern_return_t result = task_for_pid(mach_task_self(), pid, &task);
    if (result != KERN_SUCCESS && error) *error = MCPMachError(result);
    return task;
}

- (NSDictionary *)readPID:(pid_t)pid address:(uint64_t)address length:(NSUInteger)length error:(NSString **)error {
    if (!length || length > 1048576 || address > UINT64_MAX - length) {
        if (error) *error = @"length must be 1..1048576 and address range must not overflow";
        return nil;
    }
    mach_port_t task = [self taskForPID:pid error:error];
    if (task == MACH_PORT_NULL) return nil;
    NSMutableData *data = [NSMutableData dataWithLength:length];
    mach_vm_size_t actual = 0;
    kern_return_t result = mach_vm_read_overwrite(task, address, length, (mach_vm_address_t)data.mutableBytes, &actual);
    mach_port_deallocate(mach_task_self(), task);
    if (result != KERN_SUCCESS) {
        if (error) *error = MCPMachError(result);
        return nil;
    }
    data.length = (NSUInteger)actual;
    return @{@"address": [NSString stringWithFormat:@"0x%llx", address], @"length": @(actual), @"data": [data base64EncodedStringWithOptions:0]};
}

- (NSDictionary *)protectWriteTask:(mach_port_t)task
                               pid:(pid_t)pid
                           address:(uint64_t)address
                              data:(NSData *)data
                             error:(NSString **)error {
    if (!data.length || data.length > 1048576 || address > UINT64_MAX - data.length) {
        if (error) *error = @"data must contain 1..1048576 bytes and address range must not overflow";
        return nil;
    }

    mach_vm_address_t regionAddr = (mach_vm_address_t)address;
    mach_vm_size_t regionSize = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;
    kern_return_t krRegion = mach_vm_region(task, &regionAddr, &regionSize, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &object);
    if (object != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), object);
    vm_prot_t origProt = (krRegion == KERN_SUCCESS) ? info.protection : VM_PROT_READ;

    uint64_t pageSize = (uint64_t)getpagesize();
    if (!pageSize) pageSize = 16384ULL;
    mach_vm_address_t pageStart = (mach_vm_address_t)(address & ~(pageSize - 1ULL));
    mach_vm_address_t pageEnd = (mach_vm_address_t)((address + data.length + pageSize - 1ULL) & ~(pageSize - 1ULL));
    mach_vm_size_t pageSpan = pageEnd - pageStart;

    BOOL changedProt = NO;
    kern_return_t writeKr = KERN_FAILURE;
    if ((origProt & VM_PROT_WRITE) != 0) {
        writeKr = mach_vm_write(task, address, (vm_offset_t)data.bytes, (mach_msg_type_number_t)data.length);
    }

    if (writeKr != KERN_SUCCESS) {
        MCPTryEnsureProcessDebugged(pid);
        kern_return_t protKr = mach_vm_protect(task, pageStart, pageSpan, FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
        if (protKr != KERN_SUCCESS) {
            protKr = mach_vm_protect(task, pageStart, pageSpan, FALSE, VM_PROT_READ | VM_PROT_WRITE);
        }
        if (protKr != KERN_SUCCESS) {
            protKr = MCPTryHookdVmProtect(pid, pageStart, pageSpan, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
        }
        if (protKr != KERN_SUCCESS) {
            protKr = MCPTryHookdVmProtect(pid, pageStart, pageSpan, VM_PROT_READ | VM_PROT_WRITE);
        }
        if (protKr == KERN_SUCCESS) {
            changedProt = YES;
        }
        writeKr = mach_vm_write(task, address, (vm_offset_t)data.bytes, (mach_msg_type_number_t)data.length);
        if (changedProt && (origProt & VM_PROT_WRITE) == 0) {
            vm_prot_t restoreProt = origProt ? origProt : VM_PROT_READ;
            kern_return_t rKr = mach_vm_protect(task, pageStart, pageSpan, FALSE, restoreProt);
            if (rKr != KERN_SUCCESS) {
                MCPTryHookdVmProtect(pid, pageStart, pageSpan, restoreProt);
            }
        }
    }

    if (writeKr != KERN_SUCCESS) {
        if (error) *error = MCPMachError(writeKr);
        return nil;
    }

    NSMutableData *verifyBuf = [NSMutableData dataWithLength:data.length];
    mach_vm_size_t actual = 0;
    kern_return_t readKr = mach_vm_read_overwrite(task, address, data.length, (mach_vm_address_t)verifyBuf.mutableBytes, &actual);
    BOOL verified = (readKr == KERN_SUCCESS && actual == data.length && memcmp(verifyBuf.bytes, data.bytes, data.length) == 0);

    return @{
        @"address": [NSString stringWithFormat:@"0x%llx", address],
        @"written": @(data.length),
        @"verified": @(verified),
        @"cow_protected": @(changedProt),
        @"original_protection": MCPVMProtString(origProt)
    };
}

- (NSDictionary *)writePID:(pid_t)pid address:(uint64_t)address data:(NSData *)data error:(NSString **)error {
    return [self protectWritePID:pid address:address data:data error:error];
}

- (NSDictionary *)protectWritePID:(pid_t)pid address:(uint64_t)address data:(NSData *)data error:(NSString **)error {
    if (!data.length || data.length > 1048576 || address > UINT64_MAX - data.length) {
        if (error) *error = @"data must contain 1..1048576 bytes and address range must not overflow";
        return nil;
    }
    mach_port_t task = [self taskForPID:pid error:error];
    if (task == MACH_PORT_NULL) return nil;
    NSDictionary *res = [self protectWriteTask:task pid:pid address:address data:data error:error];
    mach_port_deallocate(mach_task_self(), task);
    return res;
}

- (NSDictionary *)patchSlotsPID:(pid_t)pid patches:(NSArray<NSDictionary *> *)patches error:(NSString **)error {
    if (![patches isKindOfClass:[NSArray class]]) {
        if (error) *error = @"patches must be an array";
        return nil;
    }
    if (patches.count == 0) {
        return @{@"pid": @(pid), @"patched_count": @0, @"total": @0, @"results": @[]};
    }
    mach_port_t task = [self taskForPID:pid error:error];
    if (task == MACH_PORT_NULL) return nil;

    MCPTryEnsureProcessDebugged(pid);
    NSMutableArray<NSDictionary *> *results = [NSMutableArray arrayWithCapacity:patches.count];
    NSUInteger patchedCount = 0;

    for (NSDictionary *item in patches) {
        if (![item isKindOfClass:[NSDictionary class]]) continue;
        NSString *addrStr = item[@"slot_address"] ?: item[@"address"];
        if (![addrStr isKindOfClass:[NSString class]] || !addrStr.length) continue;
        const char *cs = addrStr.UTF8String;
        char *end = NULL;
        uint64_t addr = strtoull(cs, &end, 0);
        if (!addr) continue;

        NSData *patchData = nil;
        NSString *b64 = item[@"bytes_base64"] ?: item[@"data"];
        if ([b64 isKindOfClass:[NSString class]] && b64.length) {
            patchData = [[NSData alloc] initWithBase64EncodedString:b64 options:0];
        }
        if (!patchData.length) {
            NSString *valStr = item[@"replacement_value"] ?: item[@"original_value"];
            if ([valStr isKindOfClass:[NSString class]] && valStr.length) {
                uint64_t rawVal = strtoull(valStr.UTF8String, NULL, 0);
                uint64_t leVal = OSSwapHostToLittleInt64(rawVal);
                patchData = [NSData dataWithBytes:&leVal length:sizeof(leVal)];
            }
        }
        if (!patchData.length) continue;

        NSString *slotErr = nil;
        NSDictionary *one = [self protectWriteTask:task pid:pid address:addr data:patchData error:&slotErr];
        if (one && [one[@"verified"] boolValue]) {
            patchedCount++;
            [results addObject:one];
        } else {
            [results addObject:@{
                @"address": [NSString stringWithFormat:@"0x%llx", addr],
                @"ok": @NO,
                @"error": slotErr ?: @"patch verification failed"
            }];
        }
    }

    mach_port_deallocate(mach_task_self(), task);
    return @{
        @"pid": @(pid),
        @"patched_count": @(patchedCount),
        @"total": @(patches.count),
        @"results": results
    };
}

- (NSDictionary *)searchPID:(pid_t)pid data:(NSData *)data start:(uint64_t)start end:(uint64_t)end error:(NSString **)error {
    if (!data.length || data.length > 4096 || start >= end || end - start > 16777216) {
        if (error) *error = @"pattern must contain 1..4096 bytes and search range must be 1..16777216 bytes";
        return nil;
    }
    mach_port_t task = [self taskForPID:pid error:error];
    if (task == MACH_PORT_NULL) return nil;
    NSMutableArray *matches = [NSMutableArray array];
    mach_vm_address_t cursor = start;
    NSUInteger regions = 0;
    BOOL complete = YES;
    while (cursor < end && regions++ < 4096 && matches.count < 1000) {
        mach_vm_address_t region = cursor;
        mach_vm_size_t regionSize = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object = MACH_PORT_NULL;
        kern_return_t kr = mach_vm_region(task, &region, &regionSize, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &object);
        if (object != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), object);
        if (kr != KERN_SUCCESS || !regionSize || region > UINT64_MAX - regionSize) {
            complete = NO;
            break;
        }
        if (region > cursor || !(info.protection & VM_PROT_READ)) complete = NO;
        mach_vm_address_t regionEnd = MIN(end, region + regionSize);
        mach_vm_address_t position = MAX(cursor, region);
        if ((info.protection & VM_PROT_READ) && position < regionEnd) {
            while (position < regionEnd && matches.count < 1000) {
                mach_vm_size_t amount = MIN((mach_vm_size_t)65536, regionEnd - position);
                NSMutableData *block = [NSMutableData dataWithLength:(NSUInteger)amount];
                mach_vm_size_t actual = 0;
                kr = mach_vm_read_overwrite(task, position, amount, (mach_vm_address_t)block.mutableBytes, &actual);
                if (kr != KERN_SUCCESS || actual == 0) {
                    complete = NO;
                    break;
                }
                const uint8_t *bytes = block.bytes;
                for (NSUInteger i = 0; i + data.length <= actual && matches.count < 1000; i++) {
                    if (memcmp(bytes + i, data.bytes, data.length) == 0) [matches addObject:[NSString stringWithFormat:@"0x%llx", position + i]];
                }
                if (actual <= data.length - 1) {
                    if (position + actual < regionEnd) complete = NO;
                    break;
                }
                if (position + actual >= regionEnd) break;
                position += actual - (data.length - 1);
            }
        }
        if (regionEnd <= cursor) break;
        cursor = regionEnd;
    }
    mach_port_deallocate(mach_task_self(), task);
    BOOL limited = matches.count >= 1000 || regions > 4096;
    return @{@"matches": matches, @"limited": @(limited), @"complete": @(complete && !limited)};
}

- (NSDictionary *)listRegionsPID:(pid_t)pid limit:(NSUInteger)limit error:(NSString **)error {
    if (limit == 0 || limit > 2048) limit = 256;
    mach_port_t task = [self taskForPID:pid error:error];
    if (task == MACH_PORT_NULL) return nil;

    uint64_t vaMask = MCPComputeRemoteVAMask(task);
    NSMutableArray<NSDictionary *> *images = [NSMutableArray array];
    task_dyld_info_data_t dyldInfo = {0};
    mach_msg_type_number_t dyldCount = TASK_DYLD_INFO_COUNT;
    if (task_info(task, TASK_DYLD_INFO, (task_info_t)&dyldInfo, &dyldCount) == KERN_SUCCESS &&
        dyldInfo.all_image_info_addr != 0) {
        MCPRemoteDyldAllImageInfos allInfos = {0};
        if (MCPRemoteReadExact(task, dyldInfo.all_image_info_addr, &allInfos, sizeof(allInfos), vaMask) &&
            allInfos.infoArray != 0 && allInfos.infoArrayCount > 0) {
            uint32_t imgCount = MIN(allInfos.infoArrayCount, 1024U);
            NSMutableData *arrData = [NSMutableData dataWithLength:imgCount * sizeof(MCPRemoteDyldImageInfo)];
            if (MCPRemoteReadExact(task, allInfos.infoArray, arrData.mutableBytes, arrData.length, vaMask)) {
                const MCPRemoteDyldImageInfo *entries = arrData.bytes;
                for (uint32_t i = 0; i < imgCount; i++) {
                    uint64_t base = MCPStripPAC(entries[i].imageLoadAddress, vaMask);
                    NSString *path = MCPRemoteReadCString(task, entries[i].imageFilePath, 512, vaMask) ?: @"";
                    if (base) [images addObject:@{@"base": @(base), @"path": path}];
                }
            }
        }
    }

    NSMutableArray<NSDictionary *> *regions = [NSMutableArray array];
    mach_vm_address_t cursor = 0;
    BOOL truncated = NO;
    for (NSUInteger step = 0; step < 8192; step++) {
        mach_vm_address_t addr = cursor;
        mach_vm_size_t size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj = MACH_PORT_NULL;
        kern_return_t kr = mach_vm_region(task, &addr, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &obj);
        if (obj != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), obj);
        if (kr != KERN_SUCCESS || size == 0) break;

        if (regions.count >= limit) {
            truncated = YES;
            break;
        }

        NSString *matchedImage = nil;
        for (NSDictionary *img in images) {
            uint64_t b = [img[@"base"] unsignedLongLongValue];
            if (b >= addr && b < addr + size) {
                matchedImage = img[@"path"];
                break;
            }
        }

        NSMutableDictionary *entry = [@{
            @"start": [NSString stringWithFormat:@"0x%llx", (unsigned long long)addr],
            @"end": [NSString stringWithFormat:@"0x%llx", (unsigned long long)(addr + size)],
            @"size": @(size),
            @"protection": MCPVMProtString(info.protection),
            @"max_protection": MCPVMProtString(info.max_protection),
            @"shared": @(info.shared ? YES : NO)
        } mutableCopy];
        if (matchedImage.length) entry[@"image"] = matchedImage;
        [regions addObject:entry];

        if (addr > UINT64_MAX - size) break;
        cursor = addr + size;
    }

    mach_port_deallocate(mach_task_self(), task);
    return @{
        @"pid": @(pid),
        @"count": @(regions.count),
        @"truncated": @(truncated),
        @"regions": regions
    };
}

- (NSDictionary *)dumpClassesPID:(pid_t)pid
                          filter:(NSString *)filter
                           limit:(NSUInteger)limit
                   includeSystem:(BOOL)includeSystem
                           error:(NSString **)error {
    if (limit == 0 || limit > 2000) limit = 500;
    mach_port_t task = [self taskForPID:pid error:error];
    if (task == MACH_PORT_NULL) return nil;

    uint64_t vaMask = MCPComputeRemoteVAMask(task);
    task_dyld_info_data_t dyldInfo = {0};
    mach_msg_type_number_t dyldCount = TASK_DYLD_INFO_COUNT;
    kern_return_t kr = task_info(task, TASK_DYLD_INFO, (task_info_t)&dyldInfo, &dyldCount);
    if (kr != KERN_SUCCESS || dyldInfo.all_image_info_addr == 0) {
        mach_port_deallocate(mach_task_self(), task);
        if (error) *error = [NSString stringWithFormat:@"task_info(TASK_DYLD_INFO) failed: %@", MCPMachError(kr)];
        return nil;
    }

    MCPRemoteDyldAllImageInfos allInfos = {0};
    if (!MCPRemoteReadExact(task, dyldInfo.all_image_info_addr, &allInfos, sizeof(allInfos), vaMask) ||
        allInfos.infoArray == 0 || allInfos.infoArrayCount == 0) {
        mach_port_deallocate(mach_task_self(), task);
        if (error) *error = @"Failed to read remote dyld_all_image_infos";
        return nil;
    }

    uint32_t imgCount = MIN(allInfos.infoArrayCount, 2048U);
    NSMutableData *imgBuf = [NSMutableData dataWithLength:imgCount * sizeof(MCPRemoteDyldImageInfo)];
    if (!MCPRemoteReadExact(task, allInfos.infoArray, imgBuf.mutableBytes, imgBuf.length, vaMask)) {
        mach_port_deallocate(mach_task_self(), task);
        if (error) *error = @"Failed to read remote dyld_image_info array";
        return nil;
    }

    const MCPRemoteDyldImageInfo *images = imgBuf.bytes;
    NSMutableArray<NSDictionary *> *classes = [NSMutableArray array];
    NSMutableArray<NSString *> *inspectedImages = [NSMutableArray array];
    BOOL truncated = NO;

    for (uint32_t idx = 0; idx < imgCount; idx++) {
        uint64_t loadAddr = MCPStripPAC(images[idx].imageLoadAddress, vaMask);
        if (!loadAddr) continue;
        NSString *imgPath = MCPRemoteReadCString(task, images[idx].imageFilePath, 512, vaMask) ?: @"";

        if (!includeSystem && idx > 0) {
            if ([imgPath hasPrefix:@"/System/"] ||
                [imgPath hasPrefix:@"/usr/lib/"] ||
                [imgPath hasPrefix:@"/Developer/"] ||
                [imgPath hasPrefix:@"/Library/Apple/"]) {
                continue;
            }
        }

        struct mach_header_64 hdr = {0};
        if (!MCPRemoteReadExact(task, loadAddr, &hdr, sizeof(hdr), vaMask) || hdr.magic != MH_MAGIC_64) {
            continue;
        }
        if (hdr.sizeofcmds == 0 || hdr.sizeofcmds > 262144) continue;

        NSMutableData *cmdsData = [NSMutableData dataWithLength:hdr.sizeofcmds];
        if (!MCPRemoteReadExact(task, loadAddr + sizeof(hdr), cmdsData.mutableBytes, hdr.sizeofcmds, vaMask)) {
            continue;
        }

        int64_t slide = 0;
        BOOL foundText = NO;
        uint64_t classlistVM = 0;
        uint64_t classlistSize = 0;

        const uint8_t *cp = cmdsData.bytes;
        const uint8_t *cend = cp + hdr.sizeofcmds;
        for (uint32_t c = 0; c < hdr.ncmds && cp + sizeof(struct load_command) <= cend; c++) {
            const struct load_command *lc = (const struct load_command *)cp;
            if (lc->cmdsize < sizeof(struct load_command) || cp + lc->cmdsize > cend) break;
            if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)cp;
                if (strncmp(seg->segname, "__TEXT", 16) == 0) {
                    slide = (int64_t)loadAddr - (int64_t)seg->vmaddr;
                    foundText = YES;
                }
                size_t maxSects = (lc->cmdsize - sizeof(struct segment_command_64)) / sizeof(struct section_64);
                uint32_t nsects = seg->nsects < maxSects ? seg->nsects : (uint32_t)maxSects;
                const struct section_64 *sects = (const struct section_64 *)(cp + sizeof(struct segment_command_64));
                for (uint32_t s = 0; s < nsects; s++) {
                    if (strncmp(sects[s].sectname, "__objc_classlist", 16) == 0) {
                        classlistVM = sects[s].addr;
                        classlistSize = sects[s].size;
                    }
                }
            }
            cp += lc->cmdsize;
        }

        if (!foundText || !classlistVM || classlistSize < 8) continue;
        [inspectedImages addObject:imgPath.length ? imgPath : [NSString stringWithFormat:@"0x%llx", (unsigned long long)loadAddr]];

        uint64_t runtimeClasslist = (uint64_t)((int64_t)classlistVM + slide);
        size_t numClasses = (size_t)(classlistSize / 8);
        if (numClasses > 16384) numClasses = 16384;

        NSMutableData *ptrBuf = [NSMutableData dataWithLength:numClasses * sizeof(uint64_t)];
        if (!MCPRemoteReadExact(task, runtimeClasslist, ptrBuf.mutableBytes, ptrBuf.length, vaMask)) {
            continue;
        }

        const uint64_t *classPtrs = ptrBuf.bytes;
        for (size_t k = 0; k < numClasses; k++) {
            uint64_t clsAddr = MCPStripPAC(classPtrs[k], vaMask) & ~7ULL;
            if (!clsAddr) continue;

            uint64_t roAddr = 0, isaAddr = 0, superAddr = 0;
            if (!MCPRemoteResolveClassRO(task, clsAddr, vaMask, &roAddr, &isaAddr, &superAddr)) continue;

            // Read class_ro_t (72 bytes)
            uint8_t roBytes[72] = {0};
            if (!MCPRemoteReadExact(task, roAddr, roBytes, sizeof(roBytes), vaMask)) continue;

            uint32_t instanceSize = *(const uint32_t *)(roBytes + 8);
            uint64_t namePtr = *(const uint64_t *)(roBytes + 24);
            uint64_t baseMethodsPtr = *(const uint64_t *)(roBytes + 32);
            uint64_t ivarsPtr = *(const uint64_t *)(roBytes + 48);

            NSString *className = MCPRemoteReadCString(task, namePtr, 256, vaMask);
            if (!MCPLooksLikeObjCIdentifier(className, NO)) continue;

            if (filter.length > 0 &&
                [className rangeOfString:filter options:NSCaseInsensitiveSearch].location == NSNotFound) {
                continue;
            }

            if (classes.count >= limit) {
                truncated = YES;
                break;
            }

            // Resolve superclass name (works across dyld shared cache!)
            NSString *superName = nil;
            if (superAddr) {
                uint64_t superRO = 0;
                if (MCPRemoteResolveClassRO(task, superAddr, vaMask, &superRO, NULL, NULL)) {
                    uint64_t superNamePtr = 0;
                    if (MCPRemoteReadExact(task, superRO + 24, &superNamePtr, sizeof(superNamePtr), vaMask)) {
                        NSString *cand = MCPRemoteReadCString(task, superNamePtr, 256, vaMask);
                        if (MCPLooksLikeObjCIdentifier(cand, NO)) superName = cand;
                    }
                }
            }

            NSArray<NSDictionary *> *instanceMethods = MCPRemoteReadMethodList(task, baseMethodsPtr, NO, vaMask);
            NSArray<NSDictionary *> *classMethods = @[];
            if (isaAddr && isaAddr != clsAddr) {
                uint64_t metaRO = 0;
                if (MCPRemoteResolveClassRO(task, isaAddr, vaMask, &metaRO, NULL, NULL)) {
                    uint64_t metaMethodsPtr = 0;
                    if (MCPRemoteReadExact(task, metaRO + 32, &metaMethodsPtr, sizeof(metaMethodsPtr), vaMask) && metaMethodsPtr) {
                        classMethods = MCPRemoteReadMethodList(task, metaMethodsPtr, YES, vaMask);
                    }
                }
            }

            NSMutableArray<NSDictionary *> *allMethods = [NSMutableArray arrayWithCapacity:classMethods.count + instanceMethods.count];
            [allMethods addObjectsFromArray:classMethods];
            [allMethods addObjectsFromArray:instanceMethods];

            NSArray<NSDictionary *> *ivars = MCPRemoteReadIvarList(task, ivarsPtr, vaMask);

            [classes addObject:@{
                @"name": className,
                @"superclass": superName ?: @"",
                @"address": [NSString stringWithFormat:@"0x%llx", (unsigned long long)clsAddr],
                @"image": imgPath.lastPathComponent ?: imgPath,
                @"image_path": imgPath,
                @"instance_size": @(instanceSize),
                @"methods": allMethods,
                @"ivars": ivars
            }];
        }

        if (truncated) break;
    }

    mach_port_deallocate(mach_task_self(), task);
    return @{
        @"pid": @(pid),
        @"introspection_mode": @"remote_task_for_pid_mach_vm",
        @"va_mask": [NSString stringWithFormat:@"0x%llx", (unsigned long long)vaMask],
        @"inspected_images": inspectedImages,
        @"class_count": @(classes.count),
        @"truncated": @(truncated),
        @"classes": classes
    };
}

#pragma mark - Phase 2 Helpers (ZIP, ldid, Chunked Remote Read)

static uint32_t MCPCRC32Compute(const uint8_t *buf, size_t len) {
    static uint32_t table[256];
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int k = 0; k < 8; k++) {
                c = (c & 1) ? (0xEDB88320U ^ (c >> 1)) : (c >> 1);
            }
            table[i] = c;
        }
    });
    uint32_t c = 0xFFFFFFFFU;
    for (size_t i = 0; i < len; i++) {
        c = table[(c ^ buf[i]) & 0xFFU] ^ (c >> 8);
    }
    return c ^ 0xFFFFFFFFU;
}

static void MCPAppendU16LE(NSMutableData *d, uint16_t v) {
    uint16_t le = OSSwapHostToLittleInt16(v);
    [d appendBytes:&le length:sizeof(le)];
}

static void MCPAppendU32LE(NSMutableData *d, uint32_t v) {
    uint32_t le = OSSwapHostToLittleInt32(v);
    [d appendBytes:&le length:sizeof(le)];
}

static BOOL MCPPackageDirectoryAsIPA(NSString *rootDir, NSString *outputIPAPath, NSString **error) {
    NSFileManager *fm = [NSFileManager defaultManager];
    [fm removeItemAtPath:outputIPAPath error:nil];
    NSString *parentDir = [outputIPAPath stringByDeletingLastPathComponent];
    if (parentDir.length) {
        [fm createDirectoryAtPath:parentDir withIntermediateDirectories:YES attributes:nil error:nil];
    }

    if (![fm createFileAtPath:outputIPAPath contents:nil attributes:nil]) {
        if (error) *error = [NSString stringWithFormat:@"Could not create output IPA at %@", outputIPAPath];
        return NO;
    }
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:outputIPAPath];
    if (!fh) {
        if (error) *error = [NSString stringWithFormat:@"Could not open output IPA for writing at %@", outputIPAPath];
        return NO;
    }

    NSDirectoryEnumerator *enumerator = [fm enumeratorAtPath:rootDir];
    NSMutableData *centralDir = [NSMutableData data];
    uint16_t entryCount = 0;
    uint64_t currentOffset = 0;

    for (NSString *relPath in enumerator) {
        @autoreleasepool {
            NSString *fullPath = [rootDir stringByAppendingPathComponent:relPath];
            NSDictionary *attrs = [fm attributesOfItemAtPath:fullPath error:nil];
            NSString *fileType = attrs[NSFileType];
            BOOL isDir = [fileType isEqualToString:NSFileTypeDirectory];
            BOOL isSymlink = [fileType isEqualToString:NSFileTypeSymbolicLink];
            if (isSymlink) continue;

            NSString *zipName = isDir ? [relPath stringByAppendingString:@"/"] : relPath;
            NSData *nameData = [zipName dataUsingEncoding:NSUTF8StringEncoding];
            if (!nameData.length || nameData.length > 0xFFFF) continue;

            NSData *fileData = isDir ? [NSData data] : [NSData dataWithContentsOfFile:fullPath options:NSDataReadingMappedIfSafe error:nil];
            if (!isDir && !fileData) continue;
            if (fileData.length > 0xFFFFFFFFULL) continue;

            uint32_t crc = isDir ? 0 : MCPCRC32Compute((const uint8_t *)fileData.bytes, fileData.length);
            uint32_t uncompSize = (uint32_t)fileData.length;
            uint32_t localHeaderOffset = (uint32_t)MIN(currentOffset, (uint64_t)0xFFFFFFFFULL);
            uint32_t posixMode = (uint32_t)[attrs[NSFilePosixPermissions] unsignedShortValue];
            if (posixMode == 0) posixMode = isDir ? 0755 : 0644;
            uint32_t extAttr = ((isDir ? 0040000U : 0100000U) | (posixMode & 07777U)) << 16;

            NSMutableData *localHdr = [NSMutableData dataWithCapacity:30 + nameData.length];
            MCPAppendU32LE(localHdr, 0x04034b50U);
            MCPAppendU16LE(localHdr, 20);
            MCPAppendU16LE(localHdr, 0x0800); // UTF-8
            MCPAppendU16LE(localHdr, 0);      // STORED
            MCPAppendU16LE(localHdr, 0);
            MCPAppendU16LE(localHdr, 0x5421);
            MCPAppendU32LE(localHdr, crc);
            MCPAppendU32LE(localHdr, uncompSize);
            MCPAppendU32LE(localHdr, uncompSize);
            MCPAppendU16LE(localHdr, (uint16_t)nameData.length);
            MCPAppendU16LE(localHdr, 0);
            [localHdr appendData:nameData];

            [fh writeData:localHdr];
            if (uncompSize > 0) {
                [fh writeData:fileData];
            }
            currentOffset += localHdr.length + uncompSize;

            MCPAppendU32LE(centralDir, 0x02014b50U);
            MCPAppendU16LE(centralDir, 0x031E); // Unix
            MCPAppendU16LE(centralDir, 20);
            MCPAppendU16LE(centralDir, 0x0800);
            MCPAppendU16LE(centralDir, 0);
            MCPAppendU16LE(centralDir, 0);
            MCPAppendU16LE(centralDir, 0x5421);
            MCPAppendU32LE(centralDir, crc);
            MCPAppendU32LE(centralDir, uncompSize);
            MCPAppendU32LE(centralDir, uncompSize);
            MCPAppendU16LE(centralDir, (uint16_t)nameData.length);
            MCPAppendU16LE(centralDir, 0);
            MCPAppendU16LE(centralDir, 0);
            MCPAppendU16LE(centralDir, 0);
            MCPAppendU16LE(centralDir, 0);
            MCPAppendU32LE(centralDir, extAttr);
            MCPAppendU32LE(centralDir, localHeaderOffset);
            [centralDir appendData:nameData];
            if (entryCount < 0xFFFF) entryCount++;
        }
    }

    uint32_t cdOffset = (uint32_t)MIN(currentOffset, (uint64_t)0xFFFFFFFFULL);
    uint32_t cdSize = (uint32_t)centralDir.length;
    [fh writeData:centralDir];

    NSMutableData *eocd = [NSMutableData dataWithCapacity:22];
    MCPAppendU32LE(eocd, 0x06054b50U);
    MCPAppendU16LE(eocd, 0);
    MCPAppendU16LE(eocd, 0);
    MCPAppendU16LE(eocd, entryCount);
    MCPAppendU16LE(eocd, entryCount);
    MCPAppendU32LE(eocd, cdSize);
    MCPAppendU32LE(eocd, cdOffset);
    MCPAppendU16LE(eocd, 0);
    [fh writeData:eocd];
    [fh closeFile];
    return YES;
}

static NSString *MCPFindLdidBinary(void) {
    NSArray<NSString *> *candidates = @[
        @"/usr/libexec/ios-mcp/mcp-ldid",
        @"/var/jb/usr/libexec/ios-mcp/mcp-ldid",
        @"/usr/bin/ldid",
        @"/var/jb/usr/bin/ldid"
    ];
    for (NSString *cand in candidates) {
        if (access(cand.UTF8String, X_OK) == 0) return cand;
    }
    glob_t g = {0};
    NSString *found = nil;
    if (glob("/var/containers/Bundle/Application/.jbroot-*/usr/libexec/ios-mcp/mcp-ldid", 0, NULL, &g) == 0 && g.gl_pathc > 0) {
        if (access(g.gl_pathv[0], X_OK) == 0) {
            found = [NSString stringWithUTF8String:g.gl_pathv[0]];
        }
    }
    globfree(&g);
    return found;
}

static NSData *MCPRunToolStdout(NSString *binPath, NSArray<NSString *> *args, int *outStatus) {
    if (!binPath.length || access(binPath.UTF8String, X_OK) != 0) return nil;
    int pipefd[2] = {-1, -1};
    if (pipe(pipefd) != 0) return nil;

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_addclose(&actions, pipefd[0]);
    posix_spawn_file_actions_adddup2(&actions, pipefd[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&actions, pipefd[1]);

    size_t argc = args.count + 1;
    char **argv = (char **)calloc(argc + 1, sizeof(char *));
    argv[0] = strdup(binPath.UTF8String);
    for (size_t i = 0; i < args.count; i++) {
        argv[i + 1] = strdup([args[i] UTF8String]);
    }

    pid_t child = -1;
    int rc = posix_spawn(&child, binPath.UTF8String, &actions, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&actions);
    close(pipefd[1]);
    for (size_t i = 0; i < argc; i++) free(argv[i]);
    free(argv);

    if (rc != 0 || child <= 0) {
        close(pipefd[0]);
        return nil;
    }

    NSMutableData *outData = [NSMutableData data];
    uint8_t buf[4096];
    ssize_t n = 0;
    while ((n = read(pipefd[0], buf, sizeof(buf))) > 0) {
        [outData appendBytes:buf length:(NSUInteger)n];
    }
    close(pipefd[0]);

    int status = 0;
    waitpid(child, &status, 0);
    if (outStatus) *outStatus = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    return outData;
}

static BOOL MCPResignMachOWithLdid(NSString *origBinaryPath, NSString *stagedBinaryPath) {
    NSString *ldid = MCPFindLdidBinary();
    if (!ldid) return NO;

    int st = -1;
    NSData *entData = MCPRunToolStdout(ldid, @[@"-e", origBinaryPath], &st);
    NSString *entTemp = nil;
    if (st == 0 && entData.length > 16) {
        entTemp = [NSTemporaryDirectory() stringByAppendingPathComponent:
                   [NSString stringWithFormat:@"mcp_ent_%d_%u.plist", getpid(), arc4random()]];
        [entData writeToFile:entTemp atomically:YES];
    }

    NSString *signArg = entTemp ? [NSString stringWithFormat:@"-S%@", entTemp] : @"-S";
    int signStatus = -1;
    MCPRunToolStdout(ldid, @[signArg, stagedBinaryPath], &signStatus);
    if (entTemp) [[NSFileManager defaultManager] removeItemAtPath:entTemp error:nil];
    return (signStatus == 0);
}

static BOOL MCPRemoteReadChunked(mach_port_t task, uint64_t addr, void *outBuf, size_t totalLen, uint64_t vaMask, BOOL allowPartialZeroFill) {
    uint8_t *dst = (uint8_t *)outBuf;
    size_t offset = 0;
    while (offset < totalLen) {
        size_t chunk = MIN((size_t)0x4000, totalLen - offset);
        uint64_t curAddr = MCPStripRemotePointer(addr + offset, vaMask);
        mach_vm_size_t outSize = 0;
        kern_return_t kr = mach_vm_read_overwrite(task,
                                                  (mach_vm_address_t)curAddr,
                                                  (mach_vm_size_t)chunk,
                                                  (mach_vm_address_t)(uintptr_t)(dst + offset),
                                                  &outSize);
        if (kr != KERN_SUCCESS || outSize != chunk) {
            if (!allowPartialZeroFill) return NO;
            // Try page-by-page (4KB) fallback and zero-fill unmapped holes
            size_t subOff = 0;
            while (subOff < chunk) {
                size_t subChunk = MIN((size_t)0x1000, chunk - subOff);
                mach_vm_size_t subOut = 0;
                kern_return_t subKr = mach_vm_read_overwrite(task,
                                                             (mach_vm_address_t)(curAddr + subOff),
                                                             (mach_vm_size_t)subChunk,
                                                             (mach_vm_address_t)(uintptr_t)(dst + offset + subOff),
                                                             &subOut);
                if (subKr != KERN_SUCCESS || subOut != subChunk) {
                    memset(dst + offset + subOff, 0, subChunk);
                }
                subOff += subChunk;
            }
        }
        offset += chunk;
    }
    return YES;
}

#pragma mark - Upgrade 01: Zero-Injection Out-of-Process FairPlay Decryptor & Clean IPA Packager

static BOOL MCPParseSliceEncryptionInfo(const uint8_t *sliceBase,
                                        size_t sliceLen,
                                        uint32_t *outCpuType,
                                        uint32_t *outCpuSubType,
                                        uint32_t *outCryptOff,
                                        uint32_t *outCryptSize,
                                        uint32_t *outCryptId,
                                        size_t *outCryptIdFieldOffset,
                                        NSString **outUUID) {
    if (sliceLen < sizeof(struct mach_header_64)) return NO;
    const struct mach_header_64 *hdr = (const struct mach_header_64 *)sliceBase;
    if (hdr->magic != MH_MAGIC_64) return NO;
    if (outCpuType) *outCpuType = hdr->cputype;
    if (outCpuSubType) *outCpuSubType = hdr->cpusubtype;
    if (outCryptOff) *outCryptOff = 0;
    if (outCryptSize) *outCryptSize = 0;
    if (outCryptId) *outCryptId = 0;
    if (outCryptIdFieldOffset) *outCryptIdFieldOffset = 0;

    size_t cmdOffset = sizeof(struct mach_header_64);
    size_t maxCmdOffset = MIN(sliceLen, cmdOffset + hdr->sizeofcmds);
    for (uint32_t i = 0; i < hdr->ncmds && cmdOffset + sizeof(struct load_command) <= maxCmdOffset; i++) {
        const struct load_command *lc = (const struct load_command *)(sliceBase + cmdOffset);
        if (lc->cmdsize < sizeof(struct load_command) || cmdOffset + lc->cmdsize > maxCmdOffset) break;
        if (lc->cmd == LC_ENCRYPTION_INFO_64 && lc->cmdsize >= sizeof(struct encryption_info_command_64)) {
            const struct encryption_info_command_64 *enc = (const struct encryption_info_command_64 *)lc;
            if (outCryptOff) *outCryptOff = enc->cryptoff;
            if (outCryptSize) *outCryptSize = enc->cryptsize;
            if (outCryptId) *outCryptId = enc->cryptid;
            if (outCryptIdFieldOffset) *outCryptIdFieldOffset = cmdOffset + offsetof(struct encryption_info_command_64, cryptid);
        } else if (lc->cmd == LC_UUID && lc->cmdsize >= sizeof(struct uuid_command) && outUUID) {
            const struct uuid_command *uc = (const struct uuid_command *)lc;
            NSMutableString *u = [NSMutableString stringWithCapacity:36];
            for (int b = 0; b < 16; b++) [u appendFormat:@"%02x", uc->uuid[b]];
            *outUUID = u;
        }
        cmdOffset += lc->cmdsize;
    }
    return YES;
}

- (NSDictionary *)decryptAppIPAForPID:(pid_t)pid
                           bundlePath:(NSString *)bundlePath
                           outputPath:(NSString *)outputPath
                                error:(NSString **)error {
    if (error) *error = nil;
    if (pid <= 0) {
        if (error) *error = @"Invalid PID for FairPlay decryption";
        return nil;
    }
    if (!bundlePath.length) {
        if (error) *error = @"Missing bundlePath for FairPlay decryption";
        return nil;
    }
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL isDir = NO;
    if (![fm fileExistsAtPath:bundlePath isDirectory:&isDir] || !isDir) {
        if (error) *error = [NSString stringWithFormat:@"Bundle path does not exist: %@", bundlePath];
        return nil;
    }

    MCPTryEnsureProcessDebugged(pid);
    mach_port_t task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS || task == MACH_PORT_NULL) {
        if (error) *error = [NSString stringWithFormat:@"task_for_pid(%d) failed: %s (0x%x)", pid, mach_error_string(kr), kr];
        return nil;
    }

    uint64_t vaMask = 0x00007fffffffffffULL;
    NSArray<NSDictionary *> *loadedImages = MCPRemoteEnumerateDyldImages(task, &vaMask);
    NSMutableDictionary<NSString *, NSNumber *> *loadAddrByPath = [NSMutableDictionary dictionary];
    NSMutableDictionary<NSString *, NSNumber *> *loadAddrByBasename = [NSMutableDictionary dictionary];
    for (NSDictionary *img in loadedImages) {
        NSString *p = img[@"path"];
        NSNumber *addr = img[@"address"];
        if (p.length && addr) {
            loadAddrByPath[p] = addr;
            loadAddrByPath[p.stringByResolvingSymlinksInPath] = addr;
            if (p.lastPathComponent.length) {
                loadAddrByBasename[p.lastPathComponent] = addr;
            }
        }
    }

    NSString *stageRoot = [MCPMemoryEnsureWorkDir() stringByAppendingPathComponent:
                           [NSString stringWithFormat:@"ios-mcp-decrypt-%d-%u", pid, arc4random()]];
    NSString *payloadDir = [stageRoot stringByAppendingPathComponent:@"Payload"];
    NSString *stagedAppPath = [payloadDir stringByAppendingPathComponent:bundlePath.lastPathComponent];
    [fm removeItemAtPath:stageRoot error:nil];

    NSError *copyErr = nil;
    if (![fm createDirectoryAtPath:payloadDir withIntermediateDirectories:YES attributes:nil error:&copyErr] ||
        ![fm copyItemAtPath:bundlePath toPath:stagedAppPath error:&copyErr]) {
        mach_port_deallocate(mach_task_self(), task);
        [fm removeItemAtPath:stageRoot error:nil];
        if (error) *error = [NSString stringWithFormat:@"Failed to stage app bundle: %@", copyErr.localizedDescription ?: @"copy failed"];
        return nil;
    }

    // Remove PlugIns/Watch if non-loaded extensions might fail sideloading or decrypt any that ARE loaded
    NSMutableArray<NSDictionary *> *decryptedBinaries = [NSMutableArray array];
    NSMutableArray<NSDictionary *> *skippedBinaries = [NSMutableArray array];

    NSDirectoryEnumerator *enumerator = [fm enumeratorAtPath:stagedAppPath];
    for (NSString *relPath in enumerator) {
        @autoreleasepool {
            NSString *stagedFile = [stagedAppPath stringByAppendingPathComponent:relPath];
            NSString *origFile = [bundlePath stringByAppendingPathComponent:relPath];
            NSDictionary *attrs = [fm attributesOfItemAtPath:stagedFile error:nil];
            if (![attrs[NSFileType] isEqualToString:NSFileTypeRegular]) continue;
            if ([attrs[NSFileSize] unsignedLongLongValue] < sizeof(struct mach_header_64)) continue;

            NSFileHandle *checkFh = [NSFileHandle fileHandleForReadingAtPath:stagedFile];
            NSData *magicData = [checkFh readDataOfLength:4];
            [checkFh closeFile];
            if (magicData.length < 4) continue;
            uint32_t magic = *(const uint32_t *)magicData.bytes;
            if (magic != MH_MAGIC_64 && magic != FAT_MAGIC && magic != FAT_CIGAM) continue;

            NSMutableData *fileData = [NSMutableData dataWithContentsOfFile:stagedFile];
            if (!fileData) continue;

            uint8_t *bytes = (uint8_t *)fileData.mutableBytes;
            size_t totalLen = fileData.length;

            NSMutableArray<NSDictionary *> *slices = [NSMutableArray array];
            if (magic == MH_MAGIC_64) {
                [slices addObject:@{@"offset": @0, @"size": @(totalLen)}];
            } else {
                const struct fat_header *fhdr = (const struct fat_header *)bytes;
                uint32_t nfat = OSSwapBigToHostInt32(fhdr->nfat_arch);
                size_t archOff = sizeof(struct fat_header);
                for (uint32_t a = 0; a < nfat && archOff + sizeof(struct fat_arch) <= totalLen; a++) {
                    const struct fat_arch *fa = (const struct fat_arch *)(bytes + archOff);
                    uint32_t sOff = OSSwapBigToHostInt32(fa->offset);
                    uint32_t sSize = OSSwapBigToHostInt32(fa->size);
                    if ((uint64_t)sOff + (uint64_t)sSize <= totalLen) {
                        [slices addObject:@{@"offset": @(sOff), @"size": @(sSize)}];
                    }
                    archOff += sizeof(struct fat_arch);
                }
            }

            uint64_t liveLoadAddr = [loadAddrByPath[origFile] unsignedLongLongValue];
            if (!liveLoadAddr) liveLoadAddr = [loadAddrByPath[origFile.stringByResolvingSymlinksInPath] unsignedLongLongValue];
            if (!liveLoadAddr) liveLoadAddr = [loadAddrByBasename[origFile.lastPathComponent] unsignedLongLongValue];

            uint32_t liveCpuSubType = 0;
            if (liveLoadAddr) {
                struct mach_header_64 liveHdr = {0};
                if (MCPRemoteReadExact(task, liveLoadAddr, &liveHdr, sizeof(liveHdr), vaMask) && liveHdr.magic == MH_MAGIC_64) {
                    liveCpuSubType = (uint32_t)liveHdr.cpusubtype;
                }
            }

            BOOL binaryModified = NO;
            BOOL hadEncryptedSlice = NO;

            for (NSDictionary *sliceInfo in slices) {
                size_t sOff = [sliceInfo[@"offset"] unsignedLongValue];
                size_t sSize = [sliceInfo[@"size"] unsignedLongValue];
                uint32_t cpuType = 0, cpuSubType = 0, cryptOff = 0, cryptSize = 0, cryptId = 0;
                size_t cryptIdFieldOff = 0;
                NSString *uuid = nil;
                if (!MCPParseSliceEncryptionInfo(bytes + sOff, sSize, &cpuType, &cpuSubType, &cryptOff, &cryptSize, &cryptId, &cryptIdFieldOff, &uuid)) {
                    continue;
                }
                if (cryptId == 0 || cryptSize == 0) continue;
                hadEncryptedSlice = YES;

                if (!liveLoadAddr) {
                    // Dynamically dlopen encrypted framework inside target only if not requested; here zero-injection means we only read loaded images
                    [skippedBinaries addObject:@{
                        @"relative_path": relPath,
                        @"reason": @"encrypted_image_not_loaded_in_process",
                        @"cryptid": @(cryptId),
                        @"cryptoff": @(cryptOff),
                        @"cryptsize": @(cryptSize)
                    }];
                    continue;
                }

                // Check if slice matches live CPU subtype (or single slice)
                if (slices.count > 1 && liveCpuSubType != 0 && ((cpuSubType & ~CPU_SUBTYPE_MASK) != (liveCpuSubType & ~CPU_SUBTYPE_MASK))) {
                    continue;
                }
                if ((uint64_t)cryptOff + (uint64_t)cryptSize > sSize) continue;

                void *decryptedBuf = malloc(cryptSize);
                if (!decryptedBuf) continue;

                BOOL readOk = MCPRemoteReadChunked(task, liveLoadAddr + cryptOff, decryptedBuf, cryptSize, vaMask, NO);
                if (readOk) {
                    memcpy(bytes + sOff + cryptOff, decryptedBuf, cryptSize);
                    uint32_t zeroCryptId = 0;
                    memcpy(bytes + sOff + cryptIdFieldOff, &zeroCryptId, sizeof(zeroCryptId));
                    binaryModified = YES;
                    [decryptedBinaries addObject:@{
                        @"relative_path": relPath,
                        @"load_address": [NSString stringWithFormat:@"0x%llx", (unsigned long long)liveLoadAddr],
                        @"cryptoff": @(cryptOff),
                        @"cryptsize": @(cryptSize),
                        @"original_cryptid": @(cryptId),
                        @"patched_cryptid": @0,
                        @"uuid": uuid ?: @""
                    }];
                } else {
                    [skippedBinaries addObject:@{
                        @"relative_path": relPath,
                        @"reason": @"mach_vm_read_overwrite_failed",
                        @"load_address": [NSString stringWithFormat:@"0x%llx", (unsigned long long)liveLoadAddr]
                    }];
                }
                free(decryptedBuf);
            }

            if (binaryModified) {
                [fileData writeToFile:stagedFile atomically:YES];
                chmod(stagedFile.UTF8String, 0755);
                MCPResignMachOWithLdid(origFile, stagedFile);
            } else if (hadEncryptedSlice && [relPath hasPrefix:@"PlugIns/"]) {
                // Remove unloaded encrypted app extensions so the decrypted main app installs cleanly
                [fm removeItemAtPath:[stagedAppPath stringByAppendingPathComponent:[relPath stringByDeletingLastPathComponent]] error:nil];
            }
        }
    }

    mach_port_deallocate(mach_task_self(), task);

    // Strip _CodeSignature from unloaded extensions if modified, and re-sign main executable
    NSDictionary *infoPlist = [NSDictionary dictionaryWithContentsOfFile:[stagedAppPath stringByAppendingPathComponent:@"Info.plist"]];
    NSString *execName = infoPlist[@"CFBundleExecutable"];
    if (execName.length) {
        NSString *origMain = [bundlePath stringByAppendingPathComponent:execName];
        NSString *stagedMain = [stagedAppPath stringByAppendingPathComponent:execName];
        MCPResignMachOWithLdid(origMain, stagedMain);
    }

    if (!outputPath.length) {
        NSString *bundleId = infoPlist[@"CFBundleIdentifier"] ?: @"decrypted-app";
        NSString *shortVer = infoPlist[@"CFBundleShortVersionString"] ?: @"1.0";
        outputPath = [MCPMemoryEnsureWorkDir() stringByAppendingPathComponent:
                      [NSString stringWithFormat:@"%@-%@-decrypted.ipa", bundleId, shortVer]];
    }

    NSString *zipErr = nil;
    if (!MCPPackageDirectoryAsIPA(stageRoot, outputPath, &zipErr)) {
        [fm removeItemAtPath:stageRoot error:nil];
        if (error) *error = zipErr ?: @"Failed to package decrypted IPA";
        return nil;
    }
    chmod(outputPath.UTF8String, 0666);
    chown(outputPath.UTF8String, 501, 501);

    NSDictionary *ipaAttrs = [fm attributesOfItemAtPath:outputPath error:nil];
    uint64_t ipaSize = [ipaAttrs[NSFileSize] unsignedLongLongValue];
    [fm removeItemAtPath:stageRoot error:nil];

    return @{
        @"pid": @(pid),
        @"bundle_path": bundlePath,
        @"output_ipa_path": outputPath,
        @"ipa_size_bytes": @(ipaSize),
        @"decryption_method": @"zero_injection_task_for_pid_mach_vm_read_overwrite",
        @"decrypted_count": @(decryptedBinaries.count),
        @"decrypted_binaries": decryptedBinaries,
        @"skipped_binaries": skippedBinaries
    };
}

#pragma mark - Upgrade 03: Zero-Memory-Patch ARM64 Hardware Debug Register (DBGBVR/DBGBCR) Hooking

typedef struct {
    uint64_t bvr[16];
    uint64_t bcr[16];
    uint64_t wvr[16];
    uint64_t wcr[16];
    uint64_t mdscr_el1;
} MCPRawArmDebugState64;

typedef struct {
    uint64_t x[29];
    uint64_t fp;
    uint64_t lr;
    uint64_t sp;
    uint64_t pc;
    uint32_t cpsr;
    uint32_t pad;
} MCPRawArmThreadState64;

#ifndef ARM_DEBUG_STATE64
#define ARM_DEBUG_STATE64 15
#endif
#ifndef ARM_DEBUG_STATE64_COUNT
#define ARM_DEBUG_STATE64_COUNT ((mach_msg_type_number_t)(sizeof(MCPRawArmDebugState64) / sizeof(uint32_t)))
#endif
#ifndef ARM_THREAD_STATE64
#define ARM_THREAD_STATE64 6
#endif
#ifndef ARM_THREAD_STATE64_COUNT
#define ARM_THREAD_STATE64_COUNT ((mach_msg_type_number_t)(sizeof(MCPRawArmThreadState64) / sizeof(uint32_t)))
#endif

- (NSDictionary *)hardwareBreakpointPID:(pid_t)pid
                                 action:(NSString *)action
                                   slot:(int)slot
                                address:(uint64_t)address
                        redirectAddress:(uint64_t)redirectAddress
                             durationMs:(int)durationMs
                                  error:(NSString **)error {
    if (error) *error = nil;
    if (pid <= 0) {
        if (error) *error = @"Invalid PID";
        return nil;
    }

    MCPTryEnsureProcessDebugged(pid);
    mach_port_t task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS || task == MACH_PORT_NULL) {
        if (error) *error = [NSString stringWithFormat:@"task_for_pid(%d) failed: %s (0x%x)", pid, mach_error_string(kr), kr];
        return nil;
    }

    uint64_t vaMask = 0x00007fffffffffffULL;
    MCPRemoteEnumerateDyldImages(task, &vaMask);

    thread_act_array_t threads = NULL;
    mach_msg_type_number_t threadCount = 0;
    kr = task_threads(task, &threads, &threadCount);
    if (kr != KERN_SUCCESS || threadCount == 0) {
        mach_port_deallocate(mach_task_self(), task);
        if (error) *error = [NSString stringWithFormat:@"task_threads(%d) failed: %s", pid, mach_error_string(kr)];
        return nil;
    }

    NSString *normAction = [action.lowercaseString ?: @"list" stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    int chosenSlot = slot;
    uint64_t cleanAddress = (MCPStripRemotePointer(address, vaMask)) & ~3ULL;
    uint64_t cleanRedirect = redirectAddress ? (MCPStripRemotePointer(redirectAddress, vaMask) & ~3ULL) : 0;

    // Determine free slot if needed
    if (([normAction isEqualToString:@"set"] || [normAction isEqualToString:@"install"]) && (chosenSlot < 0 || chosenSlot >= 16)) {
        MCPRawArmDebugState64 firstDbg;
        memset(&firstDbg, 0, sizeof(firstDbg));
        mach_msg_type_number_t cnt = ARM_DEBUG_STATE64_COUNT;
        if (thread_get_state(threads[0], ARM_DEBUG_STATE64, (thread_state_t)&firstDbg, &cnt) == KERN_SUCCESS) {
            chosenSlot = 0;
            for (int s = 0; s < 16; s++) {
                if ((firstDbg.bcr[s] & 1ULL) == 0 || firstDbg.bvr[s] == cleanAddress) {
                    chosenSlot = s;
                    break;
                }
            }
        } else {
            chosenSlot = 0;
        }
    }

    NSUInteger updatedThreads = 0;
    kern_return_t lastKr = KERN_SUCCESS;
    NSMutableArray<NSDictionary *> *activeSlots = [NSMutableArray array];

    for (mach_msg_type_number_t i = 0; i < threadCount; i++) {
        MCPRawArmDebugState64 dbg;
        memset(&dbg, 0, sizeof(dbg));
        mach_msg_type_number_t cnt = ARM_DEBUG_STATE64_COUNT;
        kern_return_t gkr = thread_get_state(threads[i], ARM_DEBUG_STATE64, (thread_state_t)&dbg, &cnt);
        if (gkr != KERN_SUCCESS) {
            lastKr = gkr;
            continue;
        }

        if ([normAction isEqualToString:@"set"] || [normAction isEqualToString:@"install"]) {
            if (cleanAddress == 0) {
                for (mach_msg_type_number_t j = 0; j < threadCount; j++) mach_port_deallocate(mach_task_self(), threads[j]);
                vm_deallocate(mach_task_self(), (vm_address_t)threads, threadCount * sizeof(thread_t));
                mach_port_deallocate(mach_task_self(), task);
                if (error) *error = @"Hardware breakpoint requires non-zero address";
                return nil;
            }
            dbg.bvr[chosenSlot] = cleanAddress;
            // DBGBCRn_EL1: E=1 (bit 0), PMC=10b EL0 (bits 2:1 = 0x4), BAS=1111b (bits 8:5 = 0x1E0) => 0x1E5
            dbg.bcr[chosenSlot] = 0x1E5ULL;
            kern_return_t skr = thread_set_state(threads[i], ARM_DEBUG_STATE64, (thread_state_t)&dbg, ARM_DEBUG_STATE64_COUNT);
            if (skr == KERN_SUCCESS) updatedThreads++;
            else lastKr = skr;
        } else if ([normAction isEqualToString:@"clear"] || [normAction isEqualToString:@"remove"]) {
            if (chosenSlot < 0) {
                for (int s = 0; s < 16; s++) {
                    dbg.bvr[s] = 0;
                    dbg.bcr[s] = 0;
                }
            } else if (chosenSlot < 16) {
                dbg.bvr[chosenSlot] = 0;
                dbg.bcr[chosenSlot] = 0;
            }
            dbg.mdscr_el1 &= ~1ULL;
            kern_return_t skr = thread_set_state(threads[i], ARM_DEBUG_STATE64, (thread_state_t)&dbg, ARM_DEBUG_STATE64_COUNT);
            if (skr == KERN_SUCCESS) updatedThreads++;
            else lastKr = skr;
        } else {
            updatedThreads++;
        }

        if (i == 0) {
            for (int s = 0; s < 16; s++) {
                if ((dbg.bcr[s] & 1ULL) != 0 || dbg.bvr[s] != 0) {
                    [activeSlots addObject:@{
                        @"slot": @(s),
                        @"type": @"breakpoint",
                        @"bvr": [NSString stringWithFormat:@"0x%llx", (unsigned long long)dbg.bvr[s]],
                        @"bcr": [NSString stringWithFormat:@"0x%llx", (unsigned long long)dbg.bcr[s]],
                        @"enabled": @((dbg.bcr[s] & 1ULL) != 0)
                    }];
                }
                if ((dbg.wcr[s] & 1ULL) != 0 || dbg.wvr[s] != 0) {
                    [activeSlots addObject:@{
                        @"slot": @(s),
                        @"type": @"watchpoint",
                        @"wvr": [NSString stringWithFormat:@"0x%llx", (unsigned long long)dbg.wvr[s]],
                        @"wcr": [NSString stringWithFormat:@"0x%llx", (unsigned long long)dbg.wcr[s]],
                        @"enabled": @((dbg.wcr[s] & 1ULL) != 0)
                    }];
                }
            }
        }
    }

    // Optional synchronous Mach exception port monitor if durationMs > 0
    NSMutableArray<NSDictionary *> *capturedHits = [NSMutableArray array];
    if (durationMs > 0 && ([normAction isEqualToString:@"set"] || [normAction isEqualToString:@"install"])) {
        if (durationMs > 15000) durationMs = 15000;
        mach_port_t excPort = MACH_PORT_NULL;
        if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &excPort) == KERN_SUCCESS &&
            mach_port_insert_right(mach_task_self(), excPort, excPort, MACH_MSG_TYPE_MAKE_SEND) == KERN_SUCCESS) {

            exception_mask_t savedMasks[EXC_TYPES_COUNT];
            mach_port_t savedPorts[EXC_TYPES_COUNT];
            exception_behavior_t savedBehaviors[EXC_TYPES_COUNT];
            thread_state_flavor_t savedFlavors[EXC_TYPES_COUNT];
            mach_msg_type_number_t savedCount = EXC_TYPES_COUNT;

            task_get_exception_ports(task, EXC_MASK_BREAKPOINT, savedMasks, &savedCount, savedPorts, savedBehaviors, savedFlavors);
            task_set_exception_ports(task, EXC_MASK_BREAKPOINT, excPort, EXCEPTION_DEFAULT, ARM_THREAD_STATE64);

            CFAbsoluteTime deadline = CFAbsoluteTimeGetCurrent() + ((double)durationMs / 1000.0);
            while (CFAbsoluteTimeGetCurrent() < deadline) {
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
                } MCPExcRequestMsg;

                typedef struct {
                    mach_msg_header_t Head;
                    NDR_record_t NDR;
                    kern_return_t RetCode;
                } MCPExcReplyMsg;

                MCPExcRequestMsg req;
                memset(&req, 0, sizeof(req));
                double remMs = (deadline - CFAbsoluteTimeGetCurrent()) * 1000.0;
                if (remMs < 1.0) break;
                mach_msg_return_t mr = mach_msg(&req.Head,
                                                MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                                                0,
                                                sizeof(req),
                                                excPort,
                                                (mach_msg_timeout_t)remMs,
                                                MACH_PORT_NULL);
                if (mr != MACH_MSG_SUCCESS) break;

                mach_port_t hitThread = req.thread.name;
                MCPRawArmThreadState64 ts;
                memset(&ts, 0, sizeof(ts));
                mach_msg_type_number_t tsCnt = ARM_THREAD_STATE64_COUNT;
                if (thread_get_state(hitThread, ARM_THREAD_STATE64, (thread_state_t)&ts, &tsCnt) == KERN_SUCCESS) {
                    NSMutableDictionary *regs = [NSMutableDictionary dictionaryWithCapacity:34];
                    for (int r = 0; r < 29; r++) {
                        regs[[NSString stringWithFormat:@"x%d", r]] = [NSString stringWithFormat:@"0x%llx", (unsigned long long)ts.x[r]];
                    }
                    regs[@"fp"] = [NSString stringWithFormat:@"0x%llx", (unsigned long long)ts.fp];
                    regs[@"lr"] = [NSString stringWithFormat:@"0x%llx", (unsigned long long)ts.lr];
                    regs[@"sp"] = [NSString stringWithFormat:@"0x%llx", (unsigned long long)ts.sp];
                    regs[@"pc"] = [NSString stringWithFormat:@"0x%llx", (unsigned long long)ts.pc];
                    regs[@"cpsr"] = [NSString stringWithFormat:@"0x%x", ts.cpsr];

                    [capturedHits addObject:@{
                        @"thread_port": @(hitThread),
                        @"pc": regs[@"pc"],
                        @"lr": regs[@"lr"],
                        @"registers": regs,
                        @"redirected_to": cleanRedirect ? [NSString stringWithFormat:@"0x%llx", (unsigned long long)cleanRedirect] : [NSNull null]
                    }];

                    if (cleanRedirect) {
                        ts.pc = cleanRedirect;
                        thread_set_state(hitThread, ARM_THREAD_STATE64, (thread_state_t)&ts, ARM_THREAD_STATE64_COUNT);
                    } else {
                        // Disable breakpoint on this thread or advance past breakpoint so execution continues cleanly
                        MCPRawArmDebugState64 tdbg;
                        memset(&tdbg, 0, sizeof(tdbg));
                        mach_msg_type_number_t dcnt = ARM_DEBUG_STATE64_COUNT;
                        if (thread_get_state(hitThread, ARM_DEBUG_STATE64, (thread_state_t)&tdbg, &dcnt) == KERN_SUCCESS) {
                            tdbg.bcr[chosenSlot] = 0;
                            thread_set_state(hitThread, ARM_DEBUG_STATE64, (thread_state_t)&tdbg, ARM_DEBUG_STATE64_COUNT);
                        }
                    }
                }

                MCPExcReplyMsg reply;
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

            // Restore original exception ports
            for (mach_msg_type_number_t m = 0; m < savedCount; m++) {
                if (savedMasks[m] != 0) {
                    task_set_exception_ports(task, savedMasks[m], savedPorts[m], savedBehaviors[m], savedFlavors[m]);
                }
                if (savedPorts[m] != MACH_PORT_NULL) {
                    mach_port_deallocate(mach_task_self(), savedPorts[m]);
                }
            }
            mach_port_destroy(mach_task_self(), excPort);
        }
    }

    for (mach_msg_type_number_t i = 0; i < threadCount; i++) {
        mach_port_deallocate(mach_task_self(), threads[i]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)threads, threadCount * sizeof(thread_t));
    mach_port_deallocate(mach_task_self(), task);

    if (updatedThreads == 0 && threadCount > 0) {
        if (error) *error = [NSString stringWithFormat:@"thread_get/set_state(ARM_DEBUG_STATE64) failed across all %u threads: %s (0x%x)", threadCount, mach_error_string(lastKr), lastKr];
        return nil;
    }

    return @{
        @"pid": @(pid),
        @"action": normAction,
        @"slot": @(chosenSlot),
        @"address": [NSString stringWithFormat:@"0x%llx", (unsigned long long)cleanAddress],
        @"redirect_address": cleanRedirect ? [NSString stringWithFormat:@"0x%llx", (unsigned long long)cleanRedirect] : [NSNull null],
        @"total_threads": @(threadCount),
        @"updated_threads": @(updatedThreads),
        @"zero_memory_patch": @YES,
        @"active_debug_slots": activeSlots,
        @"captured_hits": capturedHits
    };
}

#pragma mark - Upgrade 08: Live In-Memory dyld_shared_cache Framework Extractor

- (NSDictionary *)extractDyldSharedCacheImagePID:(pid_t)pid
                                       imageName:(NSString *)imageName
                                      outputPath:(NSString *)outputPath
                                           error:(NSString **)error {
    if (error) *error = nil;
    if (!imageName.length) {
        if (error) *error = @"Missing imageName to extract from dyld_shared_cache";
        return nil;
    }

    pid_t targetPid = (pid > 0) ? pid : getpid();
    if (targetPid != getpid()) {
        MCPTryEnsureProcessDebugged(targetPid);
    }

    mach_port_t task = MACH_PORT_NULL;
    kern_return_t kr = (targetPid == getpid()) ? KERN_SUCCESS : task_for_pid(mach_task_self(), targetPid, &task);
    if (targetPid == getpid() || kr != KERN_SUCCESS || task == MACH_PORT_NULL) {
        targetPid = getpid();
        task = mach_task_self();
    }

    uint64_t vaMask = 0x00007fffffffffffULL;
    NSArray<NSDictionary *> *images = MCPRemoteEnumerateDyldImages(task, &vaMask);

    uint64_t matchedAddr = 0;
    NSString *matchedPath = nil;
    NSString *needle = imageName.lowercaseString;

    for (NSDictionary *img in images) {
        NSString *p = img[@"path"];
        if (!p.length) continue;
        NSString *lower = p.lowercaseString;
        NSString *base = p.lastPathComponent.lowercaseString;
        if ([lower isEqualToString:needle] ||
            [base isEqualToString:needle] ||
            [base isEqualToString:[needle stringByAppendingString:@".dylib"]] ||
            [lower hasSuffix:[NSString stringWithFormat:@"/%@.framework/%@", needle, needle]] ||
            [lower rangeOfString:needle].location != NSNotFound) {
            matchedAddr = [img[@"address"] unsignedLongLongValue];
            matchedPath = p;
            if ([base isEqualToString:needle] || [lower isEqualToString:needle]) break;
        }
    }

    // If not yet loaded in target process, load it in our own process via dlopen so dyld maps it from dyld_shared_cache
    if (!matchedAddr) {
        if (task != mach_task_self()) {
            mach_port_deallocate(mach_task_self(), task);
            task = mach_task_self();
            targetPid = getpid();
        }
        NSArray<NSString *> *dlCandidates = @[
            imageName,
            [NSString stringWithFormat:@"/System/Library/Frameworks/%@.framework/%@", imageName, imageName],
            [NSString stringWithFormat:@"/System/Library/PrivateFrameworks/%@.framework/%@", imageName, imageName],
            [NSString stringWithFormat:@"/usr/lib/%@", [imageName hasSuffix:@".dylib"] ? imageName : [imageName stringByAppendingString:@".dylib"]],
            [NSString stringWithFormat:@"/usr/lib/system/%@", [imageName hasSuffix:@".dylib"] ? imageName : [imageName stringByAppendingString:@".dylib"]]
        ];
        for (NSString *cand in dlCandidates) {
            void *h = dlopen(cand.UTF8String, RTLD_LAZY);
            if (h) break;
        }
        uint32_t imgCount = _dyld_image_count();
        for (uint32_t i = 0; i < imgCount; i++) {
            const char *cname = _dyld_get_image_name(i);
            if (!cname) continue;
            NSString *p = [NSString stringWithUTF8String:cname];
            NSString *lower = p.lowercaseString;
            NSString *base = p.lastPathComponent.lowercaseString;
            if ([lower isEqualToString:needle] ||
                [base isEqualToString:needle] ||
                [base isEqualToString:[needle stringByAppendingString:@".dylib"]] ||
                [lower rangeOfString:needle].location != NSNotFound) {
                matchedAddr = (uint64_t)(uintptr_t)_dyld_get_image_header(i);
                matchedPath = p;
                if ([base isEqualToString:needle] || [lower isEqualToString:needle]) break;
            }
        }
    }

    if (!matchedAddr) {
        if (task != mach_task_self()) mach_port_deallocate(mach_task_self(), task);
        if (error) *error = [NSString stringWithFormat:@"Could not find or map '%@' in dyld_shared_cache", imageName];
        return nil;
    }

    struct mach_header_64 hdr = {0};
    if (!MCPRemoteReadExact(task, matchedAddr, &hdr, sizeof(hdr), vaMask) || hdr.magic != MH_MAGIC_64) {
        if (task != mach_task_self()) mach_port_deallocate(mach_task_self(), task);
        if (error) *error = [NSString stringWithFormat:@"Invalid Mach-O header at 0x%llx for %@", (unsigned long long)matchedAddr, matchedPath];
        return nil;
    }

    size_t headerAndCmdsSize = sizeof(struct mach_header_64) + hdr.sizeofcmds;
    if (headerAndCmdsSize > 256 * 1024) {
        if (task != mach_task_self()) mach_port_deallocate(mach_task_self(), task);
        if (error) *error = @"Mach-O load commands exceed 256 KB safety limit";
        return nil;
    }

    NSMutableData *cmdBuf = [NSMutableData dataWithLength:headerAndCmdsSize];
    if (!MCPRemoteReadExact(task, matchedAddr, cmdBuf.mutableBytes, headerAndCmdsSize, vaMask)) {
        if (task != mach_task_self()) mach_port_deallocate(mach_task_self(), task);
        if (error) *error = @"Failed to read Mach-O load commands from memory";
        return nil;
    }

    uint8_t *cmdBytes = (uint8_t *)cmdBuf.mutableBytes;
    struct mach_header_64 *outHdr = (struct mach_header_64 *)cmdBytes;
    outHdr->flags &= ~0x80000000U; // Clear MH_DYLIB_IN_CACHE

    uint64_t textVMAddr = 0;
    uint64_t linkeditVMAddr = 0;
    uint64_t linkeditFileOff = 0;
    size_t off = sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < hdr.ncmds && off + sizeof(struct load_command) <= headerAndCmdsSize; i++) {
        struct load_command *lc = (struct load_command *)(cmdBytes + off);
        if (lc->cmdsize < sizeof(struct load_command) || off + lc->cmdsize > headerAndCmdsSize) break;
        if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            if (strncmp(seg->segname, "__TEXT", 16) == 0) {
                textVMAddr = seg->vmaddr;
            } else if (strncmp(seg->segname, "__LINKEDIT", 16) == 0) {
                linkeditVMAddr = seg->vmaddr;
                linkeditFileOff = seg->fileoff;
            }
        }
        off += lc->cmdsize;
    }

    int64_t slide = (int64_t)matchedAddr - (int64_t)textVMAddr;
    NSMutableData *outFileData = [NSMutableData data];
    NSMutableArray<NSDictionary *> *extractedSegments = [NSMutableArray array];
    NSUInteger totalSections = 0;

    off = sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < hdr.ncmds && off + sizeof(struct load_command) <= headerAndCmdsSize; i++) {
        struct load_command *lc = (struct load_command *)(cmdBytes + off);
        if (lc->cmdsize < sizeof(struct load_command) || off + lc->cmdsize > headerAndCmdsSize) break;
        if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            char segNameBuf[17] = {0};
            memcpy(segNameBuf, seg->segname, 16);
            NSString *segName = [NSString stringWithUTF8String:segNameBuf];

            if ([segName isEqualToString:@"__PAGEZERO"] || seg->vmsize == 0) {
                off += lc->cmdsize;
                continue;
            }
            if ([segName isEqualToString:@"__LINKEDIT"]) {
                // Handled after all data/text segments so localized symtab sits cleanly at EOF
                off += lc->cmdsize;
                continue;
            }

            // Align file offset to 16KB page boundary (0 on __TEXT)
            uint64_t newFileOff = [segName isEqualToString:@"__TEXT"] ? 0 : ((outFileData.length + 0x3FFFULL) & ~0x3FFFULL);
            if (newFileOff > outFileData.length) {
                [outFileData increaseLengthBy:(NSUInteger)(newFileOff - outFileData.length)];
            }

            uint64_t dumpSize = MIN(seg->vmsize, (uint64_t)(128ULL * 1024ULL * 1024ULL));
            uint64_t alignedSize = (dumpSize + 0x3FFFULL) & ~0x3FFFULL;
            NSMutableData *segData = [NSMutableData dataWithLength:(NSUInteger)alignedSize];
            uint64_t runtimeSegAddr = (uint64_t)((int64_t)seg->vmaddr + slide);
            MCPRemoteReadChunked(task, runtimeSegAddr, segData.mutableBytes, (size_t)dumpSize, vaMask, YES);

            // Update section offsets inside this segment
            struct section_64 *secs = (struct section_64 *)((uint8_t *)seg + sizeof(struct segment_command_64));
            uint32_t nsects = seg->nsects;
            for (uint32_t s = 0; s < nsects; s++) {
                if ((uint8_t *)&secs[s + 1] > (uint8_t *)seg + seg->cmdsize) break;
                if (secs[s].addr >= seg->vmaddr && secs[s].addr < seg->vmaddr + dumpSize) {
                    secs[s].offset = (uint32_t)(newFileOff + (secs[s].addr - seg->vmaddr));
                }
                totalSections++;
            }

            seg->fileoff = newFileOff;
            seg->filesize = alignedSize;
            [outFileData appendData:segData];

            [extractedSegments addObject:@{
                @"name": segName,
                @"vmaddr": [NSString stringWithFormat:@"0x%llx", (unsigned long long)seg->vmaddr],
                @"runtime_addr": [NSString stringWithFormat:@"0x%llx", (unsigned long long)runtimeSegAddr],
                @"fileoff": @(newFileOff),
                @"filesize": @(alignedSize),
                @"nsects": @(nsects)
            }];
        }
        off += lc->cmdsize;
    }

    // Reconstruct compact localized __LINKEDIT with LC_FUNCTION_STARTS and LC_SYMTAB
    uint64_t newLinkeditFileOff = (outFileData.length + 0x3FFFULL) & ~0x3FFFULL;
    if (newLinkeditFileOff > outFileData.length) {
        [outFileData increaseLengthBy:(NSUInteger)(newLinkeditFileOff - outFileData.length)];
    }
    NSMutableData *localLinkedit = [NSMutableData data];
    NSUInteger exportedSymCount = 0;

    off = sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < hdr.ncmds && off + sizeof(struct load_command) <= headerAndCmdsSize; i++) {
        struct load_command *lc = (struct load_command *)(cmdBytes + off);
        if (lc->cmdsize < sizeof(struct load_command) || off + lc->cmdsize > headerAndCmdsSize) break;

        if (lc->cmd == LC_FUNCTION_STARTS && lc->cmdsize >= sizeof(struct linkedit_data_command) && linkeditVMAddr != 0) {
            struct linkedit_data_command *ldc = (struct linkedit_data_command *)lc;
            if (ldc->datasize > 0 && ldc->datasize <= 2 * 1024 * 1024 && ldc->dataoff >= linkeditFileOff) {
                uint64_t fsRuntimeAddr = (uint64_t)((int64_t)linkeditVMAddr + slide) + (ldc->dataoff - linkeditFileOff);
                NSMutableData *fsData = [NSMutableData dataWithLength:ldc->datasize];
                if (MCPRemoteReadChunked(task, fsRuntimeAddr, fsData.mutableBytes, ldc->datasize, vaMask, NO)) {
                    uint32_t relOff = (uint32_t)localLinkedit.length;
                    [localLinkedit appendData:fsData];
                    ldc->dataoff = (uint32_t)(newLinkeditFileOff + relOff);
                } else {
                    ldc->dataoff = 0;
                    ldc->datasize = 0;
                }
            } else {
                ldc->dataoff = 0;
                ldc->datasize = 0;
            }
        } else if (lc->cmd == LC_SYMTAB && lc->cmdsize >= sizeof(struct symtab_command) && linkeditVMAddr != 0) {
            struct symtab_command *sc = (struct symtab_command *)lc;
            uint32_t maxSyms = MIN(sc->nsyms, 65536U);
            if (maxSyms > 0 && sc->symoff >= linkeditFileOff && sc->stroff >= linkeditFileOff) {
                uint64_t symRuntimeAddr = (uint64_t)((int64_t)linkeditVMAddr + slide) + (sc->symoff - linkeditFileOff);
                uint64_t strRuntimeAddr = (uint64_t)((int64_t)linkeditVMAddr + slide) + (sc->stroff - linkeditFileOff);
                size_t symBytesLen = (size_t)maxSyms * sizeof(struct nlist_64);
                NSMutableData *symData = [NSMutableData dataWithLength:symBytesLen];
                if (MCPRemoteReadChunked(task, symRuntimeAddr, symData.mutableBytes, symBytesLen, vaMask, YES)) {
                    struct nlist_64 *nlists = (struct nlist_64 *)symData.mutableBytes;
                    NSMutableData *newStrTab = [NSMutableData dataWithBytes:"\0" length:1];
                    for (uint32_t s = 0; s < maxSyms; s++) {
                        uint32_t origStrx = nlists[s].n_un.n_strx;
                        if (origStrx > 0 && origStrx < sc->strsize) {
                            NSString *symName = MCPRemoteReadCString(task, strRuntimeAddr + origStrx, 512, vaMask);
                            if (symName.length > 0) {
                                uint32_t newStrx = (uint32_t)newStrTab.length;
                                const char *utf8 = symName.UTF8String;
                                [newStrTab appendBytes:utf8 length:strlen(utf8) + 1];
                                nlists[s].n_un.n_strx = newStrx;
                                exportedSymCount++;
                            } else {
                                nlists[s].n_un.n_strx = 0;
                            }
                        } else {
                            nlists[s].n_un.n_strx = 0;
                        }
                    }
                    // Align localLinkedit to 8 bytes
                    while (localLinkedit.length & 7) [localLinkedit appendBytes:"\0" length:1];
                    uint32_t newSymOff = (uint32_t)(newLinkeditFileOff + localLinkedit.length);
                    [localLinkedit appendData:symData];
                    uint32_t newStrOff = (uint32_t)(newLinkeditFileOff + localLinkedit.length);
                    [localLinkedit appendData:newStrTab];

                    sc->symoff = newSymOff;
                    sc->nsyms = maxSyms;
                    sc->stroff = newStrOff;
                    sc->strsize = (uint32_t)newStrTab.length;
                } else {
                    sc->symoff = 0;
                    sc->nsyms = 0;
                    sc->stroff = 0;
                    sc->strsize = 0;
                }
            }
        } else if (lc->cmd == LC_DYSYMTAB && lc->cmdsize >= sizeof(struct dysymtab_command)) {
            struct dysymtab_command *dsc = (struct dysymtab_command *)lc;
            dsc->tocoff = 0; dsc->ntoc = 0;
            dsc->modtaboff = 0; dsc->nmodtab = 0;
            dsc->extrefsymoff = 0; dsc->nextrefsyms = 0;
            dsc->indirectsymoff = 0; dsc->nindirectsyms = 0;
            dsc->extreloff = 0; dsc->nextrel = 0;
            dsc->locreloff = 0; dsc->nlocrel = 0;
        } else if ((lc->cmd == LC_DYLD_INFO || lc->cmd == LC_DYLD_INFO_ONLY) && lc->cmdsize >= sizeof(struct dyld_info_command)) {
            struct dyld_info_command *dic = (struct dyld_info_command *)lc;
            dic->rebase_off = 0; dic->rebase_size = 0;
            dic->bind_off = 0; dic->bind_size = 0;
            dic->weak_bind_off = 0; dic->weak_bind_size = 0;
            dic->lazy_bind_off = 0; dic->lazy_bind_size = 0;
            dic->export_off = 0; dic->export_size = 0;
        } else if ((lc->cmd == LC_CODE_SIGNATURE ||
                    lc->cmd == LC_SEGMENT_SPLIT_INFO ||
                    lc->cmd == LC_FUNCTION_STARTS ||
                    lc->cmd == LC_DATA_IN_CODE ||
                    lc->cmd == LC_DYLIB_CODE_SIGN_DRS ||
                    lc->cmd == LC_LINKER_OPTIMIZATION_HINT ||
                    lc->cmd == 0x80000033U /* LC_DYLD_EXPORTS_TRIE */ ||
                    lc->cmd == 0x80000034U /* LC_DYLD_CHAINED_FIXUPS */) &&
                   lc->cmdsize >= sizeof(struct linkedit_data_command)) {
            struct linkedit_data_command *ldc = (struct linkedit_data_command *)lc;
            ldc->dataoff = 0;
            ldc->datasize = 0;
        }
        off += lc->cmdsize;
    }

    // Update __LINKEDIT segment command
    off = sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < hdr.ncmds && off + sizeof(struct load_command) <= headerAndCmdsSize; i++) {
        struct load_command *lc = (struct load_command *)(cmdBytes + off);
        if (lc->cmdsize < sizeof(struct load_command) || off + lc->cmdsize > headerAndCmdsSize) break;
        if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            if (strncmp(seg->segname, "__LINKEDIT", 16) == 0) {
                seg->fileoff = newLinkeditFileOff;
                seg->filesize = localLinkedit.length;
                seg->vmsize = (localLinkedit.length + 0x3FFFULL) & ~0x3FFFULL;
                [extractedSegments addObject:@{
                    @"name": @"__LINKEDIT",
                    @"vmaddr": [NSString stringWithFormat:@"0x%llx", (unsigned long long)seg->vmaddr],
                    @"fileoff": @(newLinkeditFileOff),
                    @"filesize": @(localLinkedit.length)
                }];
                break;
            }
        }
        off += lc->cmdsize;
    }

    [outFileData appendData:localLinkedit];
    // Write updated Mach-O header and load commands at offset 0 of __TEXT
    if (outFileData.length >= headerAndCmdsSize) {
        [outFileData replaceBytesInRange:NSMakeRange(0, headerAndCmdsSize) withBytes:cmdBuf.bytes];
    }

    if (task != mach_task_self()) {
        mach_port_deallocate(mach_task_self(), task);
    }

    if (!outputPath.length) {
        NSString *safeBase = matchedPath.lastPathComponent ?: @"extracted_dylib";
        outputPath = [MCPMemoryEnsureWorkDir() stringByAppendingPathComponent:
                      [NSString stringWithFormat:@"%@.extracted.macho", safeBase]];
    }
    NSString *parentDir = [outputPath stringByDeletingLastPathComponent];
    if (parentDir.length) {
        [[NSFileManager defaultManager] createDirectoryAtPath:parentDir withIntermediateDirectories:YES attributes:nil error:nil];
        if ([parentDir hasSuffix:@"/ios-mcp-work"]) {
            chmod(parentDir.UTF8String, 0777);
            chown(parentDir.UTF8String, 501, 501);
        }
    }
    if (![outFileData writeToFile:outputPath atomically:YES]) {
        if (error) *error = [NSString stringWithFormat:@"Failed to write extracted Mach-O to %@", outputPath];
        return nil;
    }
    chmod(outputPath.UTF8String, 0666);
    chown(outputPath.UTF8String, 501, 501);

    return @{
        @"pid": @(targetPid),
        @"requested_image": imageName,
        @"resolved_image_path": matchedPath ?: @"",
        @"load_address": [NSString stringWithFormat:@"0x%llx", (unsigned long long)matchedAddr],
        @"aslr_slide": [NSString stringWithFormat:@"0x%llx", (unsigned long long)slide],
        @"output_path": outputPath,
        @"output_size_bytes": @(outFileData.length),
        @"segment_count": @(extractedSegments.count),
        @"section_count": @(totalSections),
        @"reconstructed_symbols": @(exportedSymCount),
        @"segments": extractedSegments
    };
}

@end
