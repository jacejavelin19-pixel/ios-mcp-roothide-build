#import "MemoryManager.h"
#import <ctype.h>
#import <mach/mach.h>
#import <mach-o/loader.h>
#import <string.h>
#import <unistd.h>

// The iOS SDK intentionally omits the mach_vm MIG declarations.
extern kern_return_t mach_vm_read_overwrite(vm_map_t, mach_vm_address_t, mach_vm_size_t, mach_vm_address_t, mach_vm_size_t *);
extern kern_return_t mach_vm_write(vm_map_t, mach_vm_address_t, vm_offset_t, mach_msg_type_number_t);
extern kern_return_t mach_vm_region(vm_map_t, mach_vm_address_t *, mach_vm_size_t *, vm_region_flavor_t, vm_region_info_t, mach_msg_type_number_t *, mach_port_t *);

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

- (NSDictionary *)writePID:(pid_t)pid address:(uint64_t)address data:(NSData *)data error:(NSString **)error {
    if (!data.length || data.length > 1048576 || address > UINT64_MAX - data.length) {
        if (error) *error = @"data must contain 1..1048576 bytes and address range must not overflow";
        return nil;
    }
    mach_port_t task = [self taskForPID:pid error:error];
    if (task == MACH_PORT_NULL) return nil;
    kern_return_t result = mach_vm_write(task, address, (vm_offset_t)data.bytes, (mach_msg_type_number_t)data.length);
    mach_port_deallocate(mach_task_self(), task);
    if (result != KERN_SUCCESS) {
        if (error) *error = MCPMachError(result);
        return nil;
    }
    return @{@"address": [NSString stringWithFormat:@"0x%llx", address], @"written": @(data.length)};
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

@end
