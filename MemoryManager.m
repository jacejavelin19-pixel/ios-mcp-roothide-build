#import "MemoryManager.h"
#import <mach/mach.h>

// The iOS SDK intentionally omits the mach_vm MIG declarations.
extern kern_return_t mach_vm_read_overwrite(vm_map_t, mach_vm_address_t, mach_vm_size_t, mach_vm_address_t, mach_vm_size_t *);
extern kern_return_t mach_vm_write(vm_map_t, mach_vm_address_t, vm_offset_t, mach_msg_type_number_t);
extern kern_return_t mach_vm_region(vm_map_t, mach_vm_address_t *, mach_vm_size_t *, vm_region_flavor_t, vm_region_info_t, mach_msg_type_number_t *, mach_port_t *);

static NSString *MCPMachError(kern_return_t result) {
    return [NSString stringWithFormat:@"%s (%d)", mach_error_string(result), result];
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
    while (cursor < end && regions++ < 4096 && matches.count < 1000) {
        mach_vm_address_t region = cursor;
        mach_vm_size_t regionSize = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object = MACH_PORT_NULL;
        kern_return_t kr = mach_vm_region(task, &region, &regionSize, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &object);
        if (object != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), object);
        if (kr != KERN_SUCCESS || !regionSize || region > UINT64_MAX - regionSize) break;
        mach_vm_address_t regionEnd = MIN(end, region + regionSize);
        mach_vm_address_t position = MAX(cursor, region);
        if ((info.protection & VM_PROT_READ) && position < regionEnd) {
            while (position < regionEnd && matches.count < 1000) {
                mach_vm_size_t amount = MIN((mach_vm_size_t)65536, regionEnd - position);
                NSMutableData *block = [NSMutableData dataWithLength:(NSUInteger)amount];
                mach_vm_size_t actual = 0;
                kr = mach_vm_read_overwrite(task, position, amount, (mach_vm_address_t)block.mutableBytes, &actual);
                if (kr != KERN_SUCCESS || actual == 0) break;
                const uint8_t *bytes = block.bytes;
                for (NSUInteger i = 0; i + data.length <= actual && matches.count < 1000; i++) {
                    if (memcmp(bytes + i, data.bytes, data.length) == 0) [matches addObject:[NSString stringWithFormat:@"0x%llx", position + i]];
                }
                if (actual <= data.length - 1 || position + actual >= regionEnd) break;
                position += actual - (data.length - 1);
            }
        }
        if (regionEnd <= cursor) break;
        cursor = regionEnd;
    }
    mach_port_deallocate(mach_task_self(), task);
    return @{@"matches": matches, @"limited": @(matches.count >= 1000 || regions > 4096)};
}

@end
