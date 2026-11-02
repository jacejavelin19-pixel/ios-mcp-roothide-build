#import <Foundation/Foundation.h>
#import <sys/mman.h>
#import <unistd.h>
#import "../MemoryManager.h"

int main(void) {
    @autoreleasepool {
        const size_t size = 131072;
        uint8_t *buffer = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
        if (buffer == MAP_FAILED) { perror("mmap"); return 1; }
        const uint8_t marker[] = {0x2d, 0x93, 0x57, 0xa6, 0x09, 0x6c, 0xfe, 0x81};
        memcpy(buffer + 65532, marker, sizeof(marker));
        uint64_t address = (uint64_t)(uintptr_t)buffer;
        NSData *pattern = [NSData dataWithBytes:marker length:sizeof(marker)];
        NSString *error = nil;
        MemoryManager *manager = [MemoryManager sharedInstance];
        NSDictionary *read = [manager readPID:getpid() address:address + 65532 length:sizeof(marker) error:&error];
        if (!read) { fprintf(stderr, "read failed: %s\n", error.UTF8String); return 2; }
        NSData *decoded = [[NSData alloc] initWithBase64EncodedString:read[@"data"] options:0];
        if (![decoded isEqualToData:pattern]) { fprintf(stderr, "read mismatch\n"); return 3; }
        NSDictionary *search = [manager searchPID:getpid() data:pattern start:address end:address + size error:&error];
        NSString *expected = [NSString stringWithFormat:@"0x%llx", address + 65532];
        if (!search || ![search[@"matches"] containsObject:expected]) {
            fprintf(stderr, "search failed: %s\n", error.UTF8String ?: "marker not found"); return 4;
        }
        const uint8_t replacement[] = {0x12, 0x34, 0x56, 0x78};
        NSData *write = [NSData dataWithBytes:replacement length:sizeof(replacement)];
        if (![manager writePID:getpid() address:address + 100 data:write error:&error] || memcmp(buffer + 100, replacement, sizeof(replacement))) {
            fprintf(stderr, "write failed: %s\n", error.UTF8String ?: "mismatch"); return 5;
        }
        if ([manager readPID:getpid() address:address length:0 error:&error] ||
            [manager searchPID:getpid() data:pattern start:address end:address + 16777217 error:&error]) {
            fprintf(stderr, "invalid range accepted\n"); return 6;
        }
        munmap(buffer, size);
        puts("PASS self read/write/search cross-chunk and bounds");
        return 0;
    }
}
