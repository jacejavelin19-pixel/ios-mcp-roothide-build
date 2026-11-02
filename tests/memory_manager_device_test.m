#import <Foundation/Foundation.h>
#import <sys/mman.h>
#import <spawn.h>
#import <signal.h>
#import <sys/wait.h>
#import <unistd.h>
#import "../MemoryManager.h"

extern char **environ;

int main(int argc, char **argv) {
    @autoreleasepool {
        if (argc == 2 && strcmp(argv[1], "--target") == 0) {
            static volatile uint64_t target = 0x123456789abcdef0ULL;
            printf("%llu\n", (unsigned long long)(uintptr_t)&target);
            fflush(stdout);
            sleep(30);
            return 0;
        }
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
        if (argc == 2 && strcmp(argv[1], "--cross-process") == 0) {
            int fds[2];
            if (pipe(fds) != 0) { perror("pipe"); return 7; }
            posix_spawn_file_actions_t actions;
            posix_spawn_file_actions_init(&actions);
            posix_spawn_file_actions_adddup2(&actions, fds[1], STDOUT_FILENO);
            posix_spawn_file_actions_addclose(&actions, fds[0]);
            posix_spawn_file_actions_addclose(&actions, fds[1]);
            char *childArgs[] = {argv[0], "--target", NULL};
            pid_t child = 0;
            int spawnResult = posix_spawn(&child, argv[0], &actions, NULL, childArgs, environ);
            posix_spawn_file_actions_destroy(&actions);
            close(fds[1]);
            if (spawnResult != 0) { close(fds[0]); fprintf(stderr, "spawn failed: %d\n", spawnResult); return 8; }
            FILE *stream = fdopen(fds[0], "r");
            unsigned long long remoteAddress = 0;
            int parsed = stream ? fscanf(stream, "%llu", &remoteAddress) : 0;
            if (stream) fclose(stream); else close(fds[0]);
            NSString *crossError = nil;
            NSDictionary *remote = parsed == 1 ? [manager readPID:child address:remoteAddress length:sizeof(uint64_t) error:&crossError] : nil;
            kill(child, SIGTERM);
            waitpid(child, NULL, 0);
            if (!remote) { fprintf(stderr, "cross-process read failed: %s\n", crossError.UTF8String ?: "target did not report address"); return 9; }
            NSData *remoteData = [[NSData alloc] initWithBase64EncodedString:remote[@"data"] options:0];
            uint64_t actual = 0;
            if (remoteData.length != sizeof(actual)) return 10;
            memcpy(&actual, remoteData.bytes, sizeof(actual));
            if (actual != 0x123456789abcdef0ULL) { fprintf(stderr, "cross-process read mismatch\n"); return 11; }
            puts("PASS cross-process read from dedicated child");
        }
        return 0;
    }
}
