#import <Foundation/Foundation.h>
#import <errno.h>
#import <stdlib.h>
#import <string.h>
#import "MemoryManager.h"

static BOOL parseUnsigned(const char *text, uint64_t *value) {
    if (!text || !*text || *text == '-' || *text == '+') return NO;
    errno = 0;
    char *end = NULL;
    unsigned long long parsed = strtoull(text, &end, 0);
    if (errno || !end || *end) return NO;
    *value = (uint64_t)parsed;
    return YES;
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        NSString *failure = nil;
        NSDictionary *result = nil;
        uint64_t pid = 0, address = 0, amount = 0;

        if (argc < 3 || !parseUnsigned(argv[2], &pid) || pid == 0 || pid > INT32_MAX) {
            failure = @"invalid pid or missing operation";
        } else if (strcmp(argv[1], "regions") == 0) {
            uint64_t limit = 256;
            if (argc >= 4 && !parseUnsigned(argv[3], &limit)) {
                failure = @"invalid limit";
            } else {
                result = [[MemoryManager sharedInstance] listRegionsPID:(pid_t)pid limit:(NSUInteger)limit error:&failure];
            }
        } else if (strcmp(argv[1], "classdump") == 0) {
            NSString *filter = (argc >= 4 && argv[3][0] != '\0') ? [NSString stringWithUTF8String:argv[3]] : nil;
            uint64_t limit = 500;
            BOOL includeSystem = NO;
            if (argc >= 5 && !parseUnsigned(argv[4], &limit)) {
                failure = @"invalid limit";
            } else {
                if (argc >= 6 && strcmp(argv[5], "1") == 0) includeSystem = YES;
                result = [[MemoryManager sharedInstance] dumpClassesPID:(pid_t)pid
                                                                 filter:filter
                                                                  limit:(NSUInteger)limit
                                                          includeSystem:includeSystem
                                                                  error:&failure];
            }
        } else if (strcmp(argv[1], "patch-slots") == 0 && argc == 4) {
            NSString *encoded = [NSString stringWithUTF8String:argv[3]];
            NSData *jsonData = encoded ? [[NSData alloc] initWithBase64EncodedString:encoded options:0] : nil;
            id parsed = jsonData ? [NSJSONSerialization JSONObjectWithData:jsonData options:0 error:NULL] : nil;
            if (![parsed isKindOfClass:[NSArray class]]) {
                failure = @"invalid base64 JSON patches array";
            } else {
                result = [[MemoryManager sharedInstance] patchSlotsPID:(pid_t)pid patches:(NSArray *)parsed error:&failure];
            }
        } else if (argc < 5 || !parseUnsigned(argv[3], &address)) {
            failure = @"invalid arguments";
        } else if (strcmp(argv[1], "read") == 0 && argc == 5 && parseUnsigned(argv[4], &amount) && amount <= 1048576) {
            result = [[MemoryManager sharedInstance] readPID:(pid_t)pid address:address length:(NSUInteger)amount error:&failure];
        } else if ((strcmp(argv[1], "write") == 0 || strcmp(argv[1], "write-protect") == 0) && argc == 5) {
            NSString *encoded = [NSString stringWithUTF8String:argv[4]];
            NSData *data = encoded ? [[NSData alloc] initWithBase64EncodedString:encoded options:0] : nil;
            if (!data) failure = @"invalid base64 data";
            else result = [[MemoryManager sharedInstance] protectWritePID:(pid_t)pid address:address data:data error:&failure];
        } else if (strcmp(argv[1], "search") == 0 && argc == 6 && parseUnsigned(argv[4], &amount)) {
            NSString *encoded = [NSString stringWithUTF8String:argv[5]];
            NSData *data = encoded ? [[NSData alloc] initWithBase64EncodedString:encoded options:0] : nil;
            if (!data) failure = @"invalid base64 data";
            else result = [[MemoryManager sharedInstance] searchPID:(pid_t)pid data:data start:address end:amount error:&failure];
        } else {
            failure = @"invalid operation or arguments";
        }

        NSDictionary *output = result ? @{@"ok": @YES, @"result": result} : @{@"ok": @NO, @"error": failure ?: @"operation failed"};
        NSData *json = [NSJSONSerialization dataWithJSONObject:output options:0 error:NULL];
        if (!json) return 2;
        fwrite(json.bytes, 1, json.length, stdout);
        fputc('\n', stdout);
        return result ? 0 : 1;
    }
}
