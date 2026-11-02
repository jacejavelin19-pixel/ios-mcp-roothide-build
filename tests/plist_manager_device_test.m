#import <Foundation/Foundation.h>
#import "../PlistPatchManager.h"

int main(void) {
    @autoreleasepool {
        NSString *path = [NSTemporaryDirectory() stringByAppendingPathComponent:@"ios-mcp-plist-test.tmp"];
        for (NSNumber *requested in @[@(NSPropertyListXMLFormat_v1_0), @(NSPropertyListBinaryFormat_v1_0)]) {
            NSError *error = nil;
            NSData *data = [NSPropertyListSerialization dataWithPropertyList:@{@"outer": @{@"answer": @1}} format:requested.unsignedIntegerValue options:0 error:&error];
            if (!data || ![data writeToFile:path atomically:YES]) return 1;
            NSString *message = nil;
            PlistPatchManager *manager = [PlistPatchManager sharedInstance];
            if (![[manager valueAtPath:path keypath:@"outer.answer" error:&message][@"value"] isEqual:@1]) return 2;
            if (![manager setValue:@42 atPath:path keypath:@"outer.answer" error:&message]) return 3;
            if (![[manager valueAtPath:path keypath:@"outer.answer" error:&message][@"value"] isEqual:@42]) return 4;
            NSPropertyListFormat actual;
            [NSPropertyListSerialization propertyListWithData:[NSData dataWithContentsOfFile:path] options:0 format:&actual error:&error];
            if (actual != requested.unsignedIntegerValue) return 5;
            if ([manager setValue:[NSNull null] atPath:path keypath:@"outer.answer" error:&message]) return 6;
        }
        [[NSFileManager defaultManager] removeItemAtPath:path error:NULL];
        puts("PASS plist xml binary read write preserve-format reject-null");
        return 0;
    }
}
