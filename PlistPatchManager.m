#import "PlistPatchManager.h"

@implementation PlistPatchManager

+ (instancetype)sharedInstance {
    static PlistPatchManager *instance;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ instance = [self new]; });
    return instance;
}

- (NSDictionary *)performAtPath:(NSString *)path keypath:(NSString *)keypath value:(id)value write:(BOOL)write error:(NSString **)error {
    if (![path hasPrefix:@"/"]) {
        if (error) *error = @"path must be absolute";
        return nil;
    }
    NSArray *keys = [keypath componentsSeparatedByString:@"."];
    if (!keypath.length || [keys containsObject:@""]) {
        if (error) *error = @"keypath must contain nonempty dot-separated keys";
        return nil;
    }
    NSError *e = nil;
    NSData *data = [NSData dataWithContentsOfFile:path options:0 error:&e];
    if (!data) {
        if (error) *error = e.localizedDescription;
        return nil;
    }
    NSPropertyListFormat format;
    id root = [NSPropertyListSerialization propertyListWithData:data options:NSPropertyListMutableContainersAndLeaves format:&format error:&e];
    if (!root) {
        if (error) *error = e.localizedDescription;
        return nil;
    }
    id parent = root;
    for (NSUInteger i = 0; i + 1 < keys.count; i++) {
        if (![parent isKindOfClass:[NSDictionary class]]) {
            if (error) *error = @"keypath traverses a non-dictionary";
            return nil;
        }
        parent = parent[keys[i]];
        if (!parent) {
            if (error) *error = @"keypath not found";
            return nil;
        }
    }
    if (![parent isKindOfClass:[NSMutableDictionary class]]) {
        if (error) *error = @"keypath parent is not a dictionary";
        return nil;
    }
    NSString *key = keys.lastObject;
    if (write) {
        if (!value || value == [NSNull null]) {
            if (error) *error = @"null is not a property-list value";
            return nil;
        }
        parent[key] = value;
        NSData *output = [NSPropertyListSerialization dataWithPropertyList:root format:format options:0 error:&e];
        if (!output || ![output writeToFile:path options:NSDataWritingAtomic error:&e]) {
            if (error) *error = e.localizedDescription ?: @"write failed";
            return nil;
        }
        return @{@"path": path, @"keypath": keypath, @"written": @YES};
    }
    id result = parent[key];
    if (!result) {
        if (error) *error = @"keypath not found";
        return nil;
    }
    if (![NSJSONSerialization isValidJSONObject:@[result]]) {
        if (error) *error = @"property-list value is not JSON representable";
        return nil;
    }
    return @{@"path": path, @"keypath": keypath, @"value": result};
}

- (NSDictionary *)valueAtPath:(NSString *)path keypath:(NSString *)keypath error:(NSString **)error {
    return [self performAtPath:path keypath:keypath value:nil write:NO error:error];
}

- (NSDictionary *)setValue:(id)value atPath:(NSString *)path keypath:(NSString *)keypath error:(NSString **)error {
    return [self performAtPath:path keypath:keypath value:value write:YES error:error];
}

@end
