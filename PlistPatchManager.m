#import "PlistPatchManager.h"
#import <sys/stat.h>
#if defined(MCP_ROOTHIDE) || defined(MCP_ROOTLESS)
#import "MCPProcessUtil.h"
#endif

static id MCPPlistValueToJSONSafe(id value) {
    if (!value || value == [NSNull null]) return [NSNull null];
    if ([value isKindOfClass:[NSString class]] || [value isKindOfClass:[NSNumber class]]) {
        return value;
    }
    if ([value isKindOfClass:[NSData class]]) {
        return @{
            @"_plist_type": @"data",
            @"base64": [(NSData *)value base64EncodedStringWithOptions:0] ?: @"",
            @"length": @([(NSData *)value length])
        };
    }
    if ([value isKindOfClass:[NSDate class]]) {
        NSISO8601DateFormatter *fmt = [[NSISO8601DateFormatter alloc] init];
        return @{
            @"_plist_type": @"date",
            @"iso8601": [fmt stringFromDate:(NSDate *)value] ?: @"",
            @"timestamp": @([(NSDate *)value timeIntervalSince1970])
        };
    }
    if ([value isKindOfClass:[NSArray class]]) {
        NSMutableArray *arr = [NSMutableArray arrayWithCapacity:[(NSArray *)value count]];
        for (id item in (NSArray *)value) {
            [arr addObject:MCPPlistValueToJSONSafe(item)];
        }
        return arr;
    }
    if ([value isKindOfClass:[NSDictionary class]]) {
        NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithCapacity:[(NSDictionary *)value count]];
        for (id k in (NSDictionary *)value) {
            if (![k isKindOfClass:[NSString class]]) return nil;
            id converted = MCPPlistValueToJSONSafe([(NSDictionary *)value objectForKey:k]);
            if (!converted) return nil;
            dict[k] = converted;
        }
        return dict;
    }
    return nil;
}

static id MCPJSONValueToPlistValue(id value, NSString **error) {
    if (!value || value == [NSNull null]) {
        if (error) *error = @"null is not a property-list value";
        return nil;
    }
    if ([value isKindOfClass:[NSString class]] || [value isKindOfClass:[NSNumber class]] ||
        [value isKindOfClass:[NSData class]] || [value isKindOfClass:[NSDate class]]) {
        return value;
    }
    if ([value isKindOfClass:[NSDictionary class]]) {
        NSDictionary *dict = (NSDictionary *)value;
        if ([dict[@"_plist_type"] isEqual:@"data"] && [dict[@"base64"] isKindOfClass:[NSString class]]) {
            NSData *decoded = [[NSData alloc] initWithBase64EncodedString:dict[@"base64"] options:0];
            if (!decoded) {
                if (error) *error = @"invalid base64 in _plist_type=data";
                return nil;
            }
            return decoded;
        }
        if ([dict[@"_plist_type"] isEqual:@"date"] && [dict[@"iso8601"] isKindOfClass:[NSString class]]) {
            NSISO8601DateFormatter *fmt = [[NSISO8601DateFormatter alloc] init];
            NSDate *date = [fmt dateFromString:dict[@"iso8601"]];
            if (!date) {
                if (error) *error = @"invalid iso8601 in _plist_type=date";
                return nil;
            }
            return date;
        }
        NSMutableDictionary *out = [NSMutableDictionary dictionaryWithCapacity:dict.count];
        for (id k in dict) {
            if (![k isKindOfClass:[NSString class]]) {
                if (error) *error = @"dictionary keys must be strings";
                return nil;
            }
            id converted = MCPJSONValueToPlistValue(dict[k], error);
            if (!converted) return nil;
            out[k] = converted;
        }
        return out;
    }
    if ([value isKindOfClass:[NSArray class]]) {
        NSArray *arr = (NSArray *)value;
        NSMutableArray *out = [NSMutableArray arrayWithCapacity:arr.count];
        for (id item in arr) {
            id converted = MCPJSONValueToPlistValue(item, error);
            if (!converted) return nil;
            [out addObject:converted];
        }
        return out;
    }
    if (error) *error = @"unsupported property-list value type";
    return nil;
}

static BOOL MCPParseArrayIndex(NSString *segment, NSUInteger *outIndex) {
    if (!segment.length) return NO;
    const char *s = segment.UTF8String;
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '9') return NO;
    }
    char *end = NULL;
    unsigned long long parsed = strtoull(s, &end, 10);
    if (!end || *end != '\0' || parsed > NSUIntegerMax) return NO;
    if (outIndex) *outIndex = (NSUInteger)parsed;
    return YES;
}

@implementation PlistPatchManager

+ (instancetype)sharedInstance {
    static PlistPatchManager *instance;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ instance = [self new]; });
    return instance;
}

- (NSDictionary *)performAtPath:(NSString *)path keypath:(NSString *)keypath value:(id)value write:(BOOL)write error:(NSString **)error {
    if (error) *error = nil;
    if (![path isKindOfClass:[NSString class]] || ![path hasPrefix:@"/"]) {
        if (error) *error = @"path must be absolute";
        return nil;
    }
    NSArray<NSString *> *keys = [keypath componentsSeparatedByString:@"."];
    if (![keypath isKindOfClass:[NSString class]] || !keypath.length || [keys containsObject:@""]) {
        if (error) *error = @"keypath must contain nonempty dot-separated keys";
        return nil;
    }

    NSString *resolvedPath = path;
#if defined(MCP_ROOTHIDE) || defined(MCP_ROOTLESS)
    NSString *candidate = MCPResolvedJailbreakPath(path);
    if (candidate.length) resolvedPath = candidate;
#endif

    struct stat st;
    BOOL hadStat = (stat(resolvedPath.fileSystemRepresentation, &st) == 0);

    NSError *e = nil;
    NSData *data = [NSData dataWithContentsOfFile:resolvedPath options:0 error:&e];
#if defined(MCP_ROOTHIDE) || defined(MCP_ROOTLESS)
    if (!data) {
        NSData *rootData = nil;
        BOOL truncated = NO;
        int exitCode = -1;
        NSString *rootErr = nil;
        if (MCPRunRootProcessData(@"/usr/libexec/ios-mcp/mcp-appmod",
                                  @[@"read-plist", resolvedPath],
                                  15.0,
                                  16 * 1024 * 1024,
                                  &rootData,
                                  &truncated,
                                  &exitCode,
                                  &rootErr) && exitCode == 0 && rootData.length > 0 && !truncated) {
            data = rootData;
            e = nil;
        }
    }
#endif
    if (!data) {
        if (error) *error = e.localizedDescription ?: @"cannot read plist file";
        return nil;
    }

    NSPropertyListFormat format = NSPropertyListXMLFormat_v1_0;
    id root = [NSPropertyListSerialization propertyListWithData:data
                                                        options:NSPropertyListMutableContainersAndLeaves
                                                         format:&format
                                                          error:&e];
    if (!root) {
        if (error) *error = e.localizedDescription ?: @"invalid property list";
        return nil;
    }

    id parent = root;
    for (NSUInteger i = 0; i + 1 < keys.count; i++) {
        NSString *seg = keys[i];
        if ([parent isKindOfClass:[NSDictionary class]]) {
            id next = [(NSDictionary *)parent objectForKey:seg];
            if (!next) {
                if (write && [parent isKindOfClass:[NSMutableDictionary class]]) {
                    NSMutableDictionary *created = [NSMutableDictionary dictionary];
                    [(NSMutableDictionary *)parent setObject:created forKey:seg];
                    next = created;
                } else {
                    if (error) *error = @"keypath not found";
                    return nil;
                }
            }
            parent = next;
        } else if ([parent isKindOfClass:[NSArray class]]) {
            NSUInteger idx = 0;
            if (!MCPParseArrayIndex(seg, &idx) || idx >= [(NSArray *)parent count]) {
                if (error) *error = @"array index out of range in keypath";
                return nil;
            }
            parent = [(NSArray *)parent objectAtIndex:idx];
        } else {
            if (error) *error = @"keypath traverses a non-container";
            return nil;
        }
    }

    NSString *lastKey = keys.lastObject;
    NSString *formatName = (format == NSPropertyListBinaryFormat_v1_0) ? @"binary" : @"xml";

    if (write) {
        NSString *convErr = nil;
        id plistValue = MCPJSONValueToPlistValue(value, &convErr);
        if (!plistValue) {
            if (error) *error = convErr ?: @"invalid property-list value";
            return nil;
        }
        if ([parent isKindOfClass:[NSMutableDictionary class]]) {
            [(NSMutableDictionary *)parent setObject:plistValue forKey:lastKey];
        } else if ([parent isKindOfClass:[NSMutableArray class]]) {
            NSUInteger idx = 0;
            if (!MCPParseArrayIndex(lastKey, &idx) || idx > [(NSMutableArray *)parent count]) {
                if (error) *error = @"array index out of range for write";
                return nil;
            }
            if (idx == [(NSMutableArray *)parent count]) {
                [(NSMutableArray *)parent addObject:plistValue];
            } else {
                [(NSMutableArray *)parent replaceObjectAtIndex:idx withObject:plistValue];
            }
        } else {
            if (error) *error = @"keypath parent is not a mutable dictionary or array";
            return nil;
        }

        NSData *output = [NSPropertyListSerialization dataWithPropertyList:root format:format options:0 error:&e];
        if (!output) {
            if (error) *error = e.localizedDescription ?: @"property-list serialization failed";
            return nil;
        }

        BOOL wroteDirect = [output writeToFile:resolvedPath options:NSDataWritingAtomic error:&e];
        if (wroteDirect && hadStat) {
            chmod(resolvedPath.fileSystemRepresentation, st.st_mode & 07777);
        }
#if defined(MCP_ROOTHIDE) || defined(MCP_ROOTLESS)
        if (!wroteDirect) {
            NSString *cacheDir = @"/var/mobile/Library/Caches/ios-mcp-work";
            [[NSFileManager defaultManager] createDirectoryAtPath:cacheDir withIntermediateDirectories:YES attributes:nil error:nil];
            NSString *tmpPath = [cacheDir stringByAppendingPathComponent:
                                 [NSString stringWithFormat:@"mcp-plist-%@.plist", [NSUUID UUID].UUIDString]];
            if ([output writeToFile:tmpPath options:NSDataWritingAtomic error:nil]) {
                NSString *outStr = nil;
                NSString *rootErr = nil;
                int exitCode = -1;
                BOOL ok = MCPRunRootProcess(@"/usr/libexec/ios-mcp/mcp-appmod",
                                            @[@"write-plist", resolvedPath, tmpPath],
                                            15.0,
                                            64 * 1024,
                                            &outStr,
                                            &exitCode,
                                            &rootErr);
                [[NSFileManager defaultManager] removeItemAtPath:tmpPath error:nil];
                if (ok && exitCode == 0) {
                    wroteDirect = YES;
                } else if (outStr.length > 0) {
                    if (error) *error = outStr;
                    return nil;
                }
            }
        }
#endif
        if (!wroteDirect) {
            if (error) *error = e.localizedDescription ?: @"write failed";
            return nil;
        }
        return @{
            @"path": path,
            @"resolved_path": resolvedPath,
            @"keypath": keypath,
            @"format": formatName,
            @"written": @YES
        };
    }

    id result = nil;
    if ([parent isKindOfClass:[NSDictionary class]]) {
        result = [(NSDictionary *)parent objectForKey:lastKey];
    } else if ([parent isKindOfClass:[NSArray class]]) {
        NSUInteger idx = 0;
        if (!MCPParseArrayIndex(lastKey, &idx) || idx >= [(NSArray *)parent count]) {
            if (error) *error = @"keypath not found";
            return nil;
        }
        result = [(NSArray *)parent objectAtIndex:idx];
    } else {
        if (error) *error = @"keypath parent is not a dictionary or array";
        return nil;
    }

    if (!result) {
        if (error) *error = @"keypath not found";
        return nil;
    }

    id jsonSafe = MCPPlistValueToJSONSafe(result);
    if (!jsonSafe || ![NSJSONSerialization isValidJSONObject:@[jsonSafe]]) {
        if (error) *error = @"property-list value is not JSON representable";
        return nil;
    }
    NSString *valueType = NSStringFromClass([result class]) ?: @"unknown";
    if ([result isKindOfClass:[NSNumber class]]) {
        if (CFGetTypeID((__bridge CFTypeRef)result) == CFBooleanGetTypeID()) valueType = @"boolean";
        else valueType = @"number";
    } else if ([result isKindOfClass:[NSString class]]) valueType = @"string";
    else if ([result isKindOfClass:[NSDictionary class]]) valueType = @"dictionary";
    else if ([result isKindOfClass:[NSArray class]]) valueType = @"array";
    else if ([result isKindOfClass:[NSData class]]) valueType = @"data";
    else if ([result isKindOfClass:[NSDate class]]) valueType = @"date";

    return @{
        @"path": path,
        @"resolved_path": resolvedPath,
        @"keypath": keypath,
        @"format": formatName,
        @"type": valueType,
        @"value": jsonSafe
    };
}

- (NSDictionary *)valueAtPath:(NSString *)path keypath:(NSString *)keypath error:(NSString **)error {
    return [self performAtPath:path keypath:keypath value:nil write:NO error:error];
}

- (NSDictionary *)setValue:(id)value atPath:(NSString *)path keypath:(NSString *)keypath error:(NSString **)error {
    return [self performAtPath:path keypath:keypath value:value write:YES error:error];
}

@end
