#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <stdio.h>
#import <string.h>

static NSString *MCPSecErrorDescription(OSStatus status) {
    CFStringRef msg = SecCopyErrorMessageString(status, NULL);
    NSString *desc = msg ? CFBridgingRelease(msg) : nil;
    if (desc.length) {
        return [NSString stringWithFormat:@"%@ (OSStatus %d)", desc, (int)status];
    }
    return [NSString stringWithFormat:@"OSStatus %d", (int)status];
}

static CFTypeRef MCPKeychainClassFromString(NSString *cls) {
    if ([cls isEqualToString:@"internet_password"]) return kSecClassInternetPassword;
    return kSecClassGenericPassword;
}

static CFTypeRef MCPAccessibleFromString(NSString *acc) {
    if ([acc isEqualToString:@"always"]) return kSecAttrAccessibleAlwaysThisDeviceOnly;
    if ([acc isEqualToString:@"when_unlocked"]) return kSecAttrAccessibleWhenUnlockedThisDeviceOnly;
    return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        NSDictionary *req = nil;
        if (argc == 3 && strcmp(argv[1], "--req") == 0) {
            NSString *reqPath = [NSString stringWithUTF8String:argv[2]];
            NSData *raw = reqPath ? [NSData dataWithContentsOfFile:reqPath] : nil;
            if (raw) req = [NSJSONSerialization JSONObjectWithData:raw options:0 error:NULL];
        } else if (argc == 3 && strcmp(argv[1], "--b64") == 0) {
            NSString *b64 = [NSString stringWithUTF8String:argv[2]];
            NSData *raw = b64 ? [[NSData alloc] initWithBase64EncodedString:b64 options:0] : nil;
            if (raw) req = [NSJSONSerialization JSONObjectWithData:raw options:0 error:NULL];
        }

        if (![req isKindOfClass:[NSDictionary class]]) {
            const char *err = "{\"ok\":false,\"status\":-50,\"error\":\"invalid keychain helper request\"}\n";
            fputs(err, stdout);
            return 1;
        }

        NSString *op = [req[@"op"] isKindOfClass:[NSString class]] ? req[@"op"] : @"";
        NSString *service = [req[@"service"] isKindOfClass:[NSString class]] ? req[@"service"] : @"";
        NSString *account = [req[@"account"] isKindOfClass:[NSString class]] ? req[@"account"] : @"";
        NSString *accessGroup = [req[@"access_group"] isKindOfClass:[NSString class]] ? req[@"access_group"] : @"";
        NSString *itemClass = [req[@"item_class"] isKindOfClass:[NSString class]] ? req[@"item_class"] : @"generic_password";
        NSString *accessible = [req[@"accessible"] isKindOfClass:[NSString class]] ? req[@"accessible"] : @"after_first_unlock";

        if (!service.length || !account.length) {
            const char *err = "{\"ok\":false,\"status\":-50,\"error\":\"service and account are required\"}\n";
            fputs(err, stdout);
            return 1;
        }

        NSMutableDictionary *baseQuery = [NSMutableDictionary dictionary];
        baseQuery[(__bridge id)kSecClass] = (__bridge id)MCPKeychainClassFromString(itemClass);
        if (MCPKeychainClassFromString(itemClass) == kSecClassInternetPassword) {
            baseQuery[(__bridge id)kSecAttrServer] = service;
        } else {
            baseQuery[(__bridge id)kSecAttrService] = service;
        }
        baseQuery[(__bridge id)kSecAttrAccount] = account;
        if (accessGroup.length > 0) {
            baseQuery[(__bridge id)kSecAttrAccessGroup] = accessGroup;
        }

        NSDictionary *response = nil;
        OSStatus status = errSecParam;

        if ([op isEqualToString:@"get"]) {
            NSMutableDictionary *query = [baseQuery mutableCopy];
            query[(__bridge id)kSecReturnData] = @YES;
            query[(__bridge id)kSecReturnAttributes] = @YES;
            query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;

            CFTypeRef itemRef = NULL;
            status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &itemRef);
            if (status == errSecSuccess && itemRef != NULL) {
                NSDictionary *attrs = CFBridgingRelease(itemRef);
                NSData *valData = [attrs[(__bridge id)kSecValueData] isKindOfClass:[NSData class]]
                    ? attrs[(__bridge id)kSecValueData]
                    : [NSData data];
                NSString *utf8Val = [[NSString alloc] initWithData:valData encoding:NSUTF8StringEncoding];
                NSString *actualGroup = [attrs[(__bridge id)kSecAttrAccessGroup] isKindOfClass:[NSString class]]
                    ? attrs[(__bridge id)kSecAttrAccessGroup]
                    : accessGroup;

                NSMutableDictionary *res = [@{
                    @"service": service,
                    @"account": account,
                    @"access_group": actualGroup ?: @"",
                    @"data_base64": [valData base64EncodedStringWithOptions:0] ?: @"",
                    @"length": @(valData.length)
                } mutableCopy];
                if (utf8Val != nil) {
                    res[@"value"] = utf8Val;
                    res[@"encoding"] = @"utf8";
                } else {
                    res[@"encoding"] = @"base64";
                }
                response = @{@"ok": @YES, @"status": @(status), @"result": res};
            } else {
                response = @{
                    @"ok": @NO,
                    @"status": @(status),
                    @"error": MCPSecErrorDescription(status)
                };
            }
        } else if ([op isEqualToString:@"set"]) {
            NSString *dataB64 = [req[@"data_base64"] isKindOfClass:[NSString class]] ? req[@"data_base64"] : nil;
            NSData *valueData = dataB64 ? [[NSData alloc] initWithBase64EncodedString:dataB64 options:0] : nil;
            if (!valueData) {
                response = @{@"ok": @NO, @"status": @(errSecParam), @"error": @"invalid data_base64"};
            } else {
                NSMutableDictionary *addDict = [baseQuery mutableCopy];
                addDict[(__bridge id)kSecValueData] = valueData;
                addDict[(__bridge id)kSecAttrAccessible] = (__bridge id)MCPAccessibleFromString(accessible);

                status = SecItemAdd((__bridge CFDictionaryRef)addDict, NULL);
                NSString *writeAction = @"added";
                if (status == errSecDuplicateItem) {
                    NSDictionary *updates = @{
                        (__bridge id)kSecValueData: valueData,
                        (__bridge id)kSecAttrAccessible: (__bridge id)MCPAccessibleFromString(accessible)
                    };
                    status = SecItemUpdate((__bridge CFDictionaryRef)baseQuery, (__bridge CFDictionaryRef)updates);
                    writeAction = @"updated";
                }

                if (status == errSecSuccess) {
                    response = @{
                        @"ok": @YES,
                        @"status": @(status),
                        @"result": @{
                            @"service": service,
                            @"account": account,
                            @"access_group": accessGroup ?: @"",
                            @"action": writeAction,
                            @"bytes": @(valueData.length)
                        }
                    };
                } else {
                    response = @{
                        @"ok": @NO,
                        @"status": @(status),
                        @"error": MCPSecErrorDescription(status)
                    };
                }
            }
        } else if ([op isEqualToString:@"delete"]) {
            status = SecItemDelete((__bridge CFDictionaryRef)baseQuery);
            if (status == errSecSuccess || status == errSecItemNotFound) {
                response = @{
                    @"ok": @YES,
                    @"status": @(status),
                    @"result": @{
                        @"service": service,
                        @"account": account,
                        @"access_group": accessGroup ?: @"",
                        @"deleted": @(status == errSecSuccess)
                    }
                };
            } else {
                response = @{
                    @"ok": @NO,
                    @"status": @(status),
                    @"error": MCPSecErrorDescription(status)
                };
            }
        } else {
            response = @{@"ok": @NO, @"status": @(errSecParam), @"error": @"unsupported keychain op"};
        }

        NSData *outJSON = [NSJSONSerialization dataWithJSONObject:response options:0 error:NULL];
        if (!outJSON) return 2;
        fwrite(outJSON.bytes, 1, outJSON.length, stdout);
        fputc('\n', stdout);
        return [response[@"ok"] boolValue] ? 0 : 1;
    }
}
