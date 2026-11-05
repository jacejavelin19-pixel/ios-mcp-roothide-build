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
    NSString *low = cls.lowercaseString ?: @"";
    if ([low isEqualToString:@"inet"] || [low isEqualToString:@"internet_password"]) return kSecClassInternetPassword;
    if ([low isEqualToString:@"cert"] || [low isEqualToString:@"certificate"]) return kSecClassCertificate;
    if ([low isEqualToString:@"keys"] || [low isEqualToString:@"key"]) return kSecClassKey;
    return kSecClassGenericPassword;
}

static CFTypeRef MCPAccessibleFromString(NSString *acc) {
    NSString *low = acc.lowercaseString ?: @"";
    if ([low containsString:@"always"]) return kSecAttrAccessibleAlwaysThisDeviceOnly;
    if ([low containsString:@"whenunlocked"] || [low containsString:@"when_unlocked"]) {
        return kSecAttrAccessibleWhenUnlockedThisDeviceOnly;
    }
    return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
}

static NSDictionary *MCPSerializeKeychainEntry(NSDictionary *attrs, BOOL includeData) {
    NSMutableDictionary *entry = [NSMutableDictionary dictionary];
    NSString *svc = [attrs[(__bridge id)kSecAttrService] isKindOfClass:[NSString class]] ? attrs[(__bridge id)kSecAttrService] : nil;
    NSString *acct = [attrs[(__bridge id)kSecAttrAccount] isKindOfClass:[NSString class]] ? attrs[(__bridge id)kSecAttrAccount] : nil;
    NSString *lbl = [attrs[(__bridge id)kSecAttrLabel] isKindOfClass:[NSString class]] ? attrs[(__bridge id)kSecAttrLabel] : nil;
    NSString *srv = [attrs[(__bridge id)kSecAttrServer] isKindOfClass:[NSString class]] ? attrs[(__bridge id)kSecAttrServer] : nil;
    NSString *grp = [attrs[(__bridge id)kSecAttrAccessGroup] isKindOfClass:[NSString class]] ? attrs[(__bridge id)kSecAttrAccessGroup] : nil;

    if (svc.length) entry[@"service"] = svc;
    if (acct.length) entry[@"account"] = acct;
    if (lbl.length) entry[@"label"] = lbl;
    if (srv.length) entry[@"server"] = srv;
    if (grp.length) entry[@"access_group"] = grp;

    if (includeData) {
        NSData *valData = [attrs[(__bridge id)kSecValueData] isKindOfClass:[NSData class]]
            ? attrs[(__bridge id)kSecValueData]
            : ([attrs isKindOfClass:[NSData class]] ? (NSData *)attrs : nil);
        if (valData) {
            entry[@"length"] = @(valData.length);
            entry[@"data_base64"] = [valData base64EncodedStringWithOptions:0] ?: @"";
            NSString *utf8Val = [[NSString alloc] initWithData:valData encoding:NSUTF8StringEncoding];
            if (utf8Val != nil) {
                entry[@"data_utf8"] = utf8Val;
                entry[@"value"] = utf8Val;
                entry[@"encoding"] = @"utf8";
            } else {
                entry[@"encoding"] = @"base64";
            }
        }
    }
    return entry;
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
            const char *err = "{\"ok\":false,\"status\":-50,\"osstatus\":-50,\"error\":\"invalid keychain helper request\"}\n";
            fputs(err, stdout);
            return 1;
        }

        NSString *op = [req[@"op"] isKindOfClass:[NSString class]] ? req[@"op"]
            : ([req[@"action"] isKindOfClass:[NSString class]] ? req[@"action"] : @"");
        NSString *service = [req[@"service"] isKindOfClass:[NSString class]] ? req[@"service"] : @"";
        NSString *account = [req[@"account"] isKindOfClass:[NSString class]] ? req[@"account"] : @"";
        NSString *label = [req[@"label"] isKindOfClass:[NSString class]] ? req[@"label"] : @"";
        NSString *server = [req[@"server"] isKindOfClass:[NSString class]] ? req[@"server"] : @"";
        NSString *accessGroup = [req[@"access_group"] isKindOfClass:[NSString class]] ? req[@"access_group"] : @"";
        NSString *itemClass = [req[@"class"] isKindOfClass:[NSString class]] ? req[@"class"]
            : ([req[@"item_class"] isKindOfClass:[NSString class]] ? req[@"item_class"] : @"genp");
        NSString *accessible = [req[@"accessible"] isKindOfClass:[NSString class]] ? req[@"accessible"] : @"AfterFirstUnlock";
        BOOL includeData = (req[@"include_data"] == nil) ? YES : [req[@"include_data"] boolValue];
        NSInteger limit = [req[@"limit"] respondsToSelector:@selector(integerValue)] ? [req[@"limit"] integerValue] : 50;
        if (limit < 1) limit = 1;
        if (limit > 200) limit = 200;

        CFTypeRef secClass = MCPKeychainClassFromString(itemClass);
        NSMutableDictionary *baseQuery = [NSMutableDictionary dictionary];
        baseQuery[(__bridge id)kSecClass] = (__bridge id)secClass;
        if (secClass == kSecClassInternetPassword) {
            if (server.length > 0) baseQuery[(__bridge id)kSecAttrServer] = server;
            else if (service.length > 0) baseQuery[(__bridge id)kSecAttrServer] = service;
        } else {
            if (service.length > 0) baseQuery[(__bridge id)kSecAttrService] = service;
        }
        if (account.length > 0) baseQuery[(__bridge id)kSecAttrAccount] = account;
        if (label.length > 0 && ![op isEqualToString:@"set"]) baseQuery[(__bridge id)kSecAttrLabel] = label;
        if (accessGroup.length > 0) baseQuery[(__bridge id)kSecAttrAccessGroup] = accessGroup;

        NSDictionary *response = nil;
        OSStatus status = errSecParam;

        if ([op isEqualToString:@"get"]) {
            NSMutableDictionary *query = [baseQuery mutableCopy];
            query[(__bridge id)kSecReturnAttributes] = @YES;
            if (includeData) query[(__bridge id)kSecReturnData] = @YES;
            query[(__bridge id)kSecMatchLimit] = (limit == 1)
                ? (__bridge id)kSecMatchLimitOne
                : (__bridge id)kSecMatchLimitAll;

            CFTypeRef itemRef = NULL;
            status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &itemRef);
            if (status == errSecSuccess && itemRef != NULL) {
                id bridged = CFBridgingRelease(itemRef);
                NSArray *rawItems = [bridged isKindOfClass:[NSArray class]] ? (NSArray *)bridged : @[bridged];
                NSMutableArray *items = [NSMutableArray array];
                for (id obj in rawItems) {
                    if ((NSInteger)items.count >= limit) break;
                    if ([obj isKindOfClass:[NSDictionary class]]) {
                        [items addObject:MCPSerializeKeychainEntry((NSDictionary *)obj, includeData)];
                    }
                }
                response = @{
                    @"ok": @YES,
                    @"status": @(status),
                    @"osstatus": @(status),
                    @"result": @{
                        @"count": @(items.count),
                        @"items": items
                    }
                };
            } else if (status == errSecItemNotFound || (status == errSecSuccess && itemRef == NULL)) {
                // kSecMatchLimitAll can return errSecSuccess with a NULL result
                // (instead of errSecItemNotFound) when nothing matches; treat
                // both as "no items" rather than falling through to the error path.
                response = @{
                    @"ok": @YES,
                    @"status": @(errSecItemNotFound),
                    @"osstatus": @(errSecItemNotFound),
                    @"result": @{
                        @"count": @0,
                        @"items": @[]
                    }
                };
            } else {
                response = @{
                    @"ok": @NO,
                    @"status": @(status),
                    @"osstatus": @(status),
                    @"error": MCPSecErrorDescription(status)
                };
            }
        } else if ([op isEqualToString:@"set"]) {
            if (!service.length && !account.length && !server.length) {
                response = @{@"ok": @NO, @"status": @(errSecParam), @"osstatus": @(errSecParam), @"error": @"service, server, or account is required"};
            } else {
                NSData *valueData = nil;
                if ([req[@"data_base64"] isKindOfClass:[NSString class]] && [req[@"data_base64"] length] > 0) {
                    valueData = [[NSData alloc] initWithBase64EncodedString:req[@"data_base64"] options:0];
                } else if ([req[@"data"] isKindOfClass:[NSString class]]) {
                    valueData = [(NSString *)req[@"data"] dataUsingEncoding:NSUTF8StringEncoding];
                } else if ([req[@"value"] isKindOfClass:[NSString class]]) {
                    valueData = [(NSString *)req[@"value"] dataUsingEncoding:NSUTF8StringEncoding];
                }
                if (!valueData) {
                    response = @{@"ok": @NO, @"status": @(errSecParam), @"osstatus": @(errSecParam), @"error": @"invalid data or data_base64"};
                } else {
                    NSMutableDictionary *addDict = [baseQuery mutableCopy];
                    if (label.length > 0) addDict[(__bridge id)kSecAttrLabel] = label;
                    addDict[(__bridge id)kSecValueData] = valueData;
                    addDict[(__bridge id)kSecAttrAccessible] = (__bridge id)MCPAccessibleFromString(accessible);

                    status = SecItemAdd((__bridge CFDictionaryRef)addDict, NULL);
                    NSString *writeAction = @"added";
                    if (status == errSecDuplicateItem) {
                        NSMutableDictionary *updates = [@{
                            (__bridge id)kSecValueData: valueData,
                            (__bridge id)kSecAttrAccessible: (__bridge id)MCPAccessibleFromString(accessible)
                        } mutableCopy];
                        if (label.length > 0) updates[(__bridge id)kSecAttrLabel] = label;
                        status = SecItemUpdate((__bridge CFDictionaryRef)baseQuery, (__bridge CFDictionaryRef)updates);
                        writeAction = @"updated";
                    }

                    if (status == errSecSuccess) {
                        response = @{
                            @"ok": @YES,
                            @"status": @(status),
                            @"osstatus": @(status),
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
                            @"osstatus": @(status),
                            @"error": MCPSecErrorDescription(status)
                        };
                    }
                }
            }
        } else if ([op isEqualToString:@"delete"]) {
            if (!service.length && !account.length && !label.length && !server.length && !accessGroup.length) {
                response = @{@"ok": @NO, @"status": @(errSecParam), @"osstatus": @(errSecParam), @"error": @"refusing broad delete without selector"};
            } else {
                status = SecItemDelete((__bridge CFDictionaryRef)baseQuery);
                if (status == errSecSuccess || status == errSecItemNotFound) {
                    response = @{
                        @"ok": @YES,
                        @"status": @(status),
                        @"osstatus": @(status),
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
                        @"osstatus": @(status),
                        @"error": MCPSecErrorDescription(status)
                    };
                }
            }
        } else {
            response = @{@"ok": @NO, @"status": @(errSecParam), @"osstatus": @(errSecParam), @"error": @"unsupported keychain op"};
        }

        NSData *outJSON = [NSJSONSerialization dataWithJSONObject:response options:0 error:NULL];
        if (!outJSON) return 2;
        fwrite(outJSON.bytes, 1, outJSON.length, stdout);
        fputc('\n', stdout);
        return [response[@"ok"] boolValue] ? 0 : 1;
    }
}
