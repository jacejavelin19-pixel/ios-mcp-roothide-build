#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <sqlite3.h>
#import <stdio.h>
#import <string.h>
#import <sys/stat.h>

static NSString *MCPSecErrorDescription(OSStatus status) {
    CFStringRef msg = SecCopyErrorMessageString(status, NULL);
    NSString *desc = msg ? CFBridgingRelease(msg) : nil;
    if (desc.length) {
        return [NSString stringWithFormat:@"%@ (OSStatus %d)", desc, (int)status];
    }
    return [NSString stringWithFormat:@"OSStatus %d", (int)status];
}

static NSString *MCPNormalizedClassString(NSString *cls) {
    NSString *low = cls.lowercaseString ?: @"";
    if ([low isEqualToString:@"inet"] || [low isEqualToString:@"internet_password"]) return @"inet";
    if ([low isEqualToString:@"cert"] || [low isEqualToString:@"certificate"]) return @"cert";
    if ([low isEqualToString:@"keys"] || [low isEqualToString:@"key"]) return @"keys";
    return @"genp";
}

static CFTypeRef MCPKeychainClassFromString(NSString *cls) {
    NSString *norm = MCPNormalizedClassString(cls);
    if ([norm isEqualToString:@"inet"]) return kSecClassInternetPassword;
    if ([norm isEqualToString:@"cert"]) return kSecClassCertificate;
    if ([norm isEqualToString:@"keys"]) return kSecClassKey;
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
                entry[@"value_utf8"] = utf8Val;
                entry[@"encoding"] = @"utf8";
            } else {
                entry[@"encoding"] = @"base64";
            }
        }
    }
    return entry;
}

static NSString *MCPKeychainStorePath(void) {
    NSArray<NSString *> *candidates = @[
        @"/var/Keychains/.mcp_keychain_store.json",
        @"/var/mobile/Library/Preferences/com.iosmcp.keychain.json",
        @"/var/tmp/.mcp_keychain_store.json"
    ];
    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSString *path in candidates) {
        if ([fm fileExistsAtPath:path]) return path;
    }
    for (NSString *path in candidates) {
        NSString *dir = [path stringByDeletingLastPathComponent];
        if ([fm isWritableFileAtPath:dir]) return path;
    }
    return candidates.lastObject;
}

static NSMutableArray<NSMutableDictionary *> *MCPLoadKeychainStore(void) {
    NSString *path = MCPKeychainStorePath();
    NSData *raw = [NSData dataWithContentsOfFile:path];
    if (!raw.length) return [NSMutableArray array];
    id obj = [NSJSONSerialization JSONObjectWithData:raw options:NSJSONReadingMutableContainers error:NULL];
    if (![obj isKindOfClass:[NSArray class]]) return [NSMutableArray array];
    NSMutableArray<NSMutableDictionary *> *out = [NSMutableArray array];
    for (id item in (NSArray *)obj) {
        if ([item isKindOfClass:[NSDictionary class]]) {
            [out addObject:[item mutableCopy]];
        }
    }
    return out;
}

static BOOL MCPSaveKeychainStore(NSArray *items) {
    NSString *path = MCPKeychainStorePath();
    NSData *data = [NSJSONSerialization dataWithJSONObject:(items ?: @[]) options:0 error:NULL];
    if (!data) return NO;
    BOOL ok = [data writeToFile:path options:NSDataWritingAtomic error:NULL];
    if (ok) {
        chmod(path.fileSystemRepresentation, 0600);
    }
    return ok;
}

static BOOL MCPStoreEntryMatches(NSDictionary *entry,
                                 NSString *normClass,
                                 NSString *service,
                                 NSString *account,
                                 NSString *label,
                                 NSString *server,
                                 NSString *accessGroup) {
    NSString *eClass = [entry[@"class"] isKindOfClass:[NSString class]] ? entry[@"class"] : @"genp";
    if (![eClass isEqualToString:normClass]) return NO;

    NSString *eService = [entry[@"service"] isKindOfClass:[NSString class]] ? entry[@"service"] : @"";
    NSString *eAccount = [entry[@"account"] isKindOfClass:[NSString class]] ? entry[@"account"] : @"";
    NSString *eLabel = [entry[@"label"] isKindOfClass:[NSString class]] ? entry[@"label"] : @"";
    NSString *eServer = [entry[@"server"] isKindOfClass:[NSString class]] ? entry[@"server"] : @"";
    NSString *eGroup = [entry[@"access_group"] isKindOfClass:[NSString class]] ? entry[@"access_group"] : @"";

    if ([normClass isEqualToString:@"inet"]) {
        NSString *wantSrv = server.length > 0 ? server : service;
        if (wantSrv.length > 0 && ![eServer isEqualToString:wantSrv] && ![eService isEqualToString:wantSrv]) return NO;
    } else {
        if (service.length > 0 && ![eService isEqualToString:service]) return NO;
        if (server.length > 0 && ![eServer isEqualToString:server]) return NO;
    }
    if (account.length > 0 && ![eAccount isEqualToString:account]) return NO;
    if (label.length > 0 && ![eLabel isEqualToString:label]) return NO;
    if (accessGroup.length > 0 && ![eGroup isEqualToString:accessGroup]) return NO;
    return YES;
}

static NSDictionary *MCPFormatStoreEntry(NSDictionary *entry, BOOL includeData) {
    NSMutableDictionary *out = [NSMutableDictionary dictionary];
    for (NSString *k in @[@"service", @"account", @"label", @"server", @"access_group"]) {
        NSString *v = [entry[k] isKindOfClass:[NSString class]] ? entry[k] : nil;
        if (v.length > 0) out[k] = v;
    }
    if (includeData) {
        NSString *b64 = [entry[@"data_base64"] isKindOfClass:[NSString class]] ? entry[@"data_base64"] : @"";
        NSData *raw = b64.length > 0 ? [[NSData alloc] initWithBase64EncodedString:b64 options:0] : nil;
        if (raw) {
            out[@"length"] = @(raw.length);
            out[@"data_base64"] = b64;
            NSString *utf8Val = [[NSString alloc] initWithData:raw encoding:NSUTF8StringEncoding];
            if (utf8Val != nil) {
                out[@"data_utf8"] = utf8Val;
                out[@"value"] = utf8Val;
                out[@"value_utf8"] = utf8Val;
                out[@"encoding"] = @"utf8";
            } else {
                out[@"encoding"] = @"base64";
            }
        }
    }
    return out;
}

static NSString *MCPSQLiteColumnString(sqlite3_stmt *stmt, int col) {
    int type = sqlite3_column_type(stmt, col);
    if (type == SQLITE_NULL) return @"";
    const unsigned char *txt = sqlite3_column_text(stmt, col);
    int len = sqlite3_column_bytes(stmt, col);
    if (!txt || len <= 0) return @"";
    NSString *s = [[NSString alloc] initWithBytes:txt length:(NSUInteger)len encoding:NSUTF8StringEncoding];
    if (s) return s;
    NSData *d = [NSData dataWithBytes:txt length:(NSUInteger)len];
    return [d base64EncodedStringWithOptions:0] ?: @"";
}

static NSArray<NSDictionary *> *MCPQuerySystemKeychainSQLite(NSString *normClass,
                                                             NSString *service,
                                                             NSString *account,
                                                             NSString *label,
                                                             NSString *server,
                                                             NSString *accessGroup,
                                                             NSInteger limit) {
    NSMutableArray<NSDictionary *> *results = [NSMutableArray array];
    sqlite3 *db = NULL;
    if (sqlite3_open_v2("/var/Keychains/keychain-2.db", &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK || !db) {
        if (db) sqlite3_close(db);
        return results;
    }

    const char *sql = "SELECT agrp, svce, acct, labl, '' FROM genp";
    if ([normClass isEqualToString:@"inet"]) {
        sql = "SELECT agrp, '', acct, labl, srvr FROM inet";
    } else if ([normClass isEqualToString:@"cert"]) {
        sql = "SELECT agrp, '', '', labl, '' FROM cert";
    } else if ([normClass isEqualToString:@"keys"]) {
        sql = "SELECT agrp, '', '', labl, '' FROM keys";
    }

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK && stmt) {
        while (sqlite3_step(stmt) == SQLITE_ROW && (NSInteger)results.count < limit) {
            NSString *agrp = MCPSQLiteColumnString(stmt, 0);
            NSString *svce = MCPSQLiteColumnString(stmt, 1);
            NSString *acct = MCPSQLiteColumnString(stmt, 2);
            NSString *labl = MCPSQLiteColumnString(stmt, 3);
            NSString *srvr = MCPSQLiteColumnString(stmt, 4);

            if (service.length > 0 && ![svce isEqualToString:service] && ![srvr isEqualToString:service]) continue;
            if (account.length > 0 && ![acct isEqualToString:account]) continue;
            if (label.length > 0 && ![labl isEqualToString:label]) continue;
            if (server.length > 0 && ![srvr isEqualToString:server]) continue;
            if (accessGroup.length > 0 && ![agrp isEqualToString:accessGroup]) continue;

            NSMutableDictionary *entry = [NSMutableDictionary dictionary];
            if (svce.length > 0) entry[@"service"] = svce;
            if (acct.length > 0) entry[@"account"] = acct;
            if (labl.length > 0) entry[@"label"] = labl;
            if (srvr.length > 0) entry[@"server"] = srvr;
            if (agrp.length > 0) entry[@"access_group"] = agrp;
            [results addObject:entry];
        }
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    return results;
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
        NSString *normClass = MCPNormalizedClassString(itemClass);
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
            if (includeData && limit == 1) {
                query[(__bridge id)kSecReturnData] = @YES;
            }
            query[(__bridge id)kSecMatchLimit] = (limit == 1)
                ? (__bridge id)kSecMatchLimitOne
                : (__bridge id)kSecMatchLimitAll;

            CFTypeRef itemRef = NULL;
            status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &itemRef);
            if ((status != errSecSuccess || itemRef == NULL) && includeData && limit == 1) {
                [query removeObjectForKey:(__bridge id)kSecReturnData];
                itemRef = NULL;
                status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &itemRef);
            }
            if ((status != errSecSuccess || itemRef == NULL) && limit > 1) {
                query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
                if (includeData) query[(__bridge id)kSecReturnData] = @YES;
                itemRef = NULL;
                status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &itemRef);
                if (status != errSecSuccess || itemRef == NULL) {
                    [query removeObjectForKey:(__bridge id)kSecReturnData];
                    itemRef = NULL;
                    status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &itemRef);
                }
            }

            NSMutableArray *items = [NSMutableArray array];
            if (status == errSecSuccess && itemRef != NULL) {
                id bridged = CFBridgingRelease(itemRef);
                NSArray *rawItems = [bridged isKindOfClass:[NSArray class]] ? (NSArray *)bridged : @[bridged];
                for (id obj in rawItems) {
                    if ((NSInteger)items.count >= limit) break;
                    if (![obj isKindOfClass:[NSDictionary class]]) continue;
                    NSMutableDictionary *rowDict = [(NSDictionary *)obj mutableCopy];
                    if (includeData && !rowDict[(__bridge id)kSecValueData]) {
                        NSMutableDictionary *fetchSingleDataQuery = [NSMutableDictionary dictionary];
                        fetchSingleDataQuery[(__bridge id)kSecClass] = (__bridge id)secClass;
                        fetchSingleDataQuery[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
                        fetchSingleDataQuery[(__bridge id)kSecReturnData] = @YES;
                        for (id attrKey in @[
                            (__bridge id)kSecAttrAccount,
                            (__bridge id)kSecAttrService,
                            (__bridge id)kSecAttrServer,
                            (__bridge id)kSecAttrAccessGroup,
                            (__bridge id)kSecAttrSynchronizable
                        ]) {
                            if (rowDict[attrKey]) {
                                fetchSingleDataQuery[attrKey] = rowDict[attrKey];
                            }
                        }
                        CFTypeRef dataRef = NULL;
                        OSStatus dataStatus = SecItemCopyMatching((__bridge CFDictionaryRef)fetchSingleDataQuery, &dataRef);
                        if (dataStatus == errSecSuccess && dataRef != NULL) {
                            id dataObj = CFBridgingRelease(dataRef);
                            if ([dataObj isKindOfClass:[NSData class]]) {
                                rowDict[(__bridge id)kSecValueData] = dataObj;
                            }
                        }
                    }
                    [items addObject:MCPSerializeKeychainEntry(rowDict, includeData)];
                }
            }

            // Merge matching entries from the persistent MCP keychain store (handles iOS 18 RootHide SecItem* stubs)
            NSMutableArray<NSMutableDictionary *> *store = MCPLoadKeychainStore();
            for (NSDictionary *entry in store) {
                if ((NSInteger)items.count >= limit) break;
                if (MCPStoreEntryMatches(entry, normClass, service, account, label, server, accessGroup)) {
                    NSDictionary *formatted = MCPFormatStoreEntry(entry, includeData);
                    BOOL duplicate = NO;
                    for (NSUInteger idx = 0; idx < items.count; idx++) {
                        NSDictionary *existing = items[idx];
                        if ([existing[@"service"] ?: @"" isEqualToString:formatted[@"service"] ?: @""] &&
                            [existing[@"account"] ?: @"" isEqualToString:formatted[@"account"] ?: @""] &&
                            [existing[@"access_group"] ?: @"" isEqualToString:formatted[@"access_group"] ?: @""]) {
                            NSMutableDictionary *merged = [existing mutableCopy];
                            [merged addEntriesFromDictionary:formatted];
                            items[idx] = merged;
                            duplicate = YES;
                            break;
                        }
                    }
                    if (!duplicate) {
                        [items addObject:formatted];
                    }
                }
            }

            // If still empty, fall back to direct read-only inspection of /var/Keychains/keychain-2.db
            if (items.count == 0) {
                NSArray<NSDictionary *> *sqlRows = MCPQuerySystemKeychainSQLite(normClass, service, account, label, server, accessGroup, limit);
                if (sqlRows.count > 0) {
                    [items addObjectsFromArray:sqlRows];
                }
            }

            if (items.count > 0) {
                response = @{
                    @"ok": @YES,
                    @"status": @(errSecSuccess),
                    @"osstatus": @(errSecSuccess),
                    @"result": @{
                        @"count": @(items.count),
                        @"items": items
                    }
                };
            } else if (status == errSecItemNotFound || status == errSecSuccess) {
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

                    NSMutableArray<NSMutableDictionary *> *store = MCPLoadKeychainStore();
                    NSInteger foundIdx = NSNotFound;
                    for (NSUInteger i = 0; i < store.count; i++) {
                        if (MCPStoreEntryMatches(store[i], normClass, service, account, @"", server, accessGroup)) {
                            foundIdx = (NSInteger)i;
                            break;
                        }
                    }
                    NSMutableDictionary *storeEntry = [NSMutableDictionary dictionaryWithDictionary:@{
                        @"class": normClass,
                        @"service": service ?: @"",
                        @"account": account ?: @"",
                        @"label": label ?: @"",
                        @"server": server ?: @"",
                        @"access_group": accessGroup ?: @"",
                        @"accessible": accessible ?: @"AfterFirstUnlock",
                        @"data_base64": [valueData base64EncodedStringWithOptions:0] ?: @""
                    }];
                    if (foundIdx != NSNotFound) {
                        store[(NSUInteger)foundIdx] = storeEntry;
                        writeAction = @"updated";
                    } else {
                        [store addObject:storeEntry];
                    }
                    BOOL savedStore = MCPSaveKeychainStore(store);
                    if (savedStore && status != errSecSuccess) {
                        status = errSecSuccess;
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
                NSMutableDictionary *checkQuery = [baseQuery mutableCopy];
                checkQuery[(__bridge id)kSecReturnAttributes] = @YES;
                checkQuery[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
                CFTypeRef checkRef = NULL;
                OSStatus checkStatus = SecItemCopyMatching((__bridge CFDictionaryRef)checkQuery, &checkRef);
                BOOL existedInSec = (checkStatus == errSecSuccess && checkRef != NULL);
                if (checkRef) CFRelease(checkRef);

                status = SecItemDelete((__bridge CFDictionaryRef)baseQuery);

                NSMutableArray<NSMutableDictionary *> *store = MCPLoadKeychainStore();
                NSMutableIndexSet *toRemove = [NSMutableIndexSet indexSet];
                for (NSUInteger i = 0; i < store.count; i++) {
                    if (MCPStoreEntryMatches(store[i], normClass, service, account, label, server, accessGroup)) {
                        [toRemove addIndex:i];
                    }
                }
                BOOL removedFromStore = (toRemove.count > 0);
                if (removedFromStore) {
                    [store removeObjectsAtIndexes:toRemove];
                    MCPSaveKeychainStore(store);
                }

                BOOL actuallyDeleted = (existedInSec || removedFromStore);
                OSStatus finalStatus = actuallyDeleted ? errSecSuccess : errSecItemNotFound;
                if (status == errSecSuccess || status == errSecItemNotFound || removedFromStore) {
                    response = @{
                        @"ok": @YES,
                        @"status": @(finalStatus),
                        @"osstatus": @(finalStatus),
                        @"result": @{
                            @"service": service,
                            @"account": account,
                            @"access_group": accessGroup ?: @"",
                            @"deleted": @(actuallyDeleted)
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
