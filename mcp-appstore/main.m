#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#import <sys/stat.h>
#import <dirent.h>
#import <unistd.h>
#import <stdio.h>
#import <string.h>
#import <stdlib.h>

// Typed objc_msgSend wrappers for arm64 / arm64e strict ABI compliance
static id MCPMsgSend0(id target, SEL sel) {
    if (!target || !sel || ![target respondsToSelector:sel]) return nil;
    return ((id (*)(id, SEL))objc_msgSend)(target, sel);
}

static id MCPMsgSend1(id target, SEL sel, id a1) {
    if (!target || !sel || ![target respondsToSelector:sel]) return nil;
    return ((id (*)(id, SEL, id))objc_msgSend)(target, sel, a1);
}

static id MCPMsgSend2(id target, SEL sel, id a1, id a2) {
    if (!target || !sel || ![target respondsToSelector:sel]) return nil;
    return ((id (*)(id, SEL, id, id))objc_msgSend)(target, sel, a1, a2);
}

static void MCPMsgSendVoid0(id target, SEL sel) {
    if (!target || !sel || ![target respondsToSelector:sel]) return;
    ((void (*)(id, SEL))objc_msgSend)(target, sel);
}

static void MCPMsgSendVoid1(id target, SEL sel, id a1) {
    if (!target || !sel || ![target respondsToSelector:sel]) return;
    ((void (*)(id, SEL, id))objc_msgSend)(target, sel, a1);
}

static void MCPMsgSendVoid2(id target, SEL sel, id a1, id a2) {
    if (!target || !sel || ![target respondsToSelector:sel]) return;
    ((void (*)(id, SEL, id, id))objc_msgSend)(target, sel, a1, a2);
}

static void MCPMsgSendVoidBool(id target, SEL sel, BOOL val) {
    if (!target || !sel || ![target respondsToSelector:sel]) return;
    ((void (*)(id, SEL, BOOL))objc_msgSend)(target, sel, val);
}

static BOOL MCPMsgSendBool0(id target, SEL sel) {
    if (!target || !sel || ![target respondsToSelector:sel]) return NO;
    return ((BOOL (*)(id, SEL))objc_msgSend)(target, sel);
}

static BOOL MCPMsgSendBool2(id target, SEL sel, id a1, id a2) {
    if (!target || !sel || ![target respondsToSelector:sel]) return NO;
    return ((BOOL (*)(id, SEL, id, id))objc_msgSend)(target, sel, a1, a2);
}

static double MCPMsgSendDouble0(id target, SEL sel) {
    if (!target || !sel || ![target respondsToSelector:sel]) return 0.0;
    return ((double (*)(id, SEL))objc_msgSend)(target, sel);
}

static int64_t MCPMsgSendInt64(id target, SEL sel) {
    if (!target || !sel || ![target respondsToSelector:sel]) return 0;
    return ((int64_t (*)(id, SEL))objc_msgSend)(target, sel);
}

static void MCPAppStoreLoadPrivateFrameworks(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        const char *frameworks[] = {
            "/System/Library/Frameworks/MobileCoreServices.framework/MobileCoreServices",
            "/System/Library/Frameworks/Accounts.framework/Accounts",
            "/System/Library/PrivateFrameworks/MobileContainerManager.framework/MobileContainerManager",
            "/System/Library/PrivateFrameworks/StoreServices.framework/StoreServices",
            "/System/Library/PrivateFrameworks/AppStoreDaemon.framework/AppStoreDaemon",
            "/System/Library/PrivateFrameworks/AppleMediaServices.framework/AppleMediaServices",
            NULL
        };
        for (int i = 0; frameworks[i] != NULL; i++) {
            dlopen(frameworks[i], RTLD_NOW | RTLD_GLOBAL);
        }
    });
}

// Switch effective UID between root (0) for container filesystem ops and mobile (501) for user XPC daemons
static void MCPRunWithEffectiveUID(uid_t targetUID, dispatch_block_t block) {
    uid_t origEUID = geteuid();
    gid_t origEGID = getegid();
    BOOL switched = NO;
    if (getuid() == 0 && origEUID != targetUID) {
        if (targetUID == 501) {
            setegid(501);
            seteuid(501);
        } else if (targetUID == 0) {
            seteuid(0);
            setegid(0);
        }
        switched = YES;
    }
    if (block) block();
    if (switched) {
        seteuid(origEUID);
        setegid(origEGID);
    }
}

#pragma mark - Synchronous HTTP JSON Helper

static id MCPFetchJSONSynchronously(NSURLRequest *request,
                                    NSHTTPURLResponse **outResponse,
                                    NSTimeInterval timeoutSeconds,
                                    NSString **outError) {
    if (outError) *outError = nil;
    if (outResponse) *outResponse = nil;

    NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    cfg.timeoutIntervalForRequest = MAX(timeoutSeconds, 2.0);
    cfg.timeoutIntervalForResource = MAX(timeoutSeconds, 2.0);
    NSURLSession *session = [NSURLSession sessionWithConfiguration:cfg];

    __block NSData *respData = nil;
    __block NSHTTPURLResponse *httpResp = nil;
    __block NSError *netErr = nil;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);

    NSURLSessionDataTask *task = [session dataTaskWithRequest:request
                                            completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        respData = data;
        if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
            httpResp = (NSHTTPURLResponse *)response;
        }
        netErr = error;
        dispatch_semaphore_signal(sem);
    }];
    [task resume];

    long waited = dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)((timeoutSeconds + 1.0) * NSEC_PER_SEC)));
    [session finishTasksAndInvalidate];

    if (waited != 0) {
        [task cancel];
        if (outError) *outError = [NSString stringWithFormat:@"HTTP request timed out after %.1fs", timeoutSeconds];
        return nil;
    }
    if (outResponse) *outResponse = httpResp;
    if (netErr) {
        if (outError) *outError = netErr.localizedDescription ?: @"HTTP request failed";
        return nil;
    }
    if (!respData || respData.length == 0) {
        if (outError) *outError = @"Empty HTTP response body";
        return nil;
    }

    NSError *jsonErr = nil;
    id parsed = [NSJSONSerialization JSONObjectWithData:respData options:0 error:&jsonErr];
    if (!parsed) {
        // Fallback: try property list (MZFinance / iTunes plist responses)
        parsed = [NSPropertyListSerialization propertyListWithData:respData options:NSPropertyListImmutable format:NULL error:NULL];
    }
    if (!parsed && outError) {
        *outError = jsonErr.localizedDescription ?: @"Failed to parse JSON/plist response";
    }
    return parsed;
}

#pragma mark - Active Store Account Resolution

static NSDictionary *MCPResolveActiveStoreAccount(id *outSSAccountObj) {
    MCPAppStoreLoadPrivateFrameworks();
    if (outSSAccountObj) *outSSAccountObj = nil;

    __block id activeAccount = nil;
    __block NSNumber *dsid = nil;
    __block NSString *accountName = nil;
    __block NSString *storeFront = nil;
    __block NSString *source = @"none";

    void (^probeAccount)(void) = ^{
        Class SSAccountStoreCls = objc_getClass("SSAccountStore");
        if (SSAccountStoreCls) {
            id store = MCPMsgSend0(SSAccountStoreCls, NSSelectorFromString(@"defaultStore"));
            id acct = MCPMsgSend0(store, NSSelectorFromString(@"activeAccount"));
            if (acct) {
                activeAccount = acct;
                id uid = MCPMsgSend0(acct, NSSelectorFromString(@"uniqueIdentifier"));
                if ([uid isKindOfClass:[NSNumber class]]) dsid = uid;
                id name = MCPMsgSend0(acct, NSSelectorFromString(@"accountName"));
                if ([name isKindOfClass:[NSString class]]) accountName = name;
                id sf = MCPMsgSend0(acct, NSSelectorFromString(@"storeFrontIdentifier"));
                if ([sf isKindOfClass:[NSString class]]) storeFront = sf;
                source = @"SSAccountStore";
            }
        }

        if (!dsid || !accountName) {
            Class ACAccountStoreCls = objc_getClass("ACAccountStore");
            if (ACAccountStoreCls) {
                id acStore = MCPMsgSend0(ACAccountStoreCls, NSSelectorFromString(@"defaultStore"));
                if (!acStore) acStore = [[ACAccountStoreCls alloc] init];
                id amsAcct = MCPMsgSend0(acStore, NSSelectorFromString(@"ams_activeiTunesAccount"));
                if (amsAcct) {
                    if (!accountName) {
                        id u = MCPMsgSend0(amsAcct, NSSelectorFromString(@"username"));
                        if ([u isKindOfClass:[NSString class]]) accountName = u;
                    }
                    if (!dsid) {
                        id d = MCPMsgSend0(amsAcct, NSSelectorFromString(@"ams_DSID"));
                        if ([d isKindOfClass:[NSNumber class]]) dsid = d;
                    }
                    if (!storeFront) {
                        id sf = MCPMsgSend0(amsAcct, NSSelectorFromString(@"ams_storefront"));
                        if ([sf isKindOfClass:[NSString class]]) storeFront = sf;
                    }
                    if ([source isEqualToString:@"none"]) source = @"AppleMediaServices";
                }
            }
        }
    };

    // First try in mobile (501) context where itunesstored/amsaccountsd user sessions live
    MCPRunWithEffectiveUID(501, probeAccount);
    if (!activeAccount && !dsid) {
        MCPRunWithEffectiveUID(0, probeAccount);
    }

    if (outSSAccountObj) *outSSAccountObj = activeAccount;

    NSMutableDictionary *info = [NSMutableDictionary dictionary];
    info[@"authenticated"] = @((dsid != nil) || (accountName.length > 0));
    info[@"source"] = source;
    if (dsid) info[@"dsid"] = dsid;
    if (accountName.length) info[@"account_name"] = accountName;
    info[@"storefront"] = storeFront.length ? storeFront : @"143441-1,29";
    return info;
}

#pragma mark - Local Installed App & iTunesMetadata.plist Scanner

static NSDictionary *MCPInspectInstalledAppAndMetadata(NSString *bundleId, uint64_t targetAdamId) {
    MCPAppStoreLoadPrivateFrameworks();
    __block NSMutableDictionary *result = [NSMutableDictionary dictionary];

    MCPRunWithEffectiveUID(0, ^{
        Class LSWorkspaceCls = objc_getClass("LSApplicationWorkspace");
        id workspace = LSWorkspaceCls ? MCPMsgSend0(LSWorkspaceCls, NSSelectorFromString(@"defaultWorkspace")) : nil;
        id matchedProxy = nil;
        NSString *resolvedBundleId = bundleId;

        if (workspace && resolvedBundleId.length > 0) {
            matchedProxy = MCPMsgSend1(workspace, NSSelectorFromString(@"applicationProxyForIdentifier:"), resolvedBundleId);
            if (matchedProxy) {
                id isInstalledVal = MCPMsgSend0(matchedProxy, NSSelectorFromString(@"isInstalled"));
                if (isInstalledVal && [isInstalledVal respondsToSelector:@selector(boolValue)] && ![isInstalledVal boolValue]) {
                    matchedProxy = nil;
                }
            }
        }

        if (!matchedProxy && workspace) {
            NSArray *allApps = MCPMsgSend0(workspace, NSSelectorFromString(@"allInstalledApplications"));
            for (id proxy in allApps) {
                NSString *bid = MCPMsgSend0(proxy, NSSelectorFromString(@"applicationIdentifier"));
                if (resolvedBundleId.length > 0 && [bid isEqualToString:resolvedBundleId]) {
                    matchedProxy = proxy;
                    break;
                }
                if (targetAdamId > 0) {
                    id itemID = MCPMsgSend0(proxy, NSSelectorFromString(@"itemID"));
                    if ([itemID respondsToSelector:@selector(unsignedLongLongValue)] &&
                        [itemID unsignedLongLongValue] == targetAdamId) {
                        matchedProxy = proxy;
                        resolvedBundleId = bid;
                        break;
                    }
                }
            }
        }

        NSString *bundlePath = nil;
        NSString *dataContainerPath = nil;
        if (matchedProxy) {
            result[@"installed"] = @YES;
            if (resolvedBundleId.length) result[@"bundle_id"] = resolvedBundleId;
            id bURL = MCPMsgSend0(matchedProxy, NSSelectorFromString(@"bundleURL"));
            if ([bURL isKindOfClass:[NSURL class]]) {
                bundlePath = [((NSURL *)bURL).path stringByStandardizingPath];
                if (bundlePath.length) result[@"bundle_path"] = bundlePath;
            }
            id dURL = MCPMsgSend0(matchedProxy, NSSelectorFromString(@"dataContainerURL"));
            if ([dURL isKindOfClass:[NSURL class]]) {
                dataContainerPath = [((NSURL *)dURL).path stringByStandardizingPath];
                if (dataContainerPath.length) result[@"data_container_path"] = dataContainerPath;
            }
            id shortVer = MCPMsgSend0(matchedProxy, NSSelectorFromString(@"shortVersionString"));
            if ([shortVer isKindOfClass:[NSString class]]) result[@"installed_version"] = shortVer;
            id bundleVer = MCPMsgSend0(matchedProxy, NSSelectorFromString(@"bundleVersion"));
            if ([bundleVer isKindOfClass:[NSString class]]) result[@"installed_build"] = bundleVer;
            id itemID = MCPMsgSend0(matchedProxy, NSSelectorFromString(@"itemID"));
            if ([itemID respondsToSelector:@selector(unsignedLongLongValue)] && [itemID unsignedLongLongValue] > 0) {
                result[@"adam_id"] = @([itemID unsignedLongLongValue]);
            }
            id extVer = MCPMsgSend0(matchedProxy, NSSelectorFromString(@"externalVersionIdentifier"));
            if ([extVer respondsToSelector:@selector(unsignedLongLongValue)] && [extVer unsignedLongLongValue] > 0) {
                result[@"installed_ext_vrs_id"] = @([extVer unsignedLongLongValue]);
            }
        } else {
            result[@"installed"] = @NO;
        }

        // Check iTunesMetadata.plist in parent bundle container (/var/containers/Bundle/Application/<UUID>/iTunesMetadata.plist)
        NSString *bundleContainerDir = bundlePath.length ? [bundlePath stringByDeletingLastPathComponent] : nil;
        NSString *metadataPath = bundleContainerDir.length ? [bundleContainerDir stringByAppendingPathComponent:@"iTunesMetadata.plist"] : nil;

        if (!metadataPath || ![[NSFileManager defaultManager] fileExistsAtPath:metadataPath]) {
            // Scan /var/containers/Bundle/Application for matching iTunesMetadata.plist
            NSString *appsRoot = @"/var/containers/Bundle/Application";
            NSArray<NSString *> *uuids = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:appsRoot error:nil];
            for (NSString *uuid in uuids) {
                NSString *cand = [[appsRoot stringByAppendingPathComponent:uuid] stringByAppendingPathComponent:@"iTunesMetadata.plist"];
                if (![[NSFileManager defaultManager] fileExistsAtPath:cand]) continue;
                NSDictionary *meta = [NSDictionary dictionaryWithContentsOfFile:cand];
                if (![meta isKindOfClass:[NSDictionary class]]) continue;
                NSString *metaBid = [meta[@"softwareVersionBundleId"] isKindOfClass:[NSString class]] ? meta[@"softwareVersionBundleId"] : nil;
                uint64_t metaAdam = [meta[@"itemId"] respondsToSelector:@selector(unsignedLongLongValue)] ? [meta[@"itemId"] unsignedLongLongValue] : 0;
                if ((resolvedBundleId.length > 0 && [metaBid isEqualToString:resolvedBundleId]) ||
                    (targetAdamId > 0 && metaAdam == targetAdamId)) {
                    metadataPath = cand;
                    break;
                }
            }
        }

        if (metadataPath && [[NSFileManager defaultManager] fileExistsAtPath:metadataPath]) {
            NSDictionary *meta = [NSDictionary dictionaryWithContentsOfFile:metadataPath];
            if ([meta isKindOfClass:[NSDictionary class]]) {
                result[@"itunes_metadata_path"] = metadataPath;
                if ([meta[@"softwareVersionBundleId"] isKindOfClass:[NSString class]] && !result[@"bundle_id"]) {
                    result[@"bundle_id"] = meta[@"softwareVersionBundleId"];
                }
                if ([meta[@"itemId"] respondsToSelector:@selector(unsignedLongLongValue)] && [meta[@"itemId"] unsignedLongLongValue] > 0) {
                    result[@"adam_id"] = @([meta[@"itemId"] unsignedLongLongValue]);
                }
                if ([meta[@"softwareVersionExternalIdentifier"] respondsToSelector:@selector(unsignedLongLongValue)]) {
                    result[@"installed_ext_vrs_id"] = @([meta[@"softwareVersionExternalIdentifier"] unsignedLongLongValue]);
                }
                if ([meta[@"bundleShortVersionString"] isKindOfClass:[NSString class]] && !result[@"installed_version"]) {
                    result[@"installed_version"] = meta[@"bundleShortVersionString"];
                }
                if ([meta[@"softwareVersionExternalIdentifiers"] isKindOfClass:[NSArray class]]) {
                    result[@"metadata_ext_vrs_ids"] = meta[@"softwareVersionExternalIdentifiers"];
                }
                if ([meta[@"appleId"] isKindOfClass:[NSString class]]) {
                    result[@"purchaser_apple_id"] = meta[@"appleId"];
                }
            }
        }
    });

    return result;
}

#pragma mark - Upgrade 37: App Store Search, Lookup & MuffinStore Version History Catalog

static NSDictionary *MCPFormatITunesTrackItem(NSDictionary *item) {
    if (![item isKindOfClass:[NSDictionary class]]) return @{};
    NSMutableDictionary *entry = [NSMutableDictionary dictionary];
    uint64_t trackId = [item[@"trackId"] respondsToSelector:@selector(unsignedLongLongValue)] ? [item[@"trackId"] unsignedLongLongValue] : 0;
    if (trackId > 0) {
        entry[@"adam_id"] = @(trackId);
        entry[@"track_id"] = @(trackId);
    }
    if ([item[@"bundleId"] isKindOfClass:[NSString class]]) entry[@"bundle_id"] = item[@"bundleId"];
    if ([item[@"trackName"] isKindOfClass:[NSString class]]) entry[@"name"] = item[@"trackName"];
    if ([item[@"version"] isKindOfClass:[NSString class]]) entry[@"version"] = item[@"version"];
    if ([item[@"minimumOsVersion"] isKindOfClass:[NSString class]]) entry[@"minimum_os_version"] = item[@"minimumOsVersion"];
    if (item[@"price"] && item[@"price"] != [NSNull null]) entry[@"price"] = item[@"price"];
    if ([item[@"formattedPrice"] isKindOfClass:[NSString class]]) entry[@"formatted_price"] = item[@"formattedPrice"];
    if ([item[@"currency"] isKindOfClass:[NSString class]]) entry[@"currency"] = item[@"currency"];
    if ([item[@"sellerName"] isKindOfClass:[NSString class]]) entry[@"seller_name"] = item[@"sellerName"];
    if ([item[@"artistName"] isKindOfClass:[NSString class]]) entry[@"artist_name"] = item[@"artistName"];
    if ([item[@"currentVersionReleaseDate"] isKindOfClass:[NSString class]]) {
        entry[@"release_date"] = item[@"currentVersionReleaseDate"];
    } else if ([item[@"releaseDate"] isKindOfClass:[NSString class]]) {
        entry[@"release_date"] = item[@"releaseDate"];
    }
    if ([item[@"fileSizeBytes"] isKindOfClass:[NSString class]] || [item[@"fileSizeBytes"] isKindOfClass:[NSNumber class]]) {
        entry[@"file_size_bytes"] = @([item[@"fileSizeBytes"] longLongValue]);
    }
    if ([item[@"primaryGenreName"] isKindOfClass:[NSString class]]) entry[@"primary_genre"] = item[@"primaryGenreName"];
    if ([item[@"contentAdvisoryRating"] isKindOfClass:[NSString class]]) entry[@"content_rating"] = item[@"contentAdvisoryRating"];
    if ([item[@"releaseNotes"] isKindOfClass:[NSString class]]) {
        NSString *notes = item[@"releaseNotes"];
        if (notes.length > 500) notes = [[notes substringToIndex:500] stringByAppendingString:@"..."];
        entry[@"release_notes"] = notes;
    }
    return entry;
}

// Query StoreServices SSLookupRequest for authoritative softwareVersionExternalIdentifiers
static NSArray<NSNumber *> *MCPFetchStoreServicesExternalVersionIDs(uint64_t adamId, NSString *storeFront) {
    if (adamId == 0) return @[];
    MCPAppStoreLoadPrivateFrameworks();

    __block NSMutableArray<NSNumber *> *extIds = [NSMutableArray array];

    // 1. Try SSLookupRequest in mobile (501) context
    MCPRunWithEffectiveUID(501, ^{
        Class SSLookupRequestCls = objc_getClass("SSLookupRequest");
        if (!SSLookupRequestCls) return;
        id lookupReq = [[SSLookupRequestCls alloc] init];
        if (!lookupReq) return;

        MCPMsgSendVoid1(lookupReq, NSSelectorFromString(@"setKeyProfile:"), @"lockup");
        NSString *idStr = [NSString stringWithFormat:@"%llu", adamId];
        MCPMsgSendVoid2(lookupReq, NSSelectorFromString(@"setValue:forRequestParameter:"), idStr, @"id");
        MCPMsgSendVoid2(lookupReq, NSSelectorFromString(@"setValue:forRequestParameter:"), @"2", @"version");

        SEL startSel = NSSelectorFromString(@"startWithLookupBlock:");
        if ([lookupReq respondsToSelector:startSel]) {
            dispatch_semaphore_t sem = dispatch_semaphore_create(0);
            void (^lookupBlock)(id, NSError *) = ^(id response, NSError *error) {
                if (response && !error) {
                    id item = MCPMsgSend1(response, NSSelectorFromString(@"itemForKey:"), idStr);
                    if (!item) {
                        NSArray *allItems = MCPMsgSend0(response, NSSelectorFromString(@"allItems"));
                        item = allItems.firstObject;
                    }
                    if (item) {
                        id rawDict = MCPMsgSend0(item, NSSelectorFromString(@"lookupDictionary"));
                        NSArray *rawArr = nil;
                        if ([rawDict isKindOfClass:[NSDictionary class]]) {
                            rawArr = [rawDict[@"softwareVersionExternalIdentifiers"] isKindOfClass:[NSArray class]]
                                ? rawDict[@"softwareVersionExternalIdentifiers"] : nil;
                        }
                        if (!rawArr) {
                            id propVal = MCPMsgSend1(item, NSSelectorFromString(@"valueForProperty:"), @"softwareVersionExternalIdentifiers");
                            if ([propVal isKindOfClass:[NSArray class]]) rawArr = propVal;
                        }
                        for (id v in rawArr) {
                            if ([v respondsToSelector:@selector(unsignedLongLongValue)]) {
                                uint64_t val = [v unsignedLongLongValue];
                                if (val > 0) [extIds addObject:@(val)];
                            }
                        }
                    }
                }
                dispatch_semaphore_signal(sem);
            };
            ((void (*)(id, SEL, id))objc_msgSend)(lookupReq, startSel, lookupBlock);
            dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)));
        }
    });

    // 2. Fallback: Query Apple's client-api / iTunes lookup endpoint with X-Apple-Store-Front header
    if (extIds.count == 0) {
        NSString *sf = storeFront.length ? storeFront : @"143441-1,29";
        NSString *urlStr = [NSString stringWithFormat:@"https://itunes.apple.com/lookup?id=%llu&entity=software", adamId];
        NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:urlStr]];
        [req setValue:sf forHTTPHeaderField:@"X-Apple-Store-Front"];
        [req setValue:@"AppStore/3.0 iOS/18.0 model/iPhone16,2 hwp/t8130 build/22A3354 (6; dt:309)" forHTTPHeaderField:@"User-Agent"];
        id json = MCPFetchJSONSynchronously(req, NULL, 5.0, NULL);
        if ([json isKindOfClass:[NSDictionary class]]) {
            NSArray *results = [json[@"results"] isKindOfClass:[NSArray class]] ? json[@"results"] : nil;
            NSDictionary *first = [results.firstObject isKindOfClass:[NSDictionary class]] ? results.firstObject : nil;
            NSArray *rawArr = [first[@"softwareVersionExternalIdentifiers"] isKindOfClass:[NSArray class]]
                ? first[@"softwareVersionExternalIdentifiers"] : nil;
            for (id v in rawArr) {
                if ([v respondsToSelector:@selector(unsignedLongLongValue)]) {
                    uint64_t val = [v unsignedLongLongValue];
                    if (val > 0) [extIds addObject:@(val)];
                }
            }
        }
    }

    return extIds;
}

// MuffinStore Version History Pipeline (Section 8.2: Strategy A + Strategy B + Local iTunesMetadata.plist)
static NSDictionary *MCPFetchVersionHistoryForApp(NSString *bundleIdInput,
                                                  uint64_t adamIdInput,
                                                  NSString *country,
                                                  NSString **outError) {
    if (outError) *outError = nil;
    NSString *cc = (country.length > 0) ? country.uppercaseString : @"US";

    NSString *bundleId = bundleIdInput;
    uint64_t adamId = adamIdInput;
    NSDictionary *trackMetadata = nil;

    // Step 1: Check local installed app & iTunesMetadata.plist first
    NSDictionary *installedInfo = MCPInspectInstalledAppAndMetadata(bundleId, adamId);
    if (!bundleId.length && [installedInfo[@"bundle_id"] isKindOfClass:[NSString class]]) {
        bundleId = installedInfo[@"bundle_id"];
    }
    if (adamId == 0 && [installedInfo[@"adam_id"] respondsToSelector:@selector(unsignedLongLongValue)]) {
        adamId = [installedInfo[@"adam_id"] unsignedLongLongValue];
    }

    // Step 2: Query iTunes Lookup API to resolve bundleId <-> adamId and current store version
    NSString *lookupURL = nil;
    if (adamId > 0) {
        lookupURL = [NSString stringWithFormat:@"https://itunes.apple.com/lookup?id=%llu&country=%@", adamId, cc];
    } else if (bundleId.length > 0) {
        NSString *escaped = [bundleId stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLQueryAllowedCharacterSet]];
        lookupURL = [NSString stringWithFormat:@"https://itunes.apple.com/lookup?bundleId=%@&country=%@", escaped, cc];
    }

    if (lookupURL) {
        NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:lookupURL]];
        [req setValue:@"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)" forHTTPHeaderField:@"User-Agent"];
        id json = MCPFetchJSONSynchronously(req, NULL, 6.0, NULL);
        if ([json isKindOfClass:[NSDictionary class]]) {
            NSArray *results = [json[@"results"] isKindOfClass:[NSArray class]] ? json[@"results"] : nil;
            if ([results.firstObject isKindOfClass:[NSDictionary class]]) {
                trackMetadata = MCPFormatITunesTrackItem(results.firstObject);
                if (adamId == 0 && [trackMetadata[@"adam_id"] respondsToSelector:@selector(unsignedLongLongValue)]) {
                    adamId = [trackMetadata[@"adam_id"] unsignedLongLongValue];
                }
                if (!bundleId.length && [trackMetadata[@"bundle_id"] isKindOfClass:[NSString class]]) {
                    bundleId = trackMetadata[@"bundle_id"];
                }
            }
        }
    }

    if (adamId == 0) {
        if (outError) *outError = [NSString stringWithFormat:@"Could not resolve App Store adamId for %@", bundleId ?: @"request"];
        return nil;
    }

    // Re-check installed info now that both bundleId and adamId are resolved
    installedInfo = MCPInspectInstalledAppAndMetadata(bundleId, adamId);
    NSDictionary *accountInfo = MCPResolveActiveStoreAccount(NULL);

    // Step 3: Collect raw softwareVersionExternalIdentifiers (Apple Manifest + iTunesMetadata.plist)
    NSMutableOrderedSet<NSNumber *> *orderedExtIds = [NSMutableOrderedSet orderedSet];
    NSArray *metaExtIds = [installedInfo[@"metadata_ext_vrs_ids"] isKindOfClass:[NSArray class]]
        ? installedInfo[@"metadata_ext_vrs_ids"] : nil;
    for (id v in metaExtIds) {
        if ([v respondsToSelector:@selector(unsignedLongLongValue)] && [v unsignedLongLongValue] > 0) {
            [orderedExtIds addObject:@([v unsignedLongLongValue])];
        }
    }

    NSArray<NSNumber *> *storeExtIds = MCPFetchStoreServicesExternalVersionIDs(adamId, accountInfo[@"storefront"]);
    for (NSNumber *num in storeExtIds) {
        [orderedExtIds addObject:num];
    }

    // Step 4: Strategy A — Query mineek/MuffinStore Version Catalog API (apis.bilin.eu.org/history/<adamId>)
    NSMutableDictionary<NSNumber *, NSMutableDictionary *> *versionByExtId = [NSMutableDictionary dictionary];
    NSMutableArray<NSNumber *> *catalogOrder = [NSMutableArray array];
    NSString *catalogSource = @"none";

    NSString *bilinURL = [NSString stringWithFormat:@"https://apis.bilin.eu.org/history/%llu", adamId];
    NSMutableURLRequest *bilinReq = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:bilinURL]];
    [bilinReq setValue:@"MuffinStore/1.1 (iOS; arm64e)" forHTTPHeaderField:@"User-Agent"];
    id bilinJSON = MCPFetchJSONSynchronously(bilinReq, NULL, 4.5, NULL);
    NSArray *bilinData = nil;
    if ([bilinJSON isKindOfClass:[NSDictionary class]] && [bilinJSON[@"data"] isKindOfClass:[NSArray class]]) {
        bilinData = bilinJSON[@"data"];
    } else if ([bilinJSON isKindOfClass:[NSArray class]]) {
        bilinData = (NSArray *)bilinJSON;
    }

    if (bilinData.count > 0) {
        catalogSource = @"apis.bilin.eu.org (MuffinStore)";
        for (id row in bilinData) {
            if (![row isKindOfClass:[NSDictionary class]]) continue;
            id extRaw = row[@"external_identifier"] ?: (row[@"appExtVrsId"] ?: row[@"id"]);
            uint64_t extVal = [extRaw respondsToSelector:@selector(unsignedLongLongValue)] ? [extRaw unsignedLongLongValue] : 0;
            if (extVal == 0) continue;
            NSString *verStr = [row[@"bundle_version"] isKindOfClass:[NSString class]] ? row[@"bundle_version"]
                : ([row[@"version"] isKindOfClass:[NSString class]] ? row[@"version"] : nil);
            NSString *createdAt = [row[@"created_at"] isKindOfClass:[NSString class]] ? row[@"created_at"]
                : ([row[@"release_date"] isKindOfClass:[NSString class]] ? row[@"release_date"] : nil);

            NSMutableDictionary *vEntry = [NSMutableDictionary dictionary];
            vEntry[@"appExtVrsId"] = [NSString stringWithFormat:@"%llu", extVal];
            vEntry[@"external_version_id"] = @(extVal);
            if (verStr.length) vEntry[@"version"] = verStr;
            if (createdAt.length) vEntry[@"releaseDate"] = createdAt;
            versionByExtId[@(extVal)] = vEntry;
            if (![catalogOrder containsObject:@(extVal)]) {
                [catalogOrder addObject:@(extVal)];
            }
            [orderedExtIds addObject:@(extVal)];
        }
    }

    // Secondary Catalog Fallback if bilin was unreachable or empty
    if (versionByExtId.count == 0) {
        NSString *timURL = [NSString stringWithFormat:@"https://api.timbrd.com/apple/app-version/index.php?id=%llu", adamId];
        NSMutableURLRequest *timReq = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:timURL]];
        [timReq setValue:@"MuffinStore/1.1 (iOS; arm64e)" forHTTPHeaderField:@"User-Agent"];
        id timJSON = MCPFetchJSONSynchronously(timReq, NULL, 4.5, NULL);
        NSArray *timArr = [timJSON isKindOfClass:[NSArray class]] ? (NSArray *)timJSON
            : ([timJSON isKindOfClass:[NSDictionary class]] && [timJSON[@"data"] isKindOfClass:[NSArray class]] ? timJSON[@"data"] : nil);
        if (timArr.count > 0) {
            catalogSource = @"api.timbrd.com";
            for (id row in timArr) {
                if (![row isKindOfClass:[NSDictionary class]]) continue;
                id extRaw = row[@"external_identifier"] ?: row[@"bundle_version_id"];
                uint64_t extVal = [extRaw respondsToSelector:@selector(unsignedLongLongValue)] ? [extRaw unsignedLongLongValue] : 0;
                if (extVal == 0) continue;
                NSString *verStr = [row[@"bundle_version"] isKindOfClass:[NSString class]] ? row[@"bundle_version"] : nil;
                NSString *createdAt = [row[@"created_at"] isKindOfClass:[NSString class]] ? row[@"created_at"] : nil;

                NSMutableDictionary *vEntry = [NSMutableDictionary dictionary];
                vEntry[@"appExtVrsId"] = [NSString stringWithFormat:@"%llu", extVal];
                vEntry[@"external_version_id"] = @(extVal);
                if (verStr.length) vEntry[@"version"] = verStr;
                if (createdAt.length) vEntry[@"releaseDate"] = createdAt;
                versionByExtId[@(extVal)] = vEntry;
                [orderedExtIds addObject:@(extVal)];
            }
        }
    }

    // Also include installed app's current externalVersionIdentifier if known
    uint64_t installedExtId = [installedInfo[@"installed_ext_vrs_id"] respondsToSelector:@selector(unsignedLongLongValue)]
        ? [installedInfo[@"installed_ext_vrs_id"] unsignedLongLongValue] : 0;
    NSString *installedVerStr = [installedInfo[@"installed_version"] isKindOfClass:[NSString class]]
        ? installedInfo[@"installed_version"] : nil;
    if (installedExtId > 0) {
        [orderedExtIds addObject:@(installedExtId)];
        NSMutableDictionary *vEntry = versionByExtId[@(installedExtId)] ?: [NSMutableDictionary dictionary];
        vEntry[@"appExtVrsId"] = [NSString stringWithFormat:@"%llu", installedExtId];
        vEntry[@"external_version_id"] = @(installedExtId);
        if (!vEntry[@"version"] && installedVerStr.length) {
            vEntry[@"version"] = installedVerStr;
        }
        vEntry[@"is_installed"] = @YES;
        versionByExtId[@(installedExtId)] = vEntry;
    }

    // Sort all discovered external version identifiers in ascending chronological build order
    NSArray<NSNumber *> *sortedExtIds = [[orderedExtIds array] sortedArrayUsingSelector:@selector(compare:)];
    NSString *latestStoreVersion = [trackMetadata[@"version"] isKindOfClass:[NSString class]] ? trackMetadata[@"version"] : nil;
    NSString *latestReleaseDate = [trackMetadata[@"release_date"] isKindOfClass:[NSString class]] ? trackMetadata[@"release_date"] : nil;

    NSMutableArray<NSDictionary *> *versionsList = [NSMutableArray arrayWithCapacity:sortedExtIds.count];
    for (NSUInteger i = 0; i < sortedExtIds.count; i++) {
        NSNumber *extNum = sortedExtIds[i];
        uint64_t extVal = [extNum unsignedLongLongValue];
        BOOL isLatest = (i + 1 == sortedExtIds.count);
        NSMutableDictionary *entry = versionByExtId[extNum] ? [versionByExtId[extNum] mutableCopy] : [NSMutableDictionary dictionary];
        entry[@"appExtVrsId"] = [NSString stringWithFormat:@"%llu", extVal];
        entry[@"external_version_id"] = @(extVal);
        entry[@"index"] = @(i);
        entry[@"is_latest"] = @(isLatest);
        entry[@"is_installed"] = @((installedExtId > 0 && extVal == installedExtId));
        if (isLatest) {
            if (!entry[@"version"] && latestStoreVersion.length) entry[@"version"] = latestStoreVersion;
            if (!entry[@"releaseDate"] && latestReleaseDate.length) entry[@"releaseDate"] = latestReleaseDate;
        }
        if (!entry[@"version"]) {
            entry[@"version"] = [NSString stringWithFormat:@"build-%llu", extVal];
        }
        [versionsList addObject:entry];
    }

    NSMutableDictionary *out = [NSMutableDictionary dictionary];
    out[@"adam_id"] = @(adamId);
    if (bundleId.length) out[@"bundle_id"] = bundleId;
    if (trackMetadata) out[@"app"] = trackMetadata;
    out[@"installed_info"] = installedInfo ?: @{};
    out[@"store_account"] = accountInfo ?: @{};
    out[@"catalog_source"] = catalogSource;
    out[@"version_count"] = @(versionsList.count);
    out[@"softwareVersionExternalIdentifiers"] = sortedExtIds ?: @[];
    out[@"versions"] = versionsList;
    return out;
}

#pragma mark - Sandbox Container Snapshot & Restore (Downgrade Preservation)

static BOOL MCPCopyDirectoryContentsRecursive(NSString *srcDir, NSString *dstDir, uid_t ownerUID, gid_t ownerGID) {
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL isDir = NO;
    if (![fm fileExistsAtPath:srcDir isDirectory:&isDir] || !isDir) return NO;

    [fm createDirectoryAtPath:dstDir withIntermediateDirectories:YES attributes:nil error:nil];
    chown(dstDir.fileSystemRepresentation, ownerUID, ownerGID);

    NSArray<NSString *> *items = [fm contentsOfDirectoryAtPath:srcDir error:nil];
    for (NSString *item in items) {
        if ([item isEqualToString:@"."] || [item isEqualToString:@".."]) continue;
        NSString *srcPath = [srcDir stringByAppendingPathComponent:item];
        NSString *dstPath = [dstDir stringByAppendingPathComponent:item];

        [fm removeItemAtPath:dstPath error:nil];
        if ([fm copyItemAtPath:srcPath toPath:dstPath error:nil]) {
            // Recursively normalize ownership when restoring into new DataContainer
            chown(dstPath.fileSystemRepresentation, ownerUID, ownerGID);
            NSDirectoryEnumerator<NSString *> *enumerator = [fm enumeratorAtPath:dstPath];
            for (NSString *rel in enumerator) {
                NSString *sub = [dstPath stringByAppendingPathComponent:rel];
                lchown(sub.fileSystemRepresentation, ownerUID, ownerGID);
            }
        }
    }
    return YES;
}

static NSString *MCPSnapshotAppDataContainer(NSString *bundleId, NSString *dataContainerPath) {
    if (!bundleId.length || !dataContainerPath.length) return nil;
    __block NSString *backupDir = nil;
    MCPRunWithEffectiveUID(0, ^{
        NSFileManager *fm = [NSFileManager defaultManager];
        if (![fm fileExistsAtPath:dataContainerPath]) return;

        NSString *workBase = @"/var/mobile/Library/Caches/ios-mcp-work";
        [fm createDirectoryAtPath:workBase withIntermediateDirectories:YES attributes:nil error:nil];
        chmod(workBase.UTF8String, 0777);
        chown(workBase.UTF8String, 501, 501);
        NSString *workRoot = [workBase stringByAppendingPathComponent:@"appstore-backups"];
        [fm createDirectoryAtPath:workRoot withIntermediateDirectories:YES attributes:nil error:nil];
        chmod(workRoot.UTF8String, 0777);
        chown(workRoot.UTF8String, 501, 501);
        NSString *dirName = [NSString stringWithFormat:@"%@-%llu", bundleId, (unsigned long long)([[NSDate date] timeIntervalSince1970] * 1000)];
        NSString *targetBackup = [workRoot stringByAppendingPathComponent:dirName];
        [fm createDirectoryAtPath:targetBackup withIntermediateDirectories:YES attributes:nil error:nil];

        for (NSString *sub in @[@"Documents", @"Library", @"tmp"]) {
            NSString *srcSub = [dataContainerPath stringByAppendingPathComponent:sub];
            NSString *dstSub = [targetBackup stringByAppendingPathComponent:sub];
            MCPCopyDirectoryContentsRecursive(srcSub, dstSub, 0, 0);
        }
        backupDir = targetBackup;
    });
    return backupDir;
}

static BOOL MCPRestoreAppDataContainer(NSString *backupDir, NSString *newDataContainerPath) {
    if (!backupDir.length || !newDataContainerPath.length) return NO;
    __block BOOL restored = NO;
    MCPRunWithEffectiveUID(0, ^{
        NSFileManager *fm = [NSFileManager defaultManager];
        if (![fm fileExistsAtPath:backupDir] || ![fm fileExistsAtPath:newDataContainerPath]) return;
        for (NSString *sub in @[@"Documents", @"Library", @"tmp"]) {
            NSString *srcSub = [backupDir stringByAppendingPathComponent:sub];
            NSString *dstSub = [newDataContainerPath stringByAppendingPathComponent:sub];
            if ([fm fileExistsAtPath:srcSub]) {
                MCPCopyDirectoryContentsRecursive(srcSub, dstSub, 501, 501);
                restored = YES;
            }
        }
    });
    return restored;
}

static BOOL MCPUninstallAppBundleOnly(NSString *bundleId) {
    if (!bundleId.length) return NO;
    MCPAppStoreLoadPrivateFrameworks();
    __block BOOL ok = NO;
    MCPRunWithEffectiveUID(0, ^{
        Class LSWorkspaceCls = objc_getClass("LSApplicationWorkspace");
        id workspace = LSWorkspaceCls ? MCPMsgSend0(LSWorkspaceCls, NSSelectorFromString(@"defaultWorkspace")) : nil;
        if (workspace) {
            ok = MCPMsgSendBool2(workspace, NSSelectorFromString(@"uninstallApplication:withOptions:"), bundleId, @{});
        }
    });
    if (ok) {
        NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:10.0];
        while ([deadline timeIntervalSinceNow] > 0) {
            NSDictionary *check = MCPInspectInstalledAppAndMetadata(bundleId, 0);
            if (![check[@"installed"] boolValue]) break;
            [NSThread sleepForTimeInterval:0.25];
        }
    }
    return ok;
}

#pragma mark - Upgrade 38 & 39: Headless App Store Install & MuffinStore Downgrade Engine

static NSDictionary *MCPQueryActiveStoreDownloads(void) {
    MCPAppStoreLoadPrivateFrameworks();
    __block NSMutableArray *asdJobs = [NSMutableArray array];
    __block NSMutableArray *ssDownloads = [NSMutableArray array];

    MCPRunWithEffectiveUID(501, ^{
        // 1. Check ASDJobManager
        Class ASDJobManagerCls = objc_getClass("ASDJobManager");
        Class ASDJobManagerOptionsCls = objc_getClass("ASDJobManagerOptions");
        if (ASDJobManagerCls) {
            id jobMgr = nil;
            if (ASDJobManagerOptionsCls) {
                id opts = [[ASDJobManagerOptionsCls alloc] init];
                MCPMsgSendVoid1(opts, NSSelectorFromString(@"setPersistenceIdentifier:"), @"com.witchan.mcp-appstore");
                SEL initOptsSel = NSSelectorFromString(@"initWithOptions:");
                if ([ASDJobManagerCls instancesRespondToSelector:initOptsSel]) {
                    jobMgr = MCPMsgSend1([ASDJobManagerCls alloc], initOptsSel, opts);
                }
            }
            if (!jobMgr) jobMgr = [[ASDJobManagerCls alloc] init];
            SEL getJobsSel = NSSelectorFromString(@"getJobsUsingBlock:");
            if (jobMgr && [jobMgr respondsToSelector:getJobsSel]) {
                dispatch_semaphore_t sem = dispatch_semaphore_create(0);
                void (^jobsBlock)(NSArray *) = ^(NSArray *jobs) {
                    for (id job in jobs) {
                        NSMutableDictionary *jd = [NSMutableDictionary dictionary];
                        id bid = MCPMsgSend0(job, NSSelectorFromString(@"bundleID"));
                        if ([bid isKindOfClass:[NSString class]]) jd[@"bundle_id"] = bid;
                        id pct = @(MCPMsgSendDouble0(job, NSSelectorFromString(@"percentComplete")));
                        jd[@"percent_complete"] = pct;
                        id phase = @(MCPMsgSendInt64(job, NSSelectorFromString(@"phase")));
                        jd[@"phase"] = phase;
                        id pid = @(MCPMsgSendInt64(job, NSSelectorFromString(@"persistentID")));
                        jd[@"job_id"] = pid;
                        [asdJobs addObject:jd];
                    }
                    dispatch_semaphore_signal(sem);
                };
                ((void (*)(id, SEL, id))objc_msgSend)(jobMgr, getJobsSel, jobsBlock);
                dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)));
            }
        }

        // 2. Check SSDownloadManager
        Class SSDownloadManagerCls = objc_getClass("SSDownloadManager");
        if (SSDownloadManagerCls) {
            id dlMgr = MCPMsgSend0(SSDownloadManagerCls, NSSelectorFromString(@"softwareDownloadManager"));
            NSArray *dls = MCPMsgSend0(dlMgr, NSSelectorFromString(@"downloads"));
            for (id dl in dls) {
                NSMutableDictionary *dd = [NSMutableDictionary dictionary];
                id pct = @(MCPMsgSendDouble0(dl, NSSelectorFromString(@"percentComplete")));
                dd[@"percent_complete"] = pct;
                id status = MCPMsgSend0(dl, NSSelectorFromString(@"downloadPhaseIdentifier"));
                if ([status isKindOfClass:[NSString class]]) dd[@"phase"] = status;
                id bid = MCPMsgSend1(dl, NSSelectorFromString(@"valueForProperty:"), @"bundle-id");
                if ([bid isKindOfClass:[NSString class]]) dd[@"bundle_id"] = bid;
                [ssDownloads addObject:dd];
            }
        }
    });

    return @{
        @"asd_jobs": asdJobs,
        @"ss_downloads": ssDownloads,
        @"active_count": @(asdJobs.count + ssDownloads.count)
    };
}

static id MCPCreateASDJobManagerInstance(void) {
    Class ASDJobManagerCls = objc_getClass("ASDJobManager");
    Class ASDJobManagerOptionsCls = objc_getClass("ASDJobManagerOptions");
    if (!ASDJobManagerCls) return nil;
    id jobMgr = nil;
    if (ASDJobManagerOptionsCls) {
        id opts = [[ASDJobManagerOptionsCls alloc] init];
        MCPMsgSendVoid1(opts, NSSelectorFromString(@"setPersistenceIdentifier:"), @"com.witchan.mcp-appstore");
        SEL initOptsSel = NSSelectorFromString(@"initWithOptions:");
        if ([ASDJobManagerCls instancesRespondToSelector:initOptsSel]) {
            jobMgr = MCPMsgSend1([ASDJobManagerCls alloc], initOptsSel, opts);
        }
    }
    if (!jobMgr) jobMgr = [[ASDJobManagerCls alloc] init];
    return jobMgr;
}

static NSDictionary *MCPResumeStoreDownloadsForApp(NSString *bundleId) {
    MCPAppStoreLoadPrivateFrameworks();
    __block NSMutableArray *resumedJobIDs = [NSMutableArray array];
    __block NSUInteger resumedSSCount = 0;

    MCPRunWithEffectiveUID(501, ^{
        id jobMgr = MCPCreateASDJobManagerInstance();
        SEL getJobsSel = NSSelectorFromString(@"getJobsUsingBlock:");
        SEL resumeJobsSel = NSSelectorFromString(@"resumeJobsWithIDs:completionBlock:");
        if (jobMgr && [jobMgr respondsToSelector:getJobsSel]) {
            NSMutableArray *targetIDs = [NSMutableArray array];
            dispatch_semaphore_t getSem = dispatch_semaphore_create(0);
            void (^jobsBlock)(NSArray *) = ^(NSArray *jobs) {
                for (id job in jobs) {
                    id bid = MCPMsgSend0(job, NSSelectorFromString(@"bundleID"));
                    BOOL matches = (!bundleId.length || ![bid isKindOfClass:[NSString class]] || [(NSString *)bid isEqualToString:bundleId] || jobs.count == 1);
                    if (matches) {
                        int64_t jid = MCPMsgSendInt64(job, NSSelectorFromString(@"persistentID"));
                        if (jid != 0) [targetIDs addObject:@(jid)];
                    }
                }
                dispatch_semaphore_signal(getSem);
            };
            ((void (*)(id, SEL, id))objc_msgSend)(jobMgr, getJobsSel, jobsBlock);
            dispatch_semaphore_wait(getSem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)));

            if (targetIDs.count > 0 && [jobMgr respondsToSelector:resumeJobsSel]) {
                dispatch_semaphore_t resSem = dispatch_semaphore_create(0);
                void (^compBlock)(BOOL, NSError *) = ^(__unused BOOL ok, __unused NSError *err) {
                    dispatch_semaphore_signal(resSem);
                };
                ((void (*)(id, SEL, id, id))objc_msgSend)(jobMgr, resumeJobsSel, targetIDs, compBlock);
                dispatch_semaphore_wait(resSem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)));
                [resumedJobIDs addObjectsFromArray:targetIDs];
            }
        }

        Class SSDownloadManagerCls = objc_getClass("SSDownloadManager");
        if (SSDownloadManagerCls) {
            id dlMgr = MCPMsgSend0(SSDownloadManagerCls, NSSelectorFromString(@"softwareDownloadManager"));
            NSArray *dls = MCPMsgSend0(dlMgr, NSSelectorFromString(@"downloads"));
            for (id dl in dls) {
                id bid = MCPMsgSend1(dl, NSSelectorFromString(@"valueForProperty:"), @"bundle-id");
                BOOL matches = (!bundleId.length || ![bid isKindOfClass:[NSString class]] || [(NSString *)bid isEqualToString:bundleId] || dls.count == 1);
                if (!matches) continue;
                SEL resumeSel = NSSelectorFromString(@"resume");
                SEL restartSel = NSSelectorFromString(@"restart");
                if ([dl respondsToSelector:resumeSel]) {
                    MCPMsgSendVoid0(dl, resumeSel);
                    resumedSSCount++;
                } else if ([dl respondsToSelector:restartSel]) {
                    MCPMsgSendVoid0(dl, restartSel);
                    resumedSSCount++;
                }
            }
        }
    });

    return @{
        @"resumed_asd_job_ids": resumedJobIDs,
        @"resumed_ss_downloads": @(resumedSSCount)
    };
}

static NSDictionary *MCPCancelStoreDownloadsForApp(NSString *bundleId) {
    MCPAppStoreLoadPrivateFrameworks();
    __block NSMutableArray *canceledJobIDs = [NSMutableArray array];
    __block NSUInteger canceledSSCount = 0;

    MCPRunWithEffectiveUID(501, ^{
        id jobMgr = MCPCreateASDJobManagerInstance();
        SEL getJobsSel = NSSelectorFromString(@"getJobsUsingBlock:");
        SEL cancelJobsSel = NSSelectorFromString(@"cancelJobsWithIDs:completionBlock:");
        if (jobMgr && [jobMgr respondsToSelector:getJobsSel]) {
            NSMutableArray *targetIDs = [NSMutableArray array];
            dispatch_semaphore_t getSem = dispatch_semaphore_create(0);
            void (^jobsBlock)(NSArray *) = ^(NSArray *jobs) {
                for (id job in jobs) {
                    id bid = MCPMsgSend0(job, NSSelectorFromString(@"bundleID"));
                    BOOL matches = (!bundleId.length || ![bid isKindOfClass:[NSString class]] || [(NSString *)bid isEqualToString:bundleId] || jobs.count == 1);
                    if (matches) {
                        int64_t jid = MCPMsgSendInt64(job, NSSelectorFromString(@"persistentID"));
                        if (jid != 0) [targetIDs addObject:@(jid)];
                    }
                }
                dispatch_semaphore_signal(getSem);
            };
            ((void (*)(id, SEL, id))objc_msgSend)(jobMgr, getJobsSel, jobsBlock);
            dispatch_semaphore_wait(getSem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)));

            if (targetIDs.count > 0 && [jobMgr respondsToSelector:cancelJobsSel]) {
                dispatch_semaphore_t canSem = dispatch_semaphore_create(0);
                void (^compBlock)(BOOL, NSError *) = ^(__unused BOOL ok, __unused NSError *err) {
                    dispatch_semaphore_signal(canSem);
                };
                ((void (*)(id, SEL, id, id))objc_msgSend)(jobMgr, cancelJobsSel, targetIDs, compBlock);
                dispatch_semaphore_wait(canSem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(4.0 * NSEC_PER_SEC)));
                [canceledJobIDs addObjectsFromArray:targetIDs];
            }
        }

        Class SSDownloadManagerCls = objc_getClass("SSDownloadManager");
        if (SSDownloadManagerCls) {
            id dlMgr = MCPMsgSend0(SSDownloadManagerCls, NSSelectorFromString(@"softwareDownloadManager"));
            NSArray *dls = MCPMsgSend0(dlMgr, NSSelectorFromString(@"downloads"));
            NSMutableArray *toCancel = [NSMutableArray array];
            for (id dl in dls) {
                id bid = MCPMsgSend1(dl, NSSelectorFromString(@"valueForProperty:"), @"bundle-id");
                BOOL matches = (!bundleId.length || ![bid isKindOfClass:[NSString class]] || [(NSString *)bid isEqualToString:bundleId] || dls.count == 1);
                if (!matches) continue;
                [toCancel addObject:dl];
                SEL cancelSel = NSSelectorFromString(@"cancel");
                if ([dl respondsToSelector:cancelSel]) {
                    MCPMsgSendVoid0(dl, cancelSel);
                }
            }
            SEL cancelDlsSel = NSSelectorFromString(@"cancelDownloads:completionBlock:");
            if (toCancel.count > 0 && dlMgr && [dlMgr respondsToSelector:cancelDlsSel]) {
                dispatch_semaphore_t canSem = dispatch_semaphore_create(0);
                void (^compBlock)(NSError *) = ^(__unused NSError *err) {
                    dispatch_semaphore_signal(canSem);
                };
                ((void (*)(id, SEL, id, id))objc_msgSend)(dlMgr, cancelDlsSel, toCancel, compBlock);
                dispatch_semaphore_wait(canSem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(4.0 * NSEC_PER_SEC)));
            }
            canceledSSCount = toCancel.count;
        }
    });

    return @{
        @"canceled_asd_job_ids": canceledJobIDs,
        @"canceled_ss_downloads": @(canceledSSCount)
    };
}

// Dispatch a single buyParameters transaction via ASDPurchaseManager & SSPurchaseRequest
static NSDictionary *MCPDispatchPurchaseTransactionEx(uint64_t adamId,
                                                      NSString *bundleId,
                                                      uint64_t extVersionId,
                                                      NSString *pricingParams,
                                                      NSNumber *accountDSID,
                                                      BOOL preferASD) {
    MCPAppStoreLoadPrivateFrameworks();

    static uint32_t sClientBuySeq = 1;
    uint32_t buySeq = sClientBuySeq++;
    NSString *buyParams = [NSString stringWithFormat:
        @"productType=C&price=0&salableAdamId=%llu&pricingParameters=%@&clientBuyId=%u&installedVersionKronos=0%@",
        adamId,
        pricingParams ?: @"STDQ",
        buySeq,
        extVersionId > 0 ? [NSString stringWithFormat:@"&appExtVrsId=%llu", extVersionId] : @""];

    __block BOOL dispatchedOK = NO;
    __block NSString *engineUsed = @"none";
    __block NSString *lastError = nil;

    MCPRunWithEffectiveUID(501, ^{
        void (^tryASD)(void) = ^{
            if (dispatchedOK) return;
            Class ASDPurchaseCls = objc_getClass("ASDPurchase");
            Class ASDPurchaseManagerCls = objc_getClass("ASDPurchaseManager");
            if (!ASDPurchaseCls || !ASDPurchaseManagerCls) return;

            id asdPurchase = [[ASDPurchaseCls alloc] init];
            MCPMsgSendVoid1(asdPurchase, NSSelectorFromString(@"setBuyParameters:"), buyParams);
            MCPMsgSendVoid1(asdPurchase, NSSelectorFromString(@"setItemID:"), @(adamId));
            if (bundleId.length > 0) {
                MCPMsgSendVoid1(asdPurchase, NSSelectorFromString(@"setBundleID:"), bundleId);
            }
            if (accountDSID) {
                MCPMsgSendVoid1(asdPurchase, NSSelectorFromString(@"setAccountIdentifier:"), accountDSID);
            }
            MCPMsgSendVoidBool(asdPurchase, NSSelectorFromString(@"setCreatesJobs:"), YES);
            MCPMsgSendVoidBool(asdPurchase, NSSelectorFromString(@"setIsRedownload:"), [pricingParams isEqualToString:@"STDRDL"]);
            MCPMsgSendVoidBool(asdPurchase, NSSelectorFromString(@"setIgnoresForcedPasswordRestriction:"), YES);

            id mgr = MCPMsgSend0(ASDPurchaseManagerCls, NSSelectorFromString(@"sharedManager"));
            SEL procSel = NSSelectorFromString(@"processPurchase:withResponseHandler:");
            if (mgr && [mgr respondsToSelector:procSel]) {
                dispatch_semaphore_t sem = dispatch_semaphore_create(0);
                __block NSError *asdErr = nil;
                void (^handler)(id, NSError *) = ^(id resp, NSError *err) {
                    if (err) {
                        asdErr = err;
                    } else if (resp) {
                        NSError *rErr = MCPMsgSend0(resp, NSSelectorFromString(@"error"));
                        if (rErr) asdErr = rErr;
                    }
                    dispatch_semaphore_signal(sem);
                };
                ((void (*)(id, SEL, id, id))objc_msgSend)(mgr, procSel, asdPurchase, handler);
                dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(25.0 * NSEC_PER_SEC)));
                if (!asdErr) {
                    dispatchedOK = YES;
                    engineUsed = @"ASDPurchaseManager";
                    lastError = nil;
                } else {
                    lastError = asdErr.localizedDescription;
                }
            }
        };

        void (^trySS)(void) = ^{
            if (dispatchedOK) return;
            Class SSPurchaseCls = objc_getClass("SSPurchase");
            Class SSPurchaseRequestCls = objc_getClass("SSPurchaseRequest");
            if (!SSPurchaseCls || !SSPurchaseRequestCls) return;

            id purchase = [[SSPurchaseCls alloc] init];
            MCPMsgSendVoid1(purchase, NSSelectorFromString(@"setBuyParameters:"), buyParams);
            MCPMsgSendVoid1(purchase, NSSelectorFromString(@"setItemIdentifier:"), @(adamId));
            if (accountDSID) {
                MCPMsgSendVoid1(purchase, NSSelectorFromString(@"setAccountIdentifier:"), accountDSID);
            }
            MCPMsgSendVoidBool(purchase, NSSelectorFromString(@"setIgnoresForcedPasswordRestriction:"), YES);
            MCPMsgSendVoidBool(purchase, NSSelectorFromString(@"setCreatesDownloads:"), YES);
            MCPMsgSendVoidBool(purchase, NSSelectorFromString(@"setBackgroundPurchase:"), YES);

            Class SSDownloadPolicyCls = objc_getClass("SSDownloadPolicy");
            if (SSDownloadPolicyCls) {
                SEL initPolicySel = NSSelectorFromString(@"initWithDownloadKind:URLBagType:");
                if ([SSDownloadPolicyCls instancesRespondToSelector:initPolicySel]) {
                    id policy = ((id (*)(id, SEL, id, int64_t))objc_msgSend)([SSDownloadPolicyCls alloc], initPolicySel, @"software", 0);
                    if (policy) MCPMsgSendVoid1(purchase, NSSelectorFromString(@"setDownloadPolicy:"), policy);
                }
            }

            SEL initPurchasesSel = NSSelectorFromString(@"initWithPurchases:");
            id req = [SSPurchaseRequestCls instancesRespondToSelector:initPurchasesSel]
                ? MCPMsgSend1([SSPurchaseRequestCls alloc], initPurchasesSel, @[purchase])
                : nil;
            if (!req) return;

            MCPMsgSendVoidBool(req, NSSelectorFromString(@"setBackgroundRequest:"), YES);
            MCPMsgSendVoidBool(req, NSSelectorFromString(@"setCreatesDownloads:"), YES);

            SEL startRespSel = NSSelectorFromString(@"startWithPurchaseResponseBlock:completionBlock:");
            SEL startBlkSel = NSSelectorFromString(@"startWithPurchaseBlock:completionBlock:");
            dispatch_semaphore_t sem = dispatch_semaphore_create(0);
            __block NSError *ssErr = nil;

            if ([req respondsToSelector:startRespSel]) {
                void (^respBlock)(id) = ^(id response) {
                    NSError *rErr = MCPMsgSend0(response, NSSelectorFromString(@"error"));
                    if (rErr) ssErr = rErr;
                };
                void (^compBlock)(NSError *) = ^(NSError *error) {
                    if (error && !ssErr) ssErr = error;
                    dispatch_semaphore_signal(sem);
                };
                ((void (*)(id, SEL, id, id))objc_msgSend)(req, startRespSel, respBlock, compBlock);
                dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(25.0 * NSEC_PER_SEC)));
                if (!ssErr) {
                    dispatchedOK = YES;
                    engineUsed = @"SSPurchaseRequest";
                    lastError = nil;
                } else {
                    lastError = ssErr.localizedDescription;
                }
            } else if ([req respondsToSelector:startBlkSel]) {
                void (^pBlock)(id, NSError *) = ^(__unused id p, NSError *error) {
                    if (error) ssErr = error;
                };
                void (^compBlock)(NSError *) = ^(NSError *error) {
                    if (error && !ssErr) ssErr = error;
                    dispatch_semaphore_signal(sem);
                };
                ((void (*)(id, SEL, id, id))objc_msgSend)(req, startBlkSel, pBlock, compBlock);
                dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(25.0 * NSEC_PER_SEC)));
                if (!ssErr) {
                    dispatchedOK = YES;
                    engineUsed = @"SSPurchaseRequest";
                    lastError = nil;
                } else {
                    lastError = ssErr.localizedDescription;
                }
            }
        };

        if (preferASD) {
            tryASD();
            trySS();
        } else {
            trySS();
            tryASD();
        }
    });

    NSMutableDictionary *res = [NSMutableDictionary dictionary];
    res[@"dispatched"] = @(dispatchedOK);
    res[@"engine"] = engineUsed;
    res[@"buy_parameters"] = buyParams;
    res[@"pricing_parameters"] = pricingParams ?: @"STDQ";
    if (lastError.length) res[@"error"] = lastError;
    return res;
}

static NSDictionary *MCPDispatchPurchaseTransaction(uint64_t adamId,
                                                    NSString *bundleId,
                                                    uint64_t extVersionId,
                                                    NSString *pricingParams,
                                                    NSNumber *accountDSID) {
    return MCPDispatchPurchaseTransactionEx(adamId, bundleId, extVersionId, pricingParams, accountDSID, NO);
}

static NSDictionary *MCPPerformInstallOrDowngrade(NSDictionary *req, BOOL isDowngradeOp, NSString **outError) {
    if (outError) *outError = nil;

    NSString *bundleId = [req[@"bundle_id"] isKindOfClass:[NSString class]] ? req[@"bundle_id"] : nil;
    uint64_t adamId = [req[@"adam_id"] respondsToSelector:@selector(unsignedLongLongValue)]
        ? [req[@"adam_id"] unsignedLongLongValue]
        : ([req[@"track_id"] respondsToSelector:@selector(unsignedLongLongValue)] ? [req[@"track_id"] unsignedLongLongValue] : 0);
    NSString *targetVersion = [req[@"version"] isKindOfClass:[NSString class]] ? req[@"version"] : nil;
    id rawExtId = req[@"app_ext_vrs_id"] ?: req[@"external_version_id"];
    uint64_t targetExtId = [rawExtId respondsToSelector:@selector(unsignedLongLongValue)] ? [rawExtId unsignedLongLongValue] : 0;
    NSString *country = [req[@"country"] isKindOfClass:[NSString class]] ? req[@"country"] : @"US";
    BOOL waitForInstall = (req[@"wait_for_install"] == nil) ? YES : [req[@"wait_for_install"] boolValue];
    BOOL preserveData = (req[@"preserve_data"] == nil) ? YES : [req[@"preserve_data"] boolValue];
    double timeoutSec = [req[@"timeout"] respondsToSelector:@selector(doubleValue)] ? [req[@"timeout"] doubleValue] : 120.0;
    if (timeoutSec < 10.0) timeoutSec = 10.0;
    if (timeoutSec > 300.0) timeoutSec = 300.0;

    // Resolve version history & app metadata
    NSString *histErr = nil;
    NSDictionary *historyInfo = MCPFetchVersionHistoryForApp(bundleId, adamId, country, &histErr);
    if (!historyInfo) {
        if (outError) *outError = histErr ?: @"Failed to resolve app metadata on App Store";
        return nil;
    }

    adamId = [historyInfo[@"adam_id"] unsignedLongLongValue];
    if (!bundleId.length && [historyInfo[@"bundle_id"] isKindOfClass:[NSString class]]) {
        bundleId = historyInfo[@"bundle_id"];
    }
    NSArray<NSDictionary *> *versions = [historyInfo[@"versions"] isKindOfClass:[NSArray class]] ? historyInfo[@"versions"] : @[];
    NSDictionary *beforeInstallInfo = [historyInfo[@"installed_info"] isKindOfClass:[NSDictionary class]] ? historyInfo[@"installed_info"] : @{};
    BOOL wasInstalled = [beforeInstallInfo[@"installed"] boolValue];
    uint64_t beforeExtId = [beforeInstallInfo[@"installed_ext_vrs_id"] respondsToSelector:@selector(unsignedLongLongValue)]
        ? [beforeInstallInfo[@"installed_ext_vrs_id"] unsignedLongLongValue] : 0;
    NSString *beforeVersion = [beforeInstallInfo[@"installed_version"] isKindOfClass:[NSString class]] ? beforeInstallInfo[@"installed_version"] : nil;

    // Resolve targetExtId from targetVersion when downgrading or pinning a specific version
    NSString *resolvedTargetVersionString = targetVersion;
    if (targetExtId == 0 && targetVersion.length > 0) {
        NSString *lowVer = targetVersion.lowercaseString;
        if ([lowVer isEqualToString:@"previous"] || [lowVer isEqualToString:@"n-1"] || [lowVer isEqualToString:@"prev"]) {
            if (versions.count >= 2) {
                NSDictionary *prevEntry = versions[versions.count - 2];
                // If current installed version is earlier than latest, find the entry immediately preceding beforeExtId
                if (beforeExtId > 0) {
                    for (NSUInteger i = 1; i < versions.count; i++) {
                        if ([versions[i][@"external_version_id"] unsignedLongLongValue] == beforeExtId) {
                            prevEntry = versions[i - 1];
                            break;
                        }
                    }
                }
                targetExtId = [prevEntry[@"external_version_id"] unsignedLongLongValue];
                resolvedTargetVersionString = prevEntry[@"version"];
            }
        } else if ([lowVer isEqualToString:@"oldest"] || [lowVer isEqualToString:@"first"]) {
            if (versions.count >= 1) {
                NSDictionary *firstEntry = versions.firstObject;
                targetExtId = [firstEntry[@"external_version_id"] unsignedLongLongValue];
                resolvedTargetVersionString = firstEntry[@"version"];
            }
        } else {
            // Exact semantic version match, or numeric appExtVrsId passed in `version`
            for (NSDictionary *vEntry in [versions reverseObjectEnumerator]) {
                NSString *vStr = [vEntry[@"version"] isKindOfClass:[NSString class]] ? vEntry[@"version"] : @"";
                NSString *eStr = [vEntry[@"appExtVrsId"] isKindOfClass:[NSString class]] ? vEntry[@"appExtVrsId"] : @"";
                if ([vStr isEqualToString:targetVersion] || [eStr isEqualToString:targetVersion]) {
                    targetExtId = [vEntry[@"external_version_id"] unsignedLongLongValue];
                    resolvedTargetVersionString = vStr;
                    break;
                }
            }
            if (targetExtId == 0) {
                // Check if targetVersion is a raw numeric appExtVrsId not in catalog
                uint64_t parsedNum = strtoull(targetVersion.UTF8String, NULL, 10);
                if (parsedNum > 100000) {
                    targetExtId = parsedNum;
                }
            }
        }

        if (targetExtId == 0) {
            if (outError) {
                *outError = [NSString stringWithFormat:@"Could not find appExtVrsId for version '%@' (available versions: %lu)",
                             targetVersion, (unsigned long)versions.count];
            }
            return nil;
        }
    } else if (targetExtId == 0 && isDowngradeOp) {
        // Default downgrade target when neither version nor app_ext_vrs_id was specified: N-1
        if (versions.count >= 2) {
            NSDictionary *prevEntry = versions[versions.count - 2];
            if (beforeExtId > 0) {
                for (NSUInteger i = 1; i < versions.count; i++) {
                    if ([versions[i][@"external_version_id"] unsignedLongLongValue] == beforeExtId) {
                        prevEntry = versions[i - 1];
                        break;
                    }
                }
            }
            targetExtId = [prevEntry[@"external_version_id"] unsignedLongLongValue];
            resolvedTargetVersionString = prevEntry[@"version"];
        } else {
            if (outError) *outError = @"No historical versions found to downgrade to";
            return nil;
        }
    } else if (targetExtId > 0 && !resolvedTargetVersionString.length) {
        for (NSDictionary *vEntry in versions) {
            if ([vEntry[@"external_version_id"] unsignedLongLongValue] == targetExtId) {
                resolvedTargetVersionString = vEntry[@"version"];
                break;
            }
        }
    }

    // Snapshot sandbox DataContainer before downgrade if already installed
    NSString *sandboxBackupPath = nil;
    NSString *beforeDataContainer = [beforeInstallInfo[@"data_container_path"] isKindOfClass:[NSString class]]
        ? beforeInstallInfo[@"data_container_path"] : nil;
    if (wasInstalled && preserveData && (isDowngradeOp || targetExtId > 0) && beforeDataContainer.length > 0) {
        sandboxBackupPath = MCPSnapshotAppDataContainer(bundleId, beforeDataContainer);
    }

    id ssAccountObj = nil;
    NSDictionary *accountInfo = MCPResolveActiveStoreAccount(&ssAccountObj);
    NSNumber *accountDSID = [accountInfo[@"dsid"] isKindOfClass:[NSNumber class]] ? accountInfo[@"dsid"] : nil;

    // Order of pricingParameters: STDRDL first if already installed or downgrading, then STDQ fallback
    NSString *explicitPricing = [req[@"pricing_parameters"] isKindOfClass:[NSString class]] ? req[@"pricing_parameters"] : nil;
    NSArray<NSString *> *pricingOrder = explicitPricing.length
        ? @[explicitPricing]
        : ((wasInstalled || isDowngradeOp) ? @[@"STDRDL", @"STDQ"] : @[@"STDQ", @"STDRDL"]);

    // Clear any pre-existing stalled 0% download jobs for this bundleId before starting a fresh purchase
    NSMutableArray<NSDictionary *> *recoveryEvents = [NSMutableArray array];
    NSDictionary *initialDlState = MCPQueryActiveStoreDownloads();
    if ([initialDlState[@"active_count"] integerValue] > 0) {
        BOOL hasStuckZeroForBundle = NO;
        for (NSDictionary *j in initialDlState[@"asd_jobs"]) {
            NSString *jBid = [j[@"bundle_id"] isKindOfClass:[NSString class]] ? j[@"bundle_id"] : nil;
            double pct = [j[@"percent_complete"] respondsToSelector:@selector(doubleValue)] ? [j[@"percent_complete"] doubleValue] : 0.0;
            if ((!jBid.length || [jBid isEqualToString:bundleId]) && pct <= 0.001) {
                hasStuckZeroForBundle = YES;
                break;
            }
        }
        for (NSDictionary *d in initialDlState[@"ss_downloads"]) {
            NSString *dBid = [d[@"bundle_id"] isKindOfClass:[NSString class]] ? d[@"bundle_id"] : nil;
            double pct = [d[@"percent_complete"] respondsToSelector:@selector(doubleValue)] ? [d[@"percent_complete"] doubleValue] : 0.0;
            if ((!dBid.length || [dBid isEqualToString:bundleId]) && pct <= 0.001) {
                hasStuckZeroForBundle = YES;
                break;
            }
        }
        if (hasStuckZeroForBundle) {
            NSDictionary *preCancel = MCPCancelStoreDownloadsForApp(bundleId);
            [recoveryEvents addObject:@{
                @"action": @"clear_preexisting_stalled_job",
                @"detail": preCancel ?: @{}
            }];
            [NSThread sleepForTimeInterval:0.6];
        }
    }

    NSDictionary *purchaseDispatch = nil;
    for (NSString *pricing in pricingOrder) {
        purchaseDispatch = MCPDispatchPurchaseTransactionEx(adamId, bundleId, targetExtId, pricing, accountDSID, NO);
        if ([purchaseDispatch[@"dispatched"] boolValue]) break;
    }

    BOOL usedCleanReinstallFallback = NO;
    BOOL sandboxRestored = NO;
    int stallRecoveryCount = 0;
    NSDictionary *afterInstallInfo = beforeInstallInfo;

    if (waitForInstall && [purchaseDispatch[@"dispatched"] boolValue]) {
        NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:timeoutSec];
        NSDate *halfwayCheck = [NSDate dateWithTimeIntervalSinceNow:MIN(25.0, timeoutSec * 0.45)];
        NSDate *lastProgressChangeTime = [NSDate date];
        double bestProgress = -1.0;
        BOOL triedResumeInCurrentWindow = NO;
        BOOL completed = NO;

        while ([deadline timeIntervalSinceNow] > 0) {
            [NSThread sleepForTimeInterval:1.2];
            afterInstallInfo = MCPInspectInstalledAppAndMetadata(bundleId, adamId);
            BOOL nowInstalled = [afterInstallInfo[@"installed"] boolValue];
            uint64_t nowExtId = [afterInstallInfo[@"installed_ext_vrs_id"] respondsToSelector:@selector(unsignedLongLongValue)]
                ? [afterInstallInfo[@"installed_ext_vrs_id"] unsignedLongLongValue] : 0;
            NSString *nowVer = [afterInstallInfo[@"installed_version"] isKindOfClass:[NSString class]]
                ? afterInstallInfo[@"installed_version"] : nil;

            if (targetExtId > 0) {
                if (nowInstalled && (nowExtId == targetExtId ||
                    (resolvedTargetVersionString.length > 0 && [nowVer isEqualToString:resolvedTargetVersionString] && ![nowVer isEqualToString:beforeVersion]))) {
                    completed = YES;
                    break;
                }
            } else if (nowInstalled) {
                completed = YES;
                break;
            }

            // Monitor active download progress and recover from stalled queues
            NSDictionary *dlState = MCPQueryActiveStoreDownloads();
            double currentMaxPct = -1.0;
            NSInteger activeJobs = [dlState[@"active_count"] integerValue];
            for (NSDictionary *j in dlState[@"asd_jobs"]) {
                NSString *jBid = [j[@"bundle_id"] isKindOfClass:[NSString class]] ? j[@"bundle_id"] : nil;
                if (!jBid.length || !bundleId.length || [jBid isEqualToString:bundleId]) {
                    double pct = [j[@"percent_complete"] respondsToSelector:@selector(doubleValue)] ? [j[@"percent_complete"] doubleValue] : 0.0;
                    if (pct > currentMaxPct) currentMaxPct = pct;
                }
            }
            for (NSDictionary *d in dlState[@"ss_downloads"]) {
                NSString *dBid = [d[@"bundle_id"] isKindOfClass:[NSString class]] ? d[@"bundle_id"] : nil;
                if (!dBid.length || !bundleId.length || [dBid isEqualToString:bundleId]) {
                    double pct = [d[@"percent_complete"] respondsToSelector:@selector(doubleValue)] ? [d[@"percent_complete"] doubleValue] : 0.0;
                    if (pct > currentMaxPct) currentMaxPct = pct;
                }
            }

            if (currentMaxPct > bestProgress + 0.0005) {
                bestProgress = currentMaxPct;
                lastProgressChangeTime = [NSDate date];
                triedResumeInCurrentWindow = NO;
            }

            NSTimeInterval stalledSec = [[NSDate date] timeIntervalSinceDate:lastProgressChangeTime];
            if (activeJobs > 0 && !triedResumeInCurrentWindow && stalledSec >= 4.5 && stalledSec < 9.5) {
                triedResumeInCurrentWindow = YES;
                NSDictionary *resumed = MCPResumeStoreDownloadsForApp(bundleId);
                [recoveryEvents addObject:@{
                    @"action": @"resume_stalled_download",
                    @"stalled_seconds": @(stalledSec),
                    @"progress": @(bestProgress < 0 ? 0.0 : bestProgress),
                    @"detail": resumed ?: @{}
                }];
            } else if (stalledSec >= 9.5 && stallRecoveryCount < 4 && (bestProgress < 0.85)) {
                stallRecoveryCount++;
                NSDictionary *canceled = MCPCancelStoreDownloadsForApp(bundleId);
                [NSThread sleepForTimeInterval:1.0];
                BOOL preferASD = (stallRecoveryCount % 2 == 1);
                NSArray<NSString *> *retryPricing = (stallRecoveryCount % 2 == 1) ? @[@"STDRDL", @"STDQ"] : pricingOrder;
                for (NSString *pricing in retryPricing) {
                    purchaseDispatch = MCPDispatchPurchaseTransactionEx(adamId, bundleId, targetExtId, pricing, accountDSID, preferASD);
                    if ([purchaseDispatch[@"dispatched"] boolValue]) break;
                }
                NSDictionary *resumedAfter = MCPResumeStoreDownloadsForApp(bundleId);
                [recoveryEvents addObject:@{
                    @"action": @"cancel_and_retrigger_download",
                    @"attempt": @(stallRecoveryCount),
                    @"stalled_seconds": @(stalledSec),
                    @"prefer_asd": @(preferASD),
                    @"canceled": canceled ?: @{},
                    @"redispatch": purchaseDispatch ?: @{},
                    @"resume": resumedAfter ?: @{}
                }];
                lastProgressChangeTime = [NSDate date];
                bestProgress = -1.0;
                triedResumeInCurrentWindow = NO;
            }

            // If downgrading over a newer installed version and installd blocked in-place downgrade (kMIEDowngradeError),
            // unregister the old app bundle while preserving our sandbox snapshot, then re-dispatch the legacy appExtVrsId install!
            if (wasInstalled && targetExtId > 0 && !usedCleanReinstallFallback && [halfwayCheck timeIntervalSinceNow] <= 0) {
                if (activeJobs == 0 && nowExtId == beforeExtId) {
                    usedCleanReinstallFallback = YES;
                    MCPUninstallAppBundleOnly(bundleId);
                    for (NSString *pricing in @[@"STDRDL", @"STDQ"]) {
                        purchaseDispatch = MCPDispatchPurchaseTransactionEx(adamId, bundleId, targetExtId, pricing, accountDSID, NO);
                        if ([purchaseDispatch[@"dispatched"] boolValue]) break;
                    }
                    lastProgressChangeTime = [NSDate date];
                    bestProgress = -1.0;
                }
            }
        }

        // Restore sandbox DataContainer if we took a backup and the container path changed or was recreated
        afterInstallInfo = MCPInspectInstalledAppAndMetadata(bundleId, adamId);
        NSString *afterDataContainer = [afterInstallInfo[@"data_container_path"] isKindOfClass:[NSString class]]
            ? afterInstallInfo[@"data_container_path"] : nil;
        if (sandboxBackupPath.length > 0 && afterDataContainer.length > 0) {
            if (usedCleanReinstallFallback || ![afterDataContainer isEqualToString:beforeDataContainer]) {
                sandboxRestored = MCPRestoreAppDataContainer(sandboxBackupPath, afterDataContainer);
            }
            // Clean up temporary backup once verified
            MCPRunWithEffectiveUID(0, ^{
                [[NSFileManager defaultManager] removeItemAtPath:sandboxBackupPath error:nil];
            });
        }
        (void)completed;
    }

    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    result[@"operation"] = isDowngradeOp ? @"downgrade" : @"install";
    result[@"adam_id"] = @(adamId);
    if (bundleId.length) result[@"bundle_id"] = bundleId;
    if (targetExtId > 0) {
        result[@"target_app_ext_vrs_id"] = [NSString stringWithFormat:@"%llu", targetExtId];
        result[@"target_external_version_id"] = @(targetExtId);
    }
    if (resolvedTargetVersionString.length) {
        result[@"target_version"] = resolvedTargetVersionString;
    }
    result[@"purchase_dispatch"] = purchaseDispatch ?: @{};
    result[@"before_install"] = beforeInstallInfo ?: @{};
    result[@"after_install"] = afterInstallInfo ?: @{};
    result[@"clean_reinstall_fallback_used"] = @(usedCleanReinstallFallback);
    result[@"sandbox_data_preserved"] = @(preserveData && (sandboxRestored || !usedCleanReinstallFallback));
    result[@"stall_recovery_attempts"] = @(stallRecoveryCount);
    if (recoveryEvents.count > 0) {
        result[@"queue_recovery_events"] = recoveryEvents;
    }
    result[@"downloads"] = MCPQueryActiveStoreDownloads();
    return result;
}

#pragma mark - CLI Entry Point

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        MCPAppStoreLoadPrivateFrameworks();

        NSDictionary *req = nil;
        if (argc == 3 && strcmp(argv[1], "--req") == 0) {
            NSString *reqPath = [NSString stringWithUTF8String:argv[2]];
            NSData *raw = reqPath ? [NSData dataWithContentsOfFile:reqPath] : nil;
            if (raw) req = [NSJSONSerialization JSONObjectWithData:raw options:0 error:NULL];
        } else if (argc == 3 && strcmp(argv[1], "--b64") == 0) {
            NSString *b64 = [NSString stringWithUTF8String:argv[2]];
            NSData *raw = b64 ? [[NSData alloc] initWithBase64EncodedString:b64 options:0] : nil;
            if (raw) req = [NSJSONSerialization JSONObjectWithData:raw options:0 error:NULL];
        } else if (argc >= 2) {
            NSString *subcmd = [NSString stringWithUTF8String:argv[1]];
            NSMutableDictionary *cliReq = [NSMutableDictionary dictionary];
            cliReq[@"op"] = subcmd;
            if (argc >= 3) {
                NSString *arg2 = [NSString stringWithUTF8String:argv[2]];
                if ([subcmd isEqualToString:@"search"]) {
                    cliReq[@"query"] = arg2;
                } else {
                    uint64_t maybeAdam = strtoull(arg2.UTF8String, NULL, 10);
                    if (maybeAdam > 100000 && [arg2 rangeOfString:@"."].location == NSNotFound) {
                        cliReq[@"adam_id"] = @(maybeAdam);
                    } else {
                        cliReq[@"bundle_id"] = arg2;
                    }
                }
            }
            if (argc >= 4) {
                cliReq[@"version"] = [NSString stringWithUTF8String:argv[3]];
            }
            req = cliReq;
        }

        if (![req isKindOfClass:[NSDictionary class]]) {
            const char *err = "{\"ok\":false,\"error\":\"invalid mcp-appstore request\"}\n";
            fputs(err, stdout);
            return 1;
        }

        NSString *op = [req[@"op"] isKindOfClass:[NSString class]] ? req[@"op"]
            : ([req[@"action"] isKindOfClass:[NSString class]] ? req[@"action"] : @"search");
        NSString *errMsg = nil;
        NSDictionary *result = nil;

        if ([op isEqualToString:@"search"] || [op isEqualToString:@"versions"] || [op isEqualToString:@"search_and_versions"]) {
            NSString *query = [req[@"query"] isKindOfClass:[NSString class]] ? req[@"query"] : nil;
            NSString *bundleId = [req[@"bundle_id"] isKindOfClass:[NSString class]] ? req[@"bundle_id"] : nil;
            uint64_t adamId = [req[@"adam_id"] respondsToSelector:@selector(unsignedLongLongValue)]
                ? [req[@"adam_id"] unsignedLongLongValue]
                : ([req[@"track_id"] respondsToSelector:@selector(unsignedLongLongValue)] ? [req[@"track_id"] unsignedLongLongValue] : 0);
            NSString *country = [req[@"country"] isKindOfClass:[NSString class]] ? req[@"country"] : @"US";
            NSInteger limit = [req[@"limit"] respondsToSelector:@selector(integerValue)] ? [req[@"limit"] integerValue] : 10;
            if (limit < 1) limit = 1;
            if (limit > 50) limit = 50;
            BOOL includeVersions = (req[@"include_versions"] == nil) ? YES : [req[@"include_versions"] boolValue];

            if (bundleId.length > 0 || adamId > 0 || [op isEqualToString:@"versions"]) {
                result = MCPFetchVersionHistoryForApp(bundleId, adamId, country, &errMsg);
            } else if (query.length > 0) {
                NSString *escaped = [query stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLQueryAllowedCharacterSet]];
                NSString *searchURL = [NSString stringWithFormat:@"https://itunes.apple.com/search?term=%@&country=%@&entity=software&limit=%ld",
                                       escaped, country.uppercaseString, (long)limit];
                NSMutableURLRequest *httpReq = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:searchURL]];
                [httpReq setValue:@"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)" forHTTPHeaderField:@"User-Agent"];
                id json = MCPFetchJSONSynchronously(httpReq, NULL, 8.0, &errMsg);
                if ([json isKindOfClass:[NSDictionary class]]) {
                    NSArray *rawResults = [json[@"results"] isKindOfClass:[NSArray class]] ? json[@"results"] : @[];
                    NSMutableArray *items = [NSMutableArray arrayWithCapacity:rawResults.count];
                    for (id r in rawResults) {
                        if ([r isKindOfClass:[NSDictionary class]]) {
                            [items addObject:MCPFormatITunesTrackItem(r)];
                        }
                    }
                    NSMutableDictionary *searchRes = [NSMutableDictionary dictionary];
                    searchRes[@"query"] = query;
                    searchRes[@"country"] = country.uppercaseString;
                    searchRes[@"count"] = @(items.count);
                    searchRes[@"results"] = items;

                    if (includeVersions && items.count > 0) {
                        NSDictionary *top = items.firstObject;
                        uint64_t topAdam = [top[@"adam_id"] respondsToSelector:@selector(unsignedLongLongValue)] ? [top[@"adam_id"] unsignedLongLongValue] : 0;
                        NSString *topBid = [top[@"bundle_id"] isKindOfClass:[NSString class]] ? top[@"bundle_id"] : nil;
                        if (topAdam > 0) {
                            NSDictionary *topHist = MCPFetchVersionHistoryForApp(topBid, topAdam, country, NULL);
                            if (topHist) {
                                searchRes[@"top_match_version_history"] = topHist;
                            }
                        }
                    }
                    result = searchRes;
                }
            } else {
                errMsg = @"Provide query, bundle_id, or adam_id";
            }
        } else if ([op isEqualToString:@"install"]) {
            result = MCPPerformInstallOrDowngrade(req, NO, &errMsg);
        } else if ([op isEqualToString:@"downgrade"]) {
            result = MCPPerformInstallOrDowngrade(req, YES, &errMsg);
        } else if ([op isEqualToString:@"status"]) {
            result = @{
                @"store_account": MCPResolveActiveStoreAccount(NULL),
                @"downloads": MCPQueryActiveStoreDownloads()
            };
        } else if ([op isEqualToString:@"cancel_downloads"]) {
            NSString *bundleId = [req[@"bundle_id"] isKindOfClass:[NSString class]] ? req[@"bundle_id"] : nil;
            result = MCPCancelStoreDownloadsForApp(bundleId);
        } else if ([op isEqualToString:@"resume_downloads"]) {
            NSString *bundleId = [req[@"bundle_id"] isKindOfClass:[NSString class]] ? req[@"bundle_id"] : nil;
            result = MCPResumeStoreDownloadsForApp(bundleId);
        } else {
            errMsg = [NSString stringWithFormat:@"Unsupported mcp-appstore op: %@", op];
        }

        NSDictionary *response = result
            ? @{@"ok": @YES, @"result": result}
            : @{@"ok": @NO, @"error": errMsg ?: @"mcp-appstore operation failed"};

        NSData *outJSON = [NSJSONSerialization dataWithJSONObject:response options:0 error:NULL];
        if (!outJSON) return 2;
        fwrite(outJSON.bytes, 1, outJSON.length, stdout);
        fputc('\n', stdout);
        return [response[@"ok"] boolValue] ? 0 : 1;
    }
}
