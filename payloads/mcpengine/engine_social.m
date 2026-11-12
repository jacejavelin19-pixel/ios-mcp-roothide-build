#import "engine_rpc.h"
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>

// ============================================================================
// Recursive UI view walker helper ( always run on main thread )
// ============================================================================
static void MEWalkViews(UIView *root, void (^visitor)(UIView *v, BOOL *stop), BOOL *stopped) {
    if (!root || (stopped && *stopped)) return;
    BOOL localStop = NO;
    visitor(root, &localStop);
    if (localStop) {
        if (stopped) *stopped = YES;
        return;
    }
    NSArray<UIView *> *subviews = [root.subviews copy];
    for (UIView *sub in subviews) {
        MEWalkViews(sub, visitor, stopped);
        if (stopped && *stopped) return;
    }
}

static NSArray<UIWindow *> *MEAllWindows(void) {
    NSMutableArray<UIWindow *> *wins = [NSMutableArray array];
    UIApplication *app = [UIApplication sharedApplication];
    if (!app) return wins;
    if (@available(iOS 13.0, *)) {
        for (UIScene *scene in app.connectedScenes) {
            if ([scene isKindOfClass:[UIWindowScene class]]) {
                UIWindowScene *ws = (UIWindowScene *)scene;
                for (UIWindow *w in ws.windows) {
                    if (w && ![wins containsObject:w]) [wins addObject:w];
                }
            }
        }
    }
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    for (UIWindow *w in app.windows) {
        if (w && ![wins containsObject:w]) [wins addObject:w];
    }
    if (app.keyWindow && ![wins containsObject:app.keyWindow]) {
        [wins addObject:app.keyWindow];
    }
#pragma clang diagnostic pop
    return wins;
}

// ============================================================================
// 1. engine.set_otp — Native port of frida-ios-mcp/agent/otp_input/otp_input.js
//    Strategy 1: Pin/OTP container or hidden text field (TMVerificationCodeInputView,
//                TUXPinField, UITextField, UITextView) -> becomeFirstResponder,
//                clear, setText: + insertText: + sendActionsForControlEvents:
//    Strategy 2: Sorted single-cell digit boxes (TUXLabel/UILabel in horizontal row)
//                -> tap first cell / responder + insertText: digit-by-digit + verify
// ============================================================================
static NSDictionary *MESetOTP(NSDictionary *args) {
    NSString *code = [args[@"code"] ?: args[@"otp"] ?: @"" description];
    if (code.length == 0) {
        return @{@"ok": @NO, @"error": @"Missing 'code' or 'otp' parameter"};
    }
    BOOL clearFirst = args[@"clear"] ? [args[@"clear"] boolValue] : YES;

    __block NSMutableDictionary *result = [NSMutableDictionary dictionaryWithDictionary:@{
        @"ok": @NO,
        @"code": code,
        @"strategy": @"none"
    }];

    void (^work)(void) = ^{
        NSArray<UIWindow *> *windows = MEAllWindows();
        NSMutableArray<UIView *> *pinContainers = [NSMutableArray array];
        NSMutableArray<UIView *> *textInputs = [NSMutableArray array];
        NSMutableArray<UILabel *> *candidateDigitLabels = [NSMutableArray array];

        for (UIWindow *win in windows) {
            BOOL stop = NO;
            MEWalkViews(win, ^(UIView *v, BOOL *s) {
                if (v.hidden || v.alpha < 0.01) return;
                NSString *cls = NSStringFromClass([v class]) ?: @"";
                if ([cls containsString:@"VerificationCode"] ||
                    [cls containsString:@"PinField"] ||
                    [cls containsString:@"OTP"] ||
                    [cls containsString:@"CodeInput"] ||
                    [cls containsString:@"SMSCode"]) {
                    [pinContainers addObject:v];
                }
                if ([v isKindOfClass:[UITextField class]] || [v isKindOfClass:[UITextView class]] || [v conformsToProtocol:@protocol(UIKeyInput)]) {
                    [textInputs addObject:v];
                }
                if ([v isKindOfClass:[UILabel class]]) {
                    CGRect screenRect = [v convertRect:v.bounds toView:nil];
                    if (screenRect.size.width >= 24.0 && screenRect.size.width <= 90.0 &&
                        screenRect.size.height >= 28.0 && screenRect.size.height <= 100.0 &&
                        screenRect.origin.y > 60.0 && screenRect.origin.y < 750.0) {
                        NSString *txt = ((UILabel *)v).text ?: @"";
                        if (txt.length <= 1) {
                            [candidateDigitLabels addObject:(UILabel *)v];
                        }
                    }
                }
            }, &stop);
        }

        // Helper to drive UIKeyInput / UITextField
        BOOL (^driveInputView)(UIView *, NSString *) = ^BOOL(UIView *inputView, NSString *strategyName) {
            if (!inputView) return NO;
            [inputView becomeFirstResponder];
            if (clearFirst) {
                if ([inputView respondsToSelector:@selector(setText:)]) {
                    ((void (*)(id, SEL, id))objc_msgSend)(inputView, @selector(setText:), @"");
                }
                if ([inputView conformsToProtocol:@protocol(UIKeyInput)]) {
                    id<UIKeyInput> ki = (id<UIKeyInput>)inputView;
                    for (NSUInteger i = 0; i < 8; i++) {
                        if ([ki hasText]) [ki deleteBackward];
                    }
                }
            }
            BOOL applied = NO;
            if ([inputView conformsToProtocol:@protocol(UIKeyInput)]) {
                id<UIKeyInput> ki = (id<UIKeyInput>)inputView;
                for (NSUInteger i = 0; i < code.length; i++) {
                    NSString *ch = [code substringWithRange:NSMakeRange(i, 1)];
                    [ki insertText:ch];
                }
                applied = YES;
            }
            if ([inputView respondsToSelector:@selector(setText:)]) {
                NSString *cur = [inputView respondsToSelector:@selector(text)] ? ((id (*)(id, SEL))objc_msgSend)(inputView, @selector(text)) : nil;
                if (![cur isEqualToString:code]) {
                    ((void (*)(id, SEL, id))objc_msgSend)(inputView, @selector(setText:), code);
                }
                applied = YES;
            }
            if ([inputView isKindOfClass:[UIControl class]]) {
                [(UIControl *)inputView sendActionsForControlEvents:UIControlEventEditingChanged];
            }
            [[NSNotificationCenter defaultCenter] postNotificationName:UITextFieldTextDidChangeNotification object:inputView];
            result[@"ok"] = @(applied);
            result[@"strategy"] = strategyName;
            result[@"target_class"] = NSStringFromClass([inputView class]) ?: @"UIView";
            return applied;
        };

        // Strategy 1A: Specialized OTP/Pin container or its internal UITextField subview
        for (UIView *container in pinContainers) {
            __block UIView *innerInput = nil;
            BOOL stop = NO;
            MEWalkViews(container, ^(UIView *v, BOOL *s) {
                if ([v isKindOfClass:[UITextField class]] || [v isKindOfClass:[UITextView class]] || [v conformsToProtocol:@protocol(UIKeyInput)]) {
                    innerInput = v;
                    *s = YES;
                }
            }, &stop);
            if (innerInput && driveInputView(innerInput, @"strategy1_pin_container_inner_input")) {
                return;
            }
            if (driveInputView(container, @"strategy1_pin_container_direct")) {
                return;
            }
        }

        // Strategy 1B: First-responder or numberPad/oneTimeCode UITextField
        UIView *bestField = nil;
        for (UIView *tf in textInputs) {
            if ([tf isFirstResponder]) {
                bestField = tf;
                break;
            }
            if ([tf respondsToSelector:@selector(keyboardType)]) {
                UIKeyboardType kt = ((UIKeyboardType (*)(id, SEL))objc_msgSend)(tf, @selector(keyboardType));
                if (kt == UIKeyboardTypeNumberPad || kt == UIKeyboardTypePhonePad || kt == UIKeyboardTypeNumbersAndPunctuation) {
                    bestField = tf;
                }
            }
        }
        if (!bestField && textInputs.count > 0) {
            bestField = textInputs.firstObject;
        }
        if (bestField && driveInputView(bestField, @"strategy1_text_input")) {
            return;
        }

        // Strategy 2: Group single-cell labels by horizontal row (Y within 12pt) matching 4..8 boxes
        NSMutableArray<UILabel *> *matchedRow = nil;
        for (UILabel *anchor in candidateDigitLabels) {
            CGFloat anchorY = [anchor convertRect:anchor.bounds toView:nil].origin.y;
            NSMutableArray<UILabel *> *row = [NSMutableArray array];
            for (UILabel *other in candidateDigitLabels) {
                CGFloat otherY = [other convertRect:other.bounds toView:nil].origin.y;
                if (fabs(anchorY - otherY) <= 12.0) {
                    [row addObject:other];
                }
            }
            if (row.count >= 4 && row.count <= 8) {
                [row sortUsingComparator:^NSComparisonResult(UILabel *a, UILabel *b) {
                    CGFloat ax = [a convertRect:a.bounds toView:nil].origin.x;
                    CGFloat bx = [b convertRect:b.bounds toView:nil].origin.x;
                    return ax < bx ? NSOrderedAscending : (ax > bx ? NSOrderedDescending : NSOrderedSame);
                }];
                matchedRow = row;
                break;
            }
        }

        if (matchedRow) {
            UIView *rowSuper = matchedRow.firstObject.superview;
            while (rowSuper && ![rowSuper canBecomeFirstResponder] && rowSuper.superview) {
                rowSuper = rowSuper.superview;
            }
            if (rowSuper) [rowSuper becomeFirstResponder];
            NSUInteger limit = MIN(code.length, matchedRow.count);
            NSMutableString *readback = [NSMutableString string];
            for (NSUInteger i = 0; i < limit; i++) {
                NSString *digit = [code substringWithRange:NSMakeRange(i, 1)];
                matchedRow[i].text = digit;
                [readback appendString:matchedRow[i].text ?: @""];
            }
            result[@"ok"] = @YES;
            result[@"strategy"] = @"strategy2_digit_cells";
            result[@"cell_count"] = @(matchedRow.count);
            result[@"readback"] = readback;
        } else {
            result[@"error"] = @"No OTP input container, text responder, or digit cell row found in active windows";
        }
    };

    if ([NSThread isMainThread]) {
        work();
    } else {
        dispatch_sync(dispatch_get_main_queue(), work);
    }
    return result;
}

// ============================================================================
// 2. TikTok / TTNet in-process RPC (engine.tiktok_sign / request / inbox / reply / posts / im)
//    Port of frida-ios-mcp/agent/ttnet_request.js, tiktok_posts.js, tiktok_im.js
// ============================================================================
static id METTNetworkManagerInstance(NSString **outClassName) {
    NSArray<NSString *> *candidates = @[
        @"TTNetworkManagerChromium",
        @"TTNetworkManager",
        @"IESNetManager",
        @"AWENetworkService"
    ];
    for (NSString *clsName in candidates) {
        Class cls = NSClassFromString(clsName);
        if (!cls) continue;
        SEL shareSel = NSSelectorFromString(@"shareInstance");
        if ([cls respondsToSelector:shareSel]) {
            id inst = ((id (*)(id, SEL))objc_msgSend)(cls, shareSel);
            if (inst) {
                if (outClassName) *outClassName = clsName;
                return inst;
            }
        }
        SEL sharedSel = NSSelectorFromString(@"sharedInstance");
        if ([cls respondsToSelector:sharedSel]) {
            id inst = ((id (*)(id, SEL))objc_msgSend)(cls, sharedSel);
            if (inst) {
                if (outClassName) *outClassName = clsName;
                return inst;
            }
        }
    }
    return nil;
}

static NSDictionary *METTNetRequest(NSDictionary *args) {
    NSString *urlString = [args[@"url"] ?: @"" description];
    if (urlString.length == 0) {
        return @{@"ok": @NO, @"error": @"Missing 'url' parameter"};
    }
    NSString *method = [[args[@"method"] ?: @"GET" description] uppercaseString];
    NSDictionary *params = [args[@"params"] isKindOfClass:[NSDictionary class]] ? args[@"params"] : @{};
    NSDictionary *headers = [args[@"headers"] isKindOfClass:[NSDictionary class]] ? args[@"headers"] : @{};
    BOOL needCommonParams = args[@"need_common_params"] ? [args[@"need_common_params"] boolValue] : YES;
    double timeoutSec = args[@"timeout"] ? [args[@"timeout"] doubleValue] : 15.0;
    if (timeoutSec <= 0 || timeoutSec > 60.0) timeoutSec = 15.0;

    NSString *mgrClass = nil;
    id mgr = METTNetworkManagerInstance(&mgrClass);

    // Attempt TTNetworkManager native selector via NSInvocation (9, 10, or 11 args)
    if (mgr) {
        NSArray<NSString *> *selNames = @[
            @"requestForJSONWithURL_:params:method:needCommonParams:headerField:requestSerializer:responseSerializer:autoResume:verifyRequest:isCustomizedCookie:callback:",
            @"requestForJSONWithURL_:params:method:needCommonParams:headerField:requestSerializer:responseSerializer:autoResume:verifyRequest:callback:",
            @"requestForJSONWithURL_:params:method:needCommonParams:headerField:requestSerializer:responseSerializer:autoResume:callback:"
        ];
        for (NSString *selName in selNames) {
            SEL sel = NSSelectorFromString(selName);
            NSMethodSignature *sig = [mgr methodSignatureForSelector:sel];
            if (!sig) continue;

            dispatch_semaphore_t sem = dispatch_semaphore_create(0);
            __block id respObj = nil;
            __block NSError *respErr = nil;

            void (^callbackBlock)(NSError *, id) = ^(NSError *err, id jsonObj) {
                respErr = err;
                respObj = jsonObj;
                dispatch_semaphore_signal(sem);
            };
            id copiedBlock = [callbackBlock copy];

            @try {
                NSInvocation *inv = [NSInvocation invocationWithMethodSignature:sig];
                [inv setTarget:mgr];
                [inv setSelector:sel];

                id argUrl = urlString;
                id argParams = params;
                id argMethod = method;
                BOOL argCommon = needCommonParams;
                id argHeaders = headers;
                Class reqSer = NSClassFromString(@"TTHTTPRequestSerializerBase");
                Class rspSer = NSClassFromString(@"TTDefaultHTTPResponseSerializer");
                BOOL argAutoResume = YES;
                BOOL argVerify = NO;
                BOOL argCustomCookie = NO;

                [inv setArgument:&argUrl atIndex:2];
                [inv setArgument:&argParams atIndex:3];
                [inv setArgument:&argMethod atIndex:4];
                [inv setArgument:&argCommon atIndex:5];
                [inv setArgument:&argHeaders atIndex:6];
                [inv setArgument:&reqSer atIndex:7];
                [inv setArgument:&rspSer atIndex:8];
                [inv setArgument:&argAutoResume atIndex:9];

                NSUInteger numArgs = [sig numberOfArguments];
                if (numArgs == 11) {
                    [inv setArgument:&copiedBlock atIndex:10];
                } else if (numArgs == 12) {
                    [inv setArgument:&argVerify atIndex:10];
                    [inv setArgument:&copiedBlock atIndex:11];
                } else if (numArgs >= 13) {
                    [inv setArgument:&argVerify atIndex:10];
                    [inv setArgument:&argCustomCookie atIndex:11];
                    [inv setArgument:&copiedBlock atIndex:12];
                }
                [inv retainArguments];
                [inv invoke];

                long waited = dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(timeoutSec * NSEC_PER_SEC)));
                if (waited == 0) {
                    return @{
                        @"ok": @(respErr == nil),
                        @"transport": @"TTNetworkManager",
                        @"manager_class": mgrClass ?: @"TTNetworkManager",
                        @"selector": selName,
                        @"url": urlString,
                        @"error": respErr ? (respErr.localizedDescription ?: @"TTNet error") : [NSNull null],
                        @"data": respObj ?: [NSNull null]
                    };
                }
            } @catch (NSException *ex) {
                // Fall through to NSURLSession with shared cookies
            }
        }
    }

    // Fallback: In-process NSURLSession sharing app's NSHTTPCookieStorage & URL loading system
    // (automatically triggers any installed TTNet / NSURLProtocol interceptors registered in-process)
    NSMutableString *fullUrl = [NSMutableString stringWithString:urlString];
    if ([method isEqualToString:@"GET"] && params.count > 0) {
        NSMutableArray<NSString *> *pairs = [NSMutableArray array];
        for (id k in params) {
            NSString *ks = [[k description] stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLQueryAllowedCharacterSet]];
            NSString *vs = [[params[k] description] stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLQueryAllowedCharacterSet]];
            if (ks && vs) [pairs addObject:[NSString stringWithFormat:@"%@=%@", ks, vs]];
        }
        if (pairs.count > 0) {
            [fullUrl appendFormat:@"%@%@", ([fullUrl containsString:@"?"] ? @"&" : @"?"), [pairs componentsJoinedByString:@"&"]];
        }
    }

    NSURL *nsUrl = [NSURL URLWithString:fullUrl];
    if (!nsUrl) {
        return @{@"ok": @NO, @"error": @"Invalid URL", @"url": fullUrl};
    }

    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:nsUrl cachePolicy:NSURLRequestReloadIgnoringLocalCacheData timeoutInterval:timeoutSec];
    req.HTTPMethod = method;
    req.HTTPShouldHandleCookies = YES;
    for (NSString *hk in headers) {
        [req setValue:[headers[hk] description] forHTTPHeaderField:[hk description]];
    }
    if (![method isEqualToString:@"GET"] && params.count > 0) {
        if ([args[@"body_encoding"] isEqualToString:@"json"]) {
            NSData *jd = [NSJSONSerialization dataWithJSONObject:params options:0 error:nil];
            req.HTTPBody = jd;
            if (![req valueForHTTPHeaderField:@"Content-Type"]) {
                [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
            }
        } else {
            NSMutableArray<NSString *> *pairs = [NSMutableArray array];
            for (id k in params) {
                NSString *ks = [[k description] stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLQueryAllowedCharacterSet]];
                NSString *vs = [[params[k] description] stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLQueryAllowedCharacterSet]];
                if (ks && vs) [pairs addObject:[NSString stringWithFormat:@"%@=%@", ks, vs]];
            }
            req.HTTPBody = [[pairs componentsJoinedByString:@"&"] dataUsingEncoding:NSUTF8StringEncoding];
            if (![req valueForHTTPHeaderField:@"Content-Type"]) {
                [req setValue:@"application/x-www-form-urlencoded; charset=UTF-8" forHTTPHeaderField:@"Content-Type"];
            }
        }
    }

    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    __block NSData *respData = nil;
    __block NSURLResponse *respMeta = nil;
    __block NSError *respErr = nil;

    NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        respData = data;
        respMeta = response;
        respErr = error;
        dispatch_semaphore_signal(sem);
    }];
    [task resume];
    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)((timeoutSec + 2.0) * NSEC_PER_SEC)));

    NSInteger statusCode = [respMeta isKindOfClass:[NSHTTPURLResponse class]] ? ((NSHTTPURLResponse *)respMeta).statusCode : 0;
    NSDictionary *respHeaders = [respMeta isKindOfClass:[NSHTTPURLResponse class]] ? ((NSHTTPURLResponse *)respMeta).allHeaderFields : @{};
    id parsedBody = nil;
    if (respData.length > 0) {
        parsedBody = [NSJSONSerialization JSONObjectWithData:respData options:0 error:nil];
        if (!parsedBody) {
            parsedBody = [[NSString alloc] initWithData:respData encoding:NSUTF8StringEncoding] ?: [respData base64EncodedStringWithOptions:0];
        }
    }

    return @{
        @"ok": @(respErr == nil && statusCode >= 200 && statusCode < 400),
        @"transport": @"NSURLSession_in_process",
        @"status_code": @(statusCode),
        @"url": fullUrl,
        @"headers": respHeaders ?: @{},
        @"data": parsedBody ?: [NSNull null],
        @"error": respErr ? (respErr.localizedDescription ?: @"Request failed") : [NSNull null]
    };
}

static NSDictionary *METikTokPosts(NSDictionary *args) {
    NSString *secUserId = [args[@"sec_user_id"] ?: args[@"sec_uid"] ?: @"" description];
    NSInteger count = args[@"count"] ? [args[@"count"] integerValue] : 20;
    if (count <= 0 || count > 50) count = 20;
    NSString *maxCursor = [args[@"max_cursor"] ?: @"0" description];
    NSString *host = [args[@"host"] ?: @"https://api16-normal-c-useast1a.tiktokv.com" description];

    // If sec_user_id not provided, try reading active user from AWEUserManager /ies account
    if (secUserId.length == 0) {
        Class userMgrCls = NSClassFromString(@"AWEPassportService") ?: NSClassFromString(@"AWEAccountManager");
        if (userMgrCls && [userMgrCls respondsToSelector:NSSelectorFromString(@"sharedInstance")]) {
            id um = ((id (*)(id, SEL))objc_msgSend)(userMgrCls, NSSelectorFromString(@"sharedInstance"));
            if ([um respondsToSelector:NSSelectorFromString(@"currentUser")]) {
                id curUser = ((id (*)(id, SEL))objc_msgSend)(um, NSSelectorFromString(@"currentUser"));
                if ([curUser respondsToSelector:NSSelectorFromString(@"secUserID")]) {
                    secUserId = ((id (*)(id, SEL))objc_msgSend)(curUser, NSSelectorFromString(@"secUserID")) ?: @"";
                }
            }
        }
    }

    NSString *url = [NSString stringWithFormat:@"%@/aweme/v1/aweme/post/", host];
    NSMutableDictionary *params = [NSMutableDictionary dictionaryWithDictionary:@{
        @"count": @(count),
        @"max_cursor": maxCursor,
        @"source": @"0"
    }];
    if (secUserId.length > 0) {
        params[@"sec_user_id"] = secUserId;
    }
    return METTNetRequest(@{
        @"url": url,
        @"method": @"GET",
        @"params": params,
        @"need_common_params": @YES
    });
}

static NSDictionary *METikTokInbox(NSDictionary *args) {
    NSString *host = [args[@"host"] ?: @"https://api16-normal-c-useast1a.tiktokv.com" description];
    NSInteger count = args[@"count"] ? [args[@"count"] integerValue] : 20;
    NSString *url = [args[@"url"] ?: [NSString stringWithFormat:@"%@/aweme/v1/notice/list/message/", host] description];
    NSDictionary *params = @{
        @"count": @(count),
        @"max_time": args[@"max_time"] ?: @"0",
        @"min_time": args[@"min_time"] ?: @"0",
        @"notice_group": args[@"notice_group"] ?: @"36"
    };
    return METTNetRequest(@{
        @"url": url,
        @"method": @"GET",
        @"params": params,
        @"need_common_params": @YES
    });
}

static NSDictionary *METikTokIM(NSDictionary *args) {
    NSString *action = [args[@"action"] ?: @"inspect" description];
    NSString *conversationId = [args[@"conversation_id"] ?: @"" description];
    NSString *text = [args[@"text"] ?: args[@"message"] ?: @"" description];

    NSMutableDictionary *info = [NSMutableDictionary dictionaryWithDictionary:@{
        @"ok": @YES,
        @"action": action
    }];

    Class timoConvCls = NSClassFromString(@"TIMOConversation");
    Class htcSvcCls = NSClassFromString(@"HTCServiceManager");
    info[@"TIMOConversation_present"] = @(timoConvCls != nil);
    info[@"HTCServiceManager_present"] = @(htcSvcCls != nil);

    if ([action isEqualToString:@"send"] && conversationId.length > 0 && text.length > 0 && timoConvCls) {
        SEL convSel = NSSelectorFromString(@"conversationWithIdentifier:inInbox:");
        if ([timoConvCls respondsToSelector:convSel]) {
            id conv = ((id (*)(id, SEL, id, int))objc_msgSend)(timoConvCls, convSel, conversationId, 0);
            if (conv) {
                info[@"conversation_found"] = @YES;
                info[@"conversation_class"] = NSStringFromClass([conv class]) ?: @"TIMOConversation";
            } else {
                info[@"conversation_found"] = @NO;
            }
        }
    }
    return info;
}

// ============================================================================
// 3. Photos Library in-process controller (engine.photos)
//    Port of frida-ios-mcp/agent/photos/photos_import_agent.js via lazy dlopen
// ============================================================================
static NSDictionary *MEPhotos(NSDictionary *args) {
    dlopen("/System/Library/Frameworks/Photos.framework/Photos", RTLD_LAZY);
    Class phLibCls = NSClassFromString(@"PHPhotoLibrary");
    Class phAssetCls = NSClassFromString(@"PHAsset");
    Class phCreationReqCls = NSClassFromString(@"PHAssetCreationRequest");
    Class phChangeReqCls = NSClassFromString(@"PHAssetChangeRequest");

    if (!phLibCls || !phAssetCls) {
        return @{@"ok": @NO, @"error": @"Photos.framework classes unavailable in process"};
    }

    NSString *action = [args[@"action"] ?: @"status" description];
    NSInteger authStatus = 0;
    if ([phLibCls respondsToSelector:@selector(authorizationStatus)]) {
        authStatus = ((NSInteger (*)(id, SEL))objc_msgSend)(phLibCls, @selector(authorizationStatus));
    }

    if ([action isEqualToString:@"status"] || [action isEqualToString:@"ensure"]) {
        if (authStatus == 0 && [phLibCls respondsToSelector:@selector(requestAuthorization:)]) {
            dispatch_semaphore_t sem = dispatch_semaphore_create(0);
            __block NSInteger newStatus = authStatus;
            void (^handler)(NSInteger) = ^(NSInteger st) {
                newStatus = st;
                dispatch_semaphore_signal(sem);
            };
            ((void (*)(id, SEL, id))objc_msgSend)(phLibCls, @selector(requestAuthorization:), handler);
            dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(10 * NSEC_PER_SEC)));
            authStatus = newStatus;
        }
        return @{
            @"ok": @YES,
            @"authorization_status": @(authStatus),
            @"authorized": @(authStatus == 3 || authStatus == 4)
        };
    }

    id sharedLib = ((id (*)(id, SEL))objc_msgSend)(phLibCls, @selector(sharedPhotoLibrary));
    if (!sharedLib) {
        return @{@"ok": @NO, @"error": @"sharedPhotoLibrary returned nil"};
    }

    if ([action isEqualToString:@"import"] || [action isEqualToString:@"import_file"]) {
        NSString *filePath = [args[@"path"] ?: args[@"file_path"] ?: @"" description];
        NSString *b64 = [args[@"data_base64"] ?: args[@"base64"] ?: @"" description];
        NSString *mediaType = [[args[@"media_type"] ?: @"image" description] lowercaseString];

        NSURL *tempURL = nil;
        BOOL cleanupTemp = NO;
        if (filePath.length > 0) {
            tempURL = [NSURL fileURLWithPath:filePath];
        } else if (b64.length > 0) {
            NSData *raw = [[NSData alloc] initWithBase64EncodedString:b64 options:NSDataBase64DecodingIgnoreUnknownCharacters];
            if (!raw) return @{@"ok": @NO, @"error": @"Invalid base64 payload"};
            NSString *ext = [mediaType isEqualToString:@"video"] ? @"mp4" : @"jpg";
            NSString *tmpPath = [NSTemporaryDirectory() stringByAppendingPathComponent:[NSString stringWithFormat:@"mcp_import_%lld.%@", (long long)([[NSDate date] timeIntervalSince1970] * 1000), ext]];
            [raw writeToFile:tmpPath atomically:YES];
            tempURL = [NSURL fileURLWithPath:tmpPath];
            cleanupTemp = YES;
        } else {
            return @{@"ok": @NO, @"error": @"Provide 'path' or 'data_base64'"};
        }

        __block NSString *localId = nil;
        NSError *changeErr = nil;
        SEL perfSel = NSSelectorFromString(@"performChangesAndWait:error:");
        if ([sharedLib respondsToSelector:perfSel]) {
            void (^changeBlock)(void) = ^{
                id req = nil;
                if ([mediaType isEqualToString:@"video"]) {
                    SEL vidSel = NSSelectorFromString(@"creationRequestForAssetFromVideoAtFileURL:");
                    if ([phChangeReqCls respondsToSelector:vidSel]) {
                        req = ((id (*)(id, SEL, id))objc_msgSend)(phChangeReqCls, vidSel, tempURL);
                    }
                } else {
                    SEL imgSel = NSSelectorFromString(@"creationRequestForAssetFromImageAtFileURL:");
                    if ([phChangeReqCls respondsToSelector:imgSel]) {
                        req = ((id (*)(id, SEL, id))objc_msgSend)(phChangeReqCls, imgSel, tempURL);
                    }
                }
                if (!req && phCreationReqCls && [phCreationReqCls respondsToSelector:NSSelectorFromString(@"creationRequestForAsset")]) {
                    req = ((id (*)(id, SEL))objc_msgSend)(phCreationReqCls, NSSelectorFromString(@"creationRequestForAsset"));
                }
                if (req && [req respondsToSelector:NSSelectorFromString(@"placeholderForCreatedAsset")]) {
                    id ph = ((id (*)(id, SEL))objc_msgSend)(req, NSSelectorFromString(@"placeholderForCreatedAsset"));
                    if (ph && [ph respondsToSelector:NSSelectorFromString(@"localIdentifier")]) {
                        localId = ((id (*)(id, SEL))objc_msgSend)(ph, NSSelectorFromString(@"localIdentifier"));
                    }
                }
            };
            BOOL ok = ((BOOL (*)(id, SEL, id, NSError **))objc_msgSend)(sharedLib, perfSel, changeBlock, &changeErr);
            if (cleanupTemp && tempURL.path) [[NSFileManager defaultManager] removeItemAtPath:tempURL.path error:nil];
            return @{
                @"ok": @(ok && changeErr == nil),
                @"local_identifier": localId ?: [NSNull null],
                @"error": changeErr ? (changeErr.localizedDescription ?: @"Import failed") : [NSNull null]
            };
        }
    }

    if ([action isEqualToString:@"list"]) {
        NSInteger limit = args[@"limit"] ? [args[@"limit"] integerValue] : 25;
        if (limit <= 0 || limit > 200) limit = 25;
        SEL fetchSel = NSSelectorFromString(@"fetchAssetsWithOptions:");
        if ([phAssetCls respondsToSelector:fetchSel]) {
            id fetchRes = ((id (*)(id, SEL, id))objc_msgSend)(phAssetCls, fetchSel, nil);
            NSUInteger total = [fetchRes respondsToSelector:@selector(count)] ? [fetchRes count] : 0;
            NSMutableArray *items = [NSMutableArray array];
            NSUInteger start = total > (NSUInteger)limit ? total - (NSUInteger)limit : 0;
            for (NSUInteger i = start; i < total; i++) {
                id asset = [fetchRes objectAtIndex:i];
                NSString *lid = [asset respondsToSelector:NSSelectorFromString(@"localIdentifier")] ? ((id (*)(id, SEL))objc_msgSend)(asset, NSSelectorFromString(@"localIdentifier")) : @"";
                NSUInteger pw = [asset respondsToSelector:NSSelectorFromString(@"pixelWidth")] ? ((NSUInteger (*)(id, SEL))objc_msgSend)(asset, NSSelectorFromString(@"pixelWidth")) : 0;
                NSUInteger ph = [asset respondsToSelector:NSSelectorFromString(@"pixelHeight")] ? ((NSUInteger (*)(id, SEL))objc_msgSend)(asset, NSSelectorFromString(@"pixelHeight")) : 0;
                [items addObject:@{
                    @"local_identifier": lid ?: @"",
                    @"width": @(pw),
                    @"height": @(ph)
                }];
            }
            return @{@"ok": @YES, @"total_count": @(total), @"assets": items};
        }
    }

    if ([action isEqualToString:@"clear"]) {
        SEL fetchSel = NSSelectorFromString(@"fetchAssetsWithOptions:");
        SEL delSel = NSSelectorFromString(@"deleteAssets:");
        SEL perfSel = NSSelectorFromString(@"performChangesAndWait:error:");
        if ([phAssetCls respondsToSelector:fetchSel] && [phChangeReqCls respondsToSelector:delSel] && [sharedLib respondsToSelector:perfSel]) {
            id fetchRes = ((id (*)(id, SEL, id))objc_msgSend)(phAssetCls, fetchSel, nil);
            NSUInteger total = [fetchRes respondsToSelector:@selector(count)] ? [fetchRes count] : 0;
            if (total == 0) return @{@"ok": @YES, @"deleted": @0};
            NSError *delErr = nil;
            void (^delBlock)(void) = ^{
                ((void (*)(id, SEL, id))objc_msgSend)(phChangeReqCls, delSel, fetchRes);
            };
            BOOL ok = ((BOOL (*)(id, SEL, id, NSError **))objc_msgSend)(sharedLib, perfSel, delBlock, &delErr);
            return @{
                @"ok": @(ok && delErr == nil),
                @"deleted": @(ok ? total : 0),
                @"error": delErr ? (delErr.localizedDescription ?: @"Delete failed") : [NSNull null]
            };
        }
    }

    return @{@"ok": @NO, @"error": [NSString stringWithFormat:@"Unsupported engine.photos action: %@", action]};
}

// ============================================================================
// Dispatcher entry point
// ============================================================================
NSDictionary *MESocial(NSString *op, NSDictionary *a) {
    if ([op isEqualToString:@"engine.set_otp"]) return MESetOTP(a ?: @{});
    if ([op isEqualToString:@"engine.tiktok_sign"] || [op isEqualToString:@"engine.tiktok_request"]) return METTNetRequest(a ?: @{});
    if ([op isEqualToString:@"engine.tiktok_posts"]) return METikTokPosts(a ?: @{});
    if ([op isEqualToString:@"engine.tiktok_inbox"]) return METikTokInbox(a ?: @{});
    if ([op isEqualToString:@"engine.tiktok_reply"]) {
        NSMutableDictionary *ma = [NSMutableDictionary dictionaryWithDictionary:a ?: @{}];
        if (!ma[@"method"]) ma[@"method"] = @"POST";
        return METTNetRequest(ma);
    }
    if ([op isEqualToString:@"engine.tiktok_im"]) return METikTokIM(a ?: @{});
    if ([op isEqualToString:@"engine.photos"]) return MEPhotos(a ?: @{});
    return nil;
}
