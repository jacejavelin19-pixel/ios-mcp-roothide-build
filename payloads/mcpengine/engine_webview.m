#import "engine_rpc.h"
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <JavaScriptCore/JavaScriptCore.h>
#import <objc/runtime.h>
#import <objc/message.h>

static void MEWebViewFindInView(UIView *root, NSMutableArray<WKWebView *> *outWebViews) {
    if (!root) return;
    Class wkCls = objc_getClass("WKWebView");
    if (wkCls && [root isKindOfClass:wkCls]) {
        if (![outWebViews containsObject:(WKWebView *)root]) {
            [outWebViews addObject:(WKWebView *)root];
        }
    }
    for (UIView *sub in root.subviews) {
        MEWebViewFindInView(sub, outWebViews);
    }
}

static NSArray<WKWebView *> *MECollectAllWKWebViews(void) {
    NSMutableArray<WKWebView *> *views = [NSMutableArray array];
    void (^scanBlock)(void) = ^{
        UIApplication *app = [UIApplication sharedApplication];
        if (!app) return;
        NSMutableSet<UIWindow *> *windows = [NSMutableSet set];
        if ([app respondsToSelector:@selector(windows)]) {
            for (UIWindow *w in app.windows) {
                if (w) [windows addObject:w];
            }
        }
        if ([app respondsToSelector:@selector(connectedScenes)]) {
            for (id scene in app.connectedScenes) {
                if ([scene respondsToSelector:@selector(windows)]) {
                    for (UIWindow *w in [scene valueForKey:@"windows"]) {
                        if ([w isKindOfClass:[UIWindow class]]) [windows addObject:w];
                    }
                }
            }
        }
        for (UIWindow *w in windows) {
            MEWebViewFindInView(w, views);
        }
    };
    if ([NSThread isMainThread]) scanBlock();
    else dispatch_sync(dispatch_get_main_queue(), scanBlock);
    return views;
}

static id MEEvalJSOnWebViewSync(WKWebView *wv, NSString *script, NSTimeInterval timeoutSec, NSString **outErr) {
    if (!wv || !script.length) {
        if (outErr) *outErr = @"Missing WKWebView or script";
        return nil;
    }
    __block id evalResult = nil;
    __block NSError *evalError = nil;
    __block BOOL finished = NO;

    void (^startEval)(void) = ^{
        [wv evaluateJavaScript:script completionHandler:^(id res, NSError *err) {
            evalResult = res;
            evalError = err;
            finished = YES;
        }];
    };

    if ([NSThread isMainThread]) {
        startEval();
        NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:(timeoutSec > 0 ? timeoutSec : 8.0)];
        while (!finished && [[NSDate date] compare:deadline] == NSOrderedAscending) {
            [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.02]];
        }
    } else {
        dispatch_async(dispatch_get_main_queue(), startEval);
        CFAbsoluteTime deadline = CFAbsoluteTimeGetCurrent() + (timeoutSec > 0 ? timeoutSec : 8.0);
        while (!finished && CFAbsoluteTimeGetCurrent() < deadline) {
            usleep(15 * 1000);
        }
    }

    if (!finished) {
        if (outErr) *outErr = @"WKWebView evaluateJavaScript timed out";
        return nil;
    }
    if (evalError) {
        if (outErr) *outErr = evalError.localizedDescription ?: @"JavaScript evaluation error";
        return nil;
    }
    return evalResult ?: [NSNull null];
}

NSDictionary *MEWebView(NSString *op, NSDictionary *a) {
    if (![op isEqualToString:@"engine.webview_bridge"]) return nil;

    NSString *action = [a[@"action"] isKindOfClass:NSString.class] ? [a[@"action"] lowercaseString] : @"list";
    NSArray<WKWebView *> *webViews = MECollectAllWKWebViews();
    NSUInteger targetIdx = [a[@"webview_index"] respondsToSelector:@selector(unsignedIntegerValue)]
        ? [a[@"webview_index"] unsignedIntegerValue]
        : 0;
    NSString *targetPtr = [a[@"webview_id"] isKindOfClass:NSString.class] ? a[@"webview_id"] : nil;

    WKWebView *selected = nil;
    if (targetPtr.length) {
        for (WKWebView *wv in webViews) {
            NSString *ptrStr = [NSString stringWithFormat:@"%p", wv];
            if ([ptrStr isEqualToString:targetPtr]) {
                selected = wv;
                break;
            }
        }
    }
    if (!selected && targetIdx < webViews.count) {
        selected = webViews[targetIdx];
    }

    if ([action isEqualToString:@"list"]) {
        __block NSMutableArray *list = [NSMutableArray array];
        void (^describeBlock)(void) = ^{
            NSUInteger idx = 0;
            for (WKWebView *wv in webViews) {
                CGRect screenRect = [wv convertRect:wv.bounds toView:nil];
                [list addObject:@{
                    @"index": @(idx++),
                    @"webview_id": [NSString stringWithFormat:@"%p", wv],
                    @"class": NSStringFromClass([wv class]) ?: @"WKWebView",
                    @"url": wv.URL.absoluteString ?: @"",
                    @"title": wv.title ?: @"",
                    @"loading": @(wv.isLoading),
                    @"user_agent": wv.customUserAgent ?: @"",
                    @"screen_rect": @{
                        @"x": @(screenRect.origin.x),
                        @"y": @(screenRect.origin.y),
                        @"width": @(screenRect.size.width),
                        @"height": @(screenRect.size.height)
                    }
                }];
            }
        };
        if ([NSThread isMainThread]) describeBlock();
        else dispatch_sync(dispatch_get_main_queue(), describeBlock);
        return @{
            @"action": @"list",
            @"count": @(list.count),
            @"webviews": list
        };
    }

    if (!selected) {
        return @{
            @"action": action,
            @"ok": @NO,
            @"error": @"No active WKWebView found in view hierarchy",
            @"webview_count": @(webViews.count)
        };
    }

    if ([action isEqualToString:@"eval_js"]) {
        NSString *script = MEString(a, @"script");
        NSString *err = nil;
        id val = MEEvalJSOnWebViewSync(selected, script, 10.0, &err);
        if (err) {
            return @{@"action": @"eval_js", @"ok": @NO, @"error": err};
        }
        id safeVal = val;
        if (val && val != [NSNull null] && ![NSJSONSerialization isValidJSONObject:@{@"v": val}]) {
            safeVal = [val description] ?: @"";
        }
        return @{
            @"action": @"eval_js",
            @"ok": @YES,
            @"webview_id": [NSString stringWithFormat:@"%p", selected],
            @"result": safeVal ?: [NSNull null]
        };
    }

    if ([action isEqualToString:@"dump_dom"]) {
        NSString *selector = [a[@"selector"] isKindOfClass:NSString.class] && [a[@"selector"] length]
            ? a[@"selector"]
            : @"a, button, input, select, textarea, [role='button'], [onclick], h1, h2, h3, label, span, div";
        NSUInteger limit = MELimit(a, @"limit", 250, 2000);
        __block CGRect wvScreenRect = CGRectZero;
        void (^rectBlock)(void) = ^{
            wvScreenRect = [selected convertRect:selected.bounds toView:nil];
        };
        if ([NSThread isMainThread]) rectBlock();
        else dispatch_sync(dispatch_get_main_queue(), rectBlock);

        NSString *escapedSel = [selector stringByReplacingOccurrencesOfString:@"\\" withString:@"\\\\"];
        escapedSel = [escapedSel stringByReplacingOccurrencesOfString:@"'" withString:@"\\'"];

        NSString *domJS = [NSString stringWithFormat:
            @"(function(){"
             "var ox=%f, oy=%f, max=%lu;"
             "var nodes=document.querySelectorAll('%@');"
             "var out=[];"
             "for(var i=0;i<nodes.length && out.length<max;i++){"
             "  var el=nodes[i];"
             "  var r=el.getBoundingClientRect();"
             "  if(r.width<=0 && r.height<=0) continue;"
             "  var txt=(el.innerText||el.value||el.placeholder||el.getAttribute('aria-label')||'').trim();"
             "  if(txt.length>160) txt=txt.substring(0,160);"
             "  if(el.tagName==='DIV' && el.children.length>3 && !el.getAttribute('onclick') && !el.getAttribute('role')) continue;"
             "  out.push({"
             "    index: out.length,"
             "    tag: (el.tagName||'').toLowerCase(),"
             "    id: el.id||'',"
             "    className: (typeof el.className==='string'?el.className:''),"
             "    type: el.type||'',"
             "    name: el.name||'',"
             "    text: txt,"
             "    href: el.href||'',"
             "    value: (typeof el.value==='string'?el.value:''),"
             "    rect: {x: Math.round(ox+r.left), y: Math.round(oy+r.top), width: Math.round(r.width), height: Math.round(r.height)},"
             "    tap_point: {x: Math.round(ox+r.left+r.width/2), y: Math.round(oy+r.top+r.height/2)}"
             "  });"
             "}"
             "return JSON.stringify({url: location.href, title: document.title, element_count: out.length, elements: out});"
             "})()",
            wvScreenRect.origin.x, wvScreenRect.origin.y, (unsigned long)limit, escapedSel];

        NSString *err = nil;
        id rawJSON = MEEvalJSOnWebViewSync(selected, domJS, 10.0, &err);
        if (err || ![rawJSON isKindOfClass:NSString.class]) {
            return @{@"action": @"dump_dom", @"ok": @NO, @"error": err ?: @"DOM serialization failed"};
        }
        NSDictionary *parsed = [NSJSONSerialization JSONObjectWithData:[(NSString *)rawJSON dataUsingEncoding:NSUTF8StringEncoding] options:0 error:NULL];
        return @{
            @"action": @"dump_dom",
            @"ok": @YES,
            @"webview_id": [NSString stringWithFormat:@"%p", selected],
            @"webview_screen_rect": @{
                @"x": @(wvScreenRect.origin.x),
                @"y": @(wvScreenRect.origin.y),
                @"width": @(wvScreenRect.size.width),
                @"height": @(wvScreenRect.size.height)
            },
            @"dom": parsed ?: @{}
        };
    }

    if ([action isEqualToString:@"cookies_storage"]) {
        __block NSMutableArray *wkCookies = [NSMutableArray array];
        __block BOOL cookiesDone = NO;
        void (^fetchCookies)(void) = ^{
            WKHTTPCookieStore *store = selected.configuration.websiteDataStore.httpCookieStore;
            if (!store) { cookiesDone = YES; return; }
            [store getAllCookies:^(NSArray<NSHTTPCookie *> *cookies) {
                for (NSHTTPCookie *c in cookies) {
                    [wkCookies addObject:@{
                        @"name": c.name ?: @"",
                        @"value": c.value ?: @"",
                        @"domain": c.domain ?: @"",
                        @"path": c.path ?: @"/",
                        @"secure": @(c.isSecure),
                        @"httpOnly": @(c.isHTTPOnly)
                    }];
                }
                cookiesDone = YES;
            }];
        };
        if ([NSThread isMainThread]) {
            fetchCookies();
            NSDate *dl = [NSDate dateWithTimeIntervalSinceNow:5.0];
            while (!cookiesDone && [[NSDate date] compare:dl] == NSOrderedAscending) {
                [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.02]];
            }
        } else {
            dispatch_async(dispatch_get_main_queue(), fetchCookies);
            CFAbsoluteTime dl = CFAbsoluteTimeGetCurrent() + 5.0;
            while (!cookiesDone && CFAbsoluteTimeGetCurrent() < dl) usleep(15 * 1000);
        }

        NSString *storageJS = @"(function(){"
            "var ls={}, ss={};"
            "try{for(var i=0;i<localStorage.length;i++){var k=localStorage.key(i);ls[k]=localStorage.getItem(k);}}catch(e){}"
            "try{for(var j=0;j<sessionStorage.length;j++){var k2=sessionStorage.key(j);ss[k2]=sessionStorage.getItem(k2);}}catch(e){}"
            "return JSON.stringify({localStorage: ls, sessionStorage: ss, documentCookie: document.cookie||''});"
            "})()";
        NSString *err = nil;
        id rawStorage = MEEvalJSOnWebViewSync(selected, storageJS, 5.0, &err);
        NSDictionary *storageDict = [rawStorage isKindOfClass:NSString.class]
            ? [NSJSONSerialization JSONObjectWithData:[(NSString *)rawStorage dataUsingEncoding:NSUTF8StringEncoding] options:0 error:NULL]
            : @{};

        return @{
            @"action": @"cookies_storage",
            @"ok": @YES,
            @"webview_id": [NSString stringWithFormat:@"%p", selected],
            @"wk_cookies": wkCookies,
            @"storage": storageDict ?: @{}
        };
    }

    MEFail([@"Unknown webview_bridge action: " stringByAppendingString:action]);
    return nil;
}
