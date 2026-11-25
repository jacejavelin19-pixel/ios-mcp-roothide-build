#import <UIKit/UIKit.h>
#import <CoreFoundation/CoreFoundation.h>
#import "MCPServer.h"
#import "SystemCapabilitiesManager.h"
#import "MCPLogger.h"
#import "IOSMCPPreferences.h"

#define IOS_MCP_LOG(fmt, ...) do { \
    if ([MCPLogger isDebugLoggingEnabled]) { \
        NSString *message = [NSString stringWithFormat:(fmt), ##__VA_ARGS__]; \
        NSLog(@"[witchan][ios-mcp] %@", message); \
        [MCPLogger logMessage:message]; \
    } \
} while (0)

static dispatch_queue_t ios_mcp_control_queue(void) {
    static dispatch_queue_t queue = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        dispatch_queue_attr_t attr = dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL, QOS_CLASS_UTILITY, 0);
        queue = dispatch_queue_create("com.witchan.ios-mcp.control", attr);
    });
    return queue;
}

static BOOL ios_mcp_enabled_preference(void) {
    return IOSMCPBoolPreference(IOS_MCP_ENABLED_PREFERENCE_KEY, YES);
}

static void ios_mcp_write_enabled_preference(BOOL enabled) {
    CFPreferencesSetAppValue((__bridge CFStringRef)IOS_MCP_ENABLED_PREFERENCE_KEY,
                             enabled ? kCFBooleanTrue : kCFBooleanFalse,
                             (__bridge CFStringRef)IOS_MCP_PREFERENCES_DOMAIN);
    CFPreferencesAppSynchronize((__bridge CFStringRef)IOS_MCP_PREFERENCES_DOMAIN);
}

static BOOL ios_mcp_is_springboard_process(void) {
    static BOOL isSB = NO;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSString *processName = [[NSProcessInfo processInfo] processName];
        if ([processName isEqualToString:@"SpringBoard"]) {
            isSB = YES;
        } else {
            NSString *bundleIdentifier = [[NSBundle mainBundle] bundleIdentifier];
            isSB = [bundleIdentifier isEqualToString:@"com.apple.springboard"];
        }
    });
    return isSB;
}

static uint16_t ios_mcp_start_server(void) {
    uint16_t port = IOSMCPConfiguredPort();
    // A Settings START is also the recovery path when the listener still
    // exists but its HTTP workers are wedged. Force a serialized restart.
    [[MCPServer sharedInstance] restartOnPort:port];
    return port;
}

static void ios_mcp_stop_server(void) {
    [[MCPServer sharedInstance] stop];
}

static void ios_mcp_autostart_if_needed(NSString *reason);

static void ios_mcp_handle_control_notification(CFNotificationCenterRef center,
                                                void *observer,
                                                CFStringRef name,
                                                const void *object,
                                                CFDictionaryRef userInfo) {
    if (!name) {
        return;
    }

    if (CFEqual(name, IOS_MCP_DARWIN_NOTIFICATION_START)) {
        dispatch_async(ios_mcp_control_queue(), ^{
            ios_mcp_write_enabled_preference(YES);
            uint16_t port = ios_mcp_start_server();
            IOS_MCP_LOG(@"Received start request from Settings on port %u", (unsigned int)port);
        });
        return;
    }

    if (CFEqual(name, IOS_MCP_DARWIN_NOTIFICATION_STOP)) {
        dispatch_async(ios_mcp_control_queue(), ^{
            ios_mcp_write_enabled_preference(NO);
            ios_mcp_stop_server();
            IOS_MCP_LOG(@"Received stop request from Settings");
        });
        return;
    }

    if (CFEqual(name, IOS_MCP_DARWIN_NOTIFICATION_WAN_RELOAD) ||
        CFEqual(name, CFSTR("com.apple.system.config.network_change"))) {
        static uint64_t sDebounceGen = 0;
        uint64_t gen = __sync_add_and_fetch(&sDebounceGen, 1);
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(800 * NSEC_PER_MSEC)),
                       ios_mcp_control_queue(), ^{
            if (gen != sDebounceGen) return;
            ios_mcp_autostart_if_needed(@"network_or_wan_change");
            [[MCPServer sharedInstance] handleNetworkOrWanConfigurationChange];
            [[SystemCapabilitiesManager sharedInstance] handleNetworkChangeForTunnels];
            [[MCPServer sharedInstance] publishSSEEvent:@"network_changed"
                                                payload:IOSMCPNetworkInterfacesSummary()];
        });
    }
}

static void ios_mcp_autostart_if_needed(NSString *reason) {
    if (!ios_mcp_is_springboard_process()) {
        return;
    }

    if (!ios_mcp_enabled_preference()) {
        IOS_MCP_LOG(@"Auto-start skipped (%@): disabled in Settings", reason ?: @"unknown");
        return;
    }

    uint16_t port = IOSMCPConfiguredPort();
    MCPServer *server = [MCPServer sharedInstance];
    if (server.isRunning && server.port == port) {
        return;
    }

    IOS_MCP_LOG(@"Auto-start attempt (%@) on port %u...",
                reason ?: @"unknown",
                (unsigned int)port);
    [server startOnPort:port];

    if (!server.isRunning) {
        IOS_MCP_LOG(@"Auto-start attempt (%@) did not start server; later retry may recover",
                    reason ?: @"unknown");
    }
}

static void ios_mcp_schedule_autostart_attempt(NSString *reason, NSTimeInterval delay) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay * (NSTimeInterval)NSEC_PER_SEC)),
                   ios_mcp_control_queue(), ^{
        ios_mcp_autostart_if_needed(reason);
    });
}

static void ios_mcp_schedule_bootstrap_autostart(NSString *reason) {
    if (!ios_mcp_is_springboard_process()) {
        return;
    }

    /*
     Schedule idempotent background attempts off the main UI thread so the
     MCP listener socket is brought up as soon as SpringBoard is alive without
     touching SpringBoard's main runloop.
     */
    const NSTimeInterval delays[] = {0.1, 0.5, 1.5, 3.0, 6.0, 12.0, 25.0};
    const size_t count = sizeof(delays) / sizeof(delays[0]);
    for (size_t i = 0; i < count; i++) {
        NSString *attemptReason = [NSString stringWithFormat:@"%@#%zu", reason ?: @"bootstrap", i + 1];
        ios_mcp_schedule_autostart_attempt(attemptReason, delays[i]);
    }
}

static void ios_mcp_register_lifecycle_notifications(void) {
    if (!ios_mcp_is_springboard_process()) {
        return;
    }

    static BOOL registered = NO;
    if (registered) {
        return;
    }
    registered = YES;

    NSNotificationCenter *center = [NSNotificationCenter defaultCenter];
    [center addObserverForName:UIApplicationDidFinishLaunchingNotification
                        object:nil
                         queue:nil
                    usingBlock:^(__unused NSNotification *notification) {
        dispatch_async(ios_mcp_control_queue(), ^{
            IOS_MCP_LOG(@"UIApplicationDidFinishLaunchingNotification observed");
            ios_mcp_autostart_if_needed(@"UIApplicationDidFinishLaunching-immediate");
            ios_mcp_schedule_bootstrap_autostart(@"UIApplicationDidFinishLaunching");
        });
    }];
}

static void ios_mcp_register_control_notifications(void) {
    CFNotificationCenterRef center = CFNotificationCenterGetDarwinNotifyCenter();
    CFNotificationCenterAddObserver(center,
                                    NULL,
                                    ios_mcp_handle_control_notification,
                                    IOS_MCP_DARWIN_NOTIFICATION_START,
                                    NULL,
                                    CFNotificationSuspensionBehaviorDeliverImmediately);
    CFNotificationCenterAddObserver(center,
                                    NULL,
                                    ios_mcp_handle_control_notification,
                                    IOS_MCP_DARWIN_NOTIFICATION_STOP,
                                    NULL,
                                    CFNotificationSuspensionBehaviorDeliverImmediately);
    CFNotificationCenterAddObserver(center,
                                    NULL,
                                    ios_mcp_handle_control_notification,
                                    IOS_MCP_DARWIN_NOTIFICATION_WAN_RELOAD,
                                    NULL,
                                    CFNotificationSuspensionBehaviorDeliverImmediately);
    CFNotificationCenterAddObserver(center,
                                    NULL,
                                    ios_mcp_handle_control_notification,
                                    CFSTR("com.apple.system.config.network_change"),
                                    NULL,
                                    CFNotificationSuspensionBehaviorDeliverImmediately);
}

// Start on a background utility queue when dylib is loaded into SpringBoard
__attribute__((constructor)) static void ios_mcp_init(void) {
    if (!ios_mcp_is_springboard_process()) {
        return;
    }
    IOS_MCP_LOG(@"dylib loaded into SpringBoard");
    ios_mcp_register_control_notifications();
    ios_mcp_register_lifecycle_notifications();
    dispatch_async(ios_mcp_control_queue(), ^{
        ios_mcp_autostart_if_needed(@"constructor-immediate");
    });
    ios_mcp_schedule_bootstrap_autostart(@"constructor");
}

%hook SpringBoard

- (void)applicationDidFinishLaunching:(id)application {
    %orig;

    dispatch_async(ios_mcp_control_queue(), ^{
        IOS_MCP_LOG(@"SpringBoard applicationDidFinishLaunching fired");
        ios_mcp_autostart_if_needed(@"SpringBoard.applicationDidFinishLaunching");
    });
    ios_mcp_schedule_bootstrap_autostart(@"SpringBoard.applicationDidFinishLaunching");
}

%end
