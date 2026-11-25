#import <Foundation/Foundation.h>
#import <arpa/inet.h>
#import <ifaddrs.h>
#import <net/if.h>
#import <sys/stat.h>
#import <os/lock.h>

#define IOS_MCP_DEFAULT_PORT 8090
#define IOS_MCP_MIN_PORT 1024
#define IOS_MCP_MAX_PORT 65535
#define IOS_MCP_PREFERENCES_DOMAIN @"com.witchan.ios-mcp.preferences"
#define IOS_MCP_PREFERENCES_PLIST_PATH "/var/mobile/Library/Preferences/com.witchan.ios-mcp.preferences.plist"
#define IOS_MCP_ENABLED_PREFERENCE_KEY @"enabled"
#define IOS_MCP_PORT_PREFERENCE_KEY @"port"
#define IOS_MCP_DEBUG_LOGGING_PREFERENCE_KEY @"debugLoggingEnabled"
#define IOS_MCP_PATH_SAFETY_PREFERENCE_KEY @"pathSafetyEnabled"
#define IOS_MCP_REQUIRE_WRITE_APPROVAL_KEY @"requireWriteApproval"
#define IOS_MCP_REDACT_SENSITIVE_KEY @"redactSensitiveEnabled"
#define IOS_MCP_TOOLS_TIER_KEY @"toolsTier"
#define IOS_MCP_WAN_BRIDGE_ENABLED_KEY @"wanBridgeEnabled"
#define IOS_MCP_WAN_BRIDGE_HOST_KEY @"wanBridgeHost"
#define IOS_MCP_WAN_BRIDGE_PORT_KEY @"wanBridgePort"
#define IOS_MCP_WAN_BRIDGE_SECRET_KEY @"wanBridgeSecret"
#define IOS_MCP_PREFER_CELLULAR_KEY @"preferCellularWan"
#define IOS_MCP_API_AUTH_ENABLED_KEY @"apiAuthEnabled"
#define IOS_MCP_API_AUTH_TOKEN_KEY @"apiAuthToken"
#define IOS_MCP_DEFAULT_WAN_BRIDGE_PORT 8091
#define IOS_MCP_DARWIN_NOTIFICATION_START CFSTR("com.witchan.ios-mcp.control/start")
#define IOS_MCP_DARWIN_NOTIFICATION_STOP CFSTR("com.witchan.ios-mcp.control/stop")
#define IOS_MCP_DARWIN_NOTIFICATION_WAN_RELOAD CFSTR("com.witchan.ios-mcp.control/wan-reload")

// Fast lock-protected, stat()-mtime-cached preferences dictionary reader.
// Eliminates synchronous CFPreferencesAppSynchronize IPC on SpringBoard's main thread
// and during high-frequency tool calls.
static inline NSDictionary *IOSMCPCachedPreferencesDict(void) {
    static os_unfair_lock sLock = OS_UNFAIR_LOCK_INIT;
    static NSDictionary *sCachedDict = nil;
    static time_t sLastMtimeSec = 0;
    static long sLastMtimeNsec = 0;

    struct stat st;
    if (stat(IOS_MCP_PREFERENCES_PLIST_PATH, &st) == 0) {
        os_unfair_lock_lock(&sLock);
        if (sCachedDict &&
            st.st_mtimespec.tv_sec == sLastMtimeSec &&
            st.st_mtimespec.tv_nsec == sLastMtimeNsec) {
            NSDictionary *ret = sCachedDict;
            os_unfair_lock_unlock(&sLock);
            return ret;
        }
        os_unfair_lock_unlock(&sLock);

        NSDictionary *loaded = [NSDictionary dictionaryWithContentsOfFile:@(IOS_MCP_PREFERENCES_PLIST_PATH)];
        if ([loaded isKindOfClass:[NSDictionary class]]) {
            os_unfair_lock_lock(&sLock);
            sCachedDict = [loaded copy];
            sLastMtimeSec = st.st_mtimespec.tv_sec;
            sLastMtimeNsec = st.st_mtimespec.tv_nsec;
            NSDictionary *ret = sCachedDict;
            os_unfair_lock_unlock(&sLock);
            return ret;
        }
    }

    os_unfair_lock_lock(&sLock);
    NSDictionary *fallback = sCachedDict;
    os_unfair_lock_unlock(&sLock);
    return fallback ?: @{};
}

static inline id IOSMCPPreferenceObjectForKey(NSString *key) {
    if (!key.length) return nil;
    NSDictionary *dict = IOSMCPCachedPreferencesDict();
    id val = dict[key];
    if (val) return val;
    CFPropertyListRef cfVal = CFPreferencesCopyAppValue((__bridge CFStringRef)key,
                                                        (__bridge CFStringRef)IOS_MCP_PREFERENCES_DOMAIN);
    if (cfVal) {
        id obj = (__bridge_transfer id)cfVal;
        return obj;
    }
    return nil;
}

static inline BOOL IOSMCPBoolPreference(NSString *key, BOOL defaultValue) {
    id val = IOSMCPPreferenceObjectForKey(key);
    if ([val respondsToSelector:@selector(boolValue)]) {
        return [val boolValue];
    }
    return defaultValue;
}

static inline NSString *IOSMCPStringPreference(NSString *key, NSString *defaultValue) {
    id val = IOSMCPPreferenceObjectForKey(key);
    if ([val isKindOfClass:[NSString class]]) {
        NSString *str = [(NSString *)val stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (str.length > 0) return str;
    }
    return defaultValue;
}

static inline BOOL IOSMCPPathSafetyEnabled(void) {
    return IOSMCPBoolPreference(IOS_MCP_PATH_SAFETY_PREFERENCE_KEY, YES);
}

static inline BOOL IOSMCPRequireWriteApproval(void) {
    return IOSMCPBoolPreference(IOS_MCP_REQUIRE_WRITE_APPROVAL_KEY, NO);
}

static inline BOOL IOSMCPRedactSensitiveEnabled(void) {
    return IOSMCPBoolPreference(IOS_MCP_REDACT_SENSITIVE_KEY, YES);
}

static inline BOOL IOSMCPPreferCellularWan(void) {
    return IOSMCPBoolPreference(IOS_MCP_PREFER_CELLULAR_KEY, NO);
}

static inline BOOL IOSMCPApiAuthEnabled(void) {
    return IOSMCPBoolPreference(IOS_MCP_API_AUTH_ENABLED_KEY, NO);
}

static inline NSString *IOSMCPApiAuthToken(void) {
    return IOSMCPStringPreference(IOS_MCP_API_AUTH_TOKEN_KEY, @"");
}

static inline NSString *IOSMCPWanBridgeSecret(void) {
    NSString *sec = IOSMCPStringPreference(IOS_MCP_WAN_BRIDGE_SECRET_KEY, @"");
    return sec.length > 0 ? sec : IOSMCPApiAuthToken();
}

static inline NSString *IOSMCPConfiguredToolsTier(void) {
    const char *envTier = getenv("IOS_MCP_TOOLS");
    if (envTier && envTier[0]) {
        return [[NSString stringWithUTF8String:envTier] lowercaseString];
    }
    NSString *str = [IOSMCPStringPreference(IOS_MCP_TOOLS_TIER_KEY, @"all") lowercaseString];
    return str.length > 0 ? str : @"all";
}

static inline BOOL IOSMCPParsePortValue(id value, uint16_t *outPort) {
    long long parsed = 0;
    BOOL parsedValue = NO;

    if ([value isKindOfClass:[NSNumber class]]) {
        parsed = [(NSNumber *)value longLongValue];
        parsedValue = YES;
    } else if ([value isKindOfClass:[NSString class]]) {
        NSString *text = [(NSString *)value stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (text.length > 0) {
            NSScanner *scanner = [NSScanner scannerWithString:text];
            parsedValue = [scanner scanLongLong:&parsed] && scanner.isAtEnd;
        }
    }

    if (!parsedValue || parsed < IOS_MCP_MIN_PORT || parsed > IOS_MCP_MAX_PORT) {
        return NO;
    }

    if (outPort) {
        *outPort = (uint16_t)parsed;
    }
    return YES;
}

static inline uint16_t IOSMCPConfiguredPort(void) {
    uint16_t port = IOS_MCP_DEFAULT_PORT;
    id value = IOSMCPPreferenceObjectForKey(IOS_MCP_PORT_PREFERENCE_KEY);
    if (value) {
        IOSMCPParsePortValue(value, &port);
    }
    return port;
}

static inline NSString *IOSMCPWanBridgeHost(void) {
    NSString *raw = IOSMCPStringPreference(IOS_MCP_WAN_BRIDGE_HOST_KEY, @"");
    if (!raw.length) return @"";
    // Bracketed IPv6 literal: "[2607:...]:8091" or "[2607:...]"
    if ([raw hasPrefix:@"["]) {
        NSRange closeBracket = [raw rangeOfString:@"]"];
        if (closeBracket.location != NSNotFound && closeBracket.location > 1) {
            return [raw substringWithRange:NSMakeRange(1, closeBracket.location - 1)];
        }
    }
    // Allow "host:port" shorthand for IPv4 / hostnames (avoid splitting raw IPv6 with multiple colons)
    NSRange firstColon = [raw rangeOfString:@":"];
    NSRange lastColon = [raw rangeOfString:@":" options:NSBackwardsSearch];
    if (firstColon.location != NSNotFound && firstColon.location == lastColon.location) {
        NSString *portPart = [raw substringFromIndex:lastColon.location + 1];
        uint16_t parsedPort = 0;
        if (IOSMCPParsePortValue(portPart, &parsedPort)) {
            return [raw substringToIndex:lastColon.location];
        }
    }
    return raw;
}

static inline BOOL IOSMCPWanBridgeEnabled(void) {
    id val = IOSMCPPreferenceObjectForKey(IOS_MCP_WAN_BRIDGE_ENABLED_KEY);
    if ([val respondsToSelector:@selector(boolValue)]) {
        return [val boolValue];
    }
    return IOSMCPWanBridgeHost().length > 0;
}

static inline uint16_t IOSMCPWanBridgePort(void) {
    NSString *rawHost = IOSMCPStringPreference(IOS_MCP_WAN_BRIDGE_HOST_KEY, @"");
    if ([rawHost hasPrefix:@"["]) {
        NSRange closeBracket = [rawHost rangeOfString:@"]"];
        if (closeBracket.location != NSNotFound && closeBracket.location + 2 < rawHost.length &&
            [rawHost characterAtIndex:closeBracket.location + 1] == ':') {
            NSString *portPart = [rawHost substringFromIndex:closeBracket.location + 2];
            uint16_t inlinePort = 0;
            if (IOSMCPParsePortValue(portPart, &inlinePort)) {
                return inlinePort;
            }
        }
    } else {
        NSRange firstColon = [rawHost rangeOfString:@":"];
        NSRange lastColon = [rawHost rangeOfString:@":" options:NSBackwardsSearch];
        if (firstColon.location != NSNotFound && firstColon.location == lastColon.location) {
            NSString *portPart = [rawHost substringFromIndex:lastColon.location + 1];
            uint16_t inlinePort = 0;
            if (IOSMCPParsePortValue(portPart, &inlinePort)) {
                return inlinePort;
            }
        }
    }
    uint16_t port = IOS_MCP_DEFAULT_WAN_BRIDGE_PORT;
    id value = IOSMCPPreferenceObjectForKey(IOS_MCP_WAN_BRIDGE_PORT_KEY);
    if (value) {
        IOSMCPParsePortValue(value, &port);
    }
    return port;
}

static inline BOOL IOSMCPIsCGNATOrPrivateIPv4(NSString *ip) {
    if (!ip.length) return NO;
    struct in_addr addr;
    if (inet_pton(AF_INET, ip.UTF8String, &addr) != 1) return NO;
    uint32_t h = ntohl(addr.s_addr);
    uint8_t a = (uint8_t)((h >> 24) & 0xFF);
    uint8_t b = (uint8_t)((h >> 16) & 0xFF);
    // RFC6598 CGNAT 100.64.0.0/10, RFC1918 10/8, 172.16/12, 192.168/16
    if (a == 100 && (b & 0xC0) == 64) return YES;
    if (a == 10) return YES;
    if (a == 172 && (b >= 16 && b <= 31)) return YES;
    if (a == 192 && b == 168) return YES;
    return NO;
}

static inline NSDictionary<NSString *, id> *IOSMCPNetworkInterfacesSummary(void) {
    struct ifaddrs *interfaces = NULL;
    NSString *wifiIPv4 = nil;
    NSString *wifiIPv6 = nil;
    NSString *cellularIPv4 = nil;
    NSString *cellularIPv6 = nil;
    NSString *cellularIfName = nil;
    NSString *vpnTailscaleIPv4 = nil;
    NSString *vpnTailscaleIPv6 = nil;
    NSString *usbIPv4 = nil;
    NSMutableArray<NSDictionary *> *allInterfaces = [NSMutableArray array];
    NSMutableArray<NSDictionary *> *cellularInterfaces = [NSMutableArray array];

    if (getifaddrs(&interfaces) == 0) {
        for (struct ifaddrs *interface = interfaces; interface; interface = interface->ifa_next) {
            if (!interface->ifa_addr || !interface->ifa_name) continue;
            if (!(interface->ifa_flags & IFF_UP) || (interface->ifa_flags & IFF_LOOPBACK)) continue;

            sa_family_t family = interface->ifa_addr->sa_family;
            if (family != AF_INET && family != AF_INET6) continue;

            NSString *ifName = [NSString stringWithUTF8String:interface->ifa_name];
            char addrBuf[INET6_ADDRSTRLEN] = {0};
            if (family == AF_INET) {
                const struct sockaddr_in *sin = (const struct sockaddr_in *)interface->ifa_addr;
                if (!inet_ntop(AF_INET, &sin->sin_addr, addrBuf, sizeof(addrBuf))) continue;
            } else {
                const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)interface->ifa_addr;
                if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr) || IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr)) continue;
                if (!inet_ntop(AF_INET6, &sin6->sin6_addr, addrBuf, sizeof(addrBuf))) continue;
            }

            NSString *address = [NSString stringWithUTF8String:addrBuf];
            if (!address.length || [address hasPrefix:@"169.254."]) continue;

            NSDictionary *ifEntry = @{
                @"interface": ifName,
                @"family": (family == AF_INET) ? @"IPv4" : @"IPv6",
                @"address": address
            };
            [allInterfaces addObject:ifEntry];

            if ([ifName isEqualToString:@"en0"]) {
                if (family == AF_INET && !wifiIPv4) wifiIPv4 = address;
                else if (family == AF_INET6 && !wifiIPv6) wifiIPv6 = address;
            } else if ([ifName hasPrefix:@"pdp_ip"]) {
                [cellularInterfaces addObject:ifEntry];
                // Prefer pdp_ip0 as the primary internet PDP interface when present
                BOOL preferThisIf = (!cellularIfName || [ifName isEqualToString:@"pdp_ip0"]);
                if (preferThisIf) {
                    cellularIfName = ifName;
                }
                if (family == AF_INET && (!cellularIPv4 || [ifName isEqualToString:@"pdp_ip0"])) cellularIPv4 = address;
                else if (family == AF_INET6 && (!cellularIPv6 || [ifName isEqualToString:@"pdp_ip0"])) cellularIPv6 = address;
            } else if ([ifName hasPrefix:@"utun"] || [ifName hasPrefix:@"ipsec"] || [ifName hasPrefix:@"ppp"]) {
                if (family == AF_INET && !vpnTailscaleIPv4) vpnTailscaleIPv4 = address;
                else if (family == AF_INET6 && !vpnTailscaleIPv6) vpnTailscaleIPv6 = address;
            } else if ([ifName hasPrefix:@"en"] && family == AF_INET && !usbIPv4) {
                usbIPv4 = address;
            }
        }
        freeifaddrs(interfaces);
    }

    uint16_t port = IOSMCPConfiguredPort();
    NSMutableArray<NSString *> *urls = [NSMutableArray array];
    if (wifiIPv4.length) [urls addObject:[NSString stringWithFormat:@"http://%@:%u/mcp", wifiIPv4, (unsigned int)port]];
    if (vpnTailscaleIPv4.length) [urls addObject:[NSString stringWithFormat:@"http://%@:%u/mcp", vpnTailscaleIPv4, (unsigned int)port]];
    if (cellularIPv4.length) [urls addObject:[NSString stringWithFormat:@"http://%@:%u/mcp", cellularIPv4, (unsigned int)port]];
    if (cellularIPv6.length) [urls addObject:[NSString stringWithFormat:@"http://[%@]:%u/mcp", cellularIPv6, (unsigned int)port]];
    if (wifiIPv6.length) [urls addObject:[NSString stringWithFormat:@"http://[%@]:%u/mcp", wifiIPv6, (unsigned int)port]];

    BOOL wifiConnected = (wifiIPv4.length > 0 || wifiIPv6.length > 0);
    BOOL cellularConnected = (cellularIPv4.length > 0 || cellularIPv6.length > 0);
    BOOL behindCGNAT = (cellularIPv4.length > 0 && IOSMCPIsCGNATOrPrivateIPv4(cellularIPv4));

    return @{
        @"wifi_connected": @(wifiConnected),
        @"wifi_ipv4": wifiIPv4 ?: @"",
        @"wifi_ipv6": wifiIPv6 ?: @"",
        @"cellular_connected": @(cellularConnected),
        @"cellular_interface": cellularIfName ?: @"pdp_ip0",
        @"cellular_ipv4": cellularIPv4 ?: @"",
        @"cellular_ipv6": cellularIPv6 ?: @"",
        @"cellular_interfaces": cellularInterfaces,
        @"behind_cgnat": @(behindCGNAT),
        @"vpn_tailscale_ipv4": vpnTailscaleIPv4 ?: @"",
        @"vpn_tailscale_ipv6": vpnTailscaleIPv6 ?: @"",
        @"usb_ipv4": usbIPv4 ?: @"",
        @"active_connection_mode": (wifiConnected ? (cellularConnected ? @"wifi+cellular" : @"wifi")
                                                  : (cellularConnected ? @"cellular" : @"loopback")),
        @"endpoints": urls,
        @"interfaces": allInterfaces
    };
}

static inline NSString *IOSMCPCurrentLANIPAddress(void) {
    NSDictionary *summary = IOSMCPNetworkInterfacesSummary();
    NSString *wifi = summary[@"wifi_ipv4"];
    if (wifi.length > 0 && !IOSMCPPreferCellularWan()) return wifi;
    NSString *vpn = summary[@"vpn_tailscale_ipv4"];
    if (vpn.length > 0) return vpn;
    NSString *cell4 = summary[@"cellular_ipv4"];
    if (cell4.length > 0) return cell4;
    NSString *cell6 = summary[@"cellular_ipv6"];
    if (cell6.length > 0) return [NSString stringWithFormat:@"[%@]", cell6];
    if (wifi.length > 0) return wifi;
    NSString *usb = summary[@"usb_ipv4"];
    if (usb.length > 0) return usb;
    return @"127.0.0.1";
}

static inline NSString *IOSMCPServiceURLString(void) {
    return [NSString stringWithFormat:@"http://%@:%u/mcp",
            IOSMCPCurrentLANIPAddress(),
            (unsigned int)IOSMCPConfiguredPort()];
}

static inline NSString *IOSMCPHealthURLString(void) {
    return [NSString stringWithFormat:@"http://%@:%u/health",
            IOSMCPCurrentLANIPAddress(),
            (unsigned int)IOSMCPConfiguredPort()];
}
