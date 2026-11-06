#import "engine_rpc.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <mach-o/dyld.h>

void MEFail(NSString *s) { @throw [NSException exceptionWithName:@"MCPError" reason:s userInfo:nil]; }
NSString *MEString(NSDictionary *a, NSString *key) {
    id v = a[key];
    if (![v isKindOfClass:NSString.class] || ![v length]) MEFail([@"Missing string: " stringByAppendingString:key]);
    return v;
}
NSUInteger MELimit(NSDictionary *a, NSString *key, NSUInteger fallback, NSUInteger max) {
    id v = a[key];
    if (!v) return fallback;
    if (![v isKindOfClass:NSNumber.class] || [v doubleValue] < 0 || [v doubleValue] > max ||
        [v doubleValue] != (double)[v unsignedLongLongValue]) MEFail([@"Invalid limit: " stringByAppendingString:key]);
    return [v unsignedIntegerValue];
}
uintptr_t MEWord(id v) {
    if (!v || v == NSNull.null) return 0;
    if ([v isKindOfClass:NSNumber.class]) return [v unsignedLongLongValue];
    if (![v isKindOfClass:NSString.class]) MEFail(@"Expected integer or 0x address");
    const char *s = [v UTF8String]; char *end = NULL;
    if (strncmp(s, "0x", 2) != 0 || !s[2]) MEFail(@"Address requires 0x prefix");
    errno = 0; unsigned long long n = strtoull(s + 2, &end, 16);
    if (errno || !end || *end) MEFail(@"Invalid address");
    return (uintptr_t)n;
}
NSString *MEHex(uintptr_t n) { return [NSString stringWithFormat:@"0x%llx", (unsigned long long)n]; }

static NSDictionary *MEDispatch(NSString *op, NSDictionary *a) {
    if ([op isEqual:@"engine.ping"]) {
#if defined(__arm64e__)
        NSString *arch = @"arm64e";
#else
        NSString *arch = @"arm64";
#endif
        return @{@"version":ME_VERSION, @"pid":@(getpid()), @"arch":arch,
                 @"platform":@"ios", @"module_count":@(_dyld_image_count())};
    }
    NSDictionary *r = MEHooks(op,a);
    if (!r) r = MEObjC(op,a);
    if (!r) r = MENative(op,a);
    if (!r) r = MEMemory(op,a);
    if (!r) MEFail([@"Unknown op: " stringByAppendingString:op]);
    return r;
}
static NSData *MEReply(NSData *line) {
    id requestID = NSNull.null;
    NSDictionary *reply;
    @try {
        id req = [NSJSONSerialization JSONObjectWithData:line options:0 error:NULL];
        if (![req isKindOfClass:NSDictionary.class]) MEFail(@"Request must be an object");
        requestID = req[@"id"] ?: NSNull.null;
        if (![requestID isKindOfClass:NSNumber.class] || [requestID doubleValue] != (double)[requestID longLongValue])
            MEFail(@"id must be an integer");
        NSString *op = MEString(req,@"op");
        id args = req[@"args"] ?: @{};
        if (![args isKindOfClass:NSDictionary.class]) MEFail(@"args must be an object");
        MEDepth++;
        NSDictionary *result;
        @try { result = MEDispatch(op,args); } @finally { MEDepth--; }
        reply = @{@"id":requestID,@"ok":@YES,@"result":result};
    } @catch (NSException *e) {
        reply = @{@"id":requestID,@"ok":@NO,@"error":e.reason ?: @"Operation failed"};
    }
    NSData *json = [NSJSONSerialization dataWithJSONObject:reply options:0 error:NULL];
    if (!json || json.length >= ME_MAX_FRAME)
        json = [NSJSONSerialization dataWithJSONObject:@{@"id":requestID,@"ok":@NO,@"error":@"Response exceeds frame limit; reduce limit"} options:0 error:NULL];
    NSMutableData *out = [json mutableCopy];
    [out appendBytes:"\n" length:1]; return out;
}
static BOOL MESend(int fd, NSData *data) {
    const uint8_t *p = data.bytes; size_t left = data.length;
    while (left) {
        ssize_t n = send(fd,p,left,0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return NO;
        p += n; left -= (size_t)n;
    }
    return YES;
}
static void MEClient(int fd) {
    struct timeval timeout = {10,0};
    setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
    int yes = 1; setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&yes,sizeof(yes));
    NSMutableData *pending = [NSMutableData data]; uint8_t buf[8192];
    for (;;) {
        ssize_t n = recv(fd,buf,sizeof(buf),0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        [pending appendBytes:buf length:(NSUInteger)n];
        for (;;) {
            const uint8_t *start = pending.bytes;
            const uint8_t *nl = memchr(start,'\n',pending.length);
            if (!nl) break;
            NSUInteger len = (NSUInteger)(nl-start);
            if (len >= ME_MAX_FRAME) return;
            @autoreleasepool {
                NSData *line = [pending subdataWithRange:NSMakeRange(0,len)];
                if (!MESend(fd,MEReply(line))) return;
            }
            [pending replaceBytesInRange:NSMakeRange(0,len+1) withBytes:NULL length:0];
        }
        if (pending.length >= ME_MAX_FRAME) break;
    }
}
static void *MEServer(void *unused) {
    @autoreleasepool {
        // A missing/invalid config disables the payload without affecting launch.
        NSString *tmp = NSTemporaryDirectory().stringByResolvingSymlinksInPath;
        NSString *cfg = [tmp stringByAppendingPathComponent:@".mcpe_cfg.json"];
        NSData *data = [NSData dataWithContentsOfFile:cfg];
        if (!data || data.length > 16384) return NULL;
        id config = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
        if (![config isKindOfClass:NSDictionary.class]) return NULL;
        NSString *path = config[@"socket_path"];
        if (![path isKindOfClass:NSString.class] || !path.isAbsolutePath) return NULL;
        path = path.stringByStandardizingPath;
        if (![path.stringByDeletingLastPathComponent.stringByResolvingSymlinksInPath isEqual:tmp]) return NULL;
        struct sockaddr_un addr = {0}; addr.sun_family = AF_UNIX;
        const char *p = path.fileSystemRepresentation;
        if (strlen(p) >= sizeof(addr.sun_path)) return NULL;
        memcpy(addr.sun_path,p,strlen(p)+1); addr.sun_len = sizeof(addr);
        struct stat st;
        if (lstat(p,&st) == 0) {
            if (!S_ISSOCK(st.st_mode) || st.st_uid != geteuid()) return NULL;
            int probe = socket(AF_UNIX,SOCK_STREAM,0);
            if (probe < 0) return NULL;
            int rc = connect(probe,(struct sockaddr *)&addr,sizeof(addr));
            int err = errno; close(probe);
            if (!rc || (err != ECONNREFUSED && err != ENOENT)) return NULL;
            if (unlink(p) != 0) return NULL;
        } else if (errno != ENOENT) return NULL;
        int fd = socket(AF_UNIX,SOCK_STREAM,0);
        if (fd < 0) return NULL;
        if (bind(fd,(struct sockaddr *)&addr,sizeof(addr)) || chmod(p,0600) || listen(fd,4)) { close(fd); return NULL; }
        MEInitNative();
        for (;;) {
            int client = accept(fd,NULL,NULL);
            if (client < 0) { if (errno == EINTR) continue; break; }
            @autoreleasepool { MEClient(client); }
            close(client);
        }
        close(fd); unlink(p);
    }
    return NULL;
}
__attribute__((constructor)) static void MEStart(void) {
    pthread_t thread;
    if (pthread_create(&thread,NULL,MEServer,NULL) == 0) pthread_detach(thread);
}
