#import "ScreenStreamer.h"
#import "ScreenManager.h"
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>

@implementation ScreenStreamer

+ (instancetype)sharedInstance {
    static ScreenStreamer *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[ScreenStreamer alloc] init];
    });
    return instance;
}

static BOOL MCPStreamWriteAll(int fd, const void *buf, size_t len) {
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
    const uint8_t *p = (const uint8_t *)buf;
    size_t rem = len;
    while (rem > 0) {
        ssize_t w = send(fd, p, rem, 0);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return NO;
        p += (size_t)w;
        rem -= (size_t)w;
    }
    return YES;
}

- (void)streamMJPEGToSocket:(int)clientSocket
                        fps:(NSInteger)fps
                    quality:(CGFloat)quality
                  maxFrames:(NSInteger)maxFrames {
    if (clientSocket < 0) return;
    NSInteger clampedFPS = MAX(1, MIN(fps > 0 ? fps : 15, 60));
    CGFloat clampedQuality = (quality > 0.05 && quality <= 1.0) ? quality : 0.65;
    NSInteger limitFrames = maxFrames > 0 ? maxFrames : 1800;

    NSString *header =
        @"HTTP/1.1 200 OK\r\n"
        @"Content-Type: multipart/x-mixed-replace; boundary=mcpframe\r\n"
        @"Cache-Control: no-cache, no-store, must-revalidate\r\n"
        @"Pragma: no-cache\r\n"
        @"Connection: close\r\n\r\n";
    NSData *hdrData = [header dataUsingEncoding:NSUTF8StringEncoding];
    if (!MCPStreamWriteAll(clientSocket, hdrData.bytes, hdrData.length)) {
        return;
    }

    useconds_t frameIntervalUs = (useconds_t)(1000000.0 / (double)clampedFPS);
    for (NSInteger i = 0; i < limitFrames; i++) {
        @autoreleasepool {
            CFAbsoluteTime t0 = CFAbsoluteTimeGetCurrent();
            UIImage *img = [[ScreenManager sharedInstance] captureScreenImage];
            NSData *jpeg = img ? UIImageJPEGRepresentation(img, clampedQuality) : nil;
            if (!jpeg.length) {
                NSDictionary *payload = [[ScreenManager sharedInstance] takeScreenshotPayload];
                NSString *b64 = payload[@"data"];
                if (b64.length) {
                    jpeg = [[NSData alloc] initWithBase64EncodedString:b64 options:0];
                }
            }
            if (!jpeg.length) break;

            NSString *partHdr = [NSString stringWithFormat:
                @"--mcpframe\r\n"
                @"Content-Type: image/jpeg\r\n"
                @"Content-Length: %lu\r\n\r\n",
                (unsigned long)jpeg.length];
            NSData *partHdrData = [partHdr dataUsingEncoding:NSUTF8StringEncoding];
            if (!MCPStreamWriteAll(clientSocket, partHdrData.bytes, partHdrData.length) ||
                !MCPStreamWriteAll(clientSocket, jpeg.bytes, jpeg.length) ||
                !MCPStreamWriteAll(clientSocket, "\r\n", 2)) {
                break;
            }

            CFAbsoluteTime elapsedUs = (CFAbsoluteTimeGetCurrent() - t0) * 1000000.0;
            if ((double)frameIntervalUs > elapsedUs) {
                usleep((useconds_t)((double)frameIntervalUs - elapsedUs));
            }
        }
    }
}

- (NSDictionary *)captureBurstFrames:(NSInteger)frameCount
                                 fps:(NSInteger)fps
                             quality:(CGFloat)quality {
    NSInteger count = MAX(1, MIN(frameCount > 0 ? frameCount : 3, 15));
    NSInteger clampedFPS = MAX(1, MIN(fps > 0 ? fps : 15, 60));
    CGFloat clampedQuality = (quality > 0.05 && quality <= 1.0) ? quality : 0.65;
    useconds_t intervalUs = (useconds_t)(1000000.0 / (double)clampedFPS);

    NSMutableArray *frames = [NSMutableArray arrayWithCapacity:(NSUInteger)count];
    for (NSInteger i = 0; i < count; i++) {
        @autoreleasepool {
            CFAbsoluteTime ts = CFAbsoluteTimeGetCurrent();
            UIImage *img = [[ScreenManager sharedInstance] captureScreenImage];
            NSData *jpeg = img ? UIImageJPEGRepresentation(img, clampedQuality) : nil;
            NSString *b64 = jpeg ? [jpeg base64EncodedStringWithOptions:0] : nil;
            if (!b64.length) {
                NSDictionary *payload = [[ScreenManager sharedInstance] takeScreenshotPayload];
                b64 = payload[@"data"];
            }
            if (b64.length) {
                [frames addObject:@{
                    @"index": @(i),
                    @"ts": @(ts),
                    @"bytes": @(jpeg.length),
                    @"jpeg_base64": b64
                }];
            }
            if (i + 1 < count) usleep(intervalUs);
        }
    }
    return @{
        @"fps": @(clampedFPS),
        @"quality": @(clampedQuality),
        @"frame_count": @(frames.count),
        @"stream_endpoint": @"/stream.mjpeg",
        @"frames": frames
    };
}

@end
