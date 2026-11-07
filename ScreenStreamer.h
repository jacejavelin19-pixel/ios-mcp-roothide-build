#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

@interface ScreenStreamer : NSObject

+ (instancetype)sharedInstance;

- (void)streamMJPEGToSocket:(int)clientSocket
                        fps:(NSInteger)fps
                    quality:(CGFloat)quality
                  maxFrames:(NSInteger)maxFrames;

- (NSDictionary *)captureBurstFrames:(NSInteger)frameCount
                                 fps:(NSInteger)fps
                             quality:(CGFloat)quality;

@end
