#import <Foundation/Foundation.h>

@interface CrashSymbolicateManager : NSObject

+ (instancetype)sharedInstance;
- (NSDictionary *)symbolicateCrashAtPath:(NSString *)logPath
                              allThreads:(BOOL)allThreads
                               maxFrames:(NSUInteger)maxFrames
                                   error:(NSString **)error;

@end
