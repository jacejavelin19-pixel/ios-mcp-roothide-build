#import <Foundation/Foundation.h>

@interface ClassDumpManager : NSObject

+ (instancetype)sharedInstance;
- (NSDictionary *)dumpClassesForBundleId:(NSString *)bundleId
                                  filter:(NSString *)filter
                                   limit:(NSUInteger)limit
                           includeSystem:(BOOL)includeSystem
                              autoLaunch:(BOOL)autoLaunch
                                   error:(NSString **)error;

@end
