#import <Foundation/Foundation.h>

@interface SSLKillSwitchManager : NSObject

+ (instancetype)sharedInstance;
- (NSDictionary *)bypassPinningForBundleId:(NSString *)bundleId
                                  relaunch:(BOOL)relaunch
                                     error:(NSString **)error;
- (NSDictionary *)restorePinningForBundleId:(NSString *)bundleId
                                   relaunch:(BOOL)relaunch
                                      error:(NSString **)error;

@end
