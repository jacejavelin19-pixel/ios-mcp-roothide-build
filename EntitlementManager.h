#import <Foundation/Foundation.h>

@interface EntitlementManager : NSObject

+ (instancetype)sharedInstance;
- (NSDictionary *)dumpEntitlementsForBundleId:(NSString *)bundleId error:(NSString **)error;
- (NSDictionary *)patchEntitlementsForBundleId:(NSString *)bundleId
                                         patch:(NSDictionary *)patch
                                         error:(NSString **)error;

@end
