#import <Foundation/Foundation.h>

@interface KeychainManager : NSObject

+ (instancetype)sharedInstance;
- (NSDictionary *)getKeychainItemsWithArgs:(NSDictionary *)args error:(NSString **)error;
- (NSDictionary *)setKeychainItemWithArgs:(NSDictionary *)args error:(NSString **)error;
- (NSDictionary *)deleteKeychainItemWithArgs:(NSDictionary *)args error:(NSString **)error;

@end
