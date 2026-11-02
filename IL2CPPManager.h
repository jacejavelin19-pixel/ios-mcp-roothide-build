#import <Foundation/Foundation.h>

@interface IL2CPPManager : NSObject

+ (instancetype)sharedInstance;
- (NSDictionary *)dumpIL2CPPForBundleId:(NSString *)bundleId
                             imageFilter:(NSString *)imageFilter
                              typeFilter:(NSString *)typeFilter
                                maxTypes:(NSUInteger)maxTypes
                         maxStringLiterals:(NSUInteger)maxStringLiterals
                                  error:(NSString **)error;

@end
