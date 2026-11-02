#import <Foundation/Foundation.h>

@interface DylibInjectManager : NSObject

+ (instancetype)sharedInstance;
- (NSDictionary *)injectDylibForBundleId:(NSString *)bundleId
                               dylibPath:(NSString *)dylibPath
                                destName:(NSString *)destName
                                   error:(NSString **)error;
- (NSDictionary *)removeDylibForBundleId:(NSString *)bundleId
                               dylibName:(NSString *)dylibName
                         restoreOriginal:(BOOL)restoreOriginal
                            deleteStaged:(BOOL)deleteStaged
                                   error:(NSString **)error;
- (NSDictionary *)inspectMachOAtPath:(NSString *)path error:(NSString **)error;

@end
