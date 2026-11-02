#import <Foundation/Foundation.h>

@interface NetworkCaptureManager : NSObject

+ (instancetype)sharedInstance;
- (NSDictionary *)startCaptureForBundleId:(NSString *)bundleId
                            clearExisting:(BOOL)clearExisting
                                 relaunch:(BOOL)relaunch
                                    error:(NSString **)error;
- (NSDictionary *)stopCaptureForBundleId:(NSString *)bundleId
                               clearLogs:(BOOL)clearLogs
                                relaunch:(BOOL)relaunch
                                   error:(NSString **)error;
- (NSDictionary *)getCapturedRequestsForBundleId:(NSString *)bundleId
                                           limit:(NSUInteger)limit
                                       urlFilter:(NSString *)urlFilter
                                           clear:(BOOL)clear
                                           error:(NSString **)error;

@end
