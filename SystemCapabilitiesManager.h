#import <Foundation/Foundation.h>

@interface SystemCapabilitiesManager : NSObject

+ (instancetype)sharedInstance;

- (NSDictionary *)checkpointAppStateForBundleId:(NSString *)bundleId
                                           args:(NSDictionary *)args
                                          error:(NSString **)error;

- (NSDictionary *)virtualCameraAndMicFeedForBundleId:(NSString *)bundleId
                                                args:(NSDictionary *)args
                                               error:(NSString **)error;

- (NSDictionary *)telephonySmsOtpControllerWithArgs:(NSDictionary *)args
                                              error:(NSString **)error;

- (NSDictionary *)biometricPasskeySeVaultForBundleId:(NSString *)bundleId
                                                args:(NSDictionary *)args
                                               error:(NSString **)error;

- (NSDictionary *)webkitCdpDomBridgeForBundleId:(NSString *)bundleId
                                           args:(NSDictionary *)args
                                          error:(NSString **)error;

- (NSDictionary *)gpsMotionSensorTeleporterForBundleId:(NSString *)bundleId
                                                  args:(NSDictionary *)args
                                                 error:(NSString **)error;

- (NSDictionary *)xpcMachIpcSnifferFuzzerForBundleId:(NSString *)bundleId
                                                args:(NSDictionary *)args
                                               error:(NSString **)error;

- (NSDictionary *)apnsNotificationDeeplinkBusWithArgs:(NSDictionary *)args
                                                error:(NSString **)error;

- (NSDictionary *)wirelessRadioReconSuiteWithArgs:(NSDictionary *)args
                                            error:(NSString **)error;

- (NSDictionary *)fsIoAndIokitTracerForBundleId:(NSString *)bundleId
                                           args:(NSDictionary *)args
                                          error:(NSString **)error;

- (NSDictionary *)humanTouchPhysicsAndStreamWithArgs:(NSDictionary *)args
                                               error:(NSString **)error;

- (NSDictionary *)backgroundImmortalityGovernorWithArgs:(NSDictionary *)args
                                                  error:(NSString **)error;

- (NSDictionary *)appgroupIcloudAccountInspectorWithArgs:(NSDictionary *)args
                                                   error:(NSString **)error;

@end
