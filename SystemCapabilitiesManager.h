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

- (NSDictionary *)setOtpWithArgs:(NSDictionary *)args
                           error:(NSString **)error;

- (NSDictionary *)humanPauseWithArgs:(NSDictionary *)args
                               error:(NSString **)error;

- (NSDictionary *)tiktokSocialControllerWithAction:(NSString *)action
                                              args:(NSDictionary *)args
                                             error:(NSString **)error;

- (NSDictionary *)photosLibraryControllerWithAction:(NSString *)action
                                               args:(NSDictionary *)args
                                              error:(NSString **)error;

- (NSDictionary *)tweakLifecycleWithAction:(NSString *)action
                                      args:(NSDictionary *)args
                                     error:(NSString **)error;

- (NSDictionary *)diagnosticsCollectWithArgs:(NSDictionary *)args
                                       error:(NSString **)error;

- (NSDictionary *)diagnoseRootsWithArgs:(NSDictionary *)args
                                  error:(NSString **)error;

- (NSDictionary *)portForwardWithArgs:(NSDictionary *)args
                                error:(NSString **)error;

- (NSDictionary *)sessionForceUnlockWithArgs:(NSDictionary *)args
                                       error:(NSString **)error;

- (NSDictionary *)sessionRespawnWithArgs:(NSDictionary *)args
                                   error:(NSString **)error;

- (NSDictionary *)wanCellularControllerWithArgs:(NSDictionary *)args
                                          error:(NSString **)error;

- (NSDictionary *)cellularRadioSnapshotWithEgressProbe:(BOOL)probeEgress;
- (NSDictionary *)latestRotationState;
- (NSArray<NSDictionary *> *)rotationHistory;
- (NSDictionary *)publicTunnelStatus;
- (void)handleNetworkChangeForTunnels;
- (void)clearAppEgressPinForBundleId:(NSString *)bundleId;
- (NSDictionary *)resetNetworkAndRadioStateWithArgs:(NSDictionary *)args
                                              error:(NSString **)error;

@end

