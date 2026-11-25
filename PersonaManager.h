#import <Foundation/Foundation.h>

@interface PersonaManager : NSObject

+ (instancetype)sharedInstance;

- (NSDictionary *)generateOrUpdatePersonaForBundleId:(NSString *)bundleId
                                           overrides:(NSDictionary *)overrides
                                               error:(NSString **)error;

- (NSDictionary *)ensureEngineAndSendOp:(NSString *)op
                            forBundleId:(NSString *)bundleId
                                   args:(NSDictionary *)args
                             autoInject:(BOOL)autoInject
                                  error:(NSString **)error;

- (NSDictionary *)stealthSyscallShieldForBundleId:(NSString *)bundleId
                                             args:(NSDictionary *)args
                                            error:(NSString **)error;

- (NSDictionary *)spoofDeviceFingerprintForBundleId:(NSString *)bundleId
                                               args:(NSDictionary *)args
                                              error:(NSString **)error;

- (NSDictionary *)kernelProcCloakForBundleId:(NSString *)bundleId
                                        args:(NSDictionary *)args
                                       error:(NSString **)error;

- (NSDictionary *)proxyVpnNetworkCloakForBundleId:(NSString *)bundleId
                                             args:(NSDictionary *)args
                                            error:(NSString **)error;

- (NSDictionary *)hardwareCanvasGpuAudioRandomizerForBundleId:(NSString *)bundleId
                                                         args:(NSDictionary *)args
                                                        error:(NSString **)error;

- (NSDictionary *)behavioralBiometricsGhostPlayerForBundleId:(NSString *)bundleId
                                                        args:(NSDictionary *)args
                                                       error:(NSString **)error;

- (NSDictionary *)perimeterxAkamaiDatadomeKasadaTapForBundleId:(NSString *)bundleId
                                                          args:(NSDictionary *)args
                                                         error:(NSString **)error;

- (NSDictionary *)threatmetrixSardineForterSeonNeutralizerForBundleId:(NSString *)bundleId
                                                                 args:(NSDictionary *)args
                                                                error:(NSString **)error;

- (NSDictionary *)appleAppAttestDevicecheckBridgeForBundleId:(NSString *)bundleId
                                                        args:(NSDictionary *)args
                                                       error:(NSString **)error;

- (NSDictionary *)syncFraudPersonaForBundleId:(NSString *)bundleId
                                         args:(NSDictionary *)args
                                        error:(NSString **)error;

- (NSDictionary *)objcSwizzleAndDladdrIntegrityCloakForBundleId:(NSString *)bundleId
                                                           args:(NSDictionary *)args
                                                          error:(NSString **)error;

- (NSDictionary *)threadMachPortAndStackCloakerForBundleId:(NSString *)bundleId
                                                      args:(NSDictionary *)args
                                                     error:(NSString **)error;

- (NSDictionary *)wipeFraudCanariesForBundleId:(NSString *)bundleId
                                          args:(NSDictionary *)args
                                         error:(NSString **)error;

- (NSDictionary *)applyFraudPersonaForBundleId:(NSString *)bundleId
                                          args:(NSDictionary *)args
                                         error:(NSString **)error;

- (NSDictionary *)auditFraudSurfaceForBundleId:(NSString *)bundleId
                                          args:(NSDictionary *)args
                                         error:(NSString **)error;

@end
