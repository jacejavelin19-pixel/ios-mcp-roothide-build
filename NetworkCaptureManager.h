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
- (NSDictionary *)getCapturedRequestsForBundleId:(NSString *)bundleId
                                           limit:(NSUInteger)limit
                                       urlFilter:(NSString *)urlFilter
                                           clear:(BOOL)clear
                                          redact:(BOOL)redact
                                           error:(NSString **)error;
- (NSDictionary *)netStatusForBundleId:(NSString *)bundleId
                                 error:(NSString **)error;
- (NSDictionary *)clearCaptureForBundleId:(NSString *)bundleId
                                    error:(NSString **)error;

// Phase 3: Crypto tracing, QUIC/HTTP3 + WebSocket hooks, Protobuf wire decoding, native request replay
- (NSDictionary *)traceCryptoPrimitivesForBundleId:(NSString *)bundleId
                                              args:(NSDictionary *)args
                                             error:(NSString **)error;
- (NSDictionary *)getCryptoEventsForBundleId:(NSString *)bundleId
                                        args:(NSDictionary *)args
                                       error:(NSString **)error;
- (NSDictionary *)hookQuicHttp3ForBundleId:(NSString *)bundleId
                                      args:(NSDictionary *)args
                                     error:(NSString **)error;
- (NSDictionary *)decodeProtobufWithArgs:(NSDictionary *)args
                                   error:(NSString **)error;
- (NSDictionary *)replayRequestNativeForBundleId:(NSString *)bundleId
                                            args:(NSDictionary *)args
                                           error:(NSString **)error;

@end
