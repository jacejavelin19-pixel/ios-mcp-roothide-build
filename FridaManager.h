#import <Foundation/Foundation.h>

@interface FridaManager : NSObject

+ (instancetype)sharedInstance;

/// #13: Deterministically scrub Frida/Gum cstrings & LC_ID_DYLIB across slices and re-sign.
- (NSDictionary *)scrubGadgetBinaryAtPath:(NSString *)dylibPath
                               outputPath:(NSString *)outputPath
                                     seed:(NSNumber *)seedNumber
                                    error:(NSString **)error;

/// #11 + #12 + #14 + #15: Scrub Gadget with fresh seed, stage libmcp_stealth.dylib FIRST and
/// scrubbed Gadget SECOND + Unix-socket-only .config + boot .js, inject LC_LOAD_DYLIB, sign, and optionally launch.
- (NSDictionary *)injectFridaGadgetForBundleId:(NSString *)bundleId
                                    scriptPath:(NSString *)scriptPath
                                 stealthConfig:(NSDictionary *)stealthConfig
                                        launch:(BOOL)launch
                                         error:(NSString **)error;

/// #11: Remove both Gadget and Stealth LC_LOAD_DYLIB entries & staged Frameworks files, re-sign cleanly.
- (NSDictionary *)removeFridaGadgetForBundleId:(NSString *)bundleId
                                         error:(NSString **)error;

/// #12: Evaluate JS / call rpc.exports over the randomized AF_UNIX control socket (zero TCP).
- (NSDictionary *)rpcCallForBundleId:(NSString *)bundleId
                              jsExpr:(NSString *)jsExpr
                           rpcMethod:(NSString *)rpcMethod
                             rpcArgs:(NSArray *)rpcArgs
                           timeoutMs:(NSInteger)timeoutMs
                               error:(NSString **)error;

/// Configure runtime stealth & anti-detection bypass flags in <DataContainer>/tmp/.mcp_stealth_cfg.json.
- (NSDictionary *)configureStealthForBundleId:(NSString *)bundleId
                                      options:(NSDictionary *)options
                                        error:(NSString **)error;

/// Inspect live stealth status, laundered thread table, hidden dyld images, and bypass counters.
- (NSDictionary *)stealthStatusForBundleId:(NSString *)bundleId
                                     error:(NSString **)error;

/// Execute live in-process anti-detection verification across thread names, dyld images, ports, debug, fs, exception ports, and VM protection.
- (NSDictionary *)antiDetectionProbeForBundleId:(NSString *)bundleId
                                          error:(NSString **)error;

/// Enumerate loaded modules inside the Gadget-instrumented process (comparing Gum internal vs external cloaked view).
- (NSDictionary *)listModulesForBundleId:(NSString *)bundleId
                                  filter:(NSString *)filter
                                   limit:(NSUInteger)limit
                                   error:(NSString **)error;

/// Dynamically hook/inspect/remove an Objective-C method via Frida Gum Interceptor over the Unix socket.
- (NSDictionary *)hookObjCForBundleId:(NSString *)bundleId
                                 args:(NSDictionary *)args
                                error:(NSString **)error;

/// Scan target process memory using Frida Gum pattern syntax (e.g. "48 65 6c 6c 6f" or "4d ?? 50").
- (NSDictionary *)memoryScanForBundleId:(NSString *)bundleId
                                   args:(NSDictionary *)args
                                  error:(NSString **)error;

@end
