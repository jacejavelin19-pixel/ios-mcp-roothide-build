#import <Foundation/Foundation.h>

// Server-side manager for the custom in-process instrumentation engine
// (libmcpengine). Mirrors FridaManager's shape but talks to our own engine over a
// randomized Unix-domain socket (zero TCP). The engine replaces the Frida Gadget;
// it hooks via fishhook symbol rebinding + ObjC runtime only (no RWX/JIT/inline),
// so it loads where the Gadget crashes. See sincere/CUSTOM_ENGINE_BUILD_PROMPT.md.
//
// Transport: newline-delimited JSON, request {"id","op","args"} -> response
// {"id","ok":true,"result"} | {"id","ok":false,"error"}. The socket path and the
// staged dylib names are recorded in a per-bundle session file at inject time
// (reuse FridaManager's session-file pattern + MCPNormalizeUnixSocketContainerPath).
@interface MCPEngineManager : NSObject

+ (instancetype)sharedInstance;

/// Stage libmcpengine.dylib (SECOND) behind the stealth companion (FIRST) into the
/// target's Frameworks under innocuous Apple-style names, insert LC_LOAD_DYLIB on
/// both slices, write the engine's Unix-socket config, re-sign + register trust via
/// mcp-appmod ("inject-engine" verb), persist the session, and optionally launch.
/// result: { socket_path, load_order[], engine_dylib_name, stealth_dylib_name,
///           data_container_path, launched, socket_ready }
- (NSDictionary *)injectEngineForBundleId:(NSString *)bundleId
                            stealthConfig:(NSDictionary *)stealthConfig
                                   launch:(BOOL)launch
                                    error:(NSString **)error;

/// Remove engine + stealth LC_LOAD_DYLIB, delete all staged Frameworks files
/// (sweep by prefix), re-sign cleanly, drop the session + socket/cfg files.
- (NSDictionary *)removeEngineForBundleId:(NSString *)bundleId
                                    error:(NSString **)error;

/// Low-level: send one engine RPC op and return its parsed result. All the typed
/// methods below are thin wrappers over this. (op names are the engine.* set.)
- (NSDictionary *)sendOp:(NSString *)op
             forBundleId:(NSString *)bundleId
                    args:(NSDictionary *)args
               timeoutMs:(NSInteger)timeoutMs
                   error:(NSString **)error;

/// engine.classes / engine.methods / engine.ivars — live ObjC introspection in-proc.
- (NSDictionary *)listClassesForBundleId:(NSString *)bundleId
                                  filter:(NSString *)filter
                           includeSystem:(BOOL)includeSystem
                                   limit:(NSUInteger)limit
                                   error:(NSString **)error;
- (NSDictionary *)describeClassForBundleId:(NSString *)bundleId
                                 className:(NSString *)className
                                     error:(NSString **)error; // methods+ivars+props+super

/// engine.hook_objc — swizzle a selector; record args/ret; optional return override.
/// args: { class, selector, record(bool), max_events, override_return(int|bool|"0x..") }
- (NSDictionary *)hookObjCForBundleId:(NSString *)bundleId
                                 args:(NSDictionary *)args
                                error:(NSString **)error;
/// engine.hook_events / engine.unhook — pull recorded calls / remove a hook.
- (NSDictionary *)hookEventsForBundleId:(NSString *)bundleId
                                    key:(NSString *)hookKey
                              maxEvents:(NSUInteger)maxEvents
                                  error:(NSString **)error;
- (NSDictionary *)unhookForBundleId:(NSString *)bundleId
                                key:(NSString *)hookKey
                              error:(NSString **)error;

/// engine.invoke — call a selector on an object handle or a class; boxed args/ret.
/// args: { target("class:Name"|"handle:N"|"0x..""), selector, args[] }
- (NSDictionary *)invokeForBundleId:(NSString *)bundleId
                               args:(NSDictionary *)args
                              error:(NSString **)error;

/// engine.get_ivar / engine.set_ivar on an object handle.
- (NSDictionary *)ivarForBundleId:(NSString *)bundleId
                             args:(NSDictionary *)args   // { handle, name, set?, value? }
                            error:(NSString **)error;

/// engine.prepare_native_hook — resolve target GOT slots and compute PAC-signed
/// replacement pointers in-process without crashing on read-only __DATA_CONST pages.
- (NSDictionary *)prepareNativeHookForBundleId:(NSString *)bundleId
                                          args:(NSDictionary *)args
                                         error:(NSString **)error;

/// engine.hook_native — rebind an imported symbol (fishhook) or a module export.
/// Transparently falls back to out-of-process mach_vm_protect + mach_vm_write via
/// mcp-memory when GOT slots reside in read-only __DATA_CONST / __AUTH_CONST.
/// args: { symbol | address, module?, record(bool), override_return?("0x..") }
- (NSDictionary *)hookNativeForBundleId:(NSString *)bundleId
                                   args:(NSDictionary *)args
                                  error:(NSString **)error;

/// engine.start_capture / engine.get_requests / engine.stop_capture — unified
/// NSURLSession + BoringSSL network capture inside libmcpengine.
- (NSDictionary *)startCaptureForBundleId:(NSString *)bundleId
                                     args:(NSDictionary *)args
                                    error:(NSString **)error;
- (NSDictionary *)getCapturedRequestsForBundleId:(NSString *)bundleId
                                            args:(NSDictionary *)args
                                           error:(NSString **)error;
- (NSDictionary *)stopCaptureForBundleId:(NSString *)bundleId
                                    args:(NSDictionary *)args
                                   error:(NSString **)error;

/// engine.call — invoke a native function at symbol/address with up to 8 int/ptr args.
- (NSDictionary *)callNativeForBundleId:(NSString *)bundleId
                                   args:(NSDictionary *)args // { symbol|address, module?, args[] }
                                  error:(NSString **)error;

/// engine.read_mem / write_mem / search_mem / protect — in-process (no task_for_pid).
- (NSDictionary *)readMemoryForBundleId:(NSString *)bundleId
                                address:(NSString *)address
                                 length:(NSUInteger)length
                                  error:(NSString **)error;
- (NSDictionary *)writeMemoryForBundleId:(NSString *)bundleId
                                 address:(NSString *)address
                              dataBase64:(NSString *)dataBase64
                                   error:(NSString **)error;
- (NSDictionary *)searchMemoryForBundleId:(NSString *)bundleId
                                     args:(NSDictionary *)args // { pattern|text, module?, protection?, limit }
                                    error:(NSString **)error;

/// engine.modules — loaded images (name, base, size, uuid, path) from inside the proc.
- (NSDictionary *)listModulesForBundleId:(NSString *)bundleId
                                  filter:(NSString *)filter
                                   limit:(NSUInteger)limit
                                   error:(NSString **)error;

/// engine.ping — liveness/handshake (returns engine version, pid, arch, module count).
- (NSDictionary *)pingForBundleId:(NSString *)bundleId
                            error:(NSString **)error;

@end
