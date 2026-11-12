#ifndef MCP_ENGINE_RPC_H
#define MCP_ENGINE_RPC_H
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <stdint.h>
#include <pthread.h>

/* NDJSON, UTF-8, one request/response per line, persistent connections.
 * Request: {id: integer, op: "engine.*", args: object}
 * Reply: {id, ok:true, result:object} or {id, ok:false, error:string}.
 * Config: NSTemporaryDirectory()/.mcpe_cfg.json, {socket_path:string}.
 * Socket must be inside that directory; mode 0600. Handles live until release
 * or process exit, across connections (the manager reconnects for each RPC).
 * Limits: 1 MiB frame, 256 KiB memory transfer, 4096 handles, 64 hooks/process.
 * Hook ABI: fixed integer/pointer arguments only, <=8 native/<=6 ObjC args.
 * Native hook requires arg_count except known open/close/read/write symbols.
 * open has a dedicated variadic adapter. Others must be nonvariadic.
 * Hook slots are never recycled, including after unhook, to protect in-flight
 * callers. Events are bounded and recursive instrumentation is suppressed.
 * Additional ops: methods, ivars, protocols, get_property, set_property,
 * alloc, retain, release, dlsym, dladdr. See INTEGRATION.md for full details.
 */
#define ME_VERSION @"1.0.0"
#define ME_MAX_FRAME (1024u * 1024u)
#define ME_MAX_TRANSFER (256u * 1024u)
#define ME_HOOK_SLOTS 64

void MEFail(NSString *message) __attribute__((noreturn));
NSString *MEString(NSDictionary *a, NSString *key);
NSUInteger MELimit(NSDictionary *a, NSString *key, NSUInteger fallback, NSUInteger max);
uintptr_t MEWord(id value);
NSString *MEHex(uintptr_t value);
id MEBox(id object);
id METarget(id value);
const char *METype(const char *type);
id MEBoxValue(const char *type, const void *bytes);
void MEUnboxValue(const char *type, id value, void *bytes);
NSDictionary *MEObjC(NSString *op, NSDictionary *a);
NSDictionary *MEMemory(NSString *op, NSDictionary *a);
NSDictionary *MENative(NSString *op, NSDictionary *a);
NSDictionary *MEHooks(NSString *op, NSDictionary *a);
NSDictionary *MENetCap(NSString *op, NSDictionary *a);
NSDictionary *MERE(NSString *op, NSDictionary *a);
NSDictionary *MECrypto(NSString *op, NSDictionary *a);
NSDictionary *MEAntiFraud(NSString *op, NSDictionary *a);
NSDictionary *MEWebView(NSString *op, NSDictionary *a);
NSDictionary *MEMediaBio(NSString *op, NSDictionary *a);
NSDictionary *MESocial(NSString *op, NSDictionary *a);
IMP MEOriginalIMPForReplacement(IMP imp);
void MERegisterEngineServerThread(pthread_t thread);
void *MEResolve(NSDictionary *a);
uintptr_t MECall(void *fn, const uintptr_t *args, unsigned count);
const struct mach_header *MESelfHeader(void);

@interface MEHook : NSObject
@property(nonatomic, copy) NSString *key;
@property(nonatomic, copy) NSString *symbol;
@property(nonatomic, copy) NSString *module;
@property(nonatomic) Class owner;
@property(nonatomic) SEL selector;
@property(nonatomic) IMP originalIMP;
@property(nonatomic) void *originalFunction;
@property(nonatomic) void *replacement;
@property(nonatomic) unsigned slot, argc;
@property(atomic) BOOL active;
@property(nonatomic) BOOL record, objcHook;
@property(nonatomic) uintptr_t overrideBits;
@property(nonatomic, strong) id overrideObject;
@property(nonatomic) NSUInteger maxEvents;
@property(nonatomic) uint64_t count;
@property(nonatomic, strong) NSArray<NSString *> *types;
@property(nonatomic, strong) id overrideValue;
@property(nonatomic, strong) NSMutableArray *events;
@property(nonatomic, strong) NSMutableArray<NSDictionary *> *boundSlots;
@end
MEHook *MENewHook(NSDictionary *a);
void MECheckObjCHook(Class owner, SEL selector);
void MERecord(MEHook *hook, NSArray *args, uintptr_t result);
void *MEAdapter(unsigned slot);
void MERestoreNative(MEHook *hook);
void MEInitNative(void);
extern __thread unsigned MEDepth;
#endif
