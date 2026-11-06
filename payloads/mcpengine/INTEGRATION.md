# libmcpengine integration

This source drop implements the builder scope: engine sources, payload Makefile,
and fixture changes. The integrator retains ownership of manager registration,
injection/signing/trust, top-level build wiring, CI, and physical-device testing.
No binary has been built or device-tested on this Windows host.

## Build and package

Use the repository's existing RootHide Theos environment on macos-15. Build
`payloads/mcpengine` as a library subproject and stage its output with the other
payloads. Its Makefile explicitly clears THEOS_PACKAGE_SCHEME, targets iOS 15+,
builds arm64 + arm64e, and installs `/usr/lib/ios-mcp/libmcpengine.dylib`.
It references `../common/fishhook.c`; the shared rebinder is not duplicated.

Add the subproject to the top-level build and copy/stage list in build.sh. Confirm
both slices using the package Mach-O audit. Do not substitute an arm64-only build.

## Manager seam

Use the existing repository-root `MCPEngineManager.h` unchanged. Its low-level
method is the engine's complete transport seam:

```objc
- (NSDictionary *)sendOp:(NSString *)op
             forBundleId:(NSString *)bundleId
                    args:(NSDictionary *)args
               timeoutMs:(NSInteger)timeoutMs
                   error:(NSString **)error;
```

Send `{id:<integer>,op:"engine.<operation>",args:{...}}` as UTF-8 followed by LF.
Read through LF; parse the envelope, check the matching id and ok, and return
result or report error. Socket connections may persist or reconnect per call.
Serialize requests per process. A client idle for ten seconds is disconnected.
There is one dedicated server thread; it accepts clients serially. No main-run-loop
dispatch is required for socket servicing. Request and response limits are 1 MiB.

The fixture must be foregrounded for testing. The dedicated thread does not grant
background execution or defeat iOS suspension. The existing UIKit fixture already
had a view controller, HTTP button, and UIApplicationMain run loop; this update
adds an engine probe button, a 64-byte scratch accessor, and idle-timer suppression
when launched with `--engine-test` or when its engine config exists.

## Injection seam

```text
mcp-appmod inject-engine <app_bundle> <main_exec> <engine_src_dylib> <stealth_src_dylib> <data_container>
mcp-appmod unstage-engine <app_bundle> <main_exec> <stealth_name> <engine_name>
```

Stage the existing stealth companion first and engine second, sign and trust both,
then write `<data_container>/tmp/.mcpe_cfg.json` before launching the app:

```json
{"socket_path":"<data_container>/tmp/.me_<random_hex>","stealth_cfg":"<existing_companion_config_path>"}
```

The engine only reads socket_path; stealth_cfg belongs to the companion. Resolve
container path aliases server-side with MCPNormalizeUnixSocketContainerPath. The
engine resolves symlinks when checking the socket's parent against its own tmp.
It refuses paths outside tmp, long Unix-socket paths, existing non-socket files,
and sockets with active listeners. Socket permissions are 0600. No TCP is used.

Keep the staged binary names/load order/config paths in the manager session.
Remove staged payloads/config/socket files through the integrator's existing
unstage/sign/trust flow, and restart the app to fully unload the engine. Preserve
the retained gadget directory named in the supplied build spec.

## Operations

All operation names start with `engine.`. Required arguments and response fields
follow CUSTOM_ENGINE_STUBS.md. `describe` includes local instance/class methods,
ivars, properties, protocols, superclass and metaclass; inherited declarations can
be queried by walking `super`. `methods`, `ivars`, and `protocols` return the same
description object. Module entries additionally contain slide and segment ranges.

Extensions:

| Operation | Arguments | Result |
|---|---|---|
| dlsym | symbol, module? | address |
| dladdr | address | path, base, symbol, address |
| alloc | class | ret: handle |
| retain | handle | ret: same retained handle |
| release | handle | released:true |
| get_property | handle, name | ret |
| set_property | handle, name, value | ret |

Handles strongly retain objects and survive reconnections. They are deduplicated,
not reference-counted leases: retain is idempotent; release invalidates that handle.
At most 4096 handles exist. Events can contain handles; releasing one invalidates
its use in old event records as well. JSON strings passed as object args are literal
NSString objects; `{handle:N}` or `handle:N` references an existing object.
Raw object addresses are accepted for compatibility but must be valid live objects.
Object ivar writes use object_setIvarWithStrongDefault; properties use custom
getters/setters when present. These operations do not synchronize app-owned state.
Invoke executes on the socket thread. UI-affine methods need app-provided methods
that dispatch their work to the main thread. NSInvocation supports integer, bool,
floating-point, object, class, selector, and pointer values; aggregate/vector values
are rejected. Native call supports at most eight fixed integer/pointer arguments.
It is not a variadic-function calling facility.

## Hook limits and removal

Compiled static adapters replace method implementations or imported symbol slots;
no generated machine code, JIT, inline patches, or RWX allocation are involved.
ObjC hooks support at most six explicit integer/object/pointer arguments and a
scalar/object/pointer/void return. Hooking float, aggregate, vector, and variadic
signatures is unsupported. The ObjC runtime provides no general metadata flag for
variadic selectors: callers must use fixed signatures. Lifetime selectors
dealloc/retain/release/autorelease are rejected. Explicit `+ selector` selects a
class method; bare and `- selector` select instance methods. Inherited methods get
a local replacement; superclass implementations are untouched. ObjC unhook restores
the saved IMP and refuses to overwrite a replacement installed by someone else.

Native hook accepts symbol or an address resolving exactly to a symbol entry.
It rebinds app-bundle imports by default; module optionally selects the importing
image by exact full path or filename. It does not hook direct calls, exports, or
existing pointers obtained from dlsym. Future image loads are processed through
the dyld add-image callback. open/close/read/write have known argument counts;
other fixed integer/pointer signatures require the `arg_count` extension (0..8).
open alone has a dedicated variadic adapter handling O_CREAT's mode correctly.
Allocation and runtime primitives used by recording are rejected.

The shared rebinder reports neither patched-slot counts nor individual PAC-write
failures. `installed:true` means registration/application was attempted; confirm
actual interception with hook_events after an app call. Native unhook disables
overrides and recording and keeps the static adapter forwarding to the original
export until process exit. It does not promise to restore every GOT slot, chain
third-party hooks, or unload the dylib. A native symbol can be registered only once
per process. There are 64 total hook allocations per process; slots are never
reused, protecting calls already in flight. An in-flight call may finish after an
unhook response. Restart for a clean registry.

Event capture retains object arguments before the original call. Recording has a
thread-local recursion guard; recursive calls through instrumentation are forwarded
without recursive recording. Calls made deliberately through engine.invoke are
recorded. Native errno survives instrumentation. Argument/return recording failures
are contained; calls still complete. hook_events.count is the observed outer call
count; events contains at most max_events entries (default 256, maximum 4096).
Hooks with record:false still count calls. A return override skips the original
function, including its side effects. Void methods always forward.

## Memory handling

Transfers are capped at 256 KiB. Reads and writes check mapped permissions and use
Mach copy APIs, returning errors for unmapped ranges. Mapping changes remain
possible between checks and operations. Writes to executable pages are rejected.
protect accepts three-character r/w/x masks and rejects simultaneous write+execute,
including the conflicting rwx example in the supplied stub. Mach protections affect
whole pages; callers must account for other allocations sharing those pages.

search_mem accepts UTF-8 text or exact hex bytes with optional whitespace. It scans
readable regions in overlapping chunks, up to max_bytes (default 64 MiB, maximum
512 MiB); module constrains the image span and protection constrains current region
permissions. complete:false reports a limit, budget, or inaccessible changing
mapping; next_address allows continuation with start. The search is not a snapshot
and does not guarantee matches split across separate VM regions. Module listing
inherits any filtering already applied by the existing stealth companion.

## Validation

After CI compilation, stage/inject/launch the fixture, then run smoke.py with direct
access to its Unix socket. It verifies partial/coalesced frames, error replies,
class/ivar discovery, retained object handles, invocation, PIN override/events,
scalar mutation with restoration, memory round trip with restoration, module
search, getpid calling, native open recording, and logical unhook behavior.
The visible Run Engine Probe button provides an independent app-driven trigger;
it writes engine_probe.json in tmp. The integrator must also verify both Mach-O
slices, injection/removal, PAC behavior, clean relaunch, and the seven live-device
checks in the supplied spec. Python need not ship in the payload.

Documentation consulted: Apple's ARM64 ABI describes why variadic open needs a
dedicated adapter: https://developer.apple.com/documentation/xcode/writing-arm64-code-for-apple-platforms
