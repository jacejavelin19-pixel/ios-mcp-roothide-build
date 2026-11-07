#import "FridaManager.h"
#import "AppManager.h"
#import "MCPProcessUtil.h"
#import <Security/Security.h>
#import <stdlib.h>
#import <sys/socket.h>
#import <sys/stat.h>
#import <sys/un.h>
#import <poll.h>
#import <unistd.h>

static NSString *const kMCPPreservedFridaDir = @"/var/mobile/Library/ios-mcp/frida";
static NSString *const kMCPPreservedGadgetPath = @"/var/mobile/Library/ios-mcp/frida/gadget.dylib";
static NSString *const kMCPPreservedGadgetXZPath = @"/var/mobile/Library/ios-mcp/frida/gadget.dylib.xz";
static NSString *const kMCPStealthPayloadLogicalPath = @"/usr/lib/ios-mcp/libmcp_stealth.dylib";

static NSString *MCPRandomHexString(NSUInteger byteCount) {
    NSMutableData *buf = [NSMutableData dataWithLength:byteCount];
    arc4random_buf(buf.mutableBytes, byteCount);
    const uint8_t *b = buf.bytes;
    NSMutableString *hex = [NSMutableString stringWithCapacity:byteCount * 2];
    for (NSUInteger i = 0; i < byteCount; i++) {
        [hex appendFormat:@"%02x", b[i]];
    }
    return hex;
}

static uint64_t MCPRandomNonZeroSeed(void) {
    uint64_t s = 0;
    while (s == 0) {
        arc4random_buf(&s, sizeof(s));
    }
    return s;
}

static NSString *MCPNormalizeUnixSocketContainerPath(NSString *containerPath) {
    if ([containerPath hasPrefix:@"/private/var/"]) {
        return [containerPath substringFromIndex:8]; // "/var/..." keeps sun_path <= 97 bytes (< 104 limit)
    }
    return containerPath;
}

static NSString *MCPBuildFridaBootScript(NSString *socketPath, NSString *optionalUserJS) {
    NSData *sockJsonData = [NSJSONSerialization dataWithJSONObject:@[socketPath] options:0 error:NULL];
    NSString *sockArrStr = [[NSString alloc] initWithData:sockJsonData encoding:NSUTF8StringEncoding] ?: @"[\"\"]";
    NSString *escapedSocketLiteral = [sockArrStr substringWithRange:NSMakeRange(1, sockArrStr.length - 2)];

    NSString *userBlock = @"";
    if (optionalUserJS.length > 0) {
        userBlock = [NSString stringWithFormat:
            @"\ntry {\n%@\n} catch (__userErr) {\n  globalThis.__mcpUserScriptError = String(__userErr && __userErr.stack ? __userErr.stack : __userErr);\n}\n",
            optionalUserJS];
    }

    return [NSString stringWithFormat:
@"'use strict';\n"
@"const CONTROL_SOCKET_PATH = %@;\n"
@"globalThis.__mcpControlSocketPath = CONTROL_SOCKET_PATH;\n"
@"globalThis.__mcpHooks = Object.create(null);\n"
@"globalThis.__mcpHookEvents = [];\n"
@"\n"
@"// Frida 17 compatibility polyfills\n"
@"function __mcpFindGlobalExport(sym) {\n"
@"  if (typeof Module.findGlobalExportByName === 'function') return Module.findGlobalExportByName(sym);\n"
@"  if (typeof Module.getGlobalExportByName === 'function') {\n"
@"    try { return Module.getGlobalExportByName(sym); } catch (_) { return null; }\n"
@"  }\n"
@"  if (typeof Module.findExportByName === 'function') return Module.findExportByName(null, sym);\n"
@"  return null;\n"
@"}\n"
@"if (typeof Module.findExportByName !== 'function') {\n"
@"  Module.findExportByName = function (modName, symName) {\n"
@"    if (modName === null || modName === undefined) return __mcpFindGlobalExport(symName);\n"
@"    const m = Process.findModuleByName(String(modName));\n"
@"    return m ? m.findExportByName(symName) : null;\n"
@"  };\n"
@"}\n"
@"if (typeof Memory.readUtf8String !== 'function') {\n"
@"  Memory.readUtf8String = function (p, len) { return ptr(p).readUtf8String(len); };\n"
@"}\n"
@"\n"
@"// Native libobjc.A.dylib C-API bridge for Frida 17 (where ObjC is unbundled from Gadget)\n"
@"(function initObjCBridge() {\n"
@"  if (typeof globalThis.ObjC !== 'undefined' && globalThis.ObjC && globalThis.ObjC.available) return;\n"
@"  const libobjc = Process.findModuleByName('libobjc.A.dylib');\n"
@"  if (!libobjc) {\n"
@"    globalThis.ObjC = { available: false, classes: {} };\n"
@"    return;\n"
@"  }\n"
@"  const fn = (name, ret, args) => {\n"
@"    const p = libobjc.findExportByName(name) || __mcpFindGlobalExport(name);\n"
@"    return p ? new NativeFunction(p, ret, args) : null;\n"
@"  };\n"
@"  const freePtr = __mcpFindGlobalExport('free');\n"
@"  const c_free = freePtr ? new NativeFunction(freePtr, 'void', ['pointer']) : null;\n"
@"  const objc_getClass = fn('objc_getClass', 'pointer', ['pointer']);\n"
@"  const object_getClass = fn('object_getClass', 'pointer', ['pointer']);\n"
@"  const class_getName = fn('class_getName', 'pointer', ['pointer']);\n"
@"  const class_getSuperclass = fn('class_getSuperclass', 'pointer', ['pointer']);\n"
@"  const class_copyMethodList = fn('class_copyMethodList', 'pointer', ['pointer', 'pointer']);\n"
@"  const class_getInstanceMethod = fn('class_getInstanceMethod', 'pointer', ['pointer', 'pointer']);\n"
@"  const class_getClassMethod = fn('class_getClassMethod', 'pointer', ['pointer', 'pointer']);\n"
@"  const method_getName = fn('method_getName', 'pointer', ['pointer']);\n"
@"  const method_getImplementation = fn('method_getImplementation', 'pointer', ['pointer']);\n"
@"  const method_getTypeEncoding = fn('method_getTypeEncoding', 'pointer', ['pointer']);\n"
@"  const sel_registerName = fn('sel_registerName', 'pointer', ['pointer']);\n"
@"  const sel_getName = fn('sel_getName', 'pointer', ['pointer']);\n"
@"  const objc_copyClassList = fn('objc_copyClassList', 'pointer', ['pointer']);\n"
@"  const objc_msgSend_ptr = libobjc.findExportByName('objc_msgSend') || __mcpFindGlobalExport('objc_msgSend');\n"
@"\n"
@"  function selectorPtr(name) {\n"
@"    return sel_registerName(Memory.allocUtf8String(String(name)));\n"
@"  }\n"
@"  function selectorStr(sel) {\n"
@"    const p = sel_getName(ptr(sel));\n"
@"    return p.isNull() ? '' : p.readUtf8String();\n"
@"  }\n"
@"  function listOwnMethods(clsPtr, prefix) {\n"
@"    if (!clsPtr || clsPtr.isNull() || !class_copyMethodList) return [];\n"
@"    const countBuf = Memory.alloc(4);\n"
@"    countBuf.writeU32(0);\n"
@"    const list = class_copyMethodList(clsPtr, countBuf);\n"
@"    const n = countBuf.readU32();\n"
@"    const out = [];\n"
@"    if (!list.isNull()) {\n"
@"      for (let i = 0; i < n; i++) {\n"
@"        const m = list.add(i * Process.pointerSize).readPointer();\n"
@"        const s = selectorStr(method_getName(m));\n"
@"        if (s) out.push(prefix + ' ' + s);\n"
@"      }\n"
@"      if (c_free) c_free(list);\n"
@"    }\n"
@"    return out;\n"
@"  }\n"
@"  function resolveMethod(clsPtr, spec) {\n"
@"    let isClass = null;\n"
@"    let selName = String(spec).trim();\n"
@"    if (selName.startsWith('+ ') || selName.startsWith('+')) {\n"
@"      isClass = true;\n"
@"      selName = selName.replace(/^\\+\\s*/, '');\n"
@"    } else if (selName.startsWith('- ') || selName.startsWith('-')) {\n"
@"      isClass = false;\n"
@"      selName = selName.replace(/^-\\s*/, '');\n"
@"    }\n"
@"    const sel = selectorPtr(selName);\n"
@"    let m = null;\n"
@"    if (isClass === true) {\n"
@"      m = class_getClassMethod(clsPtr, sel);\n"
@"    } else if (isClass === false) {\n"
@"      m = class_getInstanceMethod(clsPtr, sel);\n"
@"    } else {\n"
@"      m = class_getInstanceMethod(clsPtr, sel);\n"
@"      if (!m || m.isNull()) m = class_getClassMethod(clsPtr, sel);\n"
@"    }\n"
@"    if (!m || m.isNull()) return null;\n"
@"    const imp = method_getImplementation(m);\n"
@"    const encPtr = method_getTypeEncoding ? method_getTypeEncoding(m) : ptr(0);\n"
@"    return {\n"
@"      handle: m,\n"
@"      selector: sel,\n"
@"      selectorName: selName,\n"
@"      implementation: imp.strip ? imp.strip() : imp,\n"
@"      rawImplementation: imp,\n"
@"      types: (encPtr && !encPtr.isNull()) ? encPtr.readUtf8String() : ''\n"
@"    };\n"
@"  }\n"
@"  function wrapClass(clsPtr, nameHint) {\n"
@"    if (!clsPtr || clsPtr.isNull()) return null;\n"
@"    const cname = nameHint || class_getName(clsPtr).readUtf8String();\n"
@"    const metaPtr = object_getClass(clsPtr);\n"
@"    const base = {\n"
@"      handle: clsPtr,\n"
@"      $handle: clsPtr,\n"
@"      $className: cname,\n"
@"      toString() { return cname; }\n"
@"    };\n"
@"    return new Proxy(base, {\n"
@"      get(target, prop) {\n"
@"        if (prop in target) return target[prop];\n"
@"        if (prop === '$ownMethods') {\n"
@"          return listOwnMethods(metaPtr, '+').concat(listOwnMethods(clsPtr, '-'));\n"
@"        }\n"
@"        if (prop === '$superClass') {\n"
@"          const sup = class_getSuperclass(clsPtr);\n"
@"          return (sup && !sup.isNull()) ? wrapClass(sup) : null;\n"
@"        }\n"
@"        if (typeof prop === 'string' && (prop.startsWith('+ ') || prop.startsWith('- ') || prop.includes(':'))) {\n"
@"          return resolveMethod(clsPtr, prop);\n"
@"        }\n"
@"        if (typeof prop === 'string') {\n"
@"          const m = resolveMethod(clsPtr, prop);\n"
@"          if (m) return m;\n"
@"        }\n"
@"        return undefined;\n"
@"      }\n"
@"    });\n"
@"  }\n"
@"  function wrapObject(objPtr) {\n"
@"    const p = ptr(objPtr);\n"
@"    if (p.isNull()) return null;\n"
@"    const isa = object_getClass(p);\n"
@"    const cname = (!isa.isNull()) ? class_getName(isa).readUtf8String() : 'nil';\n"
@"    return {\n"
@"      handle: p,\n"
@"      $className: cname,\n"
@"      toString() {\n"
@"        if (!objc_msgSend_ptr) return '<' + cname + ': ' + p + '>';\n"
@"        try {\n"
@"          const msgObj = new NativeFunction(objc_msgSend_ptr, 'pointer', ['pointer', 'pointer']);\n"
@"          const desc = msgObj(p, selectorPtr('description'));\n"
@"          if (!desc.isNull()) {\n"
@"            const utf8 = msgObj(desc, selectorPtr('UTF8String'));\n"
@"            if (!utf8.isNull()) return utf8.readUtf8String();\n"
@"          }\n"
@"        } catch (_) {}\n"
@"        return '<' + cname + ': ' + p + '>';\n"
@"      }\n"
@"    };\n"
@"  }\n"
@"  const classesProxy = new Proxy(Object.create(null), {\n"
@"    get(_, prop) {\n"
@"      if (typeof prop !== 'string') return undefined;\n"
@"      const c = objc_getClass(Memory.allocUtf8String(prop));\n"
@"      return (!c || c.isNull()) ? undefined : wrapClass(c, prop);\n"
@"    },\n"
@"    has(_, prop) {\n"
@"      if (typeof prop !== 'string') return false;\n"
@"      const c = objc_getClass(Memory.allocUtf8String(prop));\n"
@"      return !!(c && !c.isNull());\n"
@"    }\n"
@"  });\n"
@"  globalThis.ObjC = {\n"
@"    available: true,\n"
@"    classes: classesProxy,\n"
@"    Object: wrapObject,\n"
@"    selector: selectorPtr,\n"
@"    selectorAsString: selectorStr,\n"
@"    msgSendPtr: objc_msgSend_ptr,\n"
@"    resolveMethod(className, spec) {\n"
@"      const c = objc_getClass(Memory.allocUtf8String(String(className)));\n"
@"      if (!c || c.isNull()) return null;\n"
@"      return resolveMethod(c, spec);\n"
@"    },\n"
@"    callNoArgObjectMethod(targetPtr, selName) {\n"
@"      const msg = new NativeFunction(objc_msgSend_ptr, 'pointer', ['pointer', 'pointer']);\n"
@"      return msg(ptr(targetPtr), selectorPtr(selName));\n"
@"    },\n"
@"    enumerateLoadedClassesSync() {\n"
@"      if (!objc_copyClassList) return [];\n"
@"      const countBuf = Memory.alloc(4);\n"
@"      countBuf.writeU32(0);\n"
@"      const buf = objc_copyClassList(countBuf);\n"
@"      const n = countBuf.readU32();\n"
@"      const names = [];\n"
@"      if (!buf.isNull()) {\n"
@"        for (let i = 0; i < n; i++) {\n"
@"          const c = buf.add(i * Process.pointerSize).readPointer();\n"
@"          const nm = class_getName(c);\n"
@"          if (!nm.isNull()) names.push(nm.readUtf8String());\n"
@"        }\n"
@"        if (c_free) c_free(buf);\n"
@"      }\n"
@"      return names;\n"
@"    }\n"
@"  };\n"
@"})();\n"
@"\n"
@"function __mcpSerialize(val, depth) {\n"
@"  if (depth === undefined) depth = 0;\n"
@"  if (val === null || val === undefined) return null;\n"
@"  const t = typeof val;\n"
@"  if (t === 'boolean' || t === 'number' || t === 'string') return val;\n"
@"  if (t === 'bigint') return val.toString();\n"
@"  if (val instanceof NativePointer) return val.toString();\n"
@"  if (val instanceof ArrayBuffer) {\n"
@"    const u8 = new Uint8Array(val);\n"
@"    const hex = [];\n"
@"    const cap = Math.min(u8.length, 256);\n"
@"    for (let i = 0; i < cap; i++) hex.push(u8[i].toString(16).padStart(2, '0'));\n"
@"    return { _type: 'ArrayBuffer', byteLength: u8.length, hexPreview: hex.join('') };\n"
@"  }\n"
@"  if (val instanceof Error) {\n"
@"    return { _type: 'Error', message: val.message, stack: val.stack || '' };\n"
@"  }\n"
@"  if (depth > 5) return String(val);\n"
@"  if (Array.isArray(val)) return val.map(x => __mcpSerialize(x, depth + 1));\n"
@"  if (t === 'object') {\n"
@"    if (val.handle instanceof NativePointer && val.$className) {\n"
@"      return { _objcClass: val.$className, handle: val.handle.toString(), description: val.toString() };\n"
@"    }\n"
@"    const out = {};\n"
@"    for (const k of Object.keys(val)) {\n"
@"      try { out[k] = __mcpSerialize(val[k], depth + 1); } catch (e) { out[k] = String(e); }\n"
@"    }\n"
@"    return out;\n"
@"  }\n"
@"  return String(val);\n"
@"}\n"
@"\n"
@"function __mcpInspectProcessThreads() {\n"
@"  const mach_task_self_p = __mcpFindGlobalExport('mach_task_self_');\n"
@"  const task_threads_p = __mcpFindGlobalExport('task_threads');\n"
@"  const pthread_from_mach_p = __mcpFindGlobalExport('pthread_from_mach_thread_np');\n"
@"  const pthread_getname_p = __mcpFindGlobalExport('pthread_getname_np');\n"
@"  const vm_dealloc_p = __mcpFindGlobalExport('vm_deallocate');\n"
@"  if (!mach_task_self_p || !task_threads_p || !pthread_from_mach_p || !pthread_getname_p) {\n"
@"    return { supported: false, threads: [] };\n"
@"  }\n"
@"  const taskSelf = mach_task_self_p.readU32();\n"
@"  const task_threads = new NativeFunction(task_threads_p, 'int', ['uint32', 'pointer', 'pointer']);\n"
@"  const pthread_from_mach = new NativeFunction(pthread_from_mach_p, 'pointer', ['uint32']);\n"
@"  const pthread_getname = new NativeFunction(pthread_getname_p, 'int', ['pointer', 'pointer', 'ulong']);\n"
@"  const listPtr = Memory.alloc(Process.pointerSize);\n"
@"  const cntPtr = Memory.alloc(4);\n"
@"  if (task_threads(taskSelf, listPtr, cntPtr) !== 0) return { supported: false, threads: [] };\n"
@"  const arr = listPtr.readPointer();\n"
@"  const cnt = cntPtr.readU32();\n"
@"  const nameBuf = Memory.alloc(128);\n"
@"  const names = [];\n"
@"  for (let i = 0; i < cnt; i++) {\n"
@"    const mth = arr.add(i * 4).readU32();\n"
@"    const pth = pthread_from_mach(mth);\n"
@"    let nm = '';\n"
@"    if (!pth.isNull()) {\n"
@"      nameBuf.writeU8(0);\n"
@"      if (pthread_getname(pth, nameBuf, 128) === 0) {\n"
@"        nm = nameBuf.readUtf8String() || '';\n"
@"      }\n"
@"    }\n"
@"    names.push({ index: i, mach_thread: mth, name: nm });\n"
@"  }\n"
@"  if (vm_dealloc_p && !arr.isNull()) {\n"
@"    const vm_deallocate = new NativeFunction(vm_dealloc_p, 'int', ['uint32', 'pointer', 'ulong']);\n"
@"    vm_deallocate(taskSelf, arr, cnt * 4);\n"
@"  }\n"
@"  return { supported: true, count: cnt, threads: names };\n"
@"}\n"
@"\n"
@"async function __mcpHandleCommand(msg) {\n"
@"  const op = msg.op || 'eval';\n"
@"  if (op === 'ping') {\n"
@"    return {\n"
@"      ok: true,\n"
@"      pid: Process.id,\n"
@"      arch: Process.arch,\n"
@"      platform: Process.platform,\n"
@"      page_size: Process.pageSize,\n"
@"      frida_version: Frida.version,\n"
@"      script_runtime: Script.runtime,\n"
@"      socket_path: CONTROL_SOCKET_PATH,\n"
@"      objc_available: !!(globalThis.ObjC && globalThis.ObjC.available),\n"
@"      rpc_exports: Object.keys((typeof rpc !== 'undefined' && rpc.exports) ? rpc.exports : {}),\n"
@"      user_script_error: globalThis.__mcpUserScriptError || null\n"
@"    };\n"
@"  }\n"
@"  if (op === 'eval') {\n"
@"    if (msg.rpc_method) {\n"
@"      const fn = (typeof rpc !== 'undefined' && rpc.exports) ? rpc.exports[msg.rpc_method] : null;\n"
@"      if (typeof fn !== 'function') throw new Error('rpc.exports.' + msg.rpc_method + ' is not a function');\n"
@"      const val = await fn.apply(rpc.exports, Array.isArray(msg.rpc_args) ? msg.rpc_args : []);\n"
@"      return { ok: true, value: __mcpSerialize(val) };\n"
@"    }\n"
@"    const code = String(msg.code || '');\n"
@"    const val = await (0, eval)(code);\n"
@"    return { ok: true, value: __mcpSerialize(val) };\n"
@"  }\n"
@"  if (op === 'list_modules') {\n"
@"    const mods = Process.enumerateModules();\n"
@"    const filter = msg.filter ? String(msg.filter).toLowerCase() : '';\n"
@"    const limit = msg.limit > 0 ? msg.limit : 200;\n"
@"    const filtered = [];\n"
@"    for (const m of mods) {\n"
@"      if (filter && !m.name.toLowerCase().includes(filter) && !m.path.toLowerCase().includes(filter)) continue;\n"
@"      if (filtered.length < limit) {\n"
@"        filtered.push({ name: m.name, base: m.base.toString(), size: m.size, path: m.path });\n"
@"      }\n"
@"    }\n"
@"    return { ok: true, gum_total_modules: mods.length, returned_count: filtered.length, modules: filtered };\n"
@"  }\n"
@"  if (op === 'hook_objc') {\n"
@"    const action = msg.action || 'install';\n"
@"    if (action === 'get_events') {\n"
@"      const evs = globalThis.__mcpHookEvents.slice(-(msg.max_events || 100));\n"
@"      return { ok: true, active_hooks: Object.keys(globalThis.__mcpHooks), event_count: evs.length, total_buffered: globalThis.__mcpHookEvents.length, events: evs };\n"
@"    }\n"
@"    if (action === 'clear') {\n"
@"      globalThis.__mcpHookEvents = [];\n"
@"      return { ok: true, cleared: true, active_hooks: Object.keys(globalThis.__mcpHooks) };\n"
@"    }\n"
@"    const clsName = String(msg.class_name || '');\n"
@"    const selSpec = String(msg.selector || '');\n"
@"    const key = clsName + '::' + selSpec;\n"
@"    if (action === 'remove') {\n"
@"      if (globalThis.__mcpHooks[key]) {\n"
@"        globalThis.__mcpHooks[key].detach();\n"
@"        delete globalThis.__mcpHooks[key];\n"
@"        return { ok: true, removed: true, hook_key: key };\n"
@"      }\n"
@"      return { ok: true, removed: false, hook_key: key };\n"
@"    }\n"
@"    if (!globalThis.ObjC || !globalThis.ObjC.available) throw new Error('ObjC runtime unavailable');\n"
@"    const resolved = globalThis.ObjC.resolveMethod(clsName, selSpec);\n"
@"    if (!resolved) throw new Error('Method not found: ' + clsName + ' ' + selSpec);\n"
@"    if (globalThis.__mcpHooks[key]) {\n"
@"      globalThis.__mcpHooks[key].detach();\n"
@"      delete globalThis.__mcpHooks[key];\n"
@"    }\n"
@"    const argCount = Math.max(0, (resolved.selectorName.match(/:/g) || []).length);\n"
@"    const overrideInt = (typeof msg.override_return_int === 'number') ? msg.override_return_int : null;\n"
@"    const listener = Interceptor.attach(resolved.implementation, {\n"
@"      onEnter(args) {\n"
@"        this._entry = {\n"
@"          hook: key,\n"
@"          timestamp: Date.now(),\n"
@"          thread_id: Process.getCurrentThreadId(),\n"
@"          self: args[0].toString(),\n"
@"          selector: resolved.selectorName,\n"
@"          raw_args: []\n"
@"        };\n"
@"        for (let i = 0; i < Math.min(argCount, 6); i++) {\n"
@"          this._entry.raw_args.push(args[2 + i].toString());\n"
@"        }\n"
@"      },\n"
@"      onLeave(retval) {\n"
@"        if (this._entry) {\n"
@"          this._entry.original_retval = retval.toString();\n"
@"          if (overrideInt !== null) {\n"
@"            retval.replace(ptr(overrideInt));\n"
@"            this._entry.overridden_retval = ptr(overrideInt).toString();\n"
@"          }\n"
@"          globalThis.__mcpHookEvents.push(this._entry);\n"
@"          if (globalThis.__mcpHookEvents.length > 500) globalThis.__mcpHookEvents.shift();\n"
@"        }\n"
@"      }\n"
@"    });\n"
@"    globalThis.__mcpHooks[key] = listener;\n"
@"    return {\n"
@"      ok: true,\n"
@"      installed: true,\n"
@"      hook_key: key,\n"
@"      implementation: resolved.implementation.toString(),\n"
@"      types: resolved.types,\n"
@"      arg_count: argCount\n"
@"    };\n"
@"  }\n"
@"  if (op === 'memory_scan') {\n"
@"    const pattern = String(msg.pattern || '');\n"
@"    if (!pattern) throw new Error('pattern is required');\n"
@"    const limit = msg.limit > 0 ? Math.min(msg.limit, 500) : 50;\n"
@"    const prot = msg.protection || 'r--';\n"
@"    const modName = msg.module_name ? String(msg.module_name) : null;\n"
@"    let ranges = [];\n"
@"    if (modName) {\n"
@"      const m = Process.findModuleByName(modName);\n"
@"      if (!m) throw new Error('Module not found: ' + modName);\n"
@"      ranges = [{ base: m.base, size: m.size, protection: 'r-x', module: m.name }];\n"
@"    } else {\n"
@"      ranges = Process.enumerateRanges(prot).slice(0, 512);\n"
@"    }\n"
@"    const matches = [];\n"
@"    let scannedBytes = 0;\n"
@"    for (const r of ranges) {\n"
@"      if (matches.length >= limit) break;\n"
@"      try {\n"
@"        const hits = Memory.scanSync(r.base, r.size, pattern);\n"
@"        scannedBytes += r.size;\n"
@"        for (const h of hits) {\n"
@"          matches.push({ address: h.address.toString(), size: h.size, module: r.module || null });\n"
@"          if (matches.length >= limit) break;\n"
@"        }\n"
@"      } catch (_) {}\n"
@"    }\n"
@"    return { ok: true, pattern, scanned_ranges: ranges.length, scanned_bytes: scannedBytes, match_count: matches.length, matches };\n"
@"  }\n"
@"  if (op === 'anti_detection_probe') {\n"
@"    const threadAudit = __mcpInspectProcessThreads();\n"
@"    const suspiciousTerms = ['frida', 'gum-js-loop', 'gmain', 'gdbus', 'pool-spawner', 'gadget'];\n"
@"    const leakedThreads = (threadAudit.threads || []).filter(t => {\n"
@"      const low = (t.name || '').toLowerCase();\n"
@"      return suspiciousTerms.some(s => low.includes(s));\n"
@"    });\n"
@"    let appSelfAudit = null;\n"
@"    if (globalThis.ObjC && globalThis.ObjC.available && ('MCPTestVault' in globalThis.ObjC.classes)) {\n"
@"      try {\n"
@"        const vaultCls = globalThis.ObjC.classes.MCPTestVault.$handle;\n"
@"        const jsonNS = globalThis.ObjC.callNoArgObjectMethod(vaultCls, 'runAntiDetectionAuditJSON');\n"
@"        if (jsonNS && !jsonNS.isNull()) {\n"
@"          const cstr = globalThis.ObjC.callNoArgObjectMethod(jsonNS, 'UTF8String');\n"
@"          if (cstr && !cstr.isNull()) {\n"
@"            appSelfAudit = JSON.parse(cstr.readUtf8String());\n"
@"          }\n"
@"        }\n"
@"      } catch (e) {\n"
@"        appSelfAudit = { error: String(e) };\n"
@"      }\n"
@"    }\n"
@"    return {\n"
@"      ok: true,\n"
@"      pid: Process.id,\n"
@"      transport: 'unix_domain_socket_only',\n"
@"      control_socket_path: CONTROL_SOCKET_PATH,\n"
@"      tcp_listener_opened: false,\n"
@"      thread_audit: {\n"
@"        total_threads: threadAudit.count || 0,\n"
@"        leaked_frida_threads: leakedThreads,\n"
@"        all_threads_clean: leakedThreads.length === 0,\n"
@"        threads: threadAudit.threads || []\n"
@"      },\n"
@"      gum_internal_module_count: Process.enumerateModules().length,\n"
@"      app_perspective_audit: appSelfAudit\n"
@"    };\n"
@"  }\n"
@"  throw new Error('Unknown RPC op: ' + op);\n"
@"}\n"
@"%@\n"
@"// Unlink stale Unix domain socket before listening, then chmod 0666\n"
@"(function startControlServer() {\n"
@"  const unlinkPtr = __mcpFindGlobalExport('unlink');\n"
@"  const chmodPtr = __mcpFindGlobalExport('chmod');\n"
@"  const sockCStr = Memory.allocUtf8String(CONTROL_SOCKET_PATH);\n"
@"  if (unlinkPtr) {\n"
@"    const c_unlink = new NativeFunction(unlinkPtr, 'int', ['pointer']);\n"
@"    c_unlink(sockCStr);\n"
@"  }\n"
@"  Socket.listen({ family: 'unix', path: CONTROL_SOCKET_PATH }).then(server => {\n"
@"    globalThis.__mcpServer = server;\n"
@"    if (chmodPtr) {\n"
@"      const c_chmod = new NativeFunction(chmodPtr, 'int', ['pointer', 'uint16']);\n"
@"      c_chmod(sockCStr, 0o666);\n"
@"    }\n"
@"    (async function acceptLoop() {\n"
@"      while (true) {\n"
@"        let conn;\n"
@"        try {\n"
@"          conn = await server.accept();\n"
@"        } catch (_) {\n"
@"          break;\n"
@"        }\n"
@"        (async function handleConn(c) {\n"
@"          try {\n"
@"            let acc = '';\n"
@"            while (acc.indexOf('\\n') === -1) {\n"
@"              const buf = await c.input.read(8192);\n"
@"              if (!buf || buf.byteLength === 0) break;\n"
@"              const u8 = new Uint8Array(buf);\n"
@"              let chunk = '';\n"
@"              for (let i = 0; i < u8.length; i++) chunk += String.fromCharCode(u8[i]);\n"
@"              acc += chunk;\n"
@"            }\n"
@"            const nl = acc.indexOf('\\n');\n"
@"            const line = (nl >= 0 ? acc.slice(0, nl) : acc).trim();\n"
@"            let resp;\n"
@"            try {\n"
@"              const req = JSON.parse(line);\n"
@"              resp = await __mcpHandleCommand(req);\n"
@"            } catch (err) {\n"
@"              resp = { ok: false, error: String(err && err.message ? err.message : err), stack: (err && err.stack) ? String(err.stack) : '' };\n"
@"            }\n"
@"            const jsonStr = JSON.stringify(resp) + '\\n';\n"
@"            const enc = [];\n"
@"            for (let i = 0; i < jsonStr.length; i++) {\n"
@"              const code = jsonStr.charCodeAt(i);\n"
@"              if (code < 0x80) enc.push(code);\n"
@"              else if (code < 0x800) { enc.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f)); }\n"
@"              else { enc.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f)); }\n"
@"            }\n"
@"            await c.output.writeAll(new Uint8Array(enc).buffer);\n"
@"          } catch (_) {\n"
@"          } finally {\n"
@"            try { await c.close(); } catch (_) {}\n"
@"          }\n"
@"        })(conn);\n"
@"      }\n"
@"    })();\n"
@"  }).catch(err => {\n"
@"    globalThis.__mcpListenError = String(err);\n"
@"  });\n"
@"})();\n",
        escapedSocketLiteral, userBlock];
}

@implementation FridaManager

+ (instancetype)sharedInstance {
    static FridaManager *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[FridaManager alloc] init];
    });
    return instance;
}

- (NSString *)sessionsDirectory {
    NSString *dir = [MCPResolvedJailbreakPath(kMCPPreservedFridaDir) stringByAppendingPathComponent:@"sessions"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    chmod([dir stringByDeletingLastPathComponent].UTF8String, 0777);
    chmod(dir.UTF8String, 0777);
    return dir;
}

- (NSString *)sessionFilePathForBundleId:(NSString *)bundleId {
    NSString *safe = [[bundleId componentsSeparatedByCharactersInSet:
                       [[NSCharacterSet characterSetWithCharactersInString:@"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"] invertedSet]]
                      componentsJoinedByString:@"_"];
    return [[self sessionsDirectory] stringByAppendingPathComponent:[NSString stringWithFormat:@"%@.json", safe]];
}

- (NSDictionary *)loadSessionForBundleId:(NSString *)bundleId {
    NSData *d = [NSData dataWithContentsOfFile:[self sessionFilePathForBundleId:bundleId]];
    if (!d.length) return nil;
    NSDictionary *s = [NSJSONSerialization JSONObjectWithData:d options:0 error:NULL];
    return [s isKindOfClass:[NSDictionary class]] ? s : nil;
}

- (void)saveSession:(NSDictionary *)session forBundleId:(NSString *)bundleId {
    if (![session isKindOfClass:[NSDictionary class]] || !bundleId.length) return;
    NSData *d = [NSJSONSerialization dataWithJSONObject:session options:NSJSONWritingPrettyPrinted error:NULL];
    [d writeToFile:[self sessionFilePathForBundleId:bundleId] options:NSDataWritingAtomic error:NULL];
}

- (void)deleteSessionForBundleId:(NSString *)bundleId {
    if (!bundleId.length) return;
    [[NSFileManager defaultManager] removeItemAtPath:[self sessionFilePathForBundleId:bundleId] error:nil];
}

- (NSString *)ensurePreservedGadgetAvailable:(NSString **)error {
    // kMCPPreservedGadgetPath/kMCPPreservedGadgetXZPath are logical (pre-RootHide)
    // paths; resolve them against the current .jbroot-* root on every call rather
    // than assuming a fixed location, since the jbroot id can change across
    // reinstalls/respring cycles.
    NSString *resolvedGadgetPath = MCPResolvedJailbreakPath(kMCPPreservedGadgetPath);
    NSString *resolvedGadgetXZPath = MCPResolvedJailbreakPath(kMCPPreservedGadgetXZPath);
    NSFileManager *fm = [NSFileManager defaultManager];
    if ([fm fileExistsAtPath:resolvedGadgetPath]) {
        return resolvedGadgetPath;
    }
    if ([fm fileExistsAtPath:resolvedGadgetXZPath]) {
        NSString *outStr = nil, *runErr = nil;
        int code = -1;
        BOOL ok = MCPRunRootProcess(@"/usr/libexec/ios-mcp/mcp-appmod",
                                    @[@"decompress-xz", resolvedGadgetXZPath, resolvedGadgetPath],
                                    60.0,
                                    256 * 1024,
                                    &outStr,
                                    &code,
                                    &runErr);
        if (ok && code == 0 && [fm fileExistsAtPath:resolvedGadgetPath]) {
            return resolvedGadgetPath;
        }
        if (error) *error = [NSString stringWithFormat:@"Failed to decompress preserved gadget.dylib.xz: %@", outStr ?: runErr ?: @"error"];
        return nil;
    }
    if (error) *error = [NSString stringWithFormat:@"Preserved Frida Gadget not found at %@", resolvedGadgetPath];
    return nil;
}

- (BOOL)writeContainerJSON:(NSDictionary *)dict toPath:(NSString *)destPath error:(NSString **)error {
    NSError *jsonErr = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:dict options:NSJSONWritingPrettyPrinted error:&jsonErr];
    if (!data) {
        if (error) *error = jsonErr.localizedDescription ?: @"JSON serialization failed";
        return NO;
    }
    if ([data writeToFile:destPath options:NSDataWritingAtomic error:nil]) {
        chmod(destPath.fileSystemRepresentation, 0666);
        return YES;
    }
    NSString *workDir = MCPResolvedJailbreakPath(@"/var/mobile/Library/Caches/ios-mcp-work");
    [[NSFileManager defaultManager] createDirectoryAtPath:workDir withIntermediateDirectories:YES attributes:nil error:nil];
    chmod(workDir.UTF8String, 0777);
    NSString *tmpPath = [workDir stringByAppendingPathComponent:[NSString stringWithFormat:@"cfg-%@.json", [NSUUID UUID].UUIDString]];
    if (![data writeToFile:tmpPath options:NSDataWritingAtomic error:&jsonErr]) {
        tmpPath = [NSTemporaryDirectory() stringByAppendingPathComponent:[NSString stringWithFormat:@"cfg-%@.json", [NSUUID UUID].UUIDString]];
        if (![data writeToFile:tmpPath options:NSDataWritingAtomic error:&jsonErr]) {
            if (error) *error = jsonErr.localizedDescription ?: @"Failed to write temp file";
            return NO;
        }
    }
    NSString *outStr = nil, *runErr = nil;
    int code = -1;
    BOOL ok = MCPRunRootProcess(@"/usr/libexec/ios-mcp/mcp-appmod",
                                @[@"write-file", destPath, tmpPath, @"0666"],
                                15.0,
                                65536,
                                &outStr,
                                &code,
                                &runErr);
    [[NSFileManager defaultManager] removeItemAtPath:tmpPath error:nil];
    if (!ok || code != 0) {
        if (error) *error = outStr ?: runErr ?: @"mcp-appmod write-file failed";
        return NO;
    }
    return YES;
}

- (NSDictionary *)readContainerJSONAtPath:(NSString *)path {
    if (!path.length) return nil;
    NSData *data = [NSData dataWithContentsOfFile:path];
    if (!data) {
        NSData *rootBytes = nil;
        BOOL truncated = NO;
        int code = -1;
        NSString *runErr = nil;
        if (MCPRunRootProcessData(@"/usr/libexec/ios-mcp/mcp-appmod",
                                  @[@"read-file", path, @"1048576"],
                                  10.0,
                                  1024 * 1024,
                                  &rootBytes,
                                  &truncated,
                                  &code,
                                  &runErr) && code == 0) {
            data = rootBytes;
        }
    }
    if (!data.length) return nil;
    NSDictionary *dict = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
    return [dict isKindOfClass:[NSDictionary class]] ? dict : nil;
}

#pragma mark - #13 Scrub Gadget Binary

- (NSDictionary *)scrubGadgetBinaryAtPath:(NSString *)dylibPath
                               outputPath:(NSString *)outputPath
                                     seed:(NSNumber *)seedNumber
                                    error:(NSString **)error {
    if (error) *error = nil;
    NSString *srcPath = dylibPath.length > 0 ? MCPResolvedJailbreakPath(dylibPath) : [self ensurePreservedGadgetAvailable:error];
    if (!srcPath.length) return nil;

    uint64_t seed = (seedNumber && [seedNumber respondsToSelector:@selector(unsignedLongLongValue)] && seedNumber.unsignedLongLongValue != 0)
        ? seedNumber.unsignedLongLongValue
        : MCPRandomNonZeroSeed();

    NSString *destPath = outputPath;
    if (!destPath.length) {
        NSString *workDir = @"/var/mobile/Library/Caches/ios-mcp-work";
        [[NSFileManager defaultManager] createDirectoryAtPath:workDir withIntermediateDirectories:YES attributes:nil error:nil];
        destPath = [workDir stringByAppendingPathComponent:[NSString stringWithFormat:@"libAppleAudioDSP_%@.dylib", MCPRandomHexString(4)]];
    } else {
        destPath = MCPResolvedJailbreakPath(destPath);
    }

    if ([destPath isEqualToString:MCPResolvedJailbreakPath(kMCPPreservedGadgetPath)] ||
        [destPath isEqualToString:MCPResolvedJailbreakPath(kMCPPreservedGadgetXZPath)]) {
        if (error) *error = @"Refusing to overwrite preserved gadget.dylib / gadget.dylib.xz in place; provide a distinct output_path";
        return nil;
    }

    NSString *outStr = nil, *runErr = nil;
    int exitCode = -1;
    BOOL ok = MCPRunRootProcess(@"/usr/libexec/ios-mcp/mcp-appmod",
                                @[@"scrub-dylib", srcPath, destPath, [NSString stringWithFormat:@"%llu", (unsigned long long)seed]],
                                60.0,
                                512 * 1024,
                                &outStr,
                                &exitCode,
                                &runErr);
    if (!ok) {
        if (error) *error = runErr ?: @"Failed to invoke mcp-appmod scrub-dylib";
        return nil;
    }
    NSData *respData = [outStr dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *resp = respData ? [NSJSONSerialization JSONObjectWithData:respData options:0 error:NULL] : nil;
    if (![resp isKindOfClass:[NSDictionary class]] || exitCode != 0 || ![resp[@"ok"] boolValue]) {
        if (error) *error = [resp[@"error"] isKindOfClass:[NSString class]] ? resp[@"error"] : @"scrub_gadget_binary failed";
        return nil;
    }
    return [resp[@"result"] isKindOfClass:[NSDictionary class]] ? resp[@"result"] : nil;
}

#pragma mark - #11 + #12 + #14 + #15 Inject & Remove Frida Gadget

- (NSDictionary *)injectFridaGadgetForBundleId:(NSString *)bundleId
                                    scriptPath:(NSString *)scriptPath
                                 stealthConfig:(NSDictionary *)stealthConfig
                                        launch:(BOOL)launch
                                         error:(NSString **)error {
    if (error) *error = nil;
    if (![bundleId isKindOfClass:[NSString class]] || !bundleId.length) {
        if (error) *error = @"bundle_id is required";
        return nil;
    }
    if ([bundleId isEqualToString:@"com.apple.springboard"]) {
        if (error) *error = @"Refusing to inject Frida Gadget into SpringBoard";
        return nil;
    }

    NSString *gadgetSrc = [self ensurePreservedGadgetAvailable:error];
    if (!gadgetSrc) return nil;

    NSString *stealthSrc = MCPResolvedJailbreakPath(kMCPStealthPayloadLogicalPath);
    if (![[NSFileManager defaultManager] fileExistsAtPath:stealthSrc]) {
        if (error) *error = [NSString stringWithFormat:@"Stealth companion dylib missing at %@", stealthSrc];
        return nil;
    }

    NSString *appErr = nil;
    NSDictionary *appInfo = [[AppManager sharedInstance] appInfoForBundleId:bundleId error:&appErr];
    if (!appInfo) {
        if (error) *error = appErr ?: [NSString stringWithFormat:@"App not found: %@", bundleId];
        return nil;
    }

    NSString *bundlePath = [appInfo[@"bundle_path"] isKindOfClass:[NSString class]] ? appInfo[@"bundle_path"] : nil;
    NSString *mainExec = [appInfo[@"executable_path"] isKindOfClass:[NSString class]] ? appInfo[@"executable_path"] : nil;
    id rawContainer = appInfo[@"data_container"] ?: appInfo[@"data_container_path"];
    NSString *dataContainer = [rawContainer isKindOfClass:[NSString class]] ? rawContainer : nil;
    if (!bundlePath.length || !mainExec.length || !dataContainer.length) {
        if (error) *error = [NSString stringWithFormat:@"App %@ is missing bundle_path, executable_path, or data_container_path", bundleId];
        return nil;
    }
    if ([mainExec hasPrefix:@"/System/"] || [mainExec hasPrefix:@"/Applications/"]) {
        if (error) *error = [NSString stringWithFormat:@"Refusing to modify system binary: %@", mainExec];
        return nil;
    }

    NSString *optionalUserJS = nil;
    if (scriptPath.length > 0) {
        NSString *resolvedJS = MCPResolvedJailbreakPath(scriptPath);
        NSError *jsErr = nil;
        optionalUserJS = [NSString stringWithContentsOfFile:resolvedJS encoding:NSUTF8StringEncoding error:&jsErr];
        if (!optionalUserJS) {
            if (error) *error = [NSString stringWithFormat:@"Cannot read script_path %@: %@", scriptPath, jsErr.localizedDescription ?: @"unreadable"];
            return nil;
        }
    }

    // Cleanly remove any prior Gadget session on this bundleId before re-staging
    NSDictionary *existingSession = [self loadSessionForBundleId:bundleId];
    if (existingSession) {
        [self removeFridaGadgetForBundleId:bundleId error:nil];
    } else if ([[AppManager sharedInstance] pidForBundleId:bundleId] > 0) {
        [[AppManager sharedInstance] killApp:bundleId error:nil];
        usleep(200 * 1000);
    }

    uint64_t seed = MCPRandomNonZeroSeed();
    NSString *stealthName = [NSString stringWithFormat:@"libAppleCoreSVG_%@.dylib", MCPRandomHexString(3)];
    NSString *gadgetStem = [NSString stringWithFormat:@"libAppleAudioDSP_%@", MCPRandomHexString(3)];
    NSString *gadgetName = [gadgetStem stringByAppendingString:@".dylib"];
    NSString *normContainer = MCPNormalizeUnixSocketContainerPath(dataContainer);
    NSString *socketPath = [normContainer stringByAppendingPathComponent:
                            [NSString stringWithFormat:@"tmp/.fc_%@", MCPRandomHexString(6)]];

    NSDictionary *gadgetCfgObj = @{
        @"interaction": @{
            @"type": @"script",
            @"path": [gadgetStem stringByAppendingString:@".js"],
            @"on_change": @"reload"
        },
        @"code_signing": @"optional"
    };
    NSString *bootJS = MCPBuildFridaBootScript(socketPath, optionalUserJS);

    NSString *workDir = @"/var/mobile/Library/Caches/ios-mcp-work";
    [[NSFileManager defaultManager] createDirectoryAtPath:workDir withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *cfgTmp = [workDir stringByAppendingPathComponent:[NSString stringWithFormat:@"gcfg-%@.config", [NSUUID UUID].UUIDString]];
    NSString *jsTmp = [workDir stringByAppendingPathComponent:[NSString stringWithFormat:@"gjs-%@.js", [NSUUID UUID].UUIDString]];

    NSData *cfgData = [NSJSONSerialization dataWithJSONObject:gadgetCfgObj options:NSJSONWritingPrettyPrinted error:NULL];
    NSData *jsData = [bootJS dataUsingEncoding:NSUTF8StringEncoding];
    if (![cfgData writeToFile:cfgTmp options:NSDataWritingAtomic error:nil] ||
        ![jsData writeToFile:jsTmp options:NSDataWritingAtomic error:nil]) {
        [[NSFileManager defaultManager] removeItemAtPath:cfgTmp error:nil];
        [[NSFileManager defaultManager] removeItemAtPath:jsTmp error:nil];
        if (error) *error = @"Failed to prepare temporary Gadget config/script files";
        return nil;
    }

    NSString *outStr = nil, *runErr = nil;
    int exitCode = -1;
    BOOL ok = MCPRunRootProcess(@"/usr/libexec/ios-mcp/mcp-appmod",
                                @[@"stage-frida",
                                  bundlePath,
                                  mainExec,
                                  stealthSrc,
                                  gadgetSrc,
                                  cfgTmp,
                                  jsTmp,
                                  stealthName,
                                  gadgetName,
                                  [NSString stringWithFormat:@"%llu", (unsigned long long)seed]],
                                90.0,
                                1024 * 1024,
                                &outStr,
                                &exitCode,
                                &runErr);
    [[NSFileManager defaultManager] removeItemAtPath:cfgTmp error:nil];
    [[NSFileManager defaultManager] removeItemAtPath:jsTmp error:nil];

    if (!ok) {
        if (error) *error = runErr ?: @"Failed to invoke mcp-appmod stage-frida";
        return nil;
    }
    NSData *respData = [outStr dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *resp = respData ? [NSJSONSerialization JSONObjectWithData:respData options:0 error:NULL] : nil;
    if (![resp isKindOfClass:[NSDictionary class]] || exitCode != 0 || ![resp[@"ok"] boolValue]) {
        if (error) *error = [resp[@"error"] isKindOfClass:[NSString class]] ? resp[@"error"] : @"inject_frida_gadget failed";
        return nil;
    }

    NSDictionary *stageRes = [resp[@"result"] isKindOfClass:[NSDictionary class]] ? resp[@"result"] : @{};
    NSDictionary *scrubRes = [stageRes[@"scrub"] isKindOfClass:[NSDictionary class]] ? stageRes[@"scrub"] : @{};
    NSDictionary *tokenMap = [scrubRes[@"token_map"] isKindOfClass:[NSDictionary class]] ? scrubRes[@"token_map"] : @{};

    // Write <DataContainer>/tmp/.mcp_stealth_cfg.json BEFORE launching the app so constructor(101) knows exact scrubbed tokens & filenames!
    NSMutableDictionary *cfgDoc = [@{
        @"thread_cloak": @YES,
        @"dyld_cloak": @YES,
        @"anti_debug": @YES,
        @"exception_cloak": @YES,
        @"fs_cloak": @YES,
        @"port_cloak": @YES,
        @"env_scheme_cloak": @YES,
        @"vm_integrity_cloak": @YES,
        @"hidden_dylib_names": @[stealthName, gadgetName],
        @"scrubbed_tokens": tokenMap.allValues ?: @[]
    } mutableCopy];
    if ([stealthConfig isKindOfClass:[NSDictionary class]]) {
        for (NSString *k in @[@"thread_cloak", @"dyld_cloak", @"anti_debug", @"exception_cloak",
                              @"fs_cloak", @"port_cloak", @"env_scheme_cloak", @"vm_integrity_cloak"]) {
            if (stealthConfig[k] != nil) {
                cfgDoc[k] = @([stealthConfig[k] boolValue]);
            }
        }
    }

    NSString *stealthCfgPath = [dataContainer stringByAppendingPathComponent:@"tmp/.mcp_stealth_cfg.json"];
    NSString *stealthStatusPath = [dataContainer stringByAppendingPathComponent:@"tmp/.mcp_stealth_status.json"];
    [self writeContainerJSON:cfgDoc toPath:stealthCfgPath error:nil];

    NSDictionary *sessionDoc = @{
        @"bundle_id": bundleId,
        @"bundle_path": bundlePath,
        @"main_executable": mainExec,
        @"data_container_path": dataContainer,
        @"stealth_dylib_name": stealthName,
        @"gadget_dylib_name": gadgetName,
        @"scrub_seed": [NSString stringWithFormat:@"0x%016llx", (unsigned long long)seed],
        @"scrub_token_map": tokenMap,
        @"socket_path": socketPath,
        @"stealth_cfg_path": stealthCfgPath,
        @"stealth_status_path": stealthStatusPath,
        @"custom_script_path": scriptPath ?: @"",
        @"injected_at": @([[NSDate date] timeIntervalSince1970])
    };
    [self saveSession:sessionDoc forBundleId:bundleId];

    BOOL launched = NO;
    BOOL socketReady = NO;
    NSDictionary *pingInfo = nil;
    NSString *launchErr = nil;

    if (launch) {
        launched = [[AppManager sharedInstance] launchApp:bundleId error:&launchErr];
        if (launched) {
            for (int attempt = 0; attempt < 25; attempt++) {
                NSString *pingErr = nil;
                NSDictionary *ping = [self sendUnixCommand:@{@"op": @"ping"}
                                                socketPath:socketPath
                                                 timeoutMs:1500
                                                     error:&pingErr];
                if ([ping[@"ok"] boolValue]) {
                    socketReady = YES;
                    pingInfo = ping;
                    break;
                }
                usleep(200 * 1000);
            }
        }
    }

    NSMutableDictionary *final = [NSMutableDictionary dictionaryWithDictionary:sessionDoc];
    final[@"load_order"] = stageRes[@"load_order"] ?: @[];
    final[@"scrub_replacements"] = scrubRes[@"total_replacements"] ?: @0;
    final[@"transport"] = @"unix_domain_socket_only";
    final[@"tcp_ports_opened"] = @0;
    final[@"launched"] = @(launched);
    final[@"socket_ready"] = @(socketReady);
    if (pingInfo) final[@"gadget_runtime"] = pingInfo;
    if (launchErr.length > 0) final[@"launch_warning"] = launchErr;
    return final;
}

- (NSDictionary *)removeFridaGadgetForBundleId:(NSString *)bundleId
                                         error:(NSString **)error {
    if (error) *error = nil;
    if (![bundleId isKindOfClass:[NSString class]] || !bundleId.length) {
        if (error) *error = @"bundle_id is required";
        return nil;
    }

    NSString *appErr = nil;
    NSDictionary *appInfo = [[AppManager sharedInstance] appInfoForBundleId:bundleId error:&appErr];
    if (!appInfo) {
        if (error) *error = appErr ?: [NSString stringWithFormat:@"App not found: %@", bundleId];
        return nil;
    }

    NSString *bundlePath = appInfo[@"bundle_path"] ?: @"";
    NSString *mainExec = appInfo[@"executable_path"] ?: @"";
    NSString *dataContainer = appInfo[@"data_container"] ?: appInfo[@"data_container_path"] ?: @"";

    pid_t pid = [[AppManager sharedInstance] pidForBundleId:bundleId];
    BOOL wasRunning = (pid > 0);
    if (wasRunning) {
        [[AppManager sharedInstance] killApp:bundleId error:nil];
        usleep(250 * 1000);
    }

    NSDictionary *session = [self loadSessionForBundleId:bundleId];
    NSString *stealthName = [session[@"stealth_dylib_name"] isKindOfClass:[NSString class]]
        ? session[@"stealth_dylib_name"] : @"libAppleCoreSVG_";
    NSString *gadgetName = [session[@"gadget_dylib_name"] isKindOfClass:[NSString class]]
        ? session[@"gadget_dylib_name"] : @"libAppleAudioDSP_";

    NSString *outStr = nil, *runErr = nil;
    int exitCode = -1;
    BOOL ok = MCPRunRootProcess(@"/usr/libexec/ios-mcp/mcp-appmod",
                                @[@"unstage-frida", bundlePath, mainExec, stealthName, gadgetName],
                                45.0,
                                512 * 1024,
                                &outStr,
                                &exitCode,
                                &runErr);
    if (!ok) {
        if (error) *error = runErr ?: @"Failed to invoke mcp-appmod unstage-frida";
        return nil;
    }
    NSData *respData = [outStr dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *resp = respData ? [NSJSONSerialization JSONObjectWithData:respData options:0 error:NULL] : nil;
    if (![resp isKindOfClass:[NSDictionary class]] || exitCode != 0 || ![resp[@"ok"] boolValue]) {
        if (error) *error = [resp[@"error"] isKindOfClass:[NSString class]] ? resp[@"error"] : @"remove_frida_gadget failed";
        return nil;
    }

    // Clean up Unix socket & stealth temp files inside <DataContainer>/tmp (never touching /var/mobile/Library/ios-mcp/frida/gadget.dylib!)
    NSMutableArray<NSString *> *cleanupPaths = [NSMutableArray array];
    if ([session[@"socket_path"] isKindOfClass:[NSString class]]) [cleanupPaths addObject:session[@"socket_path"]];
    if (dataContainer.length > 0) {
        [cleanupPaths addObject:[dataContainer stringByAppendingPathComponent:@"tmp/.mcp_stealth_cfg.json"]];
        [cleanupPaths addObject:[dataContainer stringByAppendingPathComponent:@"tmp/.mcp_stealth_status.json"]];
    }
    for (NSString *cp in cleanupPaths) {
        if (![[NSFileManager defaultManager] removeItemAtPath:cp error:nil]) {
            NSString *o = nil, *e = nil; int c = -1;
            MCPRunRootProcess(@"/usr/libexec/ios-mcp/mcp-appmod", @[@"delete-file", cp], 10.0, 16384, &o, &c, &e);
        }
    }
    [self deleteSessionForBundleId:bundleId];

    NSMutableDictionary *res = [([resp[@"result"] isKindOfClass:[NSDictionary class]] ? resp[@"result"] : @{}) mutableCopy];
    res[@"bundle_id"] = bundleId;
    res[@"was_running"] = @(wasRunning);
    res[@"removed"] = @YES;
    return res;
}

#pragma mark - #12 Unix Domain Socket RPC Transport

- (NSDictionary *)sendUnixCommand:(NSDictionary *)command
                       socketPath:(NSString *)rawSocketPath
                        timeoutMs:(NSInteger)timeoutMs
                            error:(NSString **)error {
    if (error) *error = nil;
    NSString *socketPath = MCPNormalizeUnixSocketContainerPath(rawSocketPath);
    if (!socketPath.length) {
        if (error) *error = @"Missing Frida control socket path";
        return nil;
    }
    if (timeoutMs <= 0) timeoutMs = 10000;

    NSError *jsonErr = nil;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:command options:0 error:&jsonErr];
    if (!jsonData) {
        if (error) *error = jsonErr.localizedDescription ?: @"Failed to serialize RPC request";
        return nil;
    }

    // Fast path: direct AF_UNIX connect from SpringBoard
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    const char *cpath = socketPath.fileSystemRepresentation;
    if (cpath && strlen(cpath) < sizeof(addr.sun_path)) {
        strncpy(addr.sun_path, cpath, sizeof(addr.sun_path) - 1);
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd >= 0) {
            int one = 1;
            setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
            if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
                NSMutableData *wire = [jsonData mutableCopy];
                [wire appendBytes:"\n" length:1];
                const uint8_t *wp = wire.bytes;
                size_t wr = wire.length;
                BOOL sentOK = YES;
                while (wr > 0) {
                    ssize_t w = send(fd, wp, wr, 0);
                    if (w < 0 && errno == EINTR) continue;
                    if (w <= 0) { sentOK = NO; break; }
                    wp += (size_t)w;
                    wr -= (size_t)w;
                }
                if (sentOK) {
                    NSMutableData *rbuf = [NSMutableData data];
                    CFAbsoluteTime deadline = CFAbsoluteTimeGetCurrent() + ((double)timeoutMs / 1000.0);
                    BOOL done = NO;
                    while (!done) {
                        double rem = deadline - CFAbsoluteTimeGetCurrent();
                        if (rem <= 0) break;
                        struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
                        int pr = poll(&pfd, 1, MAX(1, (int)(rem * 1000.0)));
                        if (pr < 0 && errno == EINTR) continue;
                        if (pr <= 0) break;
                        uint8_t chunk[8192];
                        ssize_t r = recv(fd, chunk, sizeof(chunk), 0);
                        if (r < 0 && errno == EINTR) continue;
                        if (r <= 0) break;
                        [rbuf appendBytes:chunk length:(NSUInteger)r];
                        const uint8_t *b = rbuf.bytes;
                        for (NSUInteger i = 0; i < rbuf.length; i++) {
                            if (b[i] == '\n') {
                                rbuf.length = i;
                                done = YES;
                                break;
                            }
                        }
                    }
                    close(fd);
                    if (done && rbuf.length > 0) {
                        NSDictionary *parsed = [NSJSONSerialization JSONObjectWithData:rbuf options:0 error:NULL];
                        if ([parsed isKindOfClass:[NSDictionary class]]) {
                            return parsed;
                        }
                    }
                    fd = -1;
                }
            }
            if (fd >= 0) close(fd);
        }
    }

    // Privileged fallback via mcp-appmod unix-rpc
    NSString *workDir = @"/var/mobile/Library/Caches/ios-mcp-work";
    [[NSFileManager defaultManager] createDirectoryAtPath:workDir withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *reqFile = [workDir stringByAppendingPathComponent:[NSString stringWithFormat:@"frpc-%@.json", [NSUUID UUID].UUIDString]];
    if (![jsonData writeToFile:reqFile options:NSDataWritingAtomic error:nil]) {
        if (error) *error = @"Failed to write temporary RPC request";
        return nil;
    }

    NSString *outStr = nil, *runErr = nil;
    int exitCode = -1;
    BOOL ok = MCPRunRootProcess(@"/usr/libexec/ios-mcp/mcp-appmod",
                                @[@"unix-rpc", socketPath, reqFile, [NSString stringWithFormat:@"%ld", (long)timeoutMs]],
                                ((double)timeoutMs / 1000.0) + 5.0,
                                4 * 1024 * 1024,
                                &outStr,
                                &exitCode,
                                &runErr);
    [[NSFileManager defaultManager] removeItemAtPath:reqFile error:nil];

    if (!ok) {
        if (error) *error = runErr ?: @"Failed to connect to Frida Gadget Unix control socket";
        return nil;
    }
    NSData *respData = [outStr dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *outer = respData ? [NSJSONSerialization JSONObjectWithData:respData options:0 error:NULL] : nil;
    if (![outer isKindOfClass:[NSDictionary class]] || exitCode != 0 || ![outer[@"ok"] boolValue]) {
        if (error) *error = [outer[@"error"] isKindOfClass:[NSString class]] ? outer[@"error"] : @"Frida Unix socket RPC failed";
        return nil;
    }
    return [outer[@"result"] isKindOfClass:[NSDictionary class]] ? outer[@"result"] : nil;
}

- (NSDictionary *)ensureActiveSessionForBundleId:(NSString *)bundleId
                                      socketPath:(NSString **)outSocketPath
                                           error:(NSString **)error {
    NSDictionary *session = [self loadSessionForBundleId:bundleId];
    if (!session || ![session[@"socket_path"] isKindOfClass:[NSString class]]) {
        if (error) *error = [NSString stringWithFormat:@"No active Frida Gadget session for %@; call inject_frida_gadget first", bundleId];
        return nil;
    }
    pid_t pid = [[AppManager sharedInstance] pidForBundleId:bundleId];
    if (pid <= 0) {
        // Auto-launch if already injected so RPC calls work seamlessly
        NSString *launchErr = nil;
        if ([[AppManager sharedInstance] launchApp:bundleId error:&launchErr]) {
            for (int i = 0; i < 20; i++) {
                NSDictionary *ping = [self sendUnixCommand:@{@"op": @"ping"}
                                                socketPath:session[@"socket_path"]
                                                 timeoutMs:1000
                                                     error:nil];
                if ([ping[@"ok"] boolValue]) break;
                usleep(200 * 1000);
            }
        } else {
            if (error) *error = [NSString stringWithFormat:@"Target app %@ is not running and could not be launched: %@",
                                 bundleId, launchErr ?: @"unknown"];
            return nil;
        }
    }
    if (outSocketPath) *outSocketPath = session[@"socket_path"];
    return session;
}

- (NSDictionary *)rpcCallForBundleId:(NSString *)bundleId
                              jsExpr:(NSString *)jsExpr
                           rpcMethod:(NSString *)rpcMethod
                             rpcArgs:(NSArray *)rpcArgs
                           timeoutMs:(NSInteger)timeoutMs
                               error:(NSString **)error {
    if (error) *error = nil;
    if (![bundleId isKindOfClass:[NSString class]] || !bundleId.length) {
        if (error) *error = @"bundle_id is required";
        return nil;
    }
    if (!jsExpr.length && !rpcMethod.length) {
        if (error) *error = @"js_expr (or rpc_method) is required";
        return nil;
    }

    NSString *socketPath = nil;
    NSDictionary *session = [self ensureActiveSessionForBundleId:bundleId socketPath:&socketPath error:error];
    if (!session) return nil;

    NSMutableDictionary *cmd = [@{@"op": @"eval"} mutableCopy];
    if (rpcMethod.length > 0) {
        cmd[@"rpc_method"] = rpcMethod;
        cmd[@"rpc_args"] = [rpcArgs isKindOfClass:[NSArray class]] ? rpcArgs : @[];
    } else {
        cmd[@"code"] = jsExpr;
    }

    NSDictionary *rpcResp = [self sendUnixCommand:cmd socketPath:socketPath timeoutMs:timeoutMs error:error];
    if (!rpcResp) return nil;
    if (![rpcResp[@"ok"] boolValue]) {
        if (error) *error = [rpcResp[@"error"] isKindOfClass:[NSString class]] ? rpcResp[@"error"] : @"Frida JS evaluation failed";
        return nil;
    }

    return @{
        @"bundle_id": bundleId,
        @"socket_path": socketPath,
        @"transport": @"unix_domain_socket",
        @"result": rpcResp[@"value"] ?: [NSNull null]
    };
}

#pragma mark - Frida Stealth & Deep Analysis Tools

- (NSDictionary *)configureStealthForBundleId:(NSString *)bundleId
                                      options:(NSDictionary *)options
                                        error:(NSString **)error {
    if (error) *error = nil;
    if (!bundleId.length) {
        if (error) *error = @"bundle_id is required";
        return nil;
    }
    NSString *appErr = nil;
    NSDictionary *appInfo = [[AppManager sharedInstance] appInfoForBundleId:bundleId error:&appErr];
    if (!appInfo) {
        if (error) *error = appErr ?: @"App not found";
        return nil;
    }
    NSString *dataContainer = appInfo[@"data_container"] ?: appInfo[@"data_container_path"];
    if (!dataContainer.length) {
        if (error) *error = @"App has no data_container_path";
        return nil;
    }

    NSString *cfgPath = [dataContainer stringByAppendingPathComponent:@"tmp/.mcp_stealth_cfg.json"];
    NSMutableDictionary *cfg = [([self readContainerJSONAtPath:cfgPath] ?: @{
        @"thread_cloak": @YES,
        @"dyld_cloak": @YES,
        @"anti_debug": @YES,
        @"exception_cloak": @YES,
        @"fs_cloak": @YES,
        @"port_cloak": @YES,
        @"env_scheme_cloak": @YES,
        @"vm_integrity_cloak": @YES
    }) mutableCopy];

    NSArray<NSString *> *toggleKeys = @[
        @"thread_cloak", @"dyld_cloak", @"anti_debug", @"exception_cloak",
        @"fs_cloak", @"port_cloak", @"env_scheme_cloak", @"vm_integrity_cloak"
    ];
    for (NSString *k in toggleKeys) {
        if (options[k] != nil && options[k] != [NSNull null]) {
            cfg[k] = @([options[k] boolValue]);
        }
    }

    NSDictionary *session = [self loadSessionForBundleId:bundleId];
    if (session) {
        if (!cfg[@"hidden_dylib_names"] && session[@"stealth_dylib_name"] && session[@"gadget_dylib_name"]) {
            cfg[@"hidden_dylib_names"] = @[session[@"stealth_dylib_name"], session[@"gadget_dylib_name"]];
        }
        NSDictionary *tm = [session[@"scrub_token_map"] isKindOfClass:[NSDictionary class]] ? session[@"scrub_token_map"] : nil;
        if (!cfg[@"scrubbed_tokens"] && tm) {
            cfg[@"scrubbed_tokens"] = tm.allValues;
        }
    }

    if (![self writeContainerJSON:cfg toPath:cfgPath error:error]) {
        return nil;
    }

    return @{
        @"bundle_id": bundleId,
        @"stealth_cfg_path": cfgPath,
        @"config": cfg,
        @"hot_reload_note": @"libmcp_stealth.dylib reloads .mcp_stealth_cfg.json automatically on mtime change"
    };
}

- (NSDictionary *)stealthStatusForBundleId:(NSString *)bundleId
                                     error:(NSString **)error {
    if (error) *error = nil;
    if (!bundleId.length) {
        if (error) *error = @"bundle_id is required";
        return nil;
    }
    NSString *appErr = nil;
    NSDictionary *appInfo = [[AppManager sharedInstance] appInfoForBundleId:bundleId error:&appErr];
    if (!appInfo) {
        if (error) *error = appErr ?: @"App not found";
        return nil;
    }
    NSString *dataContainer = appInfo[@"data_container"] ?: appInfo[@"data_container_path"] ?: @"";
    NSString *statusPath = [dataContainer stringByAppendingPathComponent:@"tmp/.mcp_stealth_status.json"];
    NSString *cfgPath = [dataContainer stringByAppendingPathComponent:@"tmp/.mcp_stealth_cfg.json"];

    NSDictionary *session = [self loadSessionForBundleId:bundleId];
    NSDictionary *liveStatus = [self readContainerJSONAtPath:statusPath];
    NSDictionary *cfg = [self readContainerJSONAtPath:cfgPath];
    pid_t pid = [[AppManager sharedInstance] pidForBundleId:bundleId];

    return @{
        @"bundle_id": bundleId,
        @"injected": @(session != nil),
        @"running": @(pid > 0),
        @"pid": @(pid),
        @"session": session ?: [NSNull null],
        @"config": cfg ?: [NSNull null],
        @"live_telemetry": liveStatus ?: [NSNull null]
    };
}

- (NSDictionary *)antiDetectionProbeForBundleId:(NSString *)bundleId
                                          error:(NSString **)error {
    if (error) *error = nil;
    NSString *socketPath = nil;
    NSDictionary *session = [self ensureActiveSessionForBundleId:bundleId socketPath:&socketPath error:error];
    if (!session) return nil;

    NSDictionary *probeResp = [self sendUnixCommand:@{@"op": @"anti_detection_probe"}
                                         socketPath:socketPath
                                          timeoutMs:15000
                                              error:error];
    if (!probeResp) return nil;
    if (![probeResp[@"ok"] boolValue]) {
        if (error) *error = [probeResp[@"error"] isKindOfClass:[NSString class]] ? probeResp[@"error"] : @"anti_detection_probe failed";
        return nil;
    }

    NSString *statusPath = session[@"stealth_status_path"];
    NSDictionary *telemetry = [self readContainerJSONAtPath:statusPath];

    NSMutableDictionary *combined = [NSMutableDictionary dictionaryWithDictionary:probeResp];
    combined[@"bundle_id"] = bundleId;
    combined[@"stealth_dylib_telemetry"] = telemetry ?: @{};
    combined[@"scrub_token_map"] = session[@"scrub_token_map"] ?: @{};
    return combined;
}

- (NSDictionary *)listModulesForBundleId:(NSString *)bundleId
                                  filter:(NSString *)filter
                                   limit:(NSUInteger)limit
                                   error:(NSString **)error {
    if (error) *error = nil;
    NSString *socketPath = nil;
    NSDictionary *session = [self ensureActiveSessionForBundleId:bundleId socketPath:&socketPath error:error];
    if (!session) return nil;

    NSMutableDictionary *cmd = [@{
        @"op": @"list_modules",
        @"limit": @(limit > 0 ? limit : 200)
    } mutableCopy];
    if (filter.length > 0) cmd[@"filter"] = filter;

    NSDictionary *resp = [self sendUnixCommand:cmd socketPath:socketPath timeoutMs:15000 error:error];
    if (!resp) return nil;
    if (![resp[@"ok"] boolValue]) {
        if (error) *error = [resp[@"error"] isKindOfClass:[NSString class]] ? resp[@"error"] : @"frida_list_modules failed";
        return nil;
    }

    NSDictionary *telemetry = [self readContainerJSONAtPath:session[@"stealth_status_path"]];
    NSMutableDictionary *out = [NSMutableDictionary dictionaryWithDictionary:resp];
    out[@"bundle_id"] = bundleId;
    if (telemetry[@"visible_dyld_image_count"]) {
        out[@"external_cloaked_dyld_count"] = telemetry[@"visible_dyld_image_count"];
        out[@"hidden_dyld_image_count"] = telemetry[@"hidden_dyld_image_count"];
    }
    return out;
}

- (NSDictionary *)hookObjCForBundleId:(NSString *)bundleId
                                 args:(NSDictionary *)args
                                error:(NSString **)error {
    if (error) *error = nil;
    NSString *socketPath = nil;
    NSDictionary *session = [self ensureActiveSessionForBundleId:bundleId socketPath:&socketPath error:error];
    if (!session) return nil;

    NSString *action = [args[@"action"] isKindOfClass:[NSString class]] && [args[@"action"] length]
        ? args[@"action"] : @"install";
    NSMutableDictionary *cmd = [@{@"op": @"hook_objc", @"action": action} mutableCopy];
    if ([args[@"class_name"] isKindOfClass:[NSString class]]) cmd[@"class_name"] = args[@"class_name"];
    if ([args[@"selector"] isKindOfClass:[NSString class]]) cmd[@"selector"] = args[@"selector"];
    if ([args[@"max_events"] respondsToSelector:@selector(integerValue)]) cmd[@"max_events"] = args[@"max_events"];
    if (args[@"override_return_int"] != nil && [args[@"override_return_int"] respondsToSelector:@selector(integerValue)]) {
        cmd[@"override_return_int"] = @([args[@"override_return_int"] integerValue]);
    }

    NSDictionary *resp = [self sendUnixCommand:cmd socketPath:socketPath timeoutMs:15000 error:error];
    if (!resp) return nil;
    if (![resp[@"ok"] boolValue]) {
        if (error) *error = [resp[@"error"] isKindOfClass:[NSString class]] ? resp[@"error"] : @"frida_hook_objc failed";
        return nil;
    }
    NSMutableDictionary *out = [NSMutableDictionary dictionaryWithDictionary:resp];
    out[@"bundle_id"] = bundleId;
    return out;
}

- (NSDictionary *)memoryScanForBundleId:(NSString *)bundleId
                                   args:(NSDictionary *)args
                                  error:(NSString **)error {
    if (error) *error = nil;
    NSString *socketPath = nil;
    NSDictionary *session = [self ensureActiveSessionForBundleId:bundleId socketPath:&socketPath error:error];
    if (!session) return nil;

    NSString *pattern = [args[@"pattern"] isKindOfClass:[NSString class]] ? args[@"pattern"] : nil;
    if (!pattern.length) {
        if (error) *error = @"pattern is required (e.g. '4d 43 50 5f' or '48 ?? 6c 6c 6f')";
        return nil;
    }

    NSMutableDictionary *cmd = [@{@"op": @"memory_scan", @"pattern": pattern} mutableCopy];
    if ([args[@"module_name"] isKindOfClass:[NSString class]] && [args[@"module_name"] length]) {
        cmd[@"module_name"] = args[@"module_name"];
    }
    if ([args[@"protection"] isKindOfClass:[NSString class]] && [args[@"protection"] length]) {
        cmd[@"protection"] = args[@"protection"];
    }
    if ([args[@"limit"] respondsToSelector:@selector(integerValue)]) {
        cmd[@"limit"] = @([args[@"limit"] integerValue]);
    }

    NSDictionary *resp = [self sendUnixCommand:cmd socketPath:socketPath timeoutMs:20000 error:error];
    if (!resp) return nil;
    if (![resp[@"ok"] boolValue]) {
        if (error) *error = [resp[@"error"] isKindOfClass:[NSString class]] ? resp[@"error"] : @"frida_memory_scan failed";
        return nil;
    }
    NSMutableDictionary *out = [NSMutableDictionary dictionaryWithDictionary:resp];
    out[@"bundle_id"] = bundleId;
    return out;
}

@end
