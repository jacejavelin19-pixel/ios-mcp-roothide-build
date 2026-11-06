#import "engine_rpc.h"
#include <string.h>
#include <stdlib.h>

static NSMutableDictionary<NSNumber *,id> *MEHandles;
static NSObject *MEHandleLock;
static uint64_t MENextHandle;
static void MEHandleInit(void) {
    static dispatch_once_t once;
    dispatch_once(&once,^{ MEHandles = [NSMutableDictionary dictionary]; MEHandleLock = [NSObject new]; });
}
id MEBox(id object) {
    if (!object) return NSNull.null;
    MEHandleInit();
    @synchronized(MEHandleLock) {
        for (NSNumber *key in MEHandles)
            if (MEHandles[key] == object) return @{@"handle":key,@"class":NSStringFromClass(object_getClass(object))};
        if (MEHandles.count >= 4096) MEFail(@"Handle limit reached; release handles");
        NSNumber *key = @(++MENextHandle); MEHandles[key] = object;
        return @{@"handle":key,@"class":NSStringFromClass(object_getClass(object))};
    }
}
id METarget(id value) {
    MEHandleInit();
    if ([value isKindOfClass:NSDictionary.class]) value = value[@"handle"];
    if ([value isKindOfClass:NSString.class]) {
        if ([value hasPrefix:@"class:"]) {
            Class cls = NSClassFromString([value substringFromIndex:6]);
            if (!cls) MEFail(@"Class not found"); return cls;
        }
        if ([value hasPrefix:@"0x"]) return (__bridge id)(void *)MEWord(value);
        if ([value hasPrefix:@"handle:"]) {
            NSString *number = [value substringFromIndex:7];
            NSScanner *scanner = [NSScanner scannerWithString:number];
            unsigned long long n;
            if (![scanner scanUnsignedLongLong:&n] || !scanner.isAtEnd) MEFail(@"Invalid handle");
            value = @(n);
        }
    }
    if (![value isKindOfClass:NSNumber.class]) MEFail(@"Expected class:Name or handle:N");
    @synchronized(MEHandleLock) {
        id result = MEHandles[value];
        if (!result) MEFail(@"Unknown or released handle"); return result;
    }
}
const char *METype(const char *t) {
    while (*t && strchr("rnNoORV",*t)) t++;
    return t;
}
id MEBoxValue(const char *encoding, const void *p) {
    const char *t = METype(encoding);
#define BOX(T) return @(*(const T *)p)
    switch (*t) {
        case 'v': return NSNull.null;
        case '@': case '#': {
            uintptr_t n = 0; memcpy(&n,p,sizeof(n)); return MEBox((__bridge id)(void *)n);
        }
        case 'c': BOX(signed char); case 'C': BOX(unsigned char);
        case 's': BOX(short); case 'S': BOX(unsigned short);
        case 'i': BOX(int); case 'I': BOX(unsigned int);
        case 'l': BOX(long); case 'L': BOX(unsigned long);
        case 'q': BOX(long long); case 'Q': BOX(unsigned long long);
        case 'B': BOX(BOOL); case 'f': BOX(float); case 'd': BOX(double);
        case '^': case '*': { uintptr_t n; memcpy(&n,p,sizeof(n)); return MEHex(n); }
        case ':': { SEL sel; memcpy(&sel,p,sizeof(sel)); return sel ? NSStringFromSelector(sel) : (id)NSNull.null; }
        default: MEFail(@"Unsupported value encoding (aggregate/vector/union)");
    }
#undef BOX
}
void MEUnboxValue(const char *encoding, id value, void *p) {
    const char *t = METype(encoding);
    if (*t == '@' || *t == '#') {
        id obj = nil;
        if (value && value != NSNull.null) {
            if ([value isKindOfClass:NSDictionary.class] ||
                ([value isKindOfClass:NSString.class] && ([value hasPrefix:@"handle:"] || [value hasPrefix:@"class:"]))) obj = METarget(value);
            else obj = value;
        }
        uintptr_t bits = (uintptr_t)(__bridge void *)obj; memcpy(p,&bits,sizeof(bits)); return;
    }
    if (*t == ':') {
        if (![value isKindOfClass:NSString.class]) MEFail(@"Selector value must be a string");
        SEL sel = NSSelectorFromString(value); memcpy(p,&sel,sizeof(sel)); return;
    }
    if (*t == '^' || *t == '*') { uintptr_t n = MEWord(value); memcpy(p,&n,sizeof(n)); return; }
    if (![value isKindOfClass:NSNumber.class]) MEFail(@"Scalar value must be a number");
#define UNBOX(T,M) do { T n = (T)[value M]; memcpy(p,&n,sizeof(n)); return; } while (0)
    switch (*t) {
        case 'c': UNBOX(signed char,longLongValue); case 'C': UNBOX(unsigned char,unsignedLongLongValue);
        case 's': UNBOX(short,longLongValue); case 'S': UNBOX(unsigned short,unsignedLongLongValue);
        case 'i': UNBOX(int,longLongValue); case 'I': UNBOX(unsigned int,unsignedLongLongValue);
        case 'l': UNBOX(long,longLongValue); case 'L': UNBOX(unsigned long,unsignedLongLongValue);
        case 'q': UNBOX(long long,longLongValue); case 'Q': UNBOX(unsigned long long,unsignedLongLongValue);
        case 'B': UNBOX(BOOL,boolValue); case 'f': UNBOX(float,floatValue); case 'd': UNBOX(double,doubleValue);
        default: MEFail(@"Unsupported value encoding");
    }
#undef UNBOX
}
static Class MEClass(NSDictionary *a) {
    Class cls = NSClassFromString(MEString(a,@"class"));
    if (!cls) MEFail(@"Class not found"); return cls;
}
static NSArray *MEMethods(Class cls, BOOL classMethod) {
    unsigned count = 0; Method *methods = class_copyMethodList(cls,&count);
    NSMutableArray *out = [NSMutableArray array];
    for (unsigned i=0;i<count;i++) [out addObject:@{
        @"sel":NSStringFromSelector(method_getName(methods[i])), @"class_method":@(classMethod),
        @"types":@(method_getTypeEncoding(methods[i])), @"imp":MEHex((uintptr_t)method_getImplementation(methods[i]))}];
    free(methods); return out;
}
static NSArray *MEIvars(Class cls) {
    unsigned count = 0; Ivar *ivars = class_copyIvarList(cls,&count);
    NSMutableArray *out = [NSMutableArray array];
    for (unsigned i=0;i<count;i++) [out addObject:@{@"name":@(ivar_getName(ivars[i])),
        @"type":@(ivar_getTypeEncoding(ivars[i])),@"offset":@(ivar_getOffset(ivars[i]))}];
    free(ivars); return out;
}
static NSArray *MEProperties(Class cls) {
    unsigned count = 0; objc_property_t *props = class_copyPropertyList(cls,&count);
    NSMutableArray *out = [NSMutableArray array];
    for (unsigned i=0;i<count;i++) [out addObject:@{@"name":@(property_getName(props[i])),@"attributes":@(property_getAttributes(props[i]))}];
    free(props); return out;
}
static NSDictionary *MEInvoke(id target, SEL sel, NSArray *args) {
    NSMethodSignature *sig = [target methodSignatureForSelector:sel];
    if (!sig || sig.numberOfArguments != args.count+2) MEFail(@"Selector or argument count mismatch");
    if (sig.methodReturnLength > 16) MEFail(@"Unsupported aggregate return");
    NSInvocation *inv = [NSInvocation invocationWithMethodSignature:sig];
    inv.target = target; inv.selector = sel;
    for (NSUInteger i=0;i<args.count;i++) {
        uint8_t bytes[16] = {0}; MEUnboxValue([sig getArgumentTypeAtIndex:i+2],args[i],bytes);
        [inv setArgument:bytes atIndex:i+2];
    }
    // Retain JSON-created objects and target while invoking synchronously.
    [inv retainArguments];
    BOOL suppressed = MEDepth > 0;
    if (suppressed) MEDepth--;
    @try { [inv invoke]; } @finally { if (suppressed) MEDepth++; }
    uint8_t bytes[16] = {0};
    if (sig.methodReturnLength) [inv getReturnValue:bytes];
    return @{@"ret":MEBoxValue(sig.methodReturnType,bytes)};
}
NSDictionary *MEObjC(NSString *op, NSDictionary *a) {
    if ([op isEqual:@"engine.classes"]) {
        NSUInteger limit = MELimit(a,@"limit",1000,10000); NSString *filter = a[@"filter"] ?: @"";
        if (![filter isKindOfClass:NSString.class]) MEFail(@"filter must be a string");
        unsigned count = 0; Class *classes = objc_copyClassList(&count);
        NSMutableArray *out = [NSMutableArray array]; NSUInteger total = 0;
        for (unsigned i=0;i<count;i++) {
            NSString *name = NSStringFromClass(classes[i]); const char *image = class_getImageName(classes[i]);
            NSString *path = image ? @(image) : @"";
            if (filter.length && [name rangeOfString:filter options:NSCaseInsensitiveSearch].location == NSNotFound) continue;
            if (![a[@"include_system"] boolValue] && ([path hasPrefix:@"/System/"] || [path hasPrefix:@"/usr/lib/"])) continue;
            total++;
            if (out.count < limit) [out addObject:@{@"name":name,@"super":NSStringFromClass(class_getSuperclass(classes[i])) ?: @"",@"image":path}];
        }
        free(classes); return @{@"classes":out,@"count":@(total)};
    }
    if ([op isEqual:@"engine.describe"] || [op isEqual:@"engine.methods"] || [op isEqual:@"engine.ivars"] || [op isEqual:@"engine.protocols"]) {
        Class cls = MEClass(a); NSMutableArray *methods = [MEMethods(cls,NO) mutableCopy];
        [methods addObjectsFromArray:MEMethods(object_getClass(cls),YES)];
        unsigned n = 0; Protocol *__unsafe_unretained *protocols = class_copyProtocolList(cls,&n);
        NSMutableArray *names = [NSMutableArray array];
        for (unsigned i=0;i<n;i++) [names addObject:@(protocol_getName(protocols[i]))]; free(protocols);
        return @{@"name":NSStringFromClass(cls),@"super":NSStringFromClass(class_getSuperclass(cls)) ?: @"",
                 @"metaclass":NSStringFromClass(object_getClass(cls)),@"methods":methods,@"ivars":MEIvars(cls),
                 @"properties":MEProperties(cls),@"protocols":names};
    }
    if ([op isEqual:@"engine.hook_objc"]) {
        Class cls = MEClass(a); NSString *selector = MEString(a,@"selector"); BOOL isClass = NO;
        if ([selector hasPrefix:@"+"] || [selector hasPrefix:@"-"]) {
            isClass = [selector hasPrefix:@"+"];
            selector = [[selector substringFromIndex:1] stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
        }
        Class owner = isClass ? object_getClass(cls) : cls; SEL sel = NSSelectorFromString(selector);
        MECheckObjCHook(owner,sel);
        Method method = class_getInstanceMethod(owner,sel);
        if (!method) MEFail(@"Method not found");
        NSMethodSignature *sig = [NSMethodSignature signatureWithObjCTypes:method_getTypeEncoding(method)];
        if (sig.numberOfArguments > 8) MEFail(@"Hook supports at most six explicit ObjC arguments");
        NSMutableArray *types = [NSMutableArray arrayWithObject:@(sig.methodReturnType)];
        for (NSUInteger i=0;i<sig.numberOfArguments;i++) [types addObject:@([sig getArgumentTypeAtIndex:i])];
        for (NSString *type in types) {
            char c = *METype(type.UTF8String);
            if (!strchr("vcCsSiIlLqQB@#:^*",c)) MEFail(@"Hook supports integer/object/pointer ABI only");
        }
        if ([selector isEqual:@"dealloc"] || [selector isEqual:@"retain"] || [selector isEqual:@"release"] ||
            [selector isEqual:@"autorelease"]) MEFail(@"Object lifetime methods cannot be instrumented");
        MEHook *hook = MENewHook(a); hook.objcHook = YES; hook.owner = owner; hook.selector = sel;
        hook.argc = (unsigned)sig.numberOfArguments; hook.types = types;
        hook.originalIMP = method_getImplementation(method);
        if (hook.overrideValue && *METype(sig.methodReturnType) != 'v') {
            uint8_t test[16] = {0}; MEUnboxValue(sig.methodReturnType,hook.overrideValue,test);
            uintptr_t bits=0; memcpy(&bits,test,sizeof(bits)); hook.overrideBits=bits;
            if (*METype(sig.methodReturnType)=='@' || *METype(sig.methodReturnType)=='#')
                hook.overrideObject=(__bridge id)(void *)hook.overrideBits;
        }
        hook.replacement = MEAdapter(hook.slot);
        // Create a local method when inherited, so the superclass is untouched.
        hook.active = YES;
        if (!class_addMethod(owner,sel,(IMP)hook.replacement,method_getTypeEncoding(method)))
            method_setImplementation(class_getInstanceMethod(owner,sel),(IMP)hook.replacement);
        return @{@"hook_key":hook.key,@"installed":@YES};
    }
    if ([op isEqual:@"engine.invoke"]) {
        id args = a[@"args"] ?: @[];
        if (![args isKindOfClass:NSArray.class]) MEFail(@"args must be an array");
        return MEInvoke(METarget(a[@"target"]),NSSelectorFromString(MEString(a,@"selector")),args);
    }
    if ([op isEqual:@"engine.alloc"]) {
        id object = [MEClass(a) alloc]; return @{@"ret":MEBox(object)};
    }
    if ([op isEqual:@"engine.retain"]) return @{@"ret":MEBox(METarget(a[@"handle"]))};
    if ([op isEqual:@"engine.release"]) {
        id v = a[@"handle"]; (void)METarget(v);
        if ([v isKindOfClass:NSDictionary.class]) v = v[@"handle"];
        if ([v isKindOfClass:NSString.class] && [v hasPrefix:@"handle:"]) v = @([[v substringFromIndex:7] longLongValue]);
        if (![v isKindOfClass:NSNumber.class]) MEFail(@"release requires a handle");
        @synchronized(MEHandleLock) { [MEHandles removeObjectForKey:v]; } return @{@"released":@YES};
    }
    if ([op isEqual:@"engine.get_ivar"] || [op isEqual:@"engine.set_ivar"]) {
        id object = METarget(a[@"handle"]); Ivar ivar = class_getInstanceVariable(object_getClass(object),MEString(a,@"name").UTF8String);
        if (!ivar) MEFail(@"Ivar not found");
        const char *type = METype(ivar_getTypeEncoding(ivar));
        BOOL write = [op isEqual:@"engine.set_ivar"];
        if (*type == '@') {
            if (write) {
                uintptr_t bits=0; MEUnboxValue(type,a[@"value"],&bits);
                object_setIvarWithStrongDefault(object,ivar,(__bridge id)(void *)bits);
                return @{@"ok":@YES};
            }
            return @{@"value":MEBox(object_getIvar(object,ivar))};
        }
        uint8_t *ptr = (uint8_t *)(__bridge void *)object + ivar_getOffset(ivar);
        uint8_t bytes[16] = {0}; NSUInteger size=0;
        NSGetSizeAndAlignment(type,&size,NULL);
        if (size > sizeof(bytes)) MEFail(@"Unsupported ivar size");
        if (write) { MEUnboxValue(type,a[@"value"],bytes); memcpy(ptr,bytes,size); return @{@"ok":@YES}; }
        memcpy(bytes,ptr,size); return @{@"value":MEBoxValue(type,bytes)};
    }
    if ([op isEqual:@"engine.get_property"] || [op isEqual:@"engine.set_property"]) {
        id object = METarget(a[@"handle"]); NSString *name = MEString(a,@"name");
        objc_property_t prop = class_getProperty(object_getClass(object),name.UTF8String);
        if (!prop) MEFail(@"Property not found");
        BOOL write = [op isEqual:@"engine.set_property"];
        char *custom = property_copyAttributeValue(prop,write ? "S" : "G");
        NSString *selName = custom ? @(custom) : (write ? [NSString stringWithFormat:@"set%@%@:",[[name substringToIndex:1] uppercaseString],[name substringFromIndex:1]] : name);
        free(custom);
        return MEInvoke(object,NSSelectorFromString(selName),write ? @[a[@"value"] ?: NSNull.null] : @[]);
    }
    return nil;
}
