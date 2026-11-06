#import "engine_rpc.h"
#include <mach/mach.h>
// The iOS SDK does not publish <mach/mach_vm.h>; declare the mach_vm_* entry
// points directly (same approach as MemoryManager.m). The symbols exist at
// runtime; only the public header is absent.
extern kern_return_t mach_vm_region(vm_map_t, mach_vm_address_t *, mach_vm_size_t *, vm_region_flavor_t, vm_region_info_t, mach_msg_type_number_t *, mach_port_t *);
extern kern_return_t mach_vm_read_overwrite(vm_map_t, mach_vm_address_t, mach_vm_size_t, mach_vm_address_t, mach_vm_size_t *);
extern kern_return_t mach_vm_write(vm_map_t, mach_vm_address_t, vm_offset_t, mach_msg_type_number_t);
extern kern_return_t mach_vm_protect(vm_map_t, mach_vm_address_t, mach_vm_size_t, boolean_t, vm_prot_t);
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <dlfcn.h>
#include <uuid/uuid.h>
#include <string.h>

static vm_prot_t MEProt(NSString *s) {
    if (![s isKindOfClass:NSString.class] || s.length != 3) MEFail(@"prot must have three characters");
    if (([s characterAtIndex:0]!='r' && [s characterAtIndex:0]!='-') ||
        ([s characterAtIndex:1]!='w' && [s characterAtIndex:1]!='-') ||
        ([s characterAtIndex:2]!='x' && [s characterAtIndex:2]!='-')) MEFail(@"Invalid protection");
    vm_prot_t p = ([s characterAtIndex:0]=='r' ? VM_PROT_READ:0) |
        ([s characterAtIndex:1]=='w' ? VM_PROT_WRITE:0) | ([s characterAtIndex:2]=='x' ? VM_PROT_EXECUTE:0);
    if ((p & VM_PROT_WRITE) && (p & VM_PROT_EXECUTE)) MEFail(@"Writable executable memory is forbidden");
    return p;
}
static void MECheckRange(uintptr_t address, size_t length, vm_prot_t required) {
    if (!length || address > UINTPTR_MAX-length) MEFail(@"Invalid memory range");
    mach_vm_address_t cursor = address, end = address+length;
    while (cursor < end) {
        mach_vm_address_t base = cursor; mach_vm_size_t size = 0;
        vm_region_basic_info_data_64_t info; mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object = MACH_PORT_NULL;
        kern_return_t kr = mach_vm_region(mach_task_self(),&base,&size,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&count,&object);
        if (object) mach_port_deallocate(mach_task_self(),object);
        if (kr || base > cursor || !size || base > UINT64_MAX-size || (info.protection & required) != required)
            MEFail(@"Range is unmapped or lacks required permissions");
        if ((required & VM_PROT_WRITE) && (info.protection & VM_PROT_EXECUTE)) MEFail(@"Writing executable memory is forbidden");
        cursor = MIN(end,base+size);
    }
}
static NSData *MERead(uintptr_t address, size_t length) {
    MECheckRange(address,length,VM_PROT_READ);
    NSMutableData *out = [NSMutableData dataWithLength:length]; mach_vm_size_t actual = 0;
    kern_return_t kr = mach_vm_read_overwrite(mach_task_self(),address,length,(mach_vm_address_t)out.mutableBytes,&actual);
    if (kr || actual != length) MEFail(@"Memory read failed (mapping changed)"); return out;
}
static NSArray *MEImages(void) {
    NSMutableArray *out = [NSMutableArray array]; uint32_t count = _dyld_image_count();
    for (uint32_t i=0;i<count;i++) {
        const struct mach_header_64 *h = (const void *)_dyld_get_image_header(i);
        const char *image = _dyld_get_image_name(i);
        if (!h || h->magic != MH_MAGIC_64 || !image) continue;
        intptr_t slide = _dyld_get_image_vmaddr_slide(i); uint64_t lo = UINT64_MAX, hi = 0;
        NSString *uuid = @""; NSMutableArray *segments = [NSMutableArray array];
        const uint8_t *cursor = (const void *)(h+1), *end = cursor+h->sizeofcmds;
        for (uint32_t j=0;j<h->ncmds && cursor+sizeof(struct load_command)<=end;j++) {
            const struct load_command *lc = (const void *)cursor;
            if (lc->cmdsize < sizeof(*lc) || lc->cmdsize > (size_t)(end-cursor)) break;
            if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
                const struct segment_command_64 *s = (const void *)lc;
                if (s->vmsize && strncmp(s->segname,"__PAGEZERO",16)) {
                    uint64_t base = s->vmaddr+slide;
                    lo = MIN(lo,base); hi = MAX(hi,base+s->vmsize);
                    [segments addObject:@{@"name":[[NSString alloc] initWithBytes:s->segname length:strnlen(s->segname,16) encoding:NSUTF8StringEncoding] ?: @"",
                                          @"base":MEHex(base),@"size":@(s->vmsize)}];
                }
            } else if (lc->cmd == LC_UUID && lc->cmdsize >= sizeof(struct uuid_command)) {
                char text[37]; uuid_unparse_lower(((const struct uuid_command *)lc)->uuid,text); uuid = @(text);
            }
            cursor += lc->cmdsize;
        }
        NSString *path = @(image);
        [out addObject:@{@"name":path.lastPathComponent,@"path":path,@"base":MEHex((uintptr_t)h),
                         @"slide":MEHex(slide),@"size":@(hi>lo ? hi-lo:0),@"uuid":uuid,@"segments":segments}];
    }
    return out;
}
void *MEResolve(NSDictionary *a) {
    if (a[@"address"]) { uintptr_t p = MEWord(a[@"address"]); if (!p) MEFail(@"Null function address"); return (void *)p; }
    NSString *symbol = MEString(a,@"symbol");
    void *handle = RTLD_DEFAULT; BOOL opened = NO;
    if (a[@"module"]) {
        NSString *module = MEString(a,@"module"); NSString *path = nil;
        for (NSDictionary *image in MEImages()) if ([image[@"path"] isEqual:module] || [image[@"name"] isEqual:module]) { path=image[@"path"]; break; }
        if (!path) MEFail(@"Module is not loaded");
        handle = dlopen(path.fileSystemRepresentation,RTLD_LAZY|RTLD_NOLOAD); opened = YES;
        if (!handle) MEFail(@"Unable to open loaded module");
    }
    void *ptr = dlsym(handle,symbol.UTF8String);
    if (opened) dlclose(handle);
    if (!ptr) MEFail(@"Symbol not found"); return ptr;
}
NSDictionary *MEMemory(NSString *op, NSDictionary *a) {
    if ([op isEqual:@"engine.modules"]) {
        NSString *filter = a[@"filter"] ?: @"";
        if (![filter isKindOfClass:NSString.class]) MEFail(@"filter must be a string");
        NSUInteger limit = MELimit(a,@"limit",512,4096); NSMutableArray *out = [NSMutableArray array];
        for (NSDictionary *image in MEImages()) {
            if (out.count >= limit) break;
            if (!filter.length || [image[@"path"] rangeOfString:filter options:NSCaseInsensitiveSearch].location != NSNotFound) [out addObject:image];
        }
        return @{@"modules":out};
    }
    if ([op isEqual:@"engine.dlsym"]) return @{@"address":MEHex((uintptr_t)MEResolve(a))};
    if ([op isEqual:@"engine.dladdr"]) {
        Dl_info info = {0};
        if (!dladdr((void *)MEWord(a[@"address"]),&info)) MEFail(@"Address has no image");
        return @{@"path":info.dli_fname ? @(info.dli_fname):@"",@"base":MEHex((uintptr_t)info.dli_fbase),
                 @"symbol":info.dli_sname ? @(info.dli_sname):@"",@"address":MEHex((uintptr_t)info.dli_saddr)};
    }
    if ([op isEqual:@"engine.read_mem"]) {
        uintptr_t address = MEWord(a[@"address"]); NSUInteger length = MELimit(a,@"length",0,ME_MAX_TRANSFER);
        NSData *data = MERead(address,length);
        return @{@"address":MEHex(address),@"length":@(length),@"data_base64":[data base64EncodedStringWithOptions:0]};
    }
    if ([op isEqual:@"engine.write_mem"]) {
        uintptr_t address = MEWord(a[@"address"]);
        NSString *text = MEString(a,@"data_base64");
        if (text.length > (ME_MAX_TRANSFER+2)/3*4) MEFail(@"Memory transfer exceeds limit");
        NSData *data = [[NSData alloc] initWithBase64EncodedString:text options:0];
        if (!data || !data.length || data.length > ME_MAX_TRANSFER) MEFail(@"Invalid or oversized base64");
        MECheckRange(address,data.length,VM_PROT_WRITE);
        kern_return_t kr = mach_vm_write(mach_task_self(),address,(vm_offset_t)data.bytes,(mach_msg_type_number_t)data.length);
        if (kr) MEFail(@"Memory write failed"); return @{@"address":MEHex(address),@"written":@(data.length)};
    }
    if ([op isEqual:@"engine.protect"]) {
        uintptr_t address = MEWord(a[@"address"]); NSUInteger length = MELimit(a,@"length",0,ME_MAX_TRANSFER);
        vm_prot_t prot = MEProt(MEString(a,@"prot")); MECheckRange(address,length,0);
        kern_return_t kr = mach_vm_protect(mach_task_self(),address,length,FALSE,prot);
        if (kr) MEFail([NSString stringWithFormat:@"mach_vm_protect failed: %d",kr]);
        return @{@"ok":@YES};
    }
    if ([op isEqual:@"engine.search_mem"]) {
        NSData *pattern = nil;
        if (a[@"text"]) pattern = [MEString(a,@"text") dataUsingEncoding:NSUTF8StringEncoding];
        else {
            NSString *hex = [[MEString(a,@"pattern") componentsSeparatedByCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet] componentsJoinedByString:@""];
            if (!hex.length || hex.length%2) MEFail(@"pattern requires even hexadecimal bytes");
            NSMutableData *bytes = [NSMutableData data];
            for (NSUInteger i=0;i<hex.length;i+=2) {
                NSString *pair = [hex substringWithRange:NSMakeRange(i,2)];
                if ([pair rangeOfCharacterFromSet:[[NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdefABCDEF"] invertedSet]].location != NSNotFound) MEFail(@"Invalid hex pattern");
                unsigned n=0; [[NSScanner scannerWithString:pair] scanHexInt:&n]; uint8_t b=n; [bytes appendBytes:&b length:1];
            }
            pattern = bytes;
        }
        if (!pattern.length || pattern.length > 4096) MEFail(@"Pattern length must be 1..4096");
        vm_prot_t required = a[@"protection"] ? MEProt(MEString(a,@"protection")) : VM_PROT_READ;
        required |= VM_PROT_READ;
        NSUInteger limit = MELimit(a,@"limit",256,8192);
        if (!limit) MEFail(@"Search limit must be positive");
        uint64_t budget = MELimit(a,@"max_bytes",64*1024*1024,512*1024*1024);
        uint64_t cursor = a[@"start"] ? MEWord(a[@"start"]) : 0, upper = UINT64_MAX;
        if (a[@"module"]) {
            NSString *module = MEString(a,@"module"); NSDictionary *found = nil;
            for (NSDictionary *image in MEImages()) if ([image[@"name"] isEqual:module] || [image[@"path"] isEqual:module]) { found=image; break; }
            if (!found) MEFail(@"Module not found");
            uint64_t base = MEWord(found[@"base"]); cursor = MAX(cursor,base); upper = base+[found[@"size"] unsignedLongLongValue];
        }
        NSMutableArray *matches = [NSMutableArray array]; BOOL complete = YES; uint64_t scanned=0;
        while (cursor < upper) {
            mach_vm_address_t base=cursor; mach_vm_size_t size=0;
            vm_region_basic_info_data_64_t info; mach_msg_type_number_t count=VM_REGION_BASIC_INFO_COUNT_64; mach_port_t object=0;
            kern_return_t kr=mach_vm_region(mach_task_self(),&base,&size,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&count,&object);
            if (object) mach_port_deallocate(mach_task_self(),object);
            if (kr == KERN_INVALID_ADDRESS) break;
            if (kr || !size || base>UINT64_MAX-size) { complete=NO; break; }
            if (base >= upper) break;
            uint64_t end=MIN(upper,base+size); cursor=MAX(cursor,base);
            if ((info.protection & required) != required) { cursor=end; continue; }
            while (cursor < end) {
                if (scanned >= budget || matches.count>=limit) { complete=NO; goto search_done; }
                size_t step=(size_t)MIN(MIN((uint64_t)65536,end-cursor),budget-scanned);
                size_t length=(size_t)MIN(end-cursor,(uint64_t)step+pattern.length-1);
                NSData *data;
                @try { data=MERead(cursor,length); } @catch (NSException *e) { complete=NO; cursor=end; break; }
                const uint8_t *bytes=data.bytes;
                for (size_t i=0;i<step && i+pattern.length<=length;i++) {
                    if (!memcmp(bytes+i,pattern.bytes,pattern.length)) {
                        [matches addObject:MEHex(cursor+i)];
                        if (matches.count>=limit) { cursor+=i+1; complete=NO; goto search_done; }
                    }
                }
                cursor+=step; scanned+=step;
            }
        }
search_done:
        return @{@"matches":matches,@"count":@(matches.count),@"complete":@(complete),@"next_address":MEHex(cursor),@"scanned_bytes":@(scanned)};
    }
    return nil;
}
