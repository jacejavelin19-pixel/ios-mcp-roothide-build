#import "BinaryInspector.h"
#import "AppManager.h"
#import "ClassDumpManager.h"
#import "MCPEngineManager.h"
#import "MCPProcessUtil.h"
#import "MemoryManager.h"
#import <ctype.h>
#import <dlfcn.h>
#import <libkern/OSByteOrder.h>
#import <mach-o/fat.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <stdlib.h>
#import <string.h>

typedef char *(*mcp_swift_demangle_fn)(const char *mangledName,
                                       size_t mangledNameLength,
                                       char *outputBuffer,
                                       size_t *outputBufferSize,
                                       uint32_t flags);

static NSString *MCPDemangleSwiftName(NSString *rawName) {
    if (!rawName.length) return @"";
    static mcp_swift_demangle_fn sDemangle = NULL;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        void *h = dlopen("/usr/lib/swift/libswiftCore.dylib", RTLD_LAZY);
        if (!h) h = RTLD_DEFAULT;
        sDemangle = (mcp_swift_demangle_fn)dlsym(h, "swift_demangle");
    });

    const char *cstr = rawName.UTF8String;
    if (!cstr) return rawName;

    // Built-in fast-path for standard Swift 5 primitive manglings in __swift5_typeref
    if (strcmp(cstr, "SS") == 0) return @"Swift.String";
    if (strcmp(cstr, "Si") == 0) return @"Swift.Int";
    if (strcmp(cstr, "Su") == 0) return @"Swift.UInt";
    if (strcmp(cstr, "Sb") == 0) return @"Swift.Bool";
    if (strcmp(cstr, "Sd") == 0) return @"Swift.Double";
    if (strcmp(cstr, "Sf") == 0) return @"Swift.Float";
    if (strcmp(cstr, "yp") == 0) return @"Any";
    if (strcmp(cstr, "yXl") == 0) return @"AnyObject";
    if (strcmp(cstr, "10Foundation4DataV") == 0) return @"Foundation.Data";
    if (strcmp(cstr, "10Foundation3URLV") == 0) return @"Foundation.URL";
    if (strcmp(cstr, "10Foundation4UUIDV") == 0) return @"Foundation.UUID";
    if (strcmp(cstr, "10Foundation4DateV") == 0) return @"Foundation.Date";

    if (sDemangle) {
        NSString *prefixed = ([rawName hasPrefix:@"$s"] || [rawName hasPrefix:@"_T"])
            ? rawName
            : [@"$s" stringByAppendingString:rawName];
        const char *m = prefixed.UTF8String;
        char *demangled = sDemangle(m, strlen(m), NULL, NULL, 0);
        if (demangled) {
            NSString *res = [NSString stringWithUTF8String:demangled];
            free(demangled);
            if (res.length) return res;
        }
    }

    // Fallback length-prefixed Swift identifier parser (e.g. "10Foundation4DataV" or "So8NSObjectC")
    NSMutableArray<NSString *> *parts = [NSMutableArray array];
    size_t len = strlen(cstr);
    size_t idx = 0;
    if (strncmp(cstr, "$s", 2) == 0) idx = 2;
    if (idx + 2 <= len && strncmp(cstr + idx, "So", 2) == 0) idx += 2;
    while (idx < len) {
        if (isdigit((unsigned char)cstr[idx])) {
            size_t count = 0;
            while (idx < len && isdigit((unsigned char)cstr[idx])) {
                count = count * 10 + (size_t)(cstr[idx] - '0');
                idx++;
            }
            if (count > 0 && idx + count <= len) {
                NSString *seg = [[NSString alloc] initWithBytes:cstr + idx length:count encoding:NSUTF8StringEncoding];
                if (seg.length) [parts addObject:seg];
                idx += count;
                continue;
            }
        }
        idx++;
    }
    if (parts.count > 0) {
        return [parts componentsJoinedByString:@"."];
    }
    return rawName;
}

static BOOL MCPParseHexOrUint64(id val, uint64_t *out) {
    if (!val || val == [NSNull null]) return NO;
    if ([val isKindOfClass:[NSNumber class]]) {
        *out = [val unsignedLongLongValue];
        return YES;
    }
    if ([val isKindOfClass:[NSString class]]) {
        NSString *s = [(NSString *)val stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (!s.length) return NO;
        char *end = NULL;
        errno = 0;
        unsigned long long v = strtoull(s.UTF8String, &end, 0);
        if (errno == 0 && end && *end == '\0') {
            *out = (uint64_t)v;
            return YES;
        }
    }
    return NO;
}

static int64_t MCPSignExtend64(uint64_t val, unsigned bits) {
    uint64_t shift = 64 - bits;
    return ((int64_t)(val << shift)) >> shift;
}

#pragma mark - Parsed Mach-O Slice Representation

typedef struct {
    char segname[17];
    char sectname[17];
    uint64_t addr;
    uint64_t size;
    uint32_t offset;
} MCPSectionEntry;

@interface MCPMachOSliceContext : NSObject
@property (nonatomic, strong) NSData *fileData;
@property (nonatomic, assign) size_t sliceOffset;
@property (nonatomic, assign) size_t sliceSize;
@property (nonatomic, assign) uint32_t cpuType;
@property (nonatomic, assign) uint32_t cpuSubType;
@property (nonatomic, assign) uint64_t textVMAddr;
@property (nonatomic, assign) BOOL encrypted;
@property (nonatomic, assign) uint32_t cryptOff;
@property (nonatomic, assign) uint32_t cryptSize;
@property (nonatomic, strong) NSMutableArray<NSValue *> *sections;
@property (nonatomic, strong) NSMutableDictionary<NSNumber *, NSString *> *symbolsByAddr;
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSNumber *> *addrBySymbol;
@property (nonatomic, strong) NSMutableDictionary<NSNumber *, NSString *> *selRefsByAddr;
@property (nonatomic, strong) NSMutableDictionary<NSNumber *, NSString *> *classRefsByAddr;
@property (nonatomic, strong) NSMutableDictionary<NSNumber *, NSString *> *cfStringsByAddr;
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSDictionary *> *objcMethodsByKey;
@property (nonatomic, strong) NSMutableArray<NSNumber *> *sortedFunctionStarts;
@end

@implementation MCPMachOSliceContext

- (const uint8_t *)sliceBytes {
    return (const uint8_t *)self.fileData.bytes + self.sliceOffset;
}

- (BOOL)vmAddrToSliceOffset:(uint64_t)vmAddr outOffset:(size_t *)outOffset {
    uint64_t stripped = vmAddr & 0x00007fffffffffffULL;
    // Also handle on-diskchained fixups where high bits encode dyld_chained_ptr_64_rebase target
    for (NSValue *v in self.sections) {
        MCPSectionEntry sec;
        [v getValue:&sec];
        if (stripped >= sec.addr && stripped < sec.addr + sec.size) {
            size_t off = (size_t)sec.offset + (size_t)(stripped - sec.addr);
            if (off < self.sliceSize) {
                if (outOffset) *outOffset = off;
                return YES;
            }
        }
    }
    // Check low 36-bit offset for arm64e dyld_chained_ptr_arm64e_rebase / dyld_chained_ptr_64_rebase
    uint64_t low36 = vmAddr & 0x0000000fffffffffULL;
    uint64_t rebased = self.textVMAddr + low36;
    for (NSValue *v in self.sections) {
        MCPSectionEntry sec;
        [v getValue:&sec];
        if (rebased >= sec.addr && rebased < sec.addr + sec.size) {
            size_t off = (size_t)sec.offset + (size_t)(rebased - sec.addr);
            if (off < self.sliceSize) {
                if (outOffset) *outOffset = off;
                return YES;
            }
        }
        if (low36 >= sec.offset && low36 < (uint64_t)sec.offset + sec.size) {
            if (outOffset) *outOffset = (size_t)low36;
            return YES;
        }
    }
    return NO;
}

- (NSString *)readCStringAtVMAddr:(uint64_t)vmAddr maxLen:(size_t)maxLen {
    size_t off = 0;
    if (![self vmAddrToSliceOffset:vmAddr outOffset:&off]) return nil;
    const uint8_t *base = [self sliceBytes];
    size_t avail = self.sliceSize - off;
    size_t lim = MIN(avail, maxLen);
    size_t len = 0;
    while (len < lim && base[off + len] != '\0') {
        if (base[off + len] < 0x09 || (base[off + len] > 0x0D && base[off + len] < 0x20)) return nil;
        len++;
    }
    if (len == 0 || len == lim) return nil;
    return [[NSString alloc] initWithBytes:base + off length:len encoding:NSUTF8StringEncoding];
}

- (BOOL)findSection:(const char *)segName sect:(const char *)sectName outEntry:(MCPSectionEntry *)outEntry {
    for (NSValue *v in self.sections) {
        MCPSectionEntry sec;
        [v getValue:&sec];
        if ((segName == NULL || strcmp(sec.segname, segName) == 0) &&
            strcmp(sec.sectname, sectName) == 0) {
            if (outEntry) *outEntry = sec;
            return YES;
        }
    }
    return NO;
}

- (NSString *)symbolContainingAddress:(uint64_t)vmAddr outStart:(uint64_t *)outStart {
    NSString *exact = self.symbolsByAddr[@(vmAddr)];
    if (exact) {
        if (outStart) *outStart = vmAddr;
        return exact;
    }
    uint64_t bestStart = 0;
    for (NSNumber *fnStart in self.sortedFunctionStarts) {
        uint64_t s = fnStart.unsignedLongLongValue;
        if (s <= vmAddr && s > bestStart) {
            bestStart = s;
        } else if (s > vmAddr) {
            break;
        }
    }
    if (bestStart != 0) {
        if (outStart) *outStart = bestStart;
        NSString *sym = self.symbolsByAddr[@(bestStart)];
        if (sym.length) return sym;
        return [NSString stringWithFormat:@"sub_%llx", (unsigned long long)bestStart];
    }
    if (outStart) *outStart = vmAddr;
    return [NSString stringWithFormat:@"sub_%llx", (unsigned long long)vmAddr];
}

@end

static MCPMachOSliceContext *MCPLoadMachOSliceContext(NSString *path, NSString **error) {
    NSData *data = [NSData dataWithContentsOfFile:path options:NSDataReadingMappedIfSafe error:nil];
    if (!data || data.length < sizeof(struct mach_header_64)) {
        if (error) *error = [NSString stringWithFormat:@"Could not read Mach-O file at %@", path];
        return nil;
    }

    const uint8_t *bytes = (const uint8_t *)data.bytes;
    size_t totalLen = data.length;
    size_t sliceOff = 0;
    size_t sliceLen = totalLen;

    uint32_t magic = *(const uint32_t *)bytes;
    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        const struct fat_header *fh = (const struct fat_header *)bytes;
        uint32_t nfat = OSSwapBigToHostInt32(fh->nfat_arch);
        size_t aoff = sizeof(struct fat_header);
        size_t bestOff = 0, bestSize = 0;
        for (uint32_t i = 0; i < nfat && aoff + sizeof(struct fat_arch) <= totalLen; i++) {
            const struct fat_arch *fa = (const struct fat_arch *)(bytes + aoff);
            cpu_type_t ct = (cpu_type_t)OSSwapBigToHostInt32(fa->cputype);
            cpu_subtype_t cst = (cpu_subtype_t)OSSwapBigToHostInt32(fa->cpusubtype);
            uint32_t so = OSSwapBigToHostInt32(fa->offset);
            uint32_t ss = OSSwapBigToHostInt32(fa->size);
            if (ct == CPU_TYPE_ARM64 && (uint64_t)so + ss <= totalLen) {
                bestOff = so;
                bestSize = ss;
                if ((cst & ~CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E) break;
            }
            aoff += sizeof(struct fat_arch);
        }
        if (bestSize == 0) {
            if (error) *error = @"No ARM64/ARM64e slice found in universal binary";
            return nil;
        }
        sliceOff = bestOff;
        sliceLen = bestSize;
    }

    const uint8_t *sbase = bytes + sliceOff;
    if (sliceLen < sizeof(struct mach_header_64)) {
        if (error) *error = @"Truncated Mach-O slice";
        return nil;
    }
    const struct mach_header_64 *hdr = (const struct mach_header_64 *)sbase;
    if (hdr->magic != MH_MAGIC_64) {
        if (error) *error = [NSString stringWithFormat:@"Unsupported Mach-O magic 0x%x", hdr->magic];
        return nil;
    }

    MCPMachOSliceContext *ctx = [[MCPMachOSliceContext alloc] init];
    ctx.fileData = data;
    ctx.sliceOffset = sliceOff;
    ctx.sliceSize = sliceLen;
    ctx.cpuType = (uint32_t)hdr->cputype;
    ctx.cpuSubType = (uint32_t)hdr->cpusubtype;
    ctx.textVMAddr = 0x100000000ULL;
    ctx.sections = [NSMutableArray array];
    ctx.symbolsByAddr = [NSMutableDictionary dictionary];
    ctx.addrBySymbol = [NSMutableDictionary dictionary];
    ctx.selRefsByAddr = [NSMutableDictionary dictionary];
    ctx.classRefsByAddr = [NSMutableDictionary dictionary];
    ctx.cfStringsByAddr = [NSMutableDictionary dictionary];
    ctx.objcMethodsByKey = [NSMutableDictionary dictionary];
    ctx.sortedFunctionStarts = [NSMutableArray array];

    NSMutableSet<NSNumber *> *funcStartsSet = [NSMutableSet set];
    uint32_t symoff = 0, nsyms = 0, stroff = 0, strsize = 0;
    uint32_t indirectsymoff = 0, nindirectsyms = 0;
    uint32_t funcStartsOff = 0, funcStartsSize = 0;

    size_t cmdOff = sizeof(struct mach_header_64);
    size_t maxCmdOff = MIN(sliceLen, cmdOff + hdr->sizeofcmds);
    for (uint32_t i = 0; i < hdr->ncmds && cmdOff + sizeof(struct load_command) <= maxCmdOff; i++) {
        const struct load_command *lc = (const struct load_command *)(sbase + cmdOff);
        if (lc->cmdsize < sizeof(struct load_command) || cmdOff + lc->cmdsize > maxCmdOff) break;

        if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            if (strncmp(seg->segname, "__TEXT", 16) == 0) {
                ctx.textVMAddr = seg->vmaddr;
            }
            const struct section_64 *secs = (const struct section_64 *)((const uint8_t *)seg + sizeof(struct segment_command_64));
            for (uint32_t s = 0; s < seg->nsects; s++) {
                if ((const uint8_t *)&secs[s + 1] > (const uint8_t *)seg + seg->cmdsize) break;
                MCPSectionEntry entry;
                memset(&entry, 0, sizeof(entry));
                memcpy(entry.segname, secs[s].segname, 16);
                memcpy(entry.sectname, secs[s].sectname, 16);
                entry.addr = secs[s].addr;
                entry.size = secs[s].size;
                entry.offset = secs[s].offset;
                [ctx.sections addObject:[NSValue valueWithBytes:&entry objCType:@encode(MCPSectionEntry)]];
            }
        } else if (lc->cmd == LC_ENCRYPTION_INFO_64 && lc->cmdsize >= sizeof(struct encryption_info_command_64)) {
            const struct encryption_info_command_64 *enc = (const struct encryption_info_command_64 *)lc;
            ctx.encrypted = (enc->cryptid != 0);
            ctx.cryptOff = enc->cryptoff;
            ctx.cryptSize = enc->cryptsize;
        } else if (lc->cmd == LC_SYMTAB && lc->cmdsize >= sizeof(struct symtab_command)) {
            const struct symtab_command *sc = (const struct symtab_command *)lc;
            symoff = sc->symoff;
            nsyms = sc->nsyms;
            stroff = sc->stroff;
            strsize = sc->strsize;
        } else if (lc->cmd == LC_DYSYMTAB && lc->cmdsize >= sizeof(struct dysymtab_command)) {
            const struct dysymtab_command *dsc = (const struct dysymtab_command *)lc;
            indirectsymoff = dsc->indirectsymoff;
            nindirectsyms = dsc->nindirectsyms;
        } else if (lc->cmd == LC_FUNCTION_STARTS && lc->cmdsize >= sizeof(struct linkedit_data_command)) {
            const struct linkedit_data_command *ldc = (const struct linkedit_data_command *)lc;
            funcStartsOff = ldc->dataoff;
            funcStartsSize = ldc->datasize;
        }
        cmdOff += lc->cmdsize;
    }

    // Parse LC_SYMTAB
    const struct nlist_64 *symtab = NULL;
    const char *strtab = NULL;
    if (nsyms > 0 && (uint64_t)symoff + (uint64_t)nsyms * sizeof(struct nlist_64) <= sliceLen &&
        (uint64_t)stroff + (uint64_t)strsize <= sliceLen) {
        symtab = (const struct nlist_64 *)(sbase + symoff);
        strtab = (const char *)(sbase + stroff);
        for (uint32_t i = 0; i < nsyms; i++) {
            uint32_t strx = symtab[i].n_un.n_strx;
            uint64_t val = symtab[i].n_value;
            if (val != 0 && strx > 0 && strx < strsize) {
                const char *raw = strtab + strx;
                size_t maxS = strsize - strx;
                size_t slen = strnlen(raw, MIN(maxS, (size_t)512));
                if (slen > 0) {
                    NSString *name = [[NSString alloc] initWithBytes:raw length:slen encoding:NSUTF8StringEncoding];
                    if (name.length && ![name isEqualToString:@"<redacted>"]) {
                        ctx.symbolsByAddr[@(val)] = name;
                        ctx.addrBySymbol[name] = @(val);
                        if ([name hasPrefix:@"_"]) {
                            ctx.addrBySymbol[[name substringFromIndex:1]] = @(val);
                        }
                        [funcStartsSet addObject:@(val)];
                    }
                }
            }
        }
    }

    // Parse indirect stub symbols (__stubs, __auth_stubs, __got, __auth_got)
    if (symtab && strtab && nindirectsyms > 0 &&
        (uint64_t)indirectsymoff + (uint64_t)nindirectsyms * sizeof(uint32_t) <= sliceLen) {
        const uint32_t *indirectTable = (const uint32_t *)(sbase + indirectsymoff);
        for (NSValue *v in ctx.sections) {
            MCPSectionEntry sec;
            [v getValue:&sec];
            if (strcmp(sec.sectname, "__stubs") == 0 ||
                strcmp(sec.sectname, "__auth_stubs") == 0 ||
                strcmp(sec.sectname, "__got") == 0 ||
                strcmp(sec.sectname, "__auth_got") == 0 ||
                strcmp(sec.sectname, "__la_symbol_ptr") == 0) {
                // Find original section_64 in header to read reserved1 & reserved2
                size_t cOff = sizeof(struct mach_header_64);
                for (uint32_t c = 0; c < hdr->ncmds && cOff + sizeof(struct load_command) <= maxCmdOff; c++) {
                    const struct load_command *lc = (const struct load_command *)(sbase + cOff);
                    if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
                        const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
                        const struct section_64 *secs = (const struct section_64 *)((const uint8_t *)seg + sizeof(struct segment_command_64));
                        for (uint32_t s = 0; s < seg->nsects; s++) {
                            if (secs[s].addr == sec.addr) {
                                uint32_t idxStart = secs[s].reserved1;
                                uint32_t stride = secs[s].reserved2 > 0 ? secs[s].reserved2 : 8;
                                uint32_t count = (uint32_t)(secs[s].size / stride);
                                for (uint32_t k = 0; k < count && idxStart + k < nindirectsyms; k++) {
                                    uint32_t symIdx = indirectTable[idxStart + k];
                                    if (symIdx < nsyms) {
                                        uint32_t strx = symtab[symIdx].n_un.n_strx;
                                        if (strx > 0 && strx < strsize) {
                                            NSString *sname = [NSString stringWithUTF8String:strtab + strx];
                                            if (sname.length) {
                                                uint64_t stubAddr = secs[s].addr + (uint64_t)k * stride;
                                                ctx.symbolsByAddr[@(stubAddr)] = sname;
                                                if (!ctx.addrBySymbol[sname]) ctx.addrBySymbol[sname] = @(stubAddr);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    cOff += lc->cmdsize;
                }
            }
        }
    }

    // Parse LC_FUNCTION_STARTS ULEB128 delta stream
    if (funcStartsOff > 0 && funcStartsSize > 0 && (uint64_t)funcStartsOff + funcStartsSize <= sliceLen) {
        const uint8_t *p = sbase + funcStartsOff;
        const uint8_t *end = p + funcStartsSize;
        uint64_t curAddr = ctx.textVMAddr;
        while (p < end) {
            uint64_t delta = 0;
            unsigned shift = 0;
            while (p < end) {
                uint8_t b = *p++;
                delta |= (uint64_t)(b & 0x7F) << shift;
                if ((b & 0x80) == 0) break;
                shift += 7;
                if (shift > 63) break;
            }
            if (delta == 0) break;
            curAddr += delta;
            [funcStartsSet addObject:@(curAddr)];
        }
    }

    if (!ctx.encrypted) {
        // Parse __objc_selrefs
        MCPSectionEntry selSec;
        if ([ctx findSection:NULL sect:"__objc_selrefs" outEntry:&selSec] &&
            (uint64_t)selSec.offset + selSec.size <= sliceLen) {
            uint32_t count = (uint32_t)(selSec.size / sizeof(uint64_t));
            const uint64_t *ptrs = (const uint64_t *)(sbase + selSec.offset);
            for (uint32_t i = 0; i < count; i++) {
                NSString *selName = [ctx readCStringAtVMAddr:ptrs[i] maxLen:256];
                if (selName.length) {
                    ctx.selRefsByAddr[@(selSec.addr + (uint64_t)i * 8)] = selName;
                }
            }
        }

        // Parse iOS 16+ __objc_stubs (32-byte or 16-byte small selector stubs: ADRP x1, page; LDR x1, [x1, #off]; ...)
        MCPSectionEntry objcStubsSec;
        if ([ctx findSection:NULL sect:"__objc_stubs" outEntry:&objcStubsSec] &&
            (uint64_t)objcStubsSec.offset + objcStubsSec.size <= sliceLen) {
            const uint32_t *insns = (const uint32_t *)(sbase + objcStubsSec.offset);
            size_t nInsns = objcStubsSec.size / 4;
            for (size_t i = 0; i + 1 < nInsns; i++) {
                uint32_t i0 = insns[i];
                uint32_t i1 = insns[i + 1];
                // ADRP X1, page followed by LDR X1, [X1, #imm]
                if ((i0 & 0x9F00001FU) == 0x90000001U && (i1 & 0xFFC003FFU) == 0xF9400021U) {
                    uint64_t stubPC = objcStubsSec.addr + i * 4;
                    int64_t immhi = (i0 >> 5) & 0x7FFFF;
                    int64_t immlo = (i0 >> 29) & 0x3;
                    int64_t pageDelta = MCPSignExtend64((uint64_t)((immhi << 2) | immlo), 21) << 12;
                    uint64_t page = (stubPC & ~0xFFFULL) + (uint64_t)pageDelta;
                    uint64_t ldrOff = ((uint64_t)((i1 >> 10) & 0xFFF)) * 8;
                    uint64_t selRefAddr = page + ldrOff;
                    NSString *selName = ctx.selRefsByAddr[@(selRefAddr)];
                    if (selName.length) {
                        NSString *stubSym = [NSString stringWithFormat:@"_objc_msgSend$%@", selName];
                        ctx.symbolsByAddr[@(stubPC)] = stubSym;
                        ctx.addrBySymbol[stubSym] = @(stubPC);
                    }
                }
            }
        }

        // Parse __cfstring (32 bytes per CFString on 64-bit: isa, flags, cstr_ptr, length)
        MCPSectionEntry cfSec;
        if ([ctx findSection:NULL sect:"__cfstring" outEntry:&cfSec] &&
            (uint64_t)cfSec.offset + cfSec.size <= sliceLen) {
            size_t count = cfSec.size / 32;
            for (size_t i = 0; i < count; i++) {
                const uint64_t *cf = (const uint64_t *)(sbase + cfSec.offset + i * 32);
                NSString *s = [ctx readCStringAtVMAddr:cf[2] maxLen:512];
                if (s.length) {
                    ctx.cfStringsByAddr[@(cfSec.addr + i * 32)] = s;
                }
            }
        }

        // Parse __objc_classlist & methods
        MCPSectionEntry clsListSec;
        if ([ctx findSection:NULL sect:"__objc_classlist" outEntry:&clsListSec] &&
            (uint64_t)clsListSec.offset + clsListSec.size <= sliceLen) {
            size_t count = clsListSec.size / 8;
            const uint64_t *clsPtrs = (const uint64_t *)(sbase + clsListSec.offset);
            for (size_t i = 0; i < count; i++) {
                size_t clsOff = 0;
                if (![ctx vmAddrToSliceOffset:clsPtrs[i] outOffset:&clsOff] || clsOff + 40 > sliceLen) continue;
                const uint64_t *clsWords = (const uint64_t *)(sbase + clsOff);
                uint64_t dataPtr = clsWords[4] & ~7ULL;
                size_t roOff = 0;
                if (![ctx vmAddrToSliceOffset:dataPtr outOffset:&roOff] || roOff + 48 > sliceLen) continue;
                const uint8_t *roBytes = sbase + roOff;
                uint64_t nameVM = *(const uint64_t *)(roBytes + 24);
                uint64_t methodsVM = *(const uint64_t *)(roBytes + 32);
                NSString *clsName = [ctx readCStringAtVMAddr:nameVM maxLen:256];
                if (!clsName.length) continue;

                // Map class pointer & classref
                uint64_t cleanClsVA = ctx.textVMAddr + (clsOff - 0);
                ctx.symbolsByAddr[@(cleanClsVA)] = [@"_OBJC_CLASS_$_" stringByAppendingString:clsName];

                size_t mOff = 0;
                if (methodsVM != 0 && [ctx vmAddrToSliceOffset:methodsVM outOffset:&mOff] && mOff + 8 <= sliceLen) {
                    uint32_t entsizeAndFlags = *(const uint32_t *)(sbase + mOff);
                    uint32_t mCount = *(const uint32_t *)(sbase + mOff + 4);
                    BOOL isRelative = (entsizeAndFlags & 0x80000000U) != 0;
                    uint32_t entsize = entsizeAndFlags & ~0x80000003U;
                    if (entsize == 0) entsize = isRelative ? 12 : 24;
                    size_t curM = mOff + 8;
                    for (uint32_t m = 0; m < mCount && curM + entsize <= sliceLen; m++, curM += entsize) {
                        NSString *selStr = nil;
                        uint64_t impVA = 0;
                        if (isRelative && entsize >= 12) {
                            int32_t nameRel = *(const int32_t *)(sbase + curM);
                            int32_t impRel = *(const int32_t *)(sbase + curM + 8);
                            // Compute VMAddr of curM
                            uint64_t entryVA = (methodsVM & 0x00007fffffffffffULL) + 8 + (uint64_t)m * entsize;
                            uint64_t nameTargetVA = (uint64_t)((int64_t)entryVA + nameRel);
                            selStr = ctx.selRefsByAddr[@(nameTargetVA)];
                            if (!selStr.length) {
                                size_t selPtrOff = 0;
                                if ([ctx vmAddrToSliceOffset:nameTargetVA outOffset:&selPtrOff] && selPtrOff + 8 <= sliceLen) {
                                    uint64_t derefVA = *(const uint64_t *)(sbase + selPtrOff);
                                    selStr = [ctx readCStringAtVMAddr:derefVA maxLen:256];
                                }
                                if (!selStr.length) {
                                    selStr = [ctx readCStringAtVMAddr:nameTargetVA maxLen:256];
                                }
                            }
                            impVA = (uint64_t)((int64_t)(entryVA + 8) + impRel);
                        } else if (!isRelative && entsize >= 24) {
                            uint64_t nameVA = *(const uint64_t *)(sbase + curM);
                            uint64_t rawImp = *(const uint64_t *)(sbase + curM + 16);
                            selStr = [ctx readCStringAtVMAddr:nameVA maxLen:256];
                            size_t impOff = 0;
                            if ([ctx vmAddrToSliceOffset:rawImp outOffset:&impOff]) {
                                impVA = ctx.textVMAddr + impOff;
                            }
                        }
                        if (selStr.length && impVA != 0) {
                            NSString *sym = [NSString stringWithFormat:@"-[%@ %@]", clsName, selStr];
                            ctx.symbolsByAddr[@(impVA)] = sym;
                            ctx.addrBySymbol[sym] = @(impVA);
                            ctx.objcMethodsByKey[[NSString stringWithFormat:@"%@.%@", clsName, selStr]] = @{
                                @"class": clsName,
                                @"selector": selStr,
                                @"imp": @(impVA),
                                @"symbol": sym
                            };
                            [funcStartsSet addObject:@(impVA)];
                        }
                    }
                }
            }
        }

        // Parse __objc_classrefs
        MCPSectionEntry clsRefSec;
        if ([ctx findSection:NULL sect:"__objc_classrefs" outEntry:&clsRefSec] &&
            (uint64_t)clsRefSec.offset + clsRefSec.size <= sliceLen) {
            size_t count = clsRefSec.size / 8;
            const uint64_t *ptrs = (const uint64_t *)(sbase + clsRefSec.offset);
            for (size_t i = 0; i < count; i++) {
                size_t targetOff = 0;
                if ([ctx vmAddrToSliceOffset:ptrs[i] outOffset:&targetOff]) {
                    uint64_t targetVA = ctx.textVMAddr + targetOff;
                    NSString *sym = ctx.symbolsByAddr[@(targetVA)];
                    if ([sym hasPrefix:@"_OBJC_CLASS_$_"]) {
                        ctx.classRefsByAddr[@(clsRefSec.addr + i * 8)] = [sym substringFromIndex:14];
                    }
                }
            }
        }
    }

    ctx.sortedFunctionStarts = [[[funcStartsSet allObjects] sortedArrayUsingSelector:@selector(compare:)] mutableCopy];
    return ctx;
}

#pragma mark - ARM64 / ARM64e Disassembler, Symbolic Tracker & Pseudo-C Lifter

static NSString *MCPArm64RegName(unsigned reg, BOOL is64, BOOL spAsSP) {
    if (reg == 31) {
        if (spAsSP) return is64 ? @"sp" : @"wsp";
        return is64 ? @"xzr" : @"wzr";
    }
    if (reg == 29 && is64) return @"fp";
    if (reg == 30 && is64) return @"lr";
    return [NSString stringWithFormat:@"%c%u", is64 ? 'x' : 'w', reg];
}

static NSString *MCPArm64CondName(unsigned cond) {
    static NSString *const names[16] = {
        @"eq", @"ne", @"cs", @"cc", @"mi", @"pl", @"vs", @"vc",
        @"hi", @"ls", @"ge", @"lt", @"gt", @"le", @"al", @"nv"
    };
    return names[cond & 0xF];
}

static NSString *MCPArm64CondCExpr(unsigned cond, NSString *lhs, NSString *rhs) {
    switch (cond & 0xF) {
        case 0x0: return [NSString stringWithFormat:@"%@ == %@", lhs, rhs];
        case 0x1: return [NSString stringWithFormat:@"%@ != %@", lhs, rhs];
        case 0x2: return [NSString stringWithFormat:@"(uint64_t)%@ >= (uint64_t)%@", lhs, rhs];
        case 0x3: return [NSString stringWithFormat:@"(uint64_t)%@ < (uint64_t)%@", lhs, rhs];
        case 0x4: return [NSString stringWithFormat:@"%@ < 0", lhs];
        case 0x5: return [NSString stringWithFormat:@"%@ >= 0", lhs];
        case 0x8: return [NSString stringWithFormat:@"(uint64_t)%@ > (uint64_t)%@", lhs, rhs];
        case 0x9: return [NSString stringWithFormat:@"(uint64_t)%@ <= (uint64_t)%@", lhs, rhs];
        case 0xA: return [NSString stringWithFormat:@"%@ >= %@", lhs, rhs];
        case 0xB: return [NSString stringWithFormat:@"%@ < %@", lhs, rhs];
        case 0xC: return [NSString stringWithFormat:@"%@ > %@", lhs, rhs];
        case 0xD: return [NSString stringWithFormat:@"%@ <= %@", lhs, rhs];
        default:  return [NSString stringWithFormat:@"cond_%@(%@, %@)", MCPArm64CondName(cond), lhs, rhs];
    }
}

static NSDictionary *MCPDecompileInstructionBuffer(const uint8_t *codeBytes,
                                                   size_t codeLen,
                                                   uint64_t startVA,
                                                   NSString *functionName,
                                                   MCPMachOSliceContext *sliceCtx,
                                                   NSUInteger maxInstructions) {
    size_t totalInsns = MIN(codeLen / 4, (size_t)maxInstructions);
    const uint32_t *words = (const uint32_t *)codeBytes;

    // Pass 1: Identify branch targets and function boundary
    NSMutableSet<NSNumber *> *branchTargets = [NSMutableSet setWithObject:@(startVA)];
    uint64_t maxForwardTarget = startVA;
    size_t actualInsns = totalInsns;

    for (size_t i = 0; i < totalInsns; i++) {
        uint64_t pc = startVA + i * 4;
        uint32_t insn = words[i];

        // Unconditional B
        if ((insn & 0xFC000000U) == 0x14000000U) {
            int64_t off = MCPSignExtend64(insn & 0x03FFFFFFU, 26) * 4;
            uint64_t target = (uint64_t)((int64_t)pc + off);
            if (target >= startVA && target < startVA + totalInsns * 4) {
                [branchTargets addObject:@(target)];
                if (target > maxForwardTarget) maxForwardTarget = target;
            }
            if (pc >= maxForwardTarget && i >= 2) {
                actualInsns = i + 1;
                break;
            }
        }
        // Conditional B.cond
        else if ((insn & 0xFF000010U) == 0x54000000U) {
            int64_t off = MCPSignExtend64((insn >> 5) & 0x7FFFFU, 19) * 4;
            uint64_t target = (uint64_t)((int64_t)pc + off);
            if (target >= startVA && target < startVA + totalInsns * 4) {
                [branchTargets addObject:@(target)];
                if (target > maxForwardTarget) maxForwardTarget = target;
            }
            [branchTargets addObject:@(pc + 4)];
        }
        // CBZ / CBNZ
        else if ((insn & 0x7E000000U) == 0x34000000U) {
            int64_t off = MCPSignExtend64((insn >> 5) & 0x7FFFFU, 19) * 4;
            uint64_t target = (uint64_t)((int64_t)pc + off);
            if (target >= startVA && target < startVA + totalInsns * 4) {
                [branchTargets addObject:@(target)];
                if (target > maxForwardTarget) maxForwardTarget = target;
            }
            [branchTargets addObject:@(pc + 4)];
        }
        // TBZ / TBNZ
        else if ((insn & 0x7E000000U) == 0x36000000U) {
            int64_t off = MCPSignExtend64((insn >> 5) & 0x3FFFU, 14) * 4;
            uint64_t target = (uint64_t)((int64_t)pc + off);
            if (target >= startVA && target < startVA + totalInsns * 4) {
                [branchTargets addObject:@(target)];
                if (target > maxForwardTarget) maxForwardTarget = target;
            }
            [branchTargets addObject:@(pc + 4)];
        }
        // RET / RETAA / RETAB
        else if (insn == 0xD65F03C0U || insn == 0xD65F0BFFU || insn == 0xD65F0FFFU) {
            if (pc >= maxForwardTarget) {
                actualInsns = i + 1;
                break;
            }
        }
    }

    // Pass 2: Disassemble, strip PAC, track ADRP+ADD/LDR symbolic values, and lift to Pseudo-C
    uint64_t regPage[32] = {0};
    NSMutableDictionary<NSNumber *, NSString *> *regSymbolic = [NSMutableDictionary dictionary];
    regSymbolic[@0] = @"self_or_arg0";
    regSymbolic[@1] = @"_cmd_or_arg1";
    regSymbolic[@2] = @"arg2";
    regSymbolic[@3] = @"arg3";
    NSString *lastCmpLhs = @"x0";
    NSString *lastCmpRhs = @"0";

    NSMutableArray<NSDictionary *> *disassembly = [NSMutableArray arrayWithCapacity:actualInsns];
    NSMutableArray<NSDictionary *> *cfgBlocks = [NSMutableArray array];
    NSMutableArray<NSString *> *pseudoCLines = [NSMutableArray array];
    NSMutableArray<NSDictionary *> *currentBlockInsns = [NSMutableArray array];
    uint64_t currentBlockStart = startVA;
    NSUInteger pacStrippedCount = 0;

    [pseudoCLines addObject:[NSString stringWithFormat:@"// Function: %@ @ 0x%llx", functionName ?: @"sub", (unsigned long long)startVA]];
    if ([functionName hasPrefix:@"-["] || [functionName hasPrefix:@"+["]) {
        [pseudoCLines addObject:[NSString stringWithFormat:@"id %@(id self, SEL _cmd, id arg2, id arg3) {", functionName]];
        regSymbolic[@0] = @"self";
        regSymbolic[@1] = @"_cmd";
    } else {
        [pseudoCLines addObject:[NSString stringWithFormat:@"int64_t %@(int64_t arg0, int64_t arg1, int64_t arg2, int64_t arg3) {", functionName ?: [NSString stringWithFormat:@"sub_%llx", (unsigned long long)startVA]]];
        regSymbolic[@0] = @"arg0";
        regSymbolic[@1] = @"arg1";
    }

    for (size_t i = 0; i < actualInsns; i++) {
        uint64_t pc = startVA + i * 4;
        uint32_t insn = words[i];

        if (i > 0 && [branchTargets containsObject:@(pc)]) {
            if (currentBlockInsns.count > 0) {
                [cfgBlocks addObject:@{
                    @"block_start": [NSString stringWithFormat:@"0x%llx", (unsigned long long)currentBlockStart],
                    @"instruction_count": @(currentBlockInsns.count)
                }];
                [currentBlockInsns removeAllObjects];
            }
            currentBlockStart = pc;
            [pseudoCLines addObject:[NSString stringWithFormat:@"\nloc_%llx:", (unsigned long long)pc]];
        }

        NSString *mnemonic = @"dw";
        NSString *operands = [NSString stringWithFormat:@"0x%08x", insn];
        NSString *comment = nil;
        BOOL isPAC = NO;

        // 1. PAC & Hint instructions
        if (insn == 0xD503237FU) { mnemonic = @"pacibsp"; operands = @""; isPAC = YES; comment = @"PAC stripped"; }
        else if (insn == 0xD503233FU) { mnemonic = @"paciasp"; operands = @""; isPAC = YES; comment = @"PAC stripped"; }
        else if (insn == 0xD50323FFU) { mnemonic = @"autibsp"; operands = @""; isPAC = YES; comment = @"PAC stripped"; }
        else if (insn == 0xD50323BFU) { mnemonic = @"autiasp"; operands = @""; isPAC = YES; comment = @"PAC stripped"; }
        else if (insn == 0xD503201FU) { mnemonic = @"nop"; operands = @""; }
        else if ((insn & 0xFFFFFC1FU) == 0xDAC143E0U) {
            unsigned rd = insn & 0x1F;
            mnemonic = @"xpaci";
            operands = MCPArm64RegName(rd, YES, NO);
            isPAC = YES;
        }
        // 2. RET / RETAA / RETAB
        else if (insn == 0xD65F03C0U || insn == 0xD65F0BFFU || insn == 0xD65F0FFFU) {
            mnemonic = (insn == 0xD65F03C0U) ? @"ret" : ((insn == 0xD65F0BFFU) ? @"retaa" : @"retab");
            operands = @"";
            if (insn != 0xD65F03C0U) { isPAC = YES; comment = @"PAC authenticated return"; }
            NSString *retExpr = regSymbolic[@0] ?: @"x0";
            [pseudoCLines addObject:[NSString stringWithFormat:@"    return %@;", retExpr]];
        }
        // 3. B / BL
        else if ((insn & 0x7C000000U) == 0x14000000U) {
            BOOL isLink = (insn & 0x80000000U) != 0;
            int64_t off = MCPSignExtend64(insn & 0x03FFFFFFU, 26) * 4;
            uint64_t target = (uint64_t)((int64_t)pc + off);
            mnemonic = isLink ? @"bl" : @"b";
            operands = [NSString stringWithFormat:@"0x%llx", (unsigned long long)target];
            NSString *sym = sliceCtx ? sliceCtx.symbolsByAddr[@(target)] : nil;
            if (sym.length) comment = sym;

            if (isLink || (target < startVA || target >= startVA + actualInsns * 4)) {
                if ([sym hasPrefix:@"_objc_msgSend$"]) {
                    NSString *sel = [sym substringFromIndex:14];
                    NSString *recv = regSymbolic[@0] ?: @"x0";
                    NSUInteger colonCount = [[sel componentsSeparatedByString:@":"] count] - 1;
                    NSMutableString *msg = [NSMutableString stringWithFormat:@"[%@", recv];
                    if (colonCount == 0) {
                        [msg appendFormat:@" %@]", sel];
                    } else {
                        NSArray<NSString *> *parts = [sel componentsSeparatedByString:@":"];
                        for (NSUInteger p = 0; p < colonCount; p++) {
                            NSString *argVal = regSymbolic[@(2 + p)] ?: [NSString stringWithFormat:@"x%lu", (unsigned long)(2 + p)];
                            [msg appendFormat:@" %@:%@", parts[p], argVal];
                        }
                        [msg appendString:@"]"];
                    }
                    regSymbolic[@0] = msg;
                    if (!isLink) [pseudoCLines addObject:[NSString stringWithFormat:@"    return %@;", msg]];
                    else [pseudoCLines addObject:[NSString stringWithFormat:@"    x0 = %@;", msg]];
                } else if ([sym isEqualToString:@"_objc_msgSend"] || [sym isEqualToString:@"objc_msgSend"]) {
                    NSString *recv = regSymbolic[@0] ?: @"x0";
                    NSString *sel = regSymbolic[@1] ?: @"x1";
                    if ([sel hasPrefix:@"@selector("] && [sel hasSuffix:@")"]) {
                        sel = [sel substringWithRange:NSMakeRange(10, sel.length - 11)];
                    }
                    NSUInteger colonCount = [[sel componentsSeparatedByString:@":"] count] - 1;
                    NSMutableString *msg = [NSMutableString stringWithFormat:@"[%@", recv];
                    if (colonCount == 0) {
                        [msg appendFormat:@" %@]", sel];
                    } else {
                        NSArray<NSString *> *parts = [sel componentsSeparatedByString:@":"];
                        for (NSUInteger p = 0; p < colonCount; p++) {
                            NSString *argVal = regSymbolic[@(2 + p)] ?: [NSString stringWithFormat:@"x%lu", (unsigned long)(2 + p)];
                            [msg appendFormat:@" %@:%@", parts[p], argVal];
                        }
                        [msg appendString:@"]"];
                    }
                    regSymbolic[@0] = msg;
                    if (!isLink) [pseudoCLines addObject:[NSString stringWithFormat:@"    return %@;", msg]];
                    else [pseudoCLines addObject:[NSString stringWithFormat:@"    x0 = %@;", msg]];
                } else if ([sym isEqualToString:@"_objc_retainAutoreleasedReturnValue"] ||
                           [sym isEqualToString:@"_objc_retain"] ||
                           [sym isEqualToString:@"_objc_autoreleaseReturnValue"]) {
                    // Preserve x0 symbolic expression across ARC retain/autorelease
                } else if ([sym isEqualToString:@"_objc_release"]) {
                    // Suppress ARC release noise in Pseudo-C
                } else {
                    NSString *callee = sym ?: [NSString stringWithFormat:@"sub_%llx", (unsigned long long)target];
                    NSString *a0 = regSymbolic[@0] ?: @"x0";
                    NSString *a1 = regSymbolic[@1] ?: @"x1";
                    NSString *callExpr = [NSString stringWithFormat:@"%@(%@, %@)", callee, a0, a1];
                    regSymbolic[@0] = @"x0";
                    if (!isLink) [pseudoCLines addObject:[NSString stringWithFormat:@"    return %@;", callExpr]];
                    else [pseudoCLines addObject:[NSString stringWithFormat:@"    x0 = %@;", callExpr]];
                }
            } else {
                [pseudoCLines addObject:[NSString stringWithFormat:@"    goto loc_%llx;", (unsigned long long)target]];
            }
        }
        // 4. B.cond
        else if ((insn & 0xFF000010U) == 0x54000000U) {
            unsigned cond = insn & 0xF;
            int64_t off = MCPSignExtend64((insn >> 5) & 0x7FFFFU, 19) * 4;
            uint64_t target = (uint64_t)((int64_t)pc + off);
            mnemonic = [NSString stringWithFormat:@"b.%@", MCPArm64CondName(cond)];
            operands = [NSString stringWithFormat:@"0x%llx", (unsigned long long)target];
            [pseudoCLines addObject:[NSString stringWithFormat:@"    if (%@) goto loc_%llx;", MCPArm64CondCExpr(cond, lastCmpLhs, lastCmpRhs), (unsigned long long)target]];
        }
        // 5. CBZ / CBNZ
        else if ((insn & 0x7E000000U) == 0x34000000U) {
            BOOL is64 = (insn & 0x80000000U) != 0;
            BOOL isNz = (insn & 0x01000000U) != 0;
            unsigned rt = insn & 0x1F;
            int64_t off = MCPSignExtend64((insn >> 5) & 0x7FFFFU, 19) * 4;
            uint64_t target = (uint64_t)((int64_t)pc + off);
            NSString *rname = MCPArm64RegName(rt, is64, NO);
            mnemonic = isNz ? @"cbnz" : @"cbz";
            operands = [NSString stringWithFormat:@"%@, 0x%llx", rname, (unsigned long long)target];
            NSString *symExpr = regSymbolic[@(rt)] ?: rname;
            [pseudoCLines addObject:[NSString stringWithFormat:@"    if (%@ %s 0) goto loc_%llx;", symExpr, isNz ? "!=" : "==", (unsigned long long)target]];
        }
        // 6. TBZ / TBNZ
        else if ((insn & 0x7E000000U) == 0x36000000U) {
            BOOL isNz = (insn & 0x01000000U) != 0;
            unsigned rt = insn & 0x1F;
            unsigned bit = ((insn >> 26) & 0x20U) | ((insn >> 19) & 0x1FU);
            int64_t off = MCPSignExtend64((insn >> 5) & 0x3FFFU, 14) * 4;
            uint64_t target = (uint64_t)((int64_t)pc + off);
            NSString *rname = MCPArm64RegName(rt, bit >= 32, NO);
            mnemonic = isNz ? @"tbnz" : @"tbz";
            operands = [NSString stringWithFormat:@"%@, #%u, 0x%llx", rname, bit, (unsigned long long)target];
            NSString *symExpr = regSymbolic[@(rt)] ?: rname;
            [pseudoCLines addObject:[NSString stringWithFormat:@"    if (((%@ >> %u) & 1) %s 0) goto loc_%llx;", symExpr, bit, isNz ? "!=" : "==", (unsigned long long)target]];
        }
        // 7. BLR / BR / BLRAA / BLRAB / BRAA / BRAB
        else if ((insn & 0xFE1FFC1FU) == 0xD61F0000U || (insn & 0xFE1F0000U) == 0xD71F0000U) {
            unsigned rn = (insn >> 5) & 0x1F;
            BOOL isLink = ((insn >> 21) & 0x3) == 1;
            BOOL isAuth = (insn & 0x01000000U) != 0 || ((insn >> 10) & 0x3F) != 0;
            if (isAuth) isPAC = YES;
            mnemonic = isLink ? (isAuth ? @"blraa" : @"blr") : (isAuth ? @"braa" : @"br");
            operands = MCPArm64RegName(rn, YES, NO);
            NSString *fnExpr = regSymbolic[@(rn)] ?: operands;
            if (isLink) {
                [pseudoCLines addObject:[NSString stringWithFormat:@"    x0 = ((int64_t (*)(void))%@)();", fnExpr]];
                regSymbolic[@0] = @"x0";
            } else {
                [pseudoCLines addObject:[NSString stringWithFormat:@"    return ((int64_t (*)(void))%@)();", fnExpr]];
            }
        }
        // 8. ADRP / ADR
        else if ((insn & 0x1F000000U) == 0x10000000U) {
            BOOL isPage = (insn & 0x80000000U) != 0;
            unsigned rd = insn & 0x1F;
            int64_t immhi = (insn >> 5) & 0x7FFFFU;
            int64_t immlo = (insn >> 29) & 0x3U;
            int64_t imm = MCPSignExtend64((uint64_t)((immhi << 2) | immlo), 21);
            uint64_t target = isPage ? ((pc & ~0xFFFULL) + (uint64_t)(imm << 12)) : (uint64_t)((int64_t)pc + imm);
            mnemonic = isPage ? @"adrp" : @"adr";
            operands = [NSString stringWithFormat:@"%@, 0x%llx", MCPArm64RegName(rd, YES, NO), (unsigned long long)target];
            regPage[rd] = target;
            if (!isPage && sliceCtx) {
                NSString *cstr = [sliceCtx readCStringAtVMAddr:target maxLen:256];
                if (cstr.length) {
                    comment = [NSString stringWithFormat:@"\"%@\"", cstr];
                    regSymbolic[@(rd)] = comment;
                }
            }
        }
        // 9. ADD / SUB / CMP (immediate)
        else if ((insn & 0x1F000000U) == 0x11000000U) {
            BOOL is64 = (insn & 0x80000000U) != 0;
            BOOL isSub = (insn & 0x40000000U) != 0;
            BOOL setFlags = (insn & 0x20000000U) != 0;
            unsigned shift = ((insn >> 22) & 0x1) ? 12 : 0;
            uint64_t imm12 = (uint64_t)((insn >> 10) & 0xFFFU) << shift;
            unsigned rn = (insn >> 5) & 0x1F;
            unsigned rd = insn & 0x1F;

            if (isSub && setFlags && rd == 31) {
                mnemonic = @"cmp";
                NSString *rnName = MCPArm64RegName(rn, is64, YES);
                operands = [NSString stringWithFormat:@"%@, #0x%llx", rnName, (unsigned long long)imm12];
                lastCmpLhs = regSymbolic[@(rn)] ?: rnName;
                lastCmpRhs = [NSString stringWithFormat:@"0x%llx", (unsigned long long)imm12];
            } else {
                mnemonic = isSub ? (setFlags ? @"subs" : @"sub") : (setFlags ? @"adds" : @"add");
                NSString *rdName = MCPArm64RegName(rd, is64, !setFlags);
                NSString *rnName = MCPArm64RegName(rn, is64, YES);
                operands = [NSString stringWithFormat:@"%@, %@, #0x%llx", rdName, rnName, (unsigned long long)imm12];

                if (!isSub && is64 && regPage[rn] != 0) {
                    uint64_t fullVA = regPage[rn] + imm12;
                    regPage[rd] = 0;
                    NSString *resolved = nil;
                    if (sliceCtx) {
                        NSString *cfs = sliceCtx.cfStringsByAddr[@(fullVA)];
                        if (cfs) resolved = [NSString stringWithFormat:@"@\"%@\"", cfs];
                        if (!resolved) {
                            NSString *cstr = [sliceCtx readCStringAtVMAddr:fullVA maxLen:256];
                            if (cstr.length) resolved = [NSString stringWithFormat:@"\"%@\"", cstr];
                        }
                        if (!resolved) resolved = sliceCtx.symbolsByAddr[@(fullVA)];
                    }
                    comment = resolved ?: [NSString stringWithFormat:@"0x%llx", (unsigned long long)fullVA];
                    regSymbolic[@(rd)] = resolved ?: [NSString stringWithFormat:@"0x%llx", (unsigned long long)fullVA];
                } else if (rn != 31 && rd != 31) {
                    NSString *lhs = regSymbolic[@(rn)] ?: rnName;
                    regSymbolic[@(rd)] = (imm12 == 0) ? lhs : [NSString stringWithFormat:@"(%@ %c 0x%llx)", lhs, isSub ? '-' : '+', (unsigned long long)imm12];
                }
            }
        }
        // 10. LDR / STR (unsigned immediate offset, 32/64-bit)
        else if ((insn & 0x3B000000U) == 0x39000000U) {
            unsigned size = (insn >> 30) & 0x3;
            unsigned opc = (insn >> 22) & 0x3;
            unsigned imm12 = (insn >> 10) & 0xFFF;
            unsigned rn = (insn >> 5) & 0x1F;
            unsigned rt = insn & 0x1F;
            uint64_t offset = (uint64_t)imm12 << size;
            BOOL isLoad = (opc != 0);
            BOOL is64 = (size == 3);
            mnemonic = isLoad ? (size == 0 ? @"ldrb" : (size == 1 ? @"ldrh" : @"ldr"))
                              : (size == 0 ? @"strb" : (size == 1 ? @"strh" : @"str"));
            NSString *rtName = MCPArm64RegName(rt, is64, NO);
            NSString *rnName = MCPArm64RegName(rn, YES, YES);
            operands = offset ? [NSString stringWithFormat:@"%@, [%@, #0x%llx]", rtName, rnName, (unsigned long long)offset]
                              : [NSString stringWithFormat:@"%@, [%@]", rtName, rnName];

            if (isLoad && is64 && regPage[rn] != 0) {
                uint64_t targetVA = regPage[rn] + offset;
                regPage[rt] = 0;
                if (sliceCtx) {
                    NSString *sel = sliceCtx.selRefsByAddr[@(targetVA)];
                    NSString *cls = sliceCtx.classRefsByAddr[@(targetVA)];
                    NSString *cfs = sliceCtx.cfStringsByAddr[@(targetVA)];
                    NSString *sym = sliceCtx.symbolsByAddr[@(targetVA)];
                    if (sel) {
                        comment = [NSString stringWithFormat:@"@selector(%@)", sel];
                        regSymbolic[@(rt)] = comment;
                    } else if (cls) {
                        comment = [NSString stringWithFormat:@"objc_class: %@", cls];
                        regSymbolic[@(rt)] = cls;
                    } else if (cfs) {
                        comment = [NSString stringWithFormat:@"@\"%@\"", cfs];
                        regSymbolic[@(rt)] = comment;
                    } else if (sym) {
                        comment = sym;
                        regSymbolic[@(rt)] = sym;
                    } else {
                        comment = [NSString stringWithFormat:@"*(0x%llx)", (unsigned long long)targetVA];
                        regSymbolic[@(rt)] = comment;
                    }
                }
            } else if (isLoad && rn != 31 && rn != 29) {
                NSString *baseExpr = regSymbolic[@(rn)] ?: rnName;
                regSymbolic[@(rt)] = [NSString stringWithFormat:@"*(%@ + 0x%llx)", baseExpr, (unsigned long long)offset];
            }
        }
        // 11. STP / LDP (64-bit / 32-bit pairs)
        else if ((insn & 0x3E000000U) == 0x28000000U) {
            BOOL is64 = (insn & 0x80000000U) != 0;
            BOOL isLoad = (insn & 0x00400000U) != 0;
            int64_t imm7 = MCPSignExtend64((insn >> 15) & 0x7FU, 7) * (is64 ? 8 : 4);
            unsigned rt2 = (insn >> 10) & 0x1F;
            unsigned rn = (insn >> 5) & 0x1F;
            unsigned rt = insn & 0x1F;
            mnemonic = isLoad ? @"ldp" : @"stp";
            operands = [NSString stringWithFormat:@"%@, %@, [%@, #%lld]",
                        MCPArm64RegName(rt, is64, NO),
                        MCPArm64RegName(rt2, is64, NO),
                        MCPArm64RegName(rn, YES, YES),
                        (long long)imm7];
        }
        // 12. MOVZ / MOVN / MOVK
        else if ((insn & 0x1F800000U) == 0x12800000U) {
            BOOL is64 = (insn & 0x80000000U) != 0;
            unsigned opc = (insn >> 29) & 0x3;
            unsigned hw = ((insn >> 21) & 0x3) * 16;
            uint64_t imm16 = (insn >> 5) & 0xFFFFU;
            unsigned rd = insn & 0x1F;
            mnemonic = (opc == 0) ? @"movn" : ((opc == 2) ? @"movz" : @"movk");
            NSString *rdName = MCPArm64RegName(rd, is64, NO);
            operands = hw ? [NSString stringWithFormat:@"%@, #0x%llx, lsl #%u", rdName, (unsigned long long)imm16, hw]
                          : [NSString stringWithFormat:@"%@, #0x%llx", rdName, (unsigned long long)imm16];
            if (opc == 2) {
                uint64_t val = imm16 << hw;
                regSymbolic[@(rd)] = [NSString stringWithFormat:@"0x%llx", (unsigned long long)val];
                [pseudoCLines addObject:[NSString stringWithFormat:@"    %@ = 0x%llx;", rdName, (unsigned long long)val]];
            } else if (opc == 0) {
                uint64_t val = ~(imm16 << hw);
                if (!is64) val &= 0xFFFFFFFFULL;
                regSymbolic[@(rd)] = [NSString stringWithFormat:@"0x%llx", (unsigned long long)val];
            }
        }
        // 13. ORR (register) / MOV Rd, Rm
        else if ((insn & 0x7FE0FFE0U) == 0x2A0003E0U) {
            BOOL is64 = (insn & 0x80000000U) != 0;
            unsigned rm = (insn >> 16) & 0x1F;
            unsigned rd = insn & 0x1F;
            mnemonic = @"mov";
            NSString *rdName = MCPArm64RegName(rd, is64, NO);
            NSString *rmName = MCPArm64RegName(rm, is64, NO);
            operands = [NSString stringWithFormat:@"%@, %@", rdName, rmName];
            regPage[rd] = regPage[rm];
            if (rm == 31) {
                regSymbolic[@(rd)] = @"0";
            } else {
                regSymbolic[@(rd)] = regSymbolic[@(rm)] ?: rmName;
            }
        }
        // 14. ADD / SUB / CMP (shifted register)
        else if ((insn & 0x1F200000U) == 0x0B000000U) {
            BOOL is64 = (insn & 0x80000000U) != 0;
            BOOL isSub = (insn & 0x40000000U) != 0;
            BOOL setFlags = (insn & 0x20000000U) != 0;
            unsigned rm = (insn >> 16) & 0x1F;
            unsigned rn = (insn >> 5) & 0x1F;
            unsigned rd = insn & 0x1F;
            NSString *rnName = MCPArm64RegName(rn, is64, NO);
            NSString *rmName = MCPArm64RegName(rm, is64, NO);
            if (isSub && setFlags && rd == 31) {
                mnemonic = @"cmp";
                operands = [NSString stringWithFormat:@"%@, %@", rnName, rmName];
                lastCmpLhs = regSymbolic[@(rn)] ?: rnName;
                lastCmpRhs = regSymbolic[@(rm)] ?: rmName;
            } else {
                NSString *rdName = MCPArm64RegName(rd, is64, NO);
                mnemonic = isSub ? (setFlags ? @"subs" : @"sub") : (setFlags ? @"adds" : @"add");
                operands = [NSString stringWithFormat:@"%@, %@, %@", rdName, rnName, rmName];
                regSymbolic[@(rd)] = [NSString stringWithFormat:@"(%@ %c %@)",
                                      regSymbolic[@(rn)] ?: rnName,
                                      isSub ? '-' : '+',
                                      regSymbolic[@(rm)] ?: rmName];
            }
        }
        // 15. CSEL / CSINC / CSINV / CSNEG (including CSET)
        else if ((insn & 0x1FE00000U) == 0x1A800000U) {
            BOOL is64 = (insn & 0x80000000U) != 0;
            unsigned rm = (insn >> 16) & 0x1F;
            unsigned cond = (insn >> 12) & 0xF;
            unsigned op2 = (insn >> 10) & 0x3;
            unsigned rn = (insn >> 5) & 0x1F;
            unsigned rd = insn & 0x1F;
            NSString *rdName = MCPArm64RegName(rd, is64, NO);
            if (op2 == 1 && rn == 31 && rm == 31) {
                mnemonic = @"cset";
                unsigned invCond = cond ^ 1;
                operands = [NSString stringWithFormat:@"%@, %@", rdName, MCPArm64CondName(invCond)];
                NSString *cExpr = [NSString stringWithFormat:@"(%@ ? 1 : 0)", MCPArm64CondCExpr(invCond, lastCmpLhs, lastCmpRhs)];
                regSymbolic[@(rd)] = cExpr;
                [pseudoCLines addObject:[NSString stringWithFormat:@"    %@ = %@;", rdName, cExpr]];
            } else {
                mnemonic = (op2 == 0) ? @"csel" : @"csinc";
                operands = [NSString stringWithFormat:@"%@, %@, %@, %@",
                            rdName,
                            MCPArm64RegName(rn, is64, NO),
                            MCPArm64RegName(rm, is64, NO),
                            MCPArm64CondName(cond)];
            }
        }
        // 16. SVC
        else if ((insn & 0xFFE0001FU) == 0xD4000001U) {
            unsigned imm16 = (insn >> 5) & 0xFFFFU;
            mnemonic = @"svc";
            operands = [NSString stringWithFormat:@"#0x%x", imm16];
            comment = [NSString stringWithFormat:@"syscall(x16=%@)", regSymbolic[@16] ?: @"x16"];
            [pseudoCLines addObject:[NSString stringWithFormat:@"    x0 = syscall(%@, %@, %@);",
                                     regSymbolic[@16] ?: @"x16",
                                     regSymbolic[@0] ?: @"x0",
                                     regSymbolic[@1] ?: @"x1"]];
        }

        if (isPAC) pacStrippedCount++;

        NSMutableDictionary *entry = [NSMutableDictionary dictionaryWithCapacity:6];
        entry[@"address"] = [NSString stringWithFormat:@"0x%llx", (unsigned long long)pc];
        entry[@"bytes"] = [NSString stringWithFormat:@"%08x", insn];
        entry[@"mnemonic"] = mnemonic;
        entry[@"operands"] = operands;
        if (comment.length) entry[@"comment"] = comment;
        if (isPAC) entry[@"pac_stripped"] = @YES;

        [disassembly addObject:entry];
        [currentBlockInsns addObject:entry];
    }

    if (currentBlockInsns.count > 0) {
        [cfgBlocks addObject:@{
            @"block_start": [NSString stringWithFormat:@"0x%llx", (unsigned long long)currentBlockStart],
            @"instruction_count": @(currentBlockInsns.count)
        }];
    }
    [pseudoCLines addObject:@"}"];

    return @{
        @"function_name": functionName ?: @"sub",
        @"start_address": [NSString stringWithFormat:@"0x%llx", (unsigned long long)startVA],
        @"instruction_count": @(disassembly.count),
        @"pac_instructions_stripped": @(pacStrippedCount),
        @"basic_block_count": @(cfgBlocks.count),
        @"basic_blocks": cfgBlocks,
        @"pseudo_c": [pseudoCLines componentsJoinedByString:@"\n"],
        @"disassembly": disassembly
    };
}

@implementation BinaryInspector

+ (instancetype)sharedInstance {
    static BinaryInspector *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[BinaryInspector alloc] init];
    });
    return instance;
}

- (NSString *)resolveBinaryPathFromArgs:(NSDictionary *)args
                            outBundleId:(NSString **)outBundleId
                          outBundlePath:(NSString **)outBundlePath
                                  error:(NSString **)error {
    NSString *path = [args[@"path"] isKindOfClass:[NSString class]] ? args[@"path"] : nil;
    if (!path.length && [args[@"binary_path"] isKindOfClass:[NSString class]]) {
        path = args[@"binary_path"];
    }
    NSString *bundleId = [args[@"bundle_id"] isKindOfClass:[NSString class]] ? args[@"bundle_id"] : nil;
    if (outBundleId) *outBundleId = bundleId;

    if (bundleId.length > 0) {
        NSString *appErr = nil;
        NSDictionary *info = [[AppManager sharedInstance] appInfoForBundleId:bundleId error:&appErr];
        if (outBundlePath && [info[@"bundle_path"] isKindOfClass:[NSString class]]) {
            *outBundlePath = info[@"bundle_path"];
        }
        if (!path.length && [info[@"executable_path"] isKindOfClass:[NSString class]]) {
            path = info[@"executable_path"];
        }
        if (!path.length && !info) {
            if (error) *error = appErr ?: [NSString stringWithFormat:@"App not found for bundle_id '%@'", bundleId];
            return nil;
        }
    }
    if (!path.length) {
        if (error) *error = @"Provide either 'path' (Mach-O file path) or 'bundle_id'";
        return nil;
    }
    return path;
}

#pragma mark - [Upgrade 01] decrypt_app_ipa

- (NSDictionary *)decryptAppIPAForArgs:(NSDictionary *)args error:(NSString **)error {
    if (error) *error = nil;
    NSString *bundleId = [args[@"bundle_id"] isKindOfClass:[NSString class]] ? args[@"bundle_id"] : nil;
    NSString *bundlePath = [args[@"bundle_path"] isKindOfClass:[NSString class]] ? args[@"bundle_path"] : nil;
    NSString *outputPath = [args[@"output_path"] isKindOfClass:[NSString class]] ? args[@"output_path"] : nil;
    BOOL autoLaunch = (!args[@"auto_launch"] || [args[@"auto_launch"] boolValue]);

    uint64_t rawPid = 0;
    MCPParseHexOrUint64(args[@"pid"], &rawPid);
    pid_t pid = (pid_t)rawPid;

    if (bundleId.length > 0) {
        NSString *appErr = nil;
        NSDictionary *info = [[AppManager sharedInstance] appInfoForBundleId:bundleId error:&appErr];
        if (!info) {
            if (error) *error = appErr ?: [NSString stringWithFormat:@"Could not resolve bundle_id '%@'", bundleId];
            return nil;
        }
        if (!bundlePath.length) bundlePath = info[@"bundle_path"];
        if (pid <= 0) pid = [[AppManager sharedInstance] pidForBundleId:bundleId];
        if (pid <= 0 && autoLaunch) {
            NSString *launchErr = nil;
            if ([[AppManager sharedInstance] launchApp:bundleId error:&launchErr]) {
                for (int i = 0; i < 20 && pid <= 0; i++) {
                    usleep(200 * 1000);
                    pid = [[AppManager sharedInstance] pidForBundleId:bundleId];
                }
                // Give dyld 400ms to finish mapping all embedded frameworks
                if (pid > 0) usleep(400 * 1000);
            }
        }
    }

    if (pid <= 0 || !bundlePath.length) {
        if (error) *error = @"Target app must be running (or provide a valid bundle_id with auto_launch=true) and have a valid bundle_path";
        return nil;
    }

    if (!outputPath.length) {
        NSString *safeName = bundleId.length ? bundleId : bundlePath.lastPathComponent.stringByDeletingPathExtension;
        outputPath = [NSString stringWithFormat:@"/tmp/%@-decrypted.ipa", safeName];
    }

    NSString *outStr = nil, *runErr = nil;
    int exitCode = -1;
    BOOL launched = MCPRunRootProcess(@"/usr/libexec/ios-mcp/mcp-memory",
                                      @[@"decrypt-ipa", [NSString stringWithFormat:@"%d", pid], bundlePath, outputPath],
                                      120.0,
                                      4 * 1024 * 1024,
                                      &outStr,
                                      &exitCode,
                                      &runErr);
    if (launched && outStr.length) {
        NSDictionary *resp = [NSJSONSerialization JSONObjectWithData:[outStr dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
        if ([resp isKindOfClass:[NSDictionary class]]) {
            if ([resp[@"ok"] boolValue] && [resp[@"result"] isKindOfClass:[NSDictionary class]]) {
                return resp[@"result"];
            }
            if ([resp[@"error"] isKindOfClass:[NSString class]]) {
                if (error) *error = resp[@"error"];
                return nil;
            }
        }
    }

    return [[MemoryManager sharedInstance] decryptAppIPAForPID:pid
                                                    bundlePath:bundlePath
                                                    outputPath:outputPath
                                                         error:error];
}

#pragma mark - [Upgrade 02] decompile_function & decompile_objc_method & find_xrefs_to

- (NSDictionary *)decompileFunctionForArgs:(NSDictionary *)args error:(NSString **)error {
    if (error) *error = nil;
    NSString *bundleId = nil, *bundlePath = nil;
    NSString *path = [self resolveBinaryPathFromArgs:args outBundleId:&bundleId outBundlePath:&bundlePath error:nil];

    uint64_t maxInsns64 = 128;
    if (args[@"max_instructions"]) MCPParseHexOrUint64(args[@"max_instructions"], &maxInsns64);
    else if (args[@"length"]) {
        uint64_t byteLen = 0;
        if (MCPParseHexOrUint64(args[@"length"], &byteLen) && byteLen >= 4) maxInsns64 = byteLen / 4;
    }
    if (maxInsns64 < 1) maxInsns64 = 1;
    if (maxInsns64 > 1024) maxInsns64 = 1024;

    uint64_t targetAddr = 0;
    BOOL hasAddr = MCPParseHexOrUint64(args[@"address"] ?: args[@"offset"], &targetAddr);
    NSString *symbolName = [args[@"symbol"] ?: args[@"function"] isKindOfClass:[NSString class]] ? (args[@"symbol"] ?: args[@"function"]) : nil;

    // If engine session is active and live_memory is requested or no path on disk
    if (bundleId.length && [args[@"use_engine"] boolValue]) {
        NSString *engErr = nil;
        NSDictionary *engRes = [[MCPEngineManager sharedInstance] sendOp:@"engine.decompile"
                                                             forBundleId:bundleId
                                                                    args:args
                                                               timeoutMs:15000
                                                                   error:&engErr];
        if (engRes) return engRes;
    }

    MCPMachOSliceContext *ctx = path.length ? MCPLoadMachOSliceContext(path, error) : nil;
    if (ctx) {
        if (!hasAddr && symbolName.length) {
            NSNumber *resolved = ctx.addrBySymbol[symbolName];
            if (!resolved && ![symbolName hasPrefix:@"_"]) {
                resolved = ctx.addrBySymbol[[@"_" stringByAppendingString:symbolName]];
            }
            if (resolved) {
                targetAddr = resolved.unsignedLongLongValue;
                hasAddr = YES;
            }
        }
        if (hasAddr && targetAddr < ctx.textVMAddr) {
            targetAddr += ctx.textVMAddr;
        }
        size_t sliceOff = 0;
        if (hasAddr && !ctx.encrypted && [ctx vmAddrToSliceOffset:targetAddr outOffset:&sliceOff]) {
            size_t avail = ctx.sliceSize - sliceOff;
            NSString *fnName = symbolName.length ? symbolName : [ctx symbolContainingAddress:targetAddr outStart:NULL];
            NSMutableDictionary *res = [MCPDecompileInstructionBuffer([ctx sliceBytes] + sliceOff,
                                                                      avail,
                                                                      targetAddr,
                                                                      fnName,
                                                                      ctx,
                                                                      (NSUInteger)maxInsns64) mutableCopy];
            res[@"binary_path"] = path;
            res[@"source"] = @"macho_on_disk";
            return res;
        }
    }

    // Fallback to live process memory via mcp-memory when binary is FairPlay-encrypted or address is a runtime slide address
    uint64_t pidVal = 0;
    MCPParseHexOrUint64(args[@"pid"], &pidVal);
    pid_t pid = (pid_t)pidVal;
    if (pid <= 0 && bundleId.length) {
        pid = [[AppManager sharedInstance] pidForBundleId:bundleId];
    }
    if (pid > 0 && hasAddr) {
        size_t byteCount = (size_t)maxInsns64 * 4;
        NSString *outStr = nil, *runErr = nil;
        int exitCode = -1;
        BOOL ok = MCPRunRootProcess(@"/usr/libexec/ios-mcp/mcp-memory",
                                    @[@"read", [NSString stringWithFormat:@"%d", pid],
                                      [NSString stringWithFormat:@"0x%llx", (unsigned long long)targetAddr],
                                      [NSString stringWithFormat:@"%zu", byteCount]],
                                    15.0, 1024 * 1024, &outStr, &exitCode, &runErr);
        if (ok && exitCode == 0 && outStr.length) {
            NSDictionary *resp = [NSJSONSerialization JSONObjectWithData:[outStr dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
            NSString *b64 = resp[@"result"][@"data"];
            NSData *rawCode = b64.length ? [[NSData alloc] initWithBase64EncodedString:b64 options:0] : nil;
            if (rawCode.length >= 4) {
                NSMutableDictionary *res = [MCPDecompileInstructionBuffer((const uint8_t *)rawCode.bytes,
                                                                          rawCode.length,
                                                                          targetAddr,
                                                                          symbolName ?: [NSString stringWithFormat:@"sub_%llx", (unsigned long long)targetAddr],
                                                                          ctx,
                                                                          (NSUInteger)maxInsns64) mutableCopy];
                res[@"pid"] = @(pid);
                res[@"source"] = @"live_process_memory";
                return res;
            }
        }
    }

    if (error && !*error) {
        *error = @"Could not resolve target function address in Mach-O or live process memory";
    }
    return nil;
}

- (NSDictionary *)decompileObjCMethodForArgs:(NSDictionary *)args error:(NSString **)error {
    if (error) *error = nil;
    NSString *className = [args[@"class_name"] ?: args[@"class"] isKindOfClass:[NSString class]] ? (args[@"class_name"] ?: args[@"class"]) : nil;
    NSString *selector = [args[@"selector"] ?: args[@"method"] isKindOfClass:[NSString class]] ? (args[@"selector"] ?: args[@"method"]) : nil;
    if (!className.length || !selector.length) {
        if (error) *error = @"Missing required parameters: 'class_name' and 'selector'";
        return nil;
    }

    NSString *bundleId = nil, *bundlePath = nil;
    NSString *path = [self resolveBinaryPathFromArgs:args outBundleId:&bundleId outBundlePath:&bundlePath error:nil];

    // If engine session is active, try in-process decompile first for live swizzled/decrypted IMP
    if (bundleId.length && [args[@"use_engine"] boolValue]) {
        NSString *engErr = nil;
        NSDictionary *engRes = [[MCPEngineManager sharedInstance] sendOp:@"engine.decompile"
                                                             forBundleId:bundleId
                                                                    args:@{@"class": className, @"selector": selector, @"max_instructions": args[@"max_instructions"] ?: @128}
                                                               timeoutMs:15000
                                                                   error:&engErr];
        if (engRes) return engRes;
    }

    if (path.length) {
        MCPMachOSliceContext *ctx = MCPLoadMachOSliceContext(path, nil);
        if (ctx && !ctx.encrypted) {
            NSString *key = [NSString stringWithFormat:@"%@.%@", className, selector];
            NSDictionary *mInfo = ctx.objcMethodsByKey[key];
            uint64_t impAddr = [mInfo[@"imp"] unsignedLongLongValue];
            if (!impAddr) {
                NSString *instSym = [NSString stringWithFormat:@"-[%@ %@]", className, selector];
                NSString *clsSym = [NSString stringWithFormat:@"+[%@ %@]", className, selector];
                impAddr = [ctx.addrBySymbol[instSym] ?: ctx.addrBySymbol[clsSym] unsignedLongLongValue];
            }
            if (impAddr != 0) {
                NSMutableDictionary *fArgs = [args mutableCopy];
                fArgs[@"address"] = [NSString stringWithFormat:@"0x%llx", (unsigned long long)impAddr];
                fArgs[@"symbol"] = [NSString stringWithFormat:@"-[%@ %@]", className, selector];
                fArgs[@"path"] = path;
                NSDictionary *dec = [self decompileFunctionForArgs:fArgs error:error];
                if (dec) {
                    NSMutableDictionary *out = [dec mutableCopy];
                    out[@"class_name"] = className;
                    out[@"selector"] = selector;
                    return out;
                }
            }
        }
    }

    // Fallback: resolve live IMP via ClassDumpManager (remote task_for_pid ObjC runtime walk)
    if (bundleId.length) {
        NSString *dumpErr = nil;
        NSDictionary *dump = [[ClassDumpManager sharedInstance] dumpClassesForBundleId:bundleId
                                                                                filter:className
                                                                                 limit:50
                                                                         includeSystem:YES
                                                                            autoLaunch:YES
                                                                                 error:&dumpErr];
        NSArray *classes = [dump[@"classes"] isKindOfClass:[NSArray class]] ? dump[@"classes"] : @[];
        for (NSDictionary *cls in classes) {
            if ([cls[@"name"] isEqualToString:className]) {
                NSArray *methods = [cls[@"methods"] isKindOfClass:[NSArray class]] ? cls[@"methods"] : @[];
                for (NSDictionary *m in methods) {
                    if ([m[@"name"] isEqualToString:selector] && [m[@"imp"] isKindOfClass:[NSString class]]) {
                        NSMutableDictionary *fArgs = [args mutableCopy];
                        fArgs[@"address"] = m[@"imp"];
                        fArgs[@"symbol"] = [NSString stringWithFormat:@"%@[%@ %@]", [m[@"is_class_method"] boolValue] ? @"+" : @"-", className, selector];
                        NSDictionary *dec = [self decompileFunctionForArgs:fArgs error:error];
                        if (dec) {
                            NSMutableDictionary *out = [dec mutableCopy];
                            out[@"class_name"] = className;
                            out[@"selector"] = selector;
                            out[@"encoding"] = m[@"types"] ?: @"";
                            return out;
                        }
                    }
                }
            }
        }
    }

    if (error && !*error) {
        *error = [NSString stringWithFormat:@"Could not locate Objective-C method -[%@ %@]", className, selector];
    }
    return nil;
}

- (NSDictionary *)findXrefsForArgs:(NSDictionary *)args error:(NSString **)error {
    if (error) *error = nil;
    NSString *bundleId = nil, *bundlePath = nil;
    NSString *path = [self resolveBinaryPathFromArgs:args outBundleId:&bundleId outBundlePath:&bundlePath error:error];
    if (!path.length) return nil;

    MCPMachOSliceContext *ctx = MCPLoadMachOSliceContext(path, error);
    if (!ctx) return nil;
    if (ctx.encrypted) {
        if (error) *error = @"Binary is FairPlay-encrypted on disk; run decrypt_app_ipa first or provide a decrypted Mach-O path";
        return nil;
    }

    NSMutableSet<NSNumber *> *targetAddresses = [NSMutableSet set];
    NSString *targetDesc = nil;

    uint64_t explicitAddr = 0;
    if (MCPParseHexOrUint64(args[@"target_address"] ?: args[@"address"], &explicitAddr)) {
        if (explicitAddr < ctx.textVMAddr) explicitAddr += ctx.textVMAddr;
        [targetAddresses addObject:@(explicitAddr)];
        targetDesc = [NSString stringWithFormat:@"address 0x%llx", (unsigned long long)explicitAddr];
    }

    NSString *selector = [args[@"selector"] isKindOfClass:[NSString class]] ? args[@"selector"] : nil;
    if (selector.length) {
        targetDesc = [NSString stringWithFormat:@"selector '%@'", selector];
        for (NSNumber *selRefAddr in ctx.selRefsByAddr) {
            if ([ctx.selRefsByAddr[selRefAddr] isEqualToString:selector]) {
                [targetAddresses addObject:selRefAddr];
            }
        }
        NSString *stubSym = [NSString stringWithFormat:@"_objc_msgSend$%@", selector];
        if (ctx.addrBySymbol[stubSym]) {
            [targetAddresses addObject:ctx.addrBySymbol[stubSym]];
        }
    }

    NSString *needleStr = [args[@"string"] isKindOfClass:[NSString class]] ? args[@"string"] : nil;
    if (needleStr.length) {
        targetDesc = [NSString stringWithFormat:@"string \"%@\"", needleStr];
        // Search __cstring
        MCPSectionEntry cstrSec;
        if ([ctx findSection:NULL sect:"__cstring" outEntry:&cstrSec] &&
            (uint64_t)cstrSec.offset + cstrSec.size <= ctx.sliceSize) {
            const uint8_t *sbase = [ctx sliceBytes] + cstrSec.offset;
            size_t pos = 0;
            while (pos < cstrSec.size) {
                size_t slen = strnlen((const char *)(sbase + pos), cstrSec.size - pos);
                if (slen > 0) {
                    NSString *cand = [[NSString alloc] initWithBytes:sbase + pos length:slen encoding:NSUTF8StringEncoding];
                    if (cand && [cand rangeOfString:needleStr options:NSCaseInsensitiveSearch].location != NSNotFound) {
                        [targetAddresses addObject:@(cstrSec.addr + pos)];
                    }
                }
                pos += slen + 1;
            }
        }
        for (NSNumber *cfAddr in ctx.cfStringsByAddr) {
            NSString *cfVal = ctx.cfStringsByAddr[cfAddr];
            if ([cfVal rangeOfString:needleStr options:NSCaseInsensitiveSearch].location != NSNotFound) {
                [targetAddresses addObject:cfAddr];
            }
        }
    }

    NSString *symQuery = [args[@"symbol"] isKindOfClass:[NSString class]] ? args[@"symbol"] : nil;
    if (symQuery.length) {
        targetDesc = [NSString stringWithFormat:@"symbol '%@'", symQuery];
        NSNumber *a = ctx.addrBySymbol[symQuery] ?: ctx.addrBySymbol[[@"_" stringByAppendingString:symQuery]];
        if (a) [targetAddresses addObject:a];
    }

    if (targetAddresses.count == 0) {
        if (error) *error = @"No matching target addresses found for xref scan (provide address, selector, string, or symbol)";
        return nil;
    }

    uint64_t limit64 = 200;
    MCPParseHexOrUint64(args[@"limit"], &limit64);
    if (limit64 < 1) limit64 = 1;
    if (limit64 > 2000) limit64 = 2000;

    MCPSectionEntry textSec;
    if (![ctx findSection:"__TEXT" sect:"__text" outEntry:&textSec] ||
        (uint64_t)textSec.offset + textSec.size > ctx.sliceSize) {
        if (error) *error = @"__TEXT,__text section not found in Mach-O";
        return nil;
    }

    const uint32_t *insns = (const uint32_t *)([ctx sliceBytes] + textSec.offset);
    size_t nInsns = textSec.size / 4;
    uint64_t regPage[32] = {0};
    uint64_t regPagePC[32] = {0};
    NSMutableArray<NSDictionary *> *xrefs = [NSMutableArray array];

    for (size_t i = 0; i < nInsns && xrefs.count < limit64; i++) {
        uint64_t pc = textSec.addr + i * 4;
        uint32_t insn = insns[i];

        // B / BL
        if ((insn & 0x7C000000U) == 0x14000000U) {
            BOOL isLink = (insn & 0x80000000U) != 0;
            int64_t off = MCPSignExtend64(insn & 0x03FFFFFFU, 26) * 4;
            uint64_t target = (uint64_t)((int64_t)pc + off);
            if ([targetAddresses containsObject:@(target)]) {
                uint64_t fnStart = 0;
                NSString *fnSym = [ctx symbolContainingAddress:pc outStart:&fnStart];
                [xrefs addObject:@{
                    @"instruction_address": [NSString stringWithFormat:@"0x%llx", (unsigned long long)pc],
                    @"target_address": [NSString stringWithFormat:@"0x%llx", (unsigned long long)target],
                    @"type": isLink ? @"BL" : @"B",
                    @"containing_symbol": fnSym,
                    @"function_start": [NSString stringWithFormat:@"0x%llx", (unsigned long long)fnStart]
                }];
            }
        }
        // ADRP / ADR
        else if ((insn & 0x1F000000U) == 0x10000000U) {
            BOOL isPage = (insn & 0x80000000U) != 0;
            unsigned rd = insn & 0x1F;
            int64_t immhi = (insn >> 5) & 0x7FFFFU;
            int64_t immlo = (insn >> 29) & 0x3U;
            int64_t imm = MCPSignExtend64((uint64_t)((immhi << 2) | immlo), 21);
            uint64_t target = isPage ? ((pc & ~0xFFFULL) + (uint64_t)(imm << 12)) : (uint64_t)((int64_t)pc + imm);
            if (isPage) {
                regPage[rd] = target;
                regPagePC[rd] = pc;
            } else if ([targetAddresses containsObject:@(target)]) {
                uint64_t fnStart = 0;
                NSString *fnSym = [ctx symbolContainingAddress:pc outStart:&fnStart];
                [xrefs addObject:@{
                    @"instruction_address": [NSString stringWithFormat:@"0x%llx", (unsigned long long)pc],
                    @"target_address": [NSString stringWithFormat:@"0x%llx", (unsigned long long)target],
                    @"type": @"ADR",
                    @"containing_symbol": fnSym,
                    @"function_start": [NSString stringWithFormat:@"0x%llx", (unsigned long long)fnStart]
                }];
            }
        }
        // ADD Xd, Xn, #imm12
        else if ((insn & 0xFF800000U) == 0x91000000U) {
            unsigned shift = ((insn >> 22) & 0x1) ? 12 : 0;
            uint64_t imm12 = (uint64_t)((insn >> 10) & 0xFFFU) << shift;
            unsigned rn = (insn >> 5) & 0x1F;
            unsigned rd = insn & 0x1F;
            if (regPage[rn] != 0 && (pc - regPagePC[rn]) <= 32) {
                uint64_t target = regPage[rn] + imm12;
                if ([targetAddresses containsObject:@(target)]) {
                    uint64_t fnStart = 0;
                    NSString *fnSym = [ctx symbolContainingAddress:pc outStart:&fnStart];
                    [xrefs addObject:@{
                        @"instruction_address": [NSString stringWithFormat:@"0x%llx", (unsigned long long)pc],
                        @"adrp_address": [NSString stringWithFormat:@"0x%llx", (unsigned long long)regPagePC[rn]],
                        @"target_address": [NSString stringWithFormat:@"0x%llx", (unsigned long long)target],
                        @"type": @"ADRP+ADD",
                        @"containing_symbol": fnSym,
                        @"function_start": [NSString stringWithFormat:@"0x%llx", (unsigned long long)fnStart]
                    }];
                }
            }
            if (rd == rn) regPage[rd] = 0;
        }
        // LDR Xt, [Xn, #imm12]
        else if ((insn & 0xFFC00000U) == 0xF9400000U) {
            uint64_t offset = (uint64_t)((insn >> 10) & 0xFFFU) * 8;
            unsigned rn = (insn >> 5) & 0x1F;
            unsigned rt = insn & 0x1F;
            if (regPage[rn] != 0 && (pc - regPagePC[rn]) <= 32) {
                uint64_t target = regPage[rn] + offset;
                if ([targetAddresses containsObject:@(target)]) {
                    uint64_t fnStart = 0;
                    NSString *fnSym = [ctx symbolContainingAddress:pc outStart:&fnStart];
                    [xrefs addObject:@{
                        @"instruction_address": [NSString stringWithFormat:@"0x%llx", (unsigned long long)pc],
                        @"adrp_address": [NSString stringWithFormat:@"0x%llx", (unsigned long long)regPagePC[rn]],
                        @"target_address": [NSString stringWithFormat:@"0x%llx", (unsigned long long)target],
                        @"type": @"ADRP+LDR",
                        @"containing_symbol": fnSym,
                        @"function_start": [NSString stringWithFormat:@"0x%llx", (unsigned long long)fnStart]
                    }];
                }
            }
            if (rt == rn) regPage[rt] = 0;
        }
    }

    NSMutableArray<NSString *> *resolvedTargets = [NSMutableArray array];
    for (NSNumber *n in targetAddresses) {
        [resolvedTargets addObject:[NSString stringWithFormat:@"0x%llx", n.unsignedLongLongValue]];
    }

    return @{
        @"binary_path": path,
        @"target_description": targetDesc ?: @"",
        @"target_addresses": resolvedTargets,
        @"xref_count": @(xrefs.count),
        @"xrefs": xrefs
    };
}

#pragma mark - [Upgrade 03] hardware_breakpoint_hook

- (NSDictionary *)hardwareBreakpointForArgs:(NSDictionary *)args error:(NSString **)error {
    if (error) *error = nil;
    NSString *bundleId = [args[@"bundle_id"] isKindOfClass:[NSString class]] ? args[@"bundle_id"] : nil;
    NSString *action = [args[@"action"] isKindOfClass:[NSString class]] ? args[@"action"] : @"set";

    // Prefer in-process engine hardware breakpoint handler when engine session exists and use_engine != false
    if (bundleId.length && (!args[@"use_engine"] || [args[@"use_engine"] boolValue])) {
        NSString *engErr = nil;
        NSDictionary *engRes = [[MCPEngineManager sharedInstance] sendOp:@"engine.hw_breakpoint"
                                                             forBundleId:bundleId
                                                                    args:args
                                                               timeoutMs:20000
                                                                   error:&engErr];
        if (engRes) return engRes;
    }

    uint64_t pidVal = 0;
    MCPParseHexOrUint64(args[@"pid"], &pidVal);
    pid_t pid = (pid_t)pidVal;
    if (pid <= 0 && bundleId.length) {
        pid = [[AppManager sharedInstance] pidForBundleId:bundleId];
    }
    if (pid <= 0) {
        if (error) *error = @"Provide a running 'bundle_id' or positive 'pid' for hardware_breakpoint_hook";
        return nil;
    }

    int slot = args[@"slot"] ? [args[@"slot"] intValue] : -1;
    uint64_t address = 0, redirectAddr = 0, durationMs = 0;
    MCPParseHexOrUint64(args[@"address"], &address);
    MCPParseHexOrUint64(args[@"redirect_address"] ?: args[@"redirect_pc"], &redirectAddr);
    MCPParseHexOrUint64(args[@"duration_ms"], &durationMs);

    NSString *outStr = nil, *runErr = nil;
    int exitCode = -1;
    BOOL ok = MCPRunRootProcess(@"/usr/libexec/ios-mcp/mcp-memory",
                                @[@"hw-breakpoint",
                                  [NSString stringWithFormat:@"%d", pid],
                                  action,
                                  [NSString stringWithFormat:@"%d", slot],
                                  [NSString stringWithFormat:@"0x%llx", (unsigned long long)address],
                                  [NSString stringWithFormat:@"0x%llx", (unsigned long long)redirectAddr],
                                  [NSString stringWithFormat:@"%llu", (unsigned long long)durationMs]],
                                25.0,
                                1024 * 1024,
                                &outStr,
                                &exitCode,
                                &runErr);
    if (ok && outStr.length) {
        NSDictionary *resp = [NSJSONSerialization JSONObjectWithData:[outStr dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
        if ([resp isKindOfClass:[NSDictionary class]]) {
            if ([resp[@"ok"] boolValue] && [resp[@"result"] isKindOfClass:[NSDictionary class]]) {
                return resp[@"result"];
            }
            if ([resp[@"error"] isKindOfClass:[NSString class]]) {
                if (error) *error = resp[@"error"];
                return nil;
            }
        }
    }

    return [[MemoryManager sharedInstance] hardwareBreakpointPID:pid
                                                          action:action
                                                            slot:slot
                                                         address:address
                                                 redirectAddress:redirectAddr
                                                      durationMs:(int)durationMs
                                                           error:error];
}

#pragma mark - [Upgrade 05] dump_swift_metadata

static uint64_t MCPResolveSwiftRelPtr(MCPMachOSliceContext *ctx, uint64_t fieldVMAddr, int32_t relOffset, BOOL indirectable) {
    if (relOffset == 0) return 0;
    if (indirectable && (relOffset & 1)) {
        uint64_t ptrVA = (uint64_t)((int64_t)fieldVMAddr + (int64_t)(relOffset & ~1));
        size_t off = 0;
        if ([ctx vmAddrToSliceOffset:ptrVA outOffset:&off] && off + 8 <= ctx.sliceSize) {
            return *(const uint64_t *)([ctx sliceBytes] + off);
        }
        return 0;
    }
    return (uint64_t)((int64_t)fieldVMAddr + (int64_t)relOffset);
}

- (NSDictionary *)dumpSwiftMetadataForArgs:(NSDictionary *)args error:(NSString **)error {
    if (error) *error = nil;
    NSString *bundleId = nil, *bundlePath = nil;
    NSString *path = [self resolveBinaryPathFromArgs:args outBundleId:&bundleId outBundlePath:&bundlePath error:error];
    if (!path.length) return nil;

    MCPMachOSliceContext *ctx = MCPLoadMachOSliceContext(path, error);
    if (!ctx) return nil;
    if (ctx.encrypted) {
        if (error) *error = @"Binary is FairPlay-encrypted on disk; run decrypt_app_ipa first before dump_swift_metadata";
        return nil;
    }

    NSString *filter = [args[@"filter"] isKindOfClass:[NSString class]] ? [args[@"filter"] lowercaseString] : nil;
    uint64_t limit64 = 500;
    MCPParseHexOrUint64(args[@"limit"], &limit64);
    if (limit64 < 1) limit64 = 1;
    if (limit64 > 5000) limit64 = 5000;

    const uint8_t *sbase = [ctx sliceBytes];
    NSMutableArray<NSDictionary *> *types = [NSMutableArray array];
    NSMutableArray<NSDictionary *> *protocols = [NSMutableArray array];
    NSMutableArray<NSDictionary *> *conformances = [NSMutableArray array];

    // 1. Parse __swift5_types
    MCPSectionEntry typesSec;
    if ([ctx findSection:NULL sect:"__swift5_types" outEntry:&typesSec] &&
        (uint64_t)typesSec.offset + typesSec.size <= ctx.sliceSize) {
        size_t count = typesSec.size / sizeof(int32_t);
        const int32_t *relPtrs = (const int32_t *)(sbase + typesSec.offset);

        for (size_t i = 0; i < count && types.count < limit64; i++) {
            uint64_t slotVA = typesSec.addr + i * 4;
            uint64_t descVA = MCPResolveSwiftRelPtr(ctx, slotVA, relPtrs[i], YES);
            size_t descOff = 0;
            if (!descVA || ![ctx vmAddrToSliceOffset:descVA outOffset:&descOff] || descOff + 20 > ctx.sliceSize) continue;

            uint32_t flags = *(const uint32_t *)(sbase + descOff);
            int32_t parentRel = *(const int32_t *)(sbase + descOff + 4);
            int32_t nameRel = *(const int32_t *)(sbase + descOff + 8);
            int32_t accessFnRel = *(const int32_t *)(sbase + descOff + 12);
            int32_t fieldsRel = *(const int32_t *)(sbase + descOff + 16);

            uint32_t kindCode = flags & 0x1FU;
            NSString *kindStr = @"type";
            if (kindCode == 16) kindStr = @"class";
            else if (kindCode == 17) kindStr = @"struct";
            else if (kindCode == 18) kindStr = @"enum";
            else continue;

            uint64_t nameVA = MCPResolveSwiftRelPtr(ctx, descVA + 8, nameRel, NO);
            NSString *typeName = [ctx readCStringAtVMAddr:nameVA maxLen:256];
            if (!typeName.length) continue;

            // Resolve parent module/context name if present
            NSString *moduleName = nil;
            uint64_t parentVA = MCPResolveSwiftRelPtr(ctx, descVA + 4, parentRel, YES);
            size_t parentOff = 0;
            if (parentVA && [ctx vmAddrToSliceOffset:parentVA outOffset:&parentOff] && parentOff + 12 <= ctx.sliceSize) {
                uint32_t pFlags = *(const uint32_t *)(sbase + parentOff);
                if ((pFlags & 0x1FU) == 0) { // Module descriptor
                    int32_t modNameRel = *(const int32_t *)(sbase + parentOff + 8);
                    uint64_t modNameVA = MCPResolveSwiftRelPtr(ctx, parentVA + 8, modNameRel, NO);
                    moduleName = [ctx readCStringAtVMAddr:modNameVA maxLen:128];
                }
            }

            NSString *fullName = moduleName.length ? [NSString stringWithFormat:@"%@.%@", moduleName, typeName] : typeName;
            if (filter.length && [fullName.lowercaseString rangeOfString:filter].location == NSNotFound) {
                continue;
            }

            uint64_t accessFnVA = MCPResolveSwiftRelPtr(ctx, descVA + 12, accessFnRel, NO);
            uint64_t fieldsVA = MCPResolveSwiftRelPtr(ctx, descVA + 16, fieldsRel, NO);

            NSMutableArray<NSDictionary *> *fields = [NSMutableArray array];
            size_t fDescOff = 0;
            if (fieldsVA && [ctx vmAddrToSliceOffset:fieldsVA outOffset:&fDescOff] && fDescOff + 16 <= ctx.sliceSize) {
                uint16_t fieldRecordSize = *(const uint16_t *)(sbase + fDescOff + 10);
                uint32_t numFields = *(const uint32_t *)(sbase + fDescOff + 12);
                if (fieldRecordSize >= 12 && numFields <= 512) {
                    size_t recOff = fDescOff + 16;
                    uint64_t recVA = fieldsVA + 16;
                    for (uint32_t f = 0; f < numFields && recOff + fieldRecordSize <= ctx.sliceSize; f++) {
                        uint32_t fFlags = *(const uint32_t *)(sbase + recOff);
                        int32_t mangledTypeRel = *(const int32_t *)(sbase + recOff + 4);
                        int32_t fieldNameRel = *(const int32_t *)(sbase + recOff + 8);

                        uint64_t fNameVA = MCPResolveSwiftRelPtr(ctx, recVA + 8, fieldNameRel, NO);
                        NSString *fName = [ctx readCStringAtVMAddr:fNameVA maxLen:256] ?: @"";

                        uint64_t fTypeVA = MCPResolveSwiftRelPtr(ctx, recVA + 4, mangledTypeRel, NO);
                        NSString *rawType = [ctx readCStringAtVMAddr:fTypeVA maxLen:256] ?: @"";
                        NSString *demangledType = MCPDemangleSwiftName(rawType);

                        if (fName.length) {
                            [fields addObject:@{
                                @"name": fName,
                                @"type": demangledType.length ? demangledType : @"<symbolic_typeref>",
                                @"mangled_type": rawType,
                                @"is_var": @((fFlags & 0x2U) != 0),
                                @"is_indirect_case": @((fFlags & 0x1U) != 0)
                            }];
                        }
                        recOff += fieldRecordSize;
                        recVA += fieldRecordSize;
                    }
                }
            }

            [types addObject:@{
                @"name": typeName,
                @"full_name": fullName,
                @"module": moduleName ?: @"",
                @"kind": kindStr,
                @"descriptor_address": [NSString stringWithFormat:@"0x%llx", (unsigned long long)descVA],
                @"metadata_accessor": accessFnVA ? [NSString stringWithFormat:@"0x%llx", (unsigned long long)accessFnVA] : [NSNull null],
                @"field_count": @(fields.count),
                @"fields": fields
            }];
        }
    }

    // 2. Parse __swift5_protos (Protocol Descriptors)
    MCPSectionEntry protosSec;
    if ([ctx findSection:NULL sect:"__swift5_protos" outEntry:&protosSec] &&
        (uint64_t)protosSec.offset + protosSec.size <= ctx.sliceSize) {
        size_t count = protosSec.size / sizeof(int32_t);
        const int32_t *relPtrs = (const int32_t *)(sbase + protosSec.offset);
        for (size_t i = 0; i < count && protocols.count < limit64; i++) {
            uint64_t slotVA = protosSec.addr + i * 4;
            uint64_t protoVA = MCPResolveSwiftRelPtr(ctx, slotVA, relPtrs[i], NO);
            size_t pOff = 0;
            if (!protoVA || ![ctx vmAddrToSliceOffset:protoVA outOffset:&pOff] || pOff + 24 > ctx.sliceSize) continue;
            int32_t nameRel = *(const int32_t *)(sbase + pOff + 8);
            uint32_t numRequirements = *(const uint32_t *)(sbase + pOff + 16);
            uint64_t nameVA = MCPResolveSwiftRelPtr(ctx, protoVA + 8, nameRel, NO);
            NSString *pName = [ctx readCStringAtVMAddr:nameVA maxLen:256];
            if (pName.length) {
                [protocols addObject:@{
                    @"name": pName,
                    @"descriptor_address": [NSString stringWithFormat:@"0x%llx", (unsigned long long)protoVA],
                    @"num_requirements": @(numRequirements)
                }];
            }
        }
    }

    // 3. Parse __swift5_proto (Protocol Conformances)
    MCPSectionEntry confSec;
    if ([ctx findSection:NULL sect:"__swift5_proto" outEntry:&confSec] &&
        (uint64_t)confSec.offset + confSec.size <= ctx.sliceSize) {
        size_t count = confSec.size / sizeof(int32_t);
        const int32_t *relPtrs = (const int32_t *)(sbase + confSec.offset);
        for (size_t i = 0; i < count && conformances.count < limit64; i++) {
            uint64_t slotVA = confSec.addr + i * 4;
            uint64_t confVA = MCPResolveSwiftRelPtr(ctx, slotVA, relPtrs[i], NO);
            size_t cOff = 0;
            if (!confVA || ![ctx vmAddrToSliceOffset:confVA outOffset:&cOff] || cOff + 16 > ctx.sliceSize) continue;

            int32_t protoRel = *(const int32_t *)(sbase + cOff);
            int32_t typeRefRel = *(const int32_t *)(sbase + cOff + 4);
            int32_t witnessRel = *(const int32_t *)(sbase + cOff + 8);

            uint64_t protoDescVA = MCPResolveSwiftRelPtr(ctx, confVA, protoRel, YES);
            uint64_t typeDescVA = MCPResolveSwiftRelPtr(ctx, confVA + 4, typeRefRel, YES);
            uint64_t witnessVA = MCPResolveSwiftRelPtr(ctx, confVA + 8, witnessRel, NO);

            NSString *protoName = nil;
            size_t pdOff = 0;
            if (protoDescVA && [ctx vmAddrToSliceOffset:protoDescVA outOffset:&pdOff] && pdOff + 12 <= ctx.sliceSize) {
                int32_t nRel = *(const int32_t *)(sbase + pdOff + 8);
                protoName = [ctx readCStringAtVMAddr:MCPResolveSwiftRelPtr(ctx, protoDescVA + 8, nRel, NO) maxLen:256];
            }

            NSString *typeName = nil;
            size_t tdOff = 0;
            if (typeDescVA && [ctx vmAddrToSliceOffset:typeDescVA outOffset:&tdOff] && tdOff + 12 <= ctx.sliceSize) {
                int32_t nRel = *(const int32_t *)(sbase + tdOff + 8);
                typeName = [ctx readCStringAtVMAddr:MCPResolveSwiftRelPtr(ctx, typeDescVA + 8, nRel, NO) maxLen:256];
            }

            [conformances addObject:@{
                @"conformance_address": [NSString stringWithFormat:@"0x%llx", (unsigned long long)confVA],
                @"protocol": protoName ?: [NSString stringWithFormat:@"0x%llx", (unsigned long long)protoDescVA],
                @"type": typeName ?: [NSString stringWithFormat:@"0x%llx", (unsigned long long)typeDescVA],
                @"witness_table": witnessVA ? [NSString stringWithFormat:@"0x%llx", (unsigned long long)witnessVA] : [NSNull null]
            }];
        }
    }

    return @{
        @"binary_path": path,
        @"type_count": @(types.count),
        @"protocol_count": @(protocols.count),
        @"conformance_count": @(conformances.count),
        @"types": types,
        @"protocols": protocols,
        @"conformances": conformances
    };
}

#pragma mark - [Upgrade 08] extract_dyld_shared_cache

- (NSDictionary *)extractDyldSharedCacheForArgs:(NSDictionary *)args error:(NSString **)error {
    if (error) *error = nil;
    NSString *imageName = [args[@"image_name"] ?: (args[@"framework"] ?: args[@"dylib"]) isKindOfClass:[NSString class]]
        ? (args[@"image_name"] ?: (args[@"framework"] ?: args[@"dylib"]))
        : nil;
    if (!imageName.length) {
        if (error) *error = @"Missing required parameter: 'image_name' (e.g. 'UIKitCore', 'Security', 'libobjc.A.dylib')";
        return nil;
    }

    NSString *outputPath = [args[@"output_path"] isKindOfClass:[NSString class]] ? args[@"output_path"] : nil;
    uint64_t pidVal = 0;
    MCPParseHexOrUint64(args[@"pid"], &pidVal);
    pid_t pid = (pid_t)pidVal;
    if (pid <= 0 && [args[@"bundle_id"] isKindOfClass:[NSString class]]) {
        pid = [[AppManager sharedInstance] pidForBundleId:args[@"bundle_id"]];
    }

    NSString *outStr = nil, *runErr = nil;
    int exitCode = -1;
    NSMutableArray<NSString *> *helperArgs = [NSMutableArray arrayWithObjects:
                                              @"extract-dsc",
                                              [NSString stringWithFormat:@"%d", pid > 0 ? pid : 0],
                                              imageName, nil];
    if (outputPath.length) [helperArgs addObject:outputPath];

    BOOL ok = MCPRunRootProcess(@"/usr/libexec/ios-mcp/mcp-memory",
                                helperArgs,
                                60.0,
                                4 * 1024 * 1024,
                                &outStr,
                                &exitCode,
                                &runErr);
    if (ok && outStr.length) {
        NSDictionary *resp = [NSJSONSerialization JSONObjectWithData:[outStr dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
        if ([resp isKindOfClass:[NSDictionary class]]) {
            if ([resp[@"ok"] boolValue] && [resp[@"result"] isKindOfClass:[NSDictionary class]]) {
                return resp[@"result"];
            }
            if ([resp[@"error"] isKindOfClass:[NSString class]]) {
                if (error) *error = resp[@"error"];
                return nil;
            }
        }
    }

    return [[MemoryManager sharedInstance] extractDyldSharedCacheImagePID:pid
                                                                imageName:imageName
                                                               outputPath:outputPath
                                                                    error:error];
}

#pragma mark - [Upgrade 10] inspect_hermes_flutter

static NSArray<NSString *> *MCPExtractPrintableStrings(const uint8_t *bytes, size_t len, NSUInteger maxStrings, NSArray<NSString *> **outURLs) {
    NSMutableArray<NSString *> *strings = [NSMutableArray array];
    NSMutableArray<NSString *> *urls = [NSMutableArray array];
    NSMutableSet<NSString *> *seenURLs = [NSMutableSet set];

    size_t i = 0;
    while (i < len && (strings.count < maxStrings || urls.count < 200)) {
        while (i < len && (bytes[i] < 0x20 || bytes[i] > 0x7E)) i++;
        size_t start = i;
        while (i < len && bytes[i] >= 0x20 && bytes[i] <= 0x7E) i++;
        size_t slen = i - start;
        if (slen >= 6 && slen <= 512) {
            NSString *s = [[NSString alloc] initWithBytes:bytes + start length:slen encoding:NSUTF8StringEncoding];
            if (!s.length) continue;
            if (([s hasPrefix:@"https://"] || [s hasPrefix:@"http://"] || [s hasPrefix:@"wss://"] || [s hasPrefix:@"package:"]) &&
                ![seenURLs containsObject:s] && urls.count < 200) {
                [seenURLs addObject:s];
                [urls addObject:s];
            }
            if (strings.count < maxStrings) {
                [strings addObject:s];
            }
        }
    }
    if (outURLs) *outURLs = urls;
    return strings;
}

- (NSDictionary *)inspectHermesFlutterForArgs:(NSDictionary *)args error:(NSString **)error {
    if (error) *error = nil;
    NSString *bundleId = nil, *bundlePath = nil;
    NSString *execPath = [self resolveBinaryPathFromArgs:args outBundleId:&bundleId outBundlePath:&bundlePath error:error];
    if (!execPath.length && !bundlePath.length) return nil;
    if (!bundlePath.length) {
        bundlePath = [execPath stringByDeletingLastPathComponent];
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    NSMutableDictionary *report = [NSMutableDictionary dictionary];
    report[@"bundle_path"] = bundlePath;
    if (bundleId.length) report[@"bundle_id"] = bundleId;

    // 1. Check React Native / Hermes
    NSString *hermesFw = [bundlePath stringByAppendingPathComponent:@"Frameworks/hermes.framework/hermes"];
    BOOL hasHermesFw = [fm fileExistsAtPath:hermesFw];
    NSMutableArray<NSString *> *jsBundles = [NSMutableArray array];

    NSDirectoryEnumerator *en = [fm enumeratorAtPath:bundlePath];
    for (NSString *rel in en) {
        NSString *lower = rel.lowercaseString;
        if ([lower hasSuffix:@".jsbundle"] || [lower hasSuffix:@".hbc"] || [lower hasSuffix:@"index.android.bundle"] || [lower hasSuffix:@"index.ios.bundle"]) {
            [jsBundles addObject:[bundlePath stringByAppendingPathComponent:rel]];
        }
    }

    if (hasHermesFw || jsBundles.count > 0) {
        NSMutableDictionary *rnInfo = [NSMutableDictionary dictionary];
        rnInfo[@"detected"] = @YES;
        rnInfo[@"hermes_framework_present"] = @(hasHermesFw);
        rnInfo[@"bundles"] = [NSMutableArray array];

        for (NSString *bPath in jsBundles) {
            NSData *bData = [NSData dataWithContentsOfFile:bPath options:NSDataReadingMappedIfSafe error:nil];
            if (bData.length < 64) continue;
            const uint8_t *b = (const uint8_t *)bData.bytes;
            uint64_t magic = *(const uint64_t *)b;
            const uint64_t kHermesMagic = 0x1F1903C103BC1FC6ULL;

            if (magic == kHermesMagic && bData.length >= 128) {
                uint32_t version = *(const uint32_t *)(b + 8);
                uint32_t fileLength = *(const uint32_t *)(b + 32);
                uint32_t globalCodeIndex = *(const uint32_t *)(b + 36);
                uint32_t functionCount = *(const uint32_t *)(b + 40);
                uint32_t stringKindCount = *(const uint32_t *)(b + 44);
                uint32_t identifierCount = *(const uint32_t *)(b + 48);
                uint32_t stringCount = *(const uint32_t *)(b + 52);
                uint32_t overflowStringCount = *(const uint32_t *)(b + 56);
                uint32_t stringStorageSize = *(const uint32_t *)(b + 60);

                NSMutableString *sha1Hex = [NSMutableString stringWithCapacity:40];
                for (int s = 0; s < 20; s++) [sha1Hex appendFormat:@"%02x", b[12 + s]];

                // Parse SmallFunctionHeaders (16 bytes each starting at offset 128, 32-byte aligned)
                NSMutableArray<NSDictionary *> *sampleFunctions = [NSMutableArray array];
                size_t fnTableOff = 128;
                uint32_t sampleFnLimit = MIN(functionCount, 64U);
                for (uint32_t f = 0; f < sampleFnLimit && fnTableOff + 16 <= bData.length; f++, fnTableOff += 16) {
                    uint32_t w0 = *(const uint32_t *)(b + fnTableOff);
                    uint32_t w1 = *(const uint32_t *)(b + fnTableOff + 4);
                    uint32_t w2 = *(const uint32_t *)(b + fnTableOff + 8);
                    uint32_t bcOffset = w0 & 0x01FFFFFFU;
                    uint32_t paramCount = (w0 >> 25) & 0x7FU;
                    uint32_t bcSize = w1 & 0x7FFFU;
                    uint32_t fnNameIdx = (w1 >> 15) & 0x1FFFFU;
                    uint32_t frameSize = w2 & 0xFFU;
                    [sampleFunctions addObject:@{
                        @"index": @(f),
                        @"bytecode_offset": @(bcOffset),
                        @"bytecode_size": @(bcSize),
                        @"param_count": @(paramCount),
                        @"frame_size": @(frameSize),
                        @"name_string_id": @(fnNameIdx)
                    }];
                }

                NSArray<NSString *> *urls = nil;
                NSArray<NSString *> *strings = MCPExtractPrintableStrings(b, bData.length, 200, &urls);

                [rnInfo[@"bundles"] addObject:@{
                    @"path": bPath,
                    @"format": @"hermes_bytecode_hbc",
                    @"hbc_magic": @"0x1f1903c103bc1fc6",
                    @"hbc_version": @(version),
                    @"sha1": sha1Hex,
                    @"file_length": @(fileLength),
                    @"global_code_index": @(globalCodeIndex),
                    @"function_count": @(functionCount),
                    @"string_kind_count": @(stringKindCount),
                    @"identifier_count": @(identifierCount),
                    @"string_count": @(stringCount),
                    @"overflow_string_count": @(overflowStringCount),
                    @"string_storage_size": @(stringStorageSize),
                    @"sample_functions": sampleFunctions,
                    @"extracted_urls": urls ?: @[],
                    @"sample_strings": strings ?: @[]
                }];
            } else {
                NSArray<NSString *> *urls = nil;
                NSArray<NSString *> *strings = MCPExtractPrintableStrings(b, bData.length, 150, &urls);
                [rnInfo[@"bundles"] addObject:@{
                    @"path": bPath,
                    @"format": @"javascript_source_bundle",
                    @"size_bytes": @(bData.length),
                    @"extracted_urls": urls ?: @[],
                    @"sample_strings": strings ?: @[]
                }];
            }
        }
        report[@"react_native_hermes"] = rnInfo;
    } else {
        report[@"react_native_hermes"] = @{@"detected": @NO};
    }

    // 2. Check Flutter / Dart AOT Snapshot (App.framework + Flutter.framework)
    NSString *flutterFw = [bundlePath stringByAppendingPathComponent:@"Frameworks/Flutter.framework/Flutter"];
    NSString *appFw = [bundlePath stringByAppendingPathComponent:@"Frameworks/App.framework/App"];
    if ([fm fileExistsAtPath:appFw] || [fm fileExistsAtPath:flutterFw]) {
        NSMutableDictionary *flutterInfo = [NSMutableDictionary dictionary];
        flutterInfo[@"detected"] = @YES;
        flutterInfo[@"flutter_framework_path"] = [fm fileExistsAtPath:flutterFw] ? flutterFw : [NSNull null];
        flutterInfo[@"app_framework_path"] = [fm fileExistsAtPath:appFw] ? appFw : [NSNull null];

        if ([fm fileExistsAtPath:appFw]) {
            MCPMachOSliceContext *appCtx = MCPLoadMachOSliceContext(appFw, nil);
            if (appCtx) {
                flutterInfo[@"encrypted"] = @(appCtx.encrypted);
                NSMutableDictionary *dartSymbols = [NSMutableDictionary dictionary];
                NSArray<NSString *> *kDartSyms = @[
                    @"_kDartVmSnapshotData",
                    @"_kDartVmSnapshotInstructions",
                    @"_kDartIsolateSnapshotData",
                    @"_kDartIsolateSnapshotInstructions"
                ];
                for (NSString *sym in kDartSyms) {
                    NSNumber *addr = appCtx.addrBySymbol[sym];
                    if (addr) {
                        dartSymbols[sym] = [NSString stringWithFormat:@"0x%llx", addr.unsignedLongLongValue];
                    }
                }
                flutterInfo[@"dart_aot_symbols"] = dartSymbols;

                if (!appCtx.encrypted) {
                    NSNumber *vmDataAddr = appCtx.addrBySymbol[@"_kDartVmSnapshotData"];
                    size_t vmOff = 0;
                    if (vmDataAddr && [appCtx vmAddrToSliceOffset:vmDataAddr.unsignedLongLongValue outOffset:&vmOff] &&
                        vmOff + 64 <= appCtx.sliceSize) {
                        const uint8_t *vmBytes = [appCtx sliceBytes] + vmOff;
                        uint32_t snapMagic = *(const uint32_t *)vmBytes;
                        uint64_t snapSize = *(const uint64_t *)(vmBytes + 4);
                        uint64_t snapKind = *(const uint64_t *)(vmBytes + 12);
                        flutterInfo[@"dart_snapshot_magic"] = [NSString stringWithFormat:@"0x%08x", snapMagic];
                        flutterInfo[@"dart_vm_snapshot_size"] = @(snapSize);
                        flutterInfo[@"dart_snapshot_kind"] = @(snapKind);

                        // Feature / SDK hash string starts at offset 20 or 52 inside _kDartVmSnapshotData
                        NSString *features = [appCtx readCStringAtVMAddr:vmDataAddr.unsignedLongLongValue + 52 maxLen:256];
                        if (!features.length) features = [appCtx readCStringAtVMAddr:vmDataAddr.unsignedLongLongValue + 20 maxLen:256];
                        if (features.length) flutterInfo[@"dart_snapshot_features"] = features;
                    }

                    NSArray<NSString *> *urls = nil;
                    NSArray<NSString *> *poolStrings = MCPExtractPrintableStrings([appCtx sliceBytes], appCtx.sliceSize, 250, &urls);
                    flutterInfo[@"package_and_endpoint_uris"] = urls ?: @[];
                    flutterInfo[@"object_pool_strings"] = poolStrings ?: @[];
                    flutterInfo[@"aot_function_starts_count"] = @(appCtx.sortedFunctionStarts.count);
                }
            }
        }
        report[@"flutter_dart_aot"] = flutterInfo;
    } else {
        report[@"flutter_dart_aot"] = @{@"detected": @NO};
    }

    return report;
}

@end
