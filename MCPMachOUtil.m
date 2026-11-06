#import "MCPMachOUtil.h"
#import <ctype.h>
#import <errno.h>
#import <fcntl.h>
#import <libkern/OSByteOrder.h>
#import <mach-o/fat.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <stdlib.h>
#import <string.h>
#import <sys/stat.h>
#import <unistd.h>

#ifndef LC_DYLD_EXPORTS_TRIE
#define LC_DYLD_EXPORTS_TRIE (0x33 | LC_REQ_DYLD)
#endif
#ifndef LC_DYLD_CHAINED_FIXUPS
#define LC_DYLD_CHAINED_FIXUPS (0x34 | LC_REQ_DYLD)
#endif
#ifndef CPU_SUBTYPE_ARM64E
#define CPU_SUBTYPE_ARM64E 2
#endif

#define MCP_CSMAGIC_EMBEDDED_SIGNATURE    0xfade0cc0U
#define MCP_CSMAGIC_EMBEDDED_ENTITLEMENTS 0xfade7171U
#define MCP_CSSLOT_ENTITLEMENTS           5U

typedef struct {
    uint64_t offset;
    uint64_t size;
    cpu_type_t cputype;
    cpu_subtype_t cpusubtype;
} MCPMachOSliceRange;

typedef struct {
    uint64_t vmOffset;
    __unsafe_unretained NSString *name;
    __unsafe_unretained NSString *source;
} MCPSymbolEntry;

static NSString *MCPArchName(cpu_type_t cputype, cpu_subtype_t cpusubtype) {
    uint32_t sub = (uint32_t)cpusubtype & ~CPU_SUBTYPE_MASK;
    if (cputype == CPU_TYPE_ARM64) {
        if (sub == CPU_SUBTYPE_ARM64E) return @"arm64e";
        return @"arm64";
    }
    if (cputype == CPU_TYPE_ARM) return @"armv7";
    if (cputype == CPU_TYPE_X86_64) return @"x86_64";
    return [NSString stringWithFormat:@"cpu_%d_%u", (int)cputype, sub];
}

static BOOL MCPCollectMachOSlices(const uint8_t *bytes,
                                  size_t totalLength,
                                  MCPMachOSliceRange *outSlices,
                                  size_t maxSlices,
                                  size_t *outCount,
                                  BOOL *outIsFat,
                                  NSString **error) {
    if (outCount) *outCount = 0;
    if (outIsFat) *outIsFat = NO;
    if (!bytes || totalLength < sizeof(struct mach_header_64)) {
        if (error) *error = @"File is too small to be a 64-bit Mach-O binary";
        return NO;
    }

    uint32_t magic = *(const uint32_t *)bytes;
    if (magic == MH_MAGIC_64) {
        const struct mach_header_64 *hdr = (const struct mach_header_64 *)bytes;
        if (sizeof(struct mach_header_64) + (size_t)hdr->sizeofcmds > totalLength) {
            if (error) *error = @"Corrupt Mach-O header: load commands exceed file size";
            return NO;
        }
        outSlices[0] = (MCPMachOSliceRange){
            .offset = 0,
            .size = totalLength,
            .cputype = hdr->cputype,
            .cpusubtype = hdr->cpusubtype
        };
        if (outCount) *outCount = 1;
        return YES;
    }

    uint32_t beMagic = OSSwapBigToHostInt32(magic);
    if (beMagic == FAT_MAGIC || beMagic == FAT_MAGIC_64) {
        if (outIsFat) *outIsFat = YES;
        const struct fat_header *fh = (const struct fat_header *)bytes;
        uint32_t nfat = OSSwapBigToHostInt32(fh->nfat_arch);
        if (nfat == 0 || nfat > 16) {
            if (error) *error = [NSString stringWithFormat:@"Invalid fat_header nfat_arch=%u", nfat];
            return NO;
        }
        size_t count = 0;
        for (uint32_t i = 0; i < nfat; i++) {
            uint64_t off = 0, sz = 0;
            cpu_type_t cpu = 0;
            cpu_subtype_t sub = 0;
            if (beMagic == FAT_MAGIC) {
                size_t archPos = sizeof(struct fat_header) + (size_t)i * sizeof(struct fat_arch);
                if (archPos + sizeof(struct fat_arch) > totalLength) {
                    if (error) *error = @"Truncated fat_arch table";
                    return NO;
                }
                const struct fat_arch *fa = (const struct fat_arch *)(bytes + archPos);
                off = OSSwapBigToHostInt32(fa->offset);
                sz = OSSwapBigToHostInt32(fa->size);
                cpu = (cpu_type_t)OSSwapBigToHostInt32((uint32_t)fa->cputype);
                sub = (cpu_subtype_t)OSSwapBigToHostInt32((uint32_t)fa->cpusubtype);
            } else {
                size_t archPos = sizeof(struct fat_header) + (size_t)i * sizeof(struct fat_arch_64);
                if (archPos + sizeof(struct fat_arch_64) > totalLength) {
                    if (error) *error = @"Truncated fat_arch_64 table";
                    return NO;
                }
                const struct fat_arch_64 *fa64 = (const struct fat_arch_64 *)(bytes + archPos);
                off = OSSwapBigToHostInt64(fa64->offset);
                sz = OSSwapBigToHostInt64(fa64->size);
                cpu = (cpu_type_t)OSSwapBigToHostInt32((uint32_t)fa64->cputype);
                sub = (cpu_subtype_t)OSSwapBigToHostInt32((uint32_t)fa64->cpusubtype);
            }
            if (off > totalLength || sz < sizeof(struct mach_header_64) || off + sz > totalLength) {
                if (error) *error = @"Fat slice exceeds file bounds";
                return NO;
            }
            const struct mach_header_64 *shdr = (const struct mach_header_64 *)(bytes + off);
            if (shdr->magic != MH_MAGIC_64) {
                // Skip non-64-bit legacy slices if ever encountered
                continue;
            }
            if (sizeof(struct mach_header_64) + (size_t)shdr->sizeofcmds > sz) {
                if (error) *error = @"Fat slice load commands exceed slice bounds";
                return NO;
            }
            if (count < maxSlices) {
                outSlices[count++] = (MCPMachOSliceRange){
                    .offset = off,
                    .size = sz,
                    .cputype = cpu ?: shdr->cputype,
                    .cpusubtype = sub ?: shdr->cpusubtype
                };
            }
        }
        if (count == 0) {
            if (error) *error = @"No 64-bit Mach-O slices found in universal binary";
            return NO;
        }
        if (outCount) *outCount = count;
        return YES;
    }

    if (error) *error = [NSString stringWithFormat:@"Unsupported Mach-O magic 0x%08x", magic];
    return NO;
}

static BOOL MCPWriteFreshVnodeFile(NSString *targetPath,
                                   const void *bytes,
                                   size_t length,
                                   mode_t mode,
                                   NSString **error) {
    if (!targetPath.length || !bytes || length == 0) {
        if (error) *error = @"Invalid fresh-vnode write parameters";
        return NO;
    }
    NSString *dir = [targetPath stringByDeletingLastPathComponent];
    NSString *base = targetPath.lastPathComponent ?: @"bin";
    NSString *tmpPath = [dir stringByAppendingPathComponent:
                         [NSString stringWithFormat:@".%@.mcp_tmp_%@", base, [NSUUID UUID].UUIDString]];
    const char *tmpFS = tmpPath.fileSystemRepresentation;
    const char *dstFS = targetPath.fileSystemRepresentation;
    if (!tmpFS || !dstFS) {
        if (error) *error = @"Invalid filesystem representation";
        return NO;
    }

    int fd = open(tmpFS, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0) {
        if (error) *error = [NSString stringWithFormat:@"Failed to create temp file %@: %s", tmpPath, strerror(errno)];
        return NO;
    }

    const uint8_t *cursor = (const uint8_t *)bytes;
    size_t remaining = length;
    while (remaining > 0) {
        ssize_t written = write(fd, cursor, remaining);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) {
            int saved = errno;
            close(fd);
            unlink(tmpFS);
            if (error) *error = [NSString stringWithFormat:@"Failed writing temp file: %s", strerror(saved)];
            return NO;
        }
        cursor += written;
        remaining -= (size_t)written;
    }
    fsync(fd);
    fchmod(fd, mode);
    close(fd);

    // Unlink destination first so rename attaches a brand-new vnode without stale cs_blob cache.
    unlink(dstFS);
    if (rename(tmpFS, dstFS) != 0) {
        int saved = errno;
        unlink(tmpFS);
        if (error) *error = [NSString stringWithFormat:@"Failed replacing %@: %s", targetPath, strerror(saved)];
        return NO;
    }
    chmod(dstFS, mode);
    return YES;
}

static NSString *MCPExtractEntitlementsXMLFromSlice(const uint8_t *sliceBytes, size_t sliceSize) {
    const struct mach_header_64 *hdr = (const struct mach_header_64 *)sliceBytes;
    const uint8_t *cmdPtr = sliceBytes + sizeof(struct mach_header_64);
    const uint8_t *cmdEnd = cmdPtr + hdr->sizeofcmds;
    if ((size_t)(cmdEnd - sliceBytes) > sliceSize) return nil;

    uint32_t csOff = 0, csSize = 0;
    for (uint32_t i = 0; i < hdr->ncmds && cmdPtr + sizeof(struct load_command) <= cmdEnd; i++) {
        const struct load_command *lc = (const struct load_command *)cmdPtr;
        if (lc->cmdsize < sizeof(struct load_command) || cmdPtr + lc->cmdsize > cmdEnd) break;
        if (lc->cmd == LC_CODE_SIGNATURE && lc->cmdsize >= sizeof(struct linkedit_data_command)) {
            const struct linkedit_data_command *cs = (const struct linkedit_data_command *)cmdPtr;
            csOff = cs->dataoff;
            csSize = cs->datasize;
            break;
        }
        cmdPtr += lc->cmdsize;
    }
    if (!csOff || csSize < 12 || (uint64_t)csOff + (uint64_t)csSize > sliceSize) return nil;

    const uint8_t *csBase = sliceBytes + csOff;
    uint32_t sbMagic = OSSwapBigToHostInt32(*(const uint32_t *)(csBase + 0));
    uint32_t sbLength = OSSwapBigToHostInt32(*(const uint32_t *)(csBase + 4));
    uint32_t sbCount = OSSwapBigToHostInt32(*(const uint32_t *)(csBase + 8));
    if (sbMagic != MCP_CSMAGIC_EMBEDDED_SIGNATURE) return nil;
    if (sbLength > csSize) sbLength = csSize;
    if (12ULL + (uint64_t)sbCount * 8ULL > sbLength) return nil;

    for (uint32_t i = 0; i < sbCount; i++) {
        const uint8_t *idxPtr = csBase + 12 + (size_t)i * 8;
        uint32_t slotType = OSSwapBigToHostInt32(*(const uint32_t *)(idxPtr + 0));
        uint32_t blobOffset = OSSwapBigToHostInt32(*(const uint32_t *)(idxPtr + 4));
        if (blobOffset + 8 > sbLength) continue;
        const uint8_t *blob = csBase + blobOffset;
        uint32_t blobMagic = OSSwapBigToHostInt32(*(const uint32_t *)(blob + 0));
        uint32_t blobLen = OSSwapBigToHostInt32(*(const uint32_t *)(blob + 4));
        if (blobLen < 8 || (uint64_t)blobOffset + (uint64_t)blobLen > sbLength) continue;
        if (slotType == MCP_CSSLOT_ENTITLEMENTS || blobMagic == MCP_CSMAGIC_EMBEDDED_ENTITLEMENTS) {
            if (blobMagic == MCP_CSMAGIC_EMBEDDED_ENTITLEMENTS) {
                NSData *xmlData = [NSData dataWithBytes:blob + 8 length:blobLen - 8];
                NSString *xml = [[NSString alloc] initWithData:xmlData encoding:NSUTF8StringEncoding];
                if (xml.length > 0) return xml;
            }
        }
    }
    return nil;
}

static uint64_t MCPComputeFirstContentOffsetInSlice(const uint8_t *sliceBytes, size_t sliceSize) {
    const struct mach_header_64 *hdr = (const struct mach_header_64 *)sliceBytes;
    uint64_t headerEnd = sizeof(struct mach_header_64) + hdr->sizeofcmds;
    uint64_t minOff = sliceSize;

    const uint8_t *cmdPtr = sliceBytes + sizeof(struct mach_header_64);
    const uint8_t *cmdEnd = cmdPtr + hdr->sizeofcmds;
    for (uint32_t i = 0; i < hdr->ncmds && cmdPtr + sizeof(struct load_command) <= cmdEnd; i++) {
        const struct load_command *lc = (const struct load_command *)cmdPtr;
        if (lc->cmdsize < sizeof(struct load_command) || cmdPtr + lc->cmdsize > cmdEnd) break;

        if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cmdPtr;
            if (seg->fileoff > headerEnd && seg->filesize > 0 && seg->fileoff < minOff) {
                minOff = seg->fileoff;
            }
            size_t maxSects = (lc->cmdsize - sizeof(struct segment_command_64)) / sizeof(struct section_64);
            uint32_t nsects = seg->nsects < maxSects ? seg->nsects : (uint32_t)maxSects;
            const struct section_64 *sects = (const struct section_64 *)(cmdPtr + sizeof(struct segment_command_64));
            for (uint32_t s = 0; s < nsects; s++) {
                uint32_t flagsType = sects[s].flags & SECTION_TYPE;
                if (sects[s].size == 0 || sects[s].offset == 0) continue;
                if (flagsType == S_ZEROFILL || flagsType == S_GB_ZEROFILL || flagsType == S_THREAD_LOCAL_ZEROFILL) continue;
                if (sects[s].offset >= headerEnd && sects[s].offset < minOff) {
                    minOff = sects[s].offset;
                }
            }
        } else if ((lc->cmd == LC_CODE_SIGNATURE ||
                    lc->cmd == LC_FUNCTION_STARTS ||
                    lc->cmd == LC_DATA_IN_CODE ||
                    lc->cmd == LC_DYLD_EXPORTS_TRIE ||
                    lc->cmd == LC_DYLD_CHAINED_FIXUPS ||
                    lc->cmd == LC_SEGMENT_SPLIT_INFO) &&
                   lc->cmdsize >= sizeof(struct linkedit_data_command)) {
            const struct linkedit_data_command *ld = (const struct linkedit_data_command *)cmdPtr;
            if (ld->dataoff >= headerEnd && ld->datasize > 0 && ld->dataoff < minOff) {
                minOff = ld->dataoff;
            }
        } else if (lc->cmd == LC_SYMTAB && lc->cmdsize >= sizeof(struct symtab_command)) {
            const struct symtab_command *st = (const struct symtab_command *)cmdPtr;
            if (st->symoff >= headerEnd && st->nsyms > 0 && st->symoff < minOff) minOff = st->symoff;
            if (st->stroff >= headerEnd && st->strsize > 0 && st->stroff < minOff) minOff = st->stroff;
        }
        cmdPtr += lc->cmdsize;
    }
    return minOff;
}

NSDictionary *MCPExtractEntitlementsFromMachO(NSString *path, NSString **error) {
    if (error) *error = nil;
    NSError *readErr = nil;
    NSData *data = [NSData dataWithContentsOfFile:path options:NSDataReadingMappedIfSafe error:&readErr];
    if (!data) {
        if (error) *error = readErr.localizedDescription ?: @"Cannot read binary";
        return nil;
    }

    MCPMachOSliceRange slices[16];
    size_t sliceCount = 0;
    BOOL isFat = NO;
    if (!MCPCollectMachOSlices(data.bytes, data.length, slices, 16, &sliceCount, &isFat, error)) {
        return nil;
    }

    // Prefer arm64e slice entitlements if present, otherwise first slice with entitlements.
    NSString *chosenXML = nil;
    NSString *chosenArch = nil;
    for (size_t i = 0; i < sliceCount; i++) {
        NSString *arch = MCPArchName(slices[i].cputype, slices[i].cpusubtype);
        NSString *xml = MCPExtractEntitlementsXMLFromSlice((const uint8_t *)data.bytes + slices[i].offset,
                                                           (size_t)slices[i].size);
        if (xml.length > 0) {
            if (!chosenXML || [arch isEqualToString:@"arm64e"]) {
                chosenXML = xml;
                chosenArch = arch;
            }
        }
    }

    if (!chosenXML.length) {
        return @{
            @"entitlements": @{},
            @"xml": @"",
            @"has_entitlements": @NO
        };
    }

    NSData *xmlData = [chosenXML dataUsingEncoding:NSUTF8StringEncoding];
    NSPropertyListFormat fmt = NSPropertyListXMLFormat_v1_0;
    NSError *plistErr = nil;
    id plist = xmlData ? [NSPropertyListSerialization propertyListWithData:xmlData
                                                                   options:NSPropertyListImmutable
                                                                    format:&fmt
                                                                     error:&plistErr] : nil;
    NSDictionary *dict = [plist isKindOfClass:[NSDictionary class]] ? plist : @{};
    return @{
        @"entitlements": dict,
        @"xml": chosenXML,
        @"slice_arch": chosenArch ?: @"arm64",
        @"has_entitlements": @YES
    };
}

NSDictionary *MCPInspectMachOAtPath(NSString *path, NSString **error) {
    if (error) *error = nil;
    NSError *readErr = nil;
    NSData *data = [NSData dataWithContentsOfFile:path options:NSDataReadingMappedIfSafe error:&readErr];
    if (!data) {
        if (error) *error = readErr.localizedDescription ?: @"Cannot read Mach-O file";
        return nil;
    }

    MCPMachOSliceRange slices[16];
    size_t sliceCount = 0;
    BOOL isFat = NO;
    if (!MCPCollectMachOSlices(data.bytes, data.length, slices, 16, &sliceCount, &isFat, error)) {
        return nil;
    }

    NSMutableArray<NSDictionary *> *sliceReports = [NSMutableArray arrayWithCapacity:sliceCount];
    NSMutableArray<NSString *> *archNames = [NSMutableArray arrayWithCapacity:sliceCount];

    for (size_t s = 0; s < sliceCount; s++) {
        const uint8_t *sb = (const uint8_t *)data.bytes + slices[s].offset;
        size_t sSize = (size_t)slices[s].size;
        const struct mach_header_64 *hdr = (const struct mach_header_64 *)sb;
        NSString *arch = MCPArchName(slices[s].cputype, slices[s].cpusubtype);
        [archNames addObject:arch];

        uint64_t headerEnd = sizeof(struct mach_header_64) + hdr->sizeofcmds;
        uint64_t firstContent = MCPComputeFirstContentOffsetInSlice(sb, sSize);
        uint64_t padAvail = firstContent > headerEnd ? (firstContent - headerEnd) : 0;

        NSMutableArray<NSString *> *dylibs = [NSMutableArray array];
        NSMutableArray<NSString *> *rpaths = [NSMutableArray array];
        NSMutableArray<NSDictionary *> *segments = [NSMutableArray array];
        NSString *installName = nil;
        NSString *uuidStr = nil;
        NSDictionary *encInfo = nil;
        NSDictionary *csInfo = nil;

        const uint8_t *cmdPtr = sb + sizeof(struct mach_header_64);
        const uint8_t *cmdEnd = cmdPtr + hdr->sizeofcmds;
        for (uint32_t i = 0; i < hdr->ncmds && cmdPtr + sizeof(struct load_command) <= cmdEnd; i++) {
            const struct load_command *lc = (const struct load_command *)cmdPtr;
            if (lc->cmdsize < sizeof(struct load_command) || cmdPtr + lc->cmdsize > cmdEnd) break;

            if ((lc->cmd == LC_LOAD_DYLIB || lc->cmd == LC_LOAD_WEAK_DYLIB ||
                 lc->cmd == LC_REEXPORT_DYLIB || lc->cmd == LC_LAZY_LOAD_DYLIB ||
                 lc->cmd == LC_ID_DYLIB) &&
                lc->cmdsize >= sizeof(struct dylib_command)) {
                const struct dylib_command *dc = (const struct dylib_command *)cmdPtr;
                uint32_t strOff = dc->dylib.name.offset;
                if (strOff < lc->cmdsize) {
                    size_t maxLen = lc->cmdsize - strOff;
                    const char *rawName = (const char *)(cmdPtr + strOff);
                    size_t actualLen = strnlen(rawName, maxLen);
                    NSString *str = [[NSString alloc] initWithBytes:rawName length:actualLen encoding:NSUTF8StringEncoding];
                    if (str.length) {
                        if (lc->cmd == LC_ID_DYLIB) installName = str;
                        else [dylibs addObject:str];
                    }
                }
            } else if (lc->cmd == LC_RPATH && lc->cmdsize >= sizeof(struct rpath_command)) {
                const struct rpath_command *rc = (const struct rpath_command *)cmdPtr;
                uint32_t strOff = rc->path.offset;
                if (strOff < lc->cmdsize) {
                    size_t maxLen = lc->cmdsize - strOff;
                    const char *rawPath = (const char *)(cmdPtr + strOff);
                    size_t actualLen = strnlen(rawPath, maxLen);
                    NSString *str = [[NSString alloc] initWithBytes:rawPath length:actualLen encoding:NSUTF8StringEncoding];
                    if (str.length) [rpaths addObject:str];
                }
            } else if (lc->cmd == LC_UUID && lc->cmdsize >= sizeof(struct uuid_command)) {
                const struct uuid_command *uc = (const struct uuid_command *)cmdPtr;
                NSUUID *u = [[NSUUID alloc] initWithUUIDBytes:uc->uuid];
                uuidStr = u.UUIDString;
            } else if (lc->cmd == LC_ENCRYPTION_INFO_64 && lc->cmdsize >= sizeof(struct encryption_info_command_64)) {
                const struct encryption_info_command_64 *ec = (const struct encryption_info_command_64 *)cmdPtr;
                encInfo = @{
                    @"cryptid": @(ec->cryptid),
                    @"encrypted": @(ec->cryptid != 0),
                    @"cryptoff": @(ec->cryptoff),
                    @"cryptsize": @(ec->cryptsize)
                };
            } else if (lc->cmd == LC_CODE_SIGNATURE && lc->cmdsize >= sizeof(struct linkedit_data_command)) {
                const struct linkedit_data_command *cs = (const struct linkedit_data_command *)cmdPtr;
                NSString *entXML = MCPExtractEntitlementsXMLFromSlice(sb, sSize);
                csInfo = @{
                    @"dataoff": @(cs->dataoff),
                    @"datasize": @(cs->datasize),
                    @"has_entitlements": @(entXML.length > 0)
                };
            } else if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)cmdPtr;
                char segNameBuf[17] = {0};
                memcpy(segNameBuf, seg->segname, 16);
                NSString *segName = [NSString stringWithUTF8String:segNameBuf] ?: @"";

                NSMutableArray<NSDictionary *> *sectList = [NSMutableArray array];
                size_t maxSects = (lc->cmdsize - sizeof(struct segment_command_64)) / sizeof(struct section_64);
                uint32_t nsects = seg->nsects < maxSects ? seg->nsects : (uint32_t)maxSects;
                const struct section_64 *sects = (const struct section_64 *)(cmdPtr + sizeof(struct segment_command_64));
                for (uint32_t k = 0; k < nsects; k++) {
                    char sectNameBuf[17] = {0};
                    memcpy(sectNameBuf, sects[k].sectname, 16);
                    [sectList addObject:@{
                        @"name": [NSString stringWithUTF8String:sectNameBuf] ?: @"",
                        @"addr": [NSString stringWithFormat:@"0x%llx", (unsigned long long)sects[k].addr],
                        @"size": @(sects[k].size),
                        @"offset": @(sects[k].offset)
                    }];
                }
                [segments addObject:@{
                    @"name": segName,
                    @"vmaddr": [NSString stringWithFormat:@"0x%llx", (unsigned long long)seg->vmaddr],
                    @"vmsize": @(seg->vmsize),
                    @"fileoff": @(seg->fileoff),
                    @"filesize": @(seg->filesize),
                    @"initprot": @(seg->initprot),
                    @"maxprot": @(seg->maxprot),
                    @"sections": sectList
                }];
            }
            cmdPtr += lc->cmdsize;
        }

        NSMutableDictionary *sliceDict = [@{
            @"arch": arch,
            @"offset": @(slices[s].offset),
            @"size": @(slices[s].size),
            @"filetype": @(hdr->filetype),
            @"ncmds": @(hdr->ncmds),
            @"sizeofcmds": @(hdr->sizeofcmds),
            @"flags": [NSString stringWithFormat:@"0x%x", hdr->flags],
            @"header_padding_available": @(padAvail),
            @"load_dylibs": dylibs,
            @"rpaths": rpaths,
            @"segments": segments
        } mutableCopy];
        if (installName) sliceDict[@"install_name"] = installName;
        if (uuidStr) sliceDict[@"uuid"] = uuidStr;
        if (encInfo) sliceDict[@"encryption"] = encInfo;
        if (csInfo) sliceDict[@"code_signature"] = csInfo;
        [sliceReports addObject:sliceDict];
    }

    NSDictionary *entResult = MCPExtractEntitlementsFromMachO(path, nil);
    return @{
        @"path": path,
        @"file_size": @(data.length),
        @"is_universal": @(isFat),
        @"architectures": archNames,
        @"slices": sliceReports,
        @"entitlements": entResult[@"entitlements"] ?: @{}
    };
}

NSDictionary *MCPInjectLoadDylibInMachO(NSString *binaryPath,
                                        NSString *dylibInstallPath,
                                        NSString **error) {
    if (error) *error = nil;
    if (!binaryPath.length || !dylibInstallPath.length) {
        if (error) *error = @"binaryPath and dylibInstallPath are required";
        return nil;
    }

    const char *installUTF8 = dylibInstallPath.UTF8String;
    size_t nameLen = strlen(installUTF8);
    if (nameLen == 0 || nameLen > 1024) {
        if (error) *error = @"Invalid dylibInstallPath length";
        return nil;
    }
    uint32_t newCmdSize = (uint32_t)((sizeof(struct dylib_command) + nameLen + 1 + 7) & ~7ULL);

    struct stat st;
    mode_t origMode = 0755;
    if (stat(binaryPath.fileSystemRepresentation, &st) == 0) {
        origMode = (st.st_mode & 07777) ?: 0755;
    }

    NSError *readErr = nil;
    NSData *origData = [NSData dataWithContentsOfFile:binaryPath options:0 error:&readErr];
    if (!origData) {
        if (error) *error = readErr.localizedDescription ?: @"Failed to read target Mach-O binary";
        return nil;
    }

    NSMutableData *mutable = [origData mutableCopy];
    uint8_t *bytes = (uint8_t *)mutable.mutableBytes;
    MCPMachOSliceRange slices[16];
    size_t sliceCount = 0;
    BOOL isFat = NO;
    if (!MCPCollectMachOSlices(bytes, mutable.length, slices, 16, &sliceCount, &isFat, error)) {
        return nil;
    }

    // Create reversible .mcp_orig backup once before modifying any slice.
    NSString *backupPath = [binaryPath stringByAppendingString:@".mcp_orig"];
    BOOL createdBackup = NO;
    if (![[NSFileManager defaultManager] fileExistsAtPath:backupPath]) {
        if (!MCPWriteFreshVnodeFile(backupPath, origData.bytes, origData.length, origMode, error)) {
            return nil;
        }
        createdBackup = YES;
    }

    NSMutableArray<NSString *> *modifiedSlices = [NSMutableArray array];
    NSMutableArray<NSString *> *alreadyPresentSlices = [NSMutableArray array];

    for (size_t s = 0; s < sliceCount; s++) {
        uint8_t *sb = bytes + slices[s].offset;
        size_t sSize = (size_t)slices[s].size;
        struct mach_header_64 *hdr = (struct mach_header_64 *)sb;
        NSString *arch = MCPArchName(slices[s].cputype, slices[s].cpusubtype);

        // Check if dylibInstallPath is already present in LC_LOAD_DYLIB.
        BOOL alreadyPresent = NO;
        uint8_t *cmdPtr = sb + sizeof(struct mach_header_64);
        uint8_t *cmdEnd = cmdPtr + hdr->sizeofcmds;
        for (uint32_t i = 0; i < hdr->ncmds && cmdPtr + sizeof(struct load_command) <= cmdEnd; i++) {
            struct load_command *lc = (struct load_command *)cmdPtr;
            if (lc->cmdsize < sizeof(struct load_command) || cmdPtr + lc->cmdsize > cmdEnd) break;
            if ((lc->cmd == LC_LOAD_DYLIB || lc->cmd == LC_LOAD_WEAK_DYLIB) &&
                lc->cmdsize >= sizeof(struct dylib_command)) {
                struct dylib_command *dc = (struct dylib_command *)cmdPtr;
                uint32_t strOff = dc->dylib.name.offset;
                if (strOff < lc->cmdsize) {
                    const char *existing = (const char *)(cmdPtr + strOff);
                    size_t maxL = lc->cmdsize - strOff;
                    if (strncmp(existing, installUTF8, maxL) == 0) {
                        alreadyPresent = YES;
                        break;
                    }
                }
            }
            cmdPtr += lc->cmdsize;
        }

        if (alreadyPresent) {
            [alreadyPresentSlices addObject:arch];
            continue;
        }

        uint64_t headerEnd = sizeof(struct mach_header_64) + hdr->sizeofcmds;
        uint64_t firstContent = MCPComputeFirstContentOffsetInSlice(sb, sSize);
        if (firstContent < headerEnd || (firstContent - headerEnd) < newCmdSize) {
            if (error) {
                *error = [NSString stringWithFormat:@"Insufficient Mach-O header padding in slice %@ (need %u bytes, have %llu bytes)",
                          arch, newCmdSize, (unsigned long long)(firstContent > headerEnd ? (firstContent - headerEnd) : 0)];
            }
            return nil;
        }

        uint8_t *insertAt = sb + headerEnd;
        memset(insertAt, 0, newCmdSize);
        struct dylib_command *newCmd = (struct dylib_command *)insertAt;
        newCmd->cmd = LC_LOAD_DYLIB;
        newCmd->cmdsize = newCmdSize;
        newCmd->dylib.name.offset = sizeof(struct dylib_command);
        newCmd->dylib.timestamp = 2;
        newCmd->dylib.current_version = 0x00010000;
        newCmd->dylib.compatibility_version = 0x00010000;
        memcpy(insertAt + sizeof(struct dylib_command), installUTF8, nameLen);

        hdr->ncmds += 1;
        hdr->sizeofcmds += newCmdSize;
        [modifiedSlices addObject:arch];
    }

    if (modifiedSlices.count > 0) {
        if (!MCPWriteFreshVnodeFile(binaryPath, mutable.bytes, mutable.length, origMode, error)) {
            return nil;
        }
    }

    return @{
        @"binary_path": binaryPath,
        @"backup_path": backupPath,
        @"backup_created": @(createdBackup),
        @"dylib_install_path": dylibInstallPath,
        @"cmdsize": @(newCmdSize),
        @"modified_slices": modifiedSlices,
        @"already_injected_slices": alreadyPresentSlices
    };
}

static BOOL MCPDylibPathMatchesQuery(NSString *existingPath, NSString * _Nullable query) {
    if (!existingPath.length) return NO;
    if (!query.length) {
        return [existingPath hasPrefix:@"@executable_path/Frameworks/"] ||
               [existingPath hasPrefix:@"@rpath/libmcp_"] ||
               [existingPath.lastPathComponent hasPrefix:@"libmcp_"];
    }
    if ([existingPath isEqualToString:query]) return YES;
    if ([existingPath.lastPathComponent isEqualToString:query.lastPathComponent]) return YES;
    return NO;
}

NSDictionary *MCPRemoveLoadDylibFromMachO(NSString *binaryPath,
                                          NSString * _Nullable dylibMatch,
                                          BOOL restoreOriginal,
                                          NSString **error) {
    if (error) *error = nil;
    if (!binaryPath.length) {
        if (error) *error = @"binaryPath is required";
        return nil;
    }

    struct stat st;
    mode_t origMode = 0755;
    if (stat(binaryPath.fileSystemRepresentation, &st) == 0) {
        origMode = (st.st_mode & 07777) ?: 0755;
    }

    NSString *backupPath = [binaryPath stringByAppendingString:@".mcp_orig"];
    if (restoreOriginal && [[NSFileManager defaultManager] fileExistsAtPath:backupPath]) {
        NSError *bErr = nil;
        NSData *backupData = [NSData dataWithContentsOfFile:backupPath options:0 error:&bErr];
        if (!backupData) {
            if (error) *error = bErr.localizedDescription ?: @"Failed reading .mcp_orig backup";
            return nil;
        }
        if (!MCPWriteFreshVnodeFile(binaryPath, backupData.bytes, backupData.length, origMode, error)) {
            return nil;
        }
        [[NSFileManager defaultManager] removeItemAtPath:backupPath error:nil];
        return @{
            @"binary_path": binaryPath,
            @"restored_from_backup": @YES,
            @"removed_dylibs": @[@"(all - restored .mcp_orig)"]
        };
    }

    NSError *readErr = nil;
    NSData *origData = [NSData dataWithContentsOfFile:binaryPath options:0 error:&readErr];
    if (!origData) {
        if (error) *error = readErr.localizedDescription ?: @"Failed reading Mach-O binary";
        return nil;
    }

    NSMutableData *mutable = [origData mutableCopy];
    uint8_t *bytes = (uint8_t *)mutable.mutableBytes;
    MCPMachOSliceRange slices[16];
    size_t sliceCount = 0;
    BOOL isFat = NO;
    if (!MCPCollectMachOSlices(bytes, mutable.length, slices, 16, &sliceCount, &isFat, error)) {
        return nil;
    }

    NSMutableOrderedSet<NSString *> *removedNames = [NSMutableOrderedSet orderedSet];
    NSMutableArray<NSString *> *modifiedSlices = [NSMutableArray array];

    for (size_t s = 0; s < sliceCount; s++) {
        uint8_t *sb = bytes + slices[s].offset;
        struct mach_header_64 *hdr = (struct mach_header_64 *)sb;
        NSString *arch = MCPArchName(slices[s].cputype, slices[s].cpusubtype);

        uint8_t *cmdStart = sb + sizeof(struct mach_header_64);
        uint32_t origSizeOfCmds = hdr->sizeofcmds;
        uint8_t *cmdEnd = cmdStart + origSizeOfCmds;
        uint8_t *cursor = cmdStart;
        uint32_t idx = 0;
        uint32_t removedInSlice = 0;

        while (idx < hdr->ncmds && cursor + sizeof(struct load_command) <= cmdEnd) {
            struct load_command *lc = (struct load_command *)cursor;
            uint32_t csize = lc->cmdsize;
            if (csize < sizeof(struct load_command) || cursor + csize > cmdEnd) break;

            BOOL shouldRemove = NO;
            if ((lc->cmd == LC_LOAD_DYLIB || lc->cmd == LC_LOAD_WEAK_DYLIB ||
                 lc->cmd == LC_REEXPORT_DYLIB || lc->cmd == LC_LAZY_LOAD_DYLIB) &&
                csize >= sizeof(struct dylib_command)) {
                struct dylib_command *dc = (struct dylib_command *)cursor;
                uint32_t strOff = dc->dylib.name.offset;
                if (strOff < csize) {
                    const char *raw = (const char *)(cursor + strOff);
                    size_t len = strnlen(raw, csize - strOff);
                    NSString *existing = [[NSString alloc] initWithBytes:raw length:len encoding:NSUTF8StringEncoding];
                    if (MCPDylibPathMatchesQuery(existing, dylibMatch)) {
                        shouldRemove = YES;
                        if (existing) [removedNames addObject:existing];
                    }
                }
            }

            if (shouldRemove) {
                size_t tailBytes = (size_t)(cmdEnd - (cursor + csize));
                if (tailBytes > 0) {
                    memmove(cursor, cursor + csize, tailBytes);
                }
                memset(cmdEnd - csize, 0, csize);
                cmdEnd -= csize;
                hdr->ncmds -= 1;
                hdr->sizeofcmds -= csize;
                removedInSlice++;
                continue;
            }

            cursor += csize;
            idx++;
        }

        if (removedInSlice > 0) {
            [modifiedSlices addObject:arch];
        }
    }

    if (modifiedSlices.count > 0) {
        if (!MCPWriteFreshVnodeFile(binaryPath, mutable.bytes, mutable.length, origMode, error)) {
            return nil;
        }
    }

    return @{
        @"binary_path": binaryPath,
        @"restored_from_backup": @NO,
        @"modified_slices": modifiedSlices,
        @"removed_dylibs": removedNames.array ?: @[]
    };
}

#pragma mark - On-Device Symbolication (SYMTAB + Export Trie + ObjC ClassList + Function Starts)

static uint64_t MCPReadULEB128(const uint8_t **p, const uint8_t *end, BOOL *ok) {
    uint64_t result = 0;
    int bit = 0;
    while (*p < end) {
        uint8_t byte = **p;
        (*p)++;
        if (bit >= 64) {
            if (ok) *ok = NO;
            return 0;
        }
        result |= ((uint64_t)(byte & 0x7f)) << bit;
        if ((byte & 0x80) == 0) {
            if (ok) *ok = YES;
            return result;
        }
        bit += 7;
    }
    if (ok) *ok = NO;
    return 0;
}

static void MCPWalkExportTrie(const uint8_t *trieStart,
                              const uint8_t *trieEnd,
                              const uint8_t *node,
                              NSString *prefix,
                              uint32_t depth,
                              NSMutableArray<NSDictionary *> *outExports) {
    if (!node || node < trieStart || node >= trieEnd || depth > 256 || outExports.count >= 65536) {
        return;
    }
    const uint8_t *p = node;
    BOOL ok = NO;
    uint64_t termSize = MCPReadULEB128(&p, trieEnd, &ok);
    if (!ok || p + termSize > trieEnd) return;

    if (termSize != 0 && prefix.length > 0) {
        const uint8_t *tp = p;
        uint64_t flags = MCPReadULEB128(&tp, p + termSize, &ok);
        if (ok) {
            uint64_t kind = flags & EXPORT_SYMBOL_FLAGS_KIND_MASK;
            BOOL isReexport = (flags & EXPORT_SYMBOL_FLAGS_REEXPORT) != 0;
            BOOL isStubAndResolver = (flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER) != 0;
            if (!isReexport && kind == EXPORT_SYMBOL_FLAGS_KIND_REGULAR) {
                uint64_t symOffset = MCPReadULEB128(&tp, p + termSize, &ok);
                if (ok && isStubAndResolver) {
                    uint64_t resolverOffset = MCPReadULEB128(&tp, p + termSize, &ok);
                    if (ok && resolverOffset > 0) symOffset = resolverOffset;
                }
                if (ok && symOffset > 0) {
                    NSString *clean = [prefix hasPrefix:@"_"] ? [prefix substringFromIndex:1] : prefix;
                    [outExports addObject:@{@"offset": @(symOffset), @"name": clean, @"source": @"export_trie"}];
                }
            }
        }
    }

    p += termSize;
    if (p >= trieEnd) return;
    uint8_t childCount = *p++;
    for (uint8_t i = 0; i < childCount; i++) {
        const uint8_t *edgeStart = p;
        while (p < trieEnd && *p != 0) p++;
        if (p >= trieEnd) return;
        NSString *edge = [[NSString alloc] initWithBytes:edgeStart
                                                  length:(NSUInteger)(p - edgeStart)
                                                encoding:NSUTF8StringEncoding];
        p++; // skip NUL
        uint64_t childOff = MCPReadULEB128(&p, trieEnd, &ok);
        if (!ok || childOff >= (uint64_t)(trieEnd - trieStart)) continue;
        if (edge) {
            MCPWalkExportTrie(trieStart,
                              trieEnd,
                              trieStart + childOff,
                              [prefix stringByAppendingString:edge],
                              depth + 1,
                              outExports);
        }
    }
}

typedef struct {
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
} MCPSegMap;

static BOOL MCPVMAddrToSliceOffset(uint64_t vmaddr,
                                   const MCPSegMap *segs,
                                   size_t segCount,
                                   size_t sliceSize,
                                   uint64_t *outOff) {
    for (size_t i = 0; i < segCount; i++) {
        if (vmaddr >= segs[i].vmaddr && vmaddr < segs[i].vmaddr + segs[i].filesize) {
            uint64_t off = segs[i].fileoff + (vmaddr - segs[i].vmaddr);
            if (off < sliceSize) {
                if (outOff) *outOff = off;
                return YES;
            }
        }
    }
    return NO;
}

static uint64_t MCPDecodeOnDiskPointer(uint64_t raw,
                                       BOOL isArm64e,
                                       uint64_t textVMAddr,
                                       uint64_t maxVMAddr) {
    if (raw == 0) return 0;
    if (raw >= textVMAddr && raw < maxVMAddr) return raw;

    // arm64e auth_rebase: bit 63 (auth) == 1, bit 62 (bind) == 0, bits 0..31 = 32-bit target offset from __TEXT
    if (isArm64e && ((raw >> 62) == 2ULL)) {
        uint64_t cand = textVMAddr + (uint64_t)(uint32_t)(raw & 0xFFFFFFFFULL);
        if (cand >= textVMAddr && cand < maxVMAddr) return cand;
    }
    // auth_bind or 64-bit bind
    if ((raw >> 62) == 3ULL || (!isArm64e && (raw >> 63) == 1ULL)) {
        return 0;
    }
    // DYLD_CHAINED_PTR_64_OFFSET / ARM64E_USERLAND / ARM64E_USERLAND24: 36-bit target offset
    uint64_t off36 = raw & 0x0000000FFFFFFFFFULL;
    if (off36 > 0 && textVMAddr + off36 < maxVMAddr) {
        return textVMAddr + off36;
    }
    // DYLD_CHAINED_PTR_64 / ARM64E unauthenticated vmaddr rebase: 43-bit target vmaddr
    uint64_t vm43 = raw & 0x000007FFFFFFFFFFULL;
    if (vm43 >= textVMAddr && vm43 < maxVMAddr) {
        return vm43;
    }
    return 0;
}

static NSString *MCPReadCStringAtVMAddr(uint64_t vmaddr,
                                        const uint8_t *sb,
                                        size_t sSize,
                                        const MCPSegMap *segs,
                                        size_t segCount) {
    uint64_t off = 0;
    if (!MCPVMAddrToSliceOffset(vmaddr, segs, segCount, sSize, &off)) return nil;
    size_t maxLen = sSize - (size_t)off;
    if (maxLen > 512) maxLen = 512;
    size_t len = strnlen((const char *)(sb + off), maxLen);
    if (len == 0 || len == maxLen) return nil;
    return [[NSString alloc] initWithBytes:sb + off length:len encoding:NSUTF8StringEncoding];
}

static void MCPExtractObjCMethodsFromClassRO(uint64_t roVMAddr,
                                             NSString *fallbackClassName,
                                             BOOL isMeta,
                                             BOOL isArm64e,
                                             uint64_t textVMAddr,
                                             uint64_t maxVMAddr,
                                             const uint8_t *sb,
                                             size_t sSize,
                                             const MCPSegMap *segs,
                                             size_t segCount,
                                             NSMutableArray<NSDictionary *> *outSymbols) {
    uint64_t roOff = 0;
    if (!roVMAddr || !MCPVMAddrToSliceOffset(roVMAddr, segs, segCount, sSize, &roOff)) return;
    if (roOff + 48 > sSize) return;

    // 64-bit class_ro_t layout:
    // +0  uint32_t flags
    // +4  uint32_t instanceStart
    // +8  uint32_t instanceSize
    // +12 uint32_t reserved
    // +16 uint64_t ivarLayout (or union)
    // +24 uint64_t name
    // +32 uint64_t baseMethodList
    uint64_t rawNamePtr = *(const uint64_t *)(sb + roOff + 24);
    uint64_t rawMethodsPtr = *(const uint64_t *)(sb + roOff + 32);

    uint64_t nameVM = MCPDecodeOnDiskPointer(rawNamePtr, isArm64e, textVMAddr, maxVMAddr);
    NSString *clsName = nameVM ? MCPReadCStringAtVMAddr(nameVM, sb, sSize, segs, segCount) : nil;
    if (!clsName.length) clsName = fallbackClassName;
    if (!clsName.length) return;

    uint64_t methodsVM = MCPDecodeOnDiskPointer(rawMethodsPtr, isArm64e, textVMAddr, maxVMAddr);
    uint64_t methodsOff = 0;
    if (!methodsVM || !MCPVMAddrToSliceOffset(methodsVM, segs, segCount, sSize, &methodsOff)) return;
    if (methodsOff + 8 > sSize) return;

    uint32_t entsizeAndFlags = *(const uint32_t *)(sb + methodsOff + 0);
    uint32_t count = *(const uint32_t *)(sb + methodsOff + 4);
    if (count == 0 || count > 8192) return;

    BOOL isRelative = (entsizeAndFlags & 0x80000000U) != 0;
    uint32_t entsize = entsizeAndFlags & 0x0000FFFCU;
    if (entsize == 0) entsize = isRelative ? 12 : 24;

    NSString *prefixSign = isMeta ? @"+" : @"-";
    uint64_t cursorOff = methodsOff + 8;
    uint64_t cursorVM = methodsVM + 8;

    for (uint32_t i = 0; i < count; i++) {
        if (cursorOff + entsize > sSize) break;
        NSString *selName = nil;
        uint64_t impVM = 0;

        if (isRelative && entsize >= 12) {
            int32_t nameRel = *(const int32_t *)(sb + cursorOff + 0);
            int32_t impRel = *(const int32_t *)(sb + cursorOff + 8);
            uint64_t selRefVM = (uint64_t)((int64_t)cursorVM + (int64_t)nameRel);
            impVM = (uint64_t)((int64_t)(cursorVM + 8) + (int64_t)impRel);

            // In relative method lists, nameRel points either directly to a C-string or to a __objc_selrefs pointer.
            uint64_t selRefOff = 0;
            if (MCPVMAddrToSliceOffset(selRefVM, segs, segCount, sSize, &selRefOff) && selRefOff + 8 <= sSize) {
                uint64_t maybePtr = *(const uint64_t *)(sb + selRefOff);
                uint64_t decodedSelVM = MCPDecodeOnDiskPointer(maybePtr, isArm64e, textVMAddr, maxVMAddr);
                if (decodedSelVM) {
                    selName = MCPReadCStringAtVMAddr(decodedSelVM, sb, sSize, segs, segCount);
                }
                if (!selName.length) {
                    selName = MCPReadCStringAtVMAddr(selRefVM, sb, sSize, segs, segCount);
                }
            }
        } else if (!isRelative && entsize >= 24) {
            uint64_t rawSel = *(const uint64_t *)(sb + cursorOff + 0);
            uint64_t rawImp = *(const uint64_t *)(sb + cursorOff + 16);
            uint64_t selVM = MCPDecodeOnDiskPointer(rawSel, isArm64e, textVMAddr, maxVMAddr);
            impVM = MCPDecodeOnDiskPointer(rawImp, isArm64e, textVMAddr, maxVMAddr);
            if (selVM) selName = MCPReadCStringAtVMAddr(selVM, sb, sSize, segs, segCount);
        }

        if (selName.length > 0 && impVM > textVMAddr && impVM < maxVMAddr) {
            NSString *fullName = [NSString stringWithFormat:@"%@[%@ %@]", prefixSign, clsName, selName];
            [outSymbols addObject:@{
                @"offset": @(impVM - textVMAddr),
                @"name": fullName,
                @"source": @"objc_metadata"
            }];
        }

        cursorOff += entsize;
        cursorVM += entsize;
    }
}

NSDictionary<NSNumber *, NSDictionary *> *MCPSymbolicateOffsetsInMachO(
    NSString *binaryPath,
    NSString * _Nullable preferredArch,
    NSArray<NSNumber *> *imageOffsets,
    NSString **error) {
    if (error) *error = nil;
    if (!binaryPath.length || !imageOffsets.count) return @{};

    NSError *readErr = nil;
    NSData *data = [NSData dataWithContentsOfFile:binaryPath options:NSDataReadingMappedIfSafe error:&readErr];
    if (!data) {
        if (error) *error = readErr.localizedDescription ?: @"Cannot read binary for symbolication";
        return nil;
    }

    MCPMachOSliceRange slices[16];
    size_t sliceCount = 0;
    BOOL isFat = NO;
    if (!MCPCollectMachOSlices(data.bytes, data.length, slices, 16, &sliceCount, &isFat, error)) {
        return nil;
    }

    size_t chosenIdx = 0;
    for (size_t i = 0; i < sliceCount; i++) {
        NSString *arch = MCPArchName(slices[i].cputype, slices[i].cpusubtype);
        if (preferredArch.length && [arch isEqualToString:preferredArch]) {
            chosenIdx = i;
            break;
        }
        if (!preferredArch.length && [arch isEqualToString:@"arm64e"]) {
            chosenIdx = i;
        }
    }

    const uint8_t *sb = (const uint8_t *)data.bytes + slices[chosenIdx].offset;
    size_t sSize = (size_t)slices[chosenIdx].size;
    NSString *sliceArch = MCPArchName(slices[chosenIdx].cputype, slices[chosenIdx].cpusubtype);
    BOOL isArm64e = [sliceArch isEqualToString:@"arm64e"];

    const struct mach_header_64 *hdr = (const struct mach_header_64 *)sb;
    MCPSegMap segs[32];
    size_t segCount = 0;
    uint64_t textVMAddr = 0;
    BOOL foundText = NO;
    uint64_t maxVMAddr = 0;

    uint32_t symoff = 0, nsyms = 0, stroff = 0, strsize = 0;
    uint32_t exportOff = 0, exportSize = 0;
    uint32_t funcStartsOff = 0, funcStartsSize = 0;
    uint64_t classlistOff = 0, classlistSize = 0;

    const uint8_t *cmdPtr = sb + sizeof(struct mach_header_64);
    const uint8_t *cmdEnd = cmdPtr + hdr->sizeofcmds;
    for (uint32_t i = 0; i < hdr->ncmds && cmdPtr + sizeof(struct load_command) <= cmdEnd; i++) {
        const struct load_command *lc = (const struct load_command *)cmdPtr;
        if (lc->cmdsize < sizeof(struct load_command) || cmdPtr + lc->cmdsize > cmdEnd) break;

        if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cmdPtr;
            if (strncmp(seg->segname, "__PAGEZERO", 16) != 0) {
                if (segCount < 32) {
                    segs[segCount++] = (MCPSegMap){
                        .vmaddr = seg->vmaddr,
                        .vmsize = seg->vmsize,
                        .fileoff = seg->fileoff,
                        .filesize = seg->filesize
                    };
                }
                if (strncmp(seg->segname, "__TEXT", 16) == 0) {
                    textVMAddr = seg->vmaddr;
                    foundText = YES;
                }
                if (seg->vmaddr + seg->vmsize > maxVMAddr) {
                    maxVMAddr = seg->vmaddr + seg->vmsize;
                }
            }
            size_t maxSects = (lc->cmdsize - sizeof(struct segment_command_64)) / sizeof(struct section_64);
            uint32_t nsects = seg->nsects < maxSects ? seg->nsects : (uint32_t)maxSects;
            const struct section_64 *sects = (const struct section_64 *)(cmdPtr + sizeof(struct segment_command_64));
            for (uint32_t k = 0; k < nsects; k++) {
                if (strncmp(sects[k].sectname, "__objc_classlist", 16) == 0) {
                    classlistOff = sects[k].offset;
                    classlistSize = sects[k].size;
                }
            }
        } else if (lc->cmd == LC_SYMTAB && lc->cmdsize >= sizeof(struct symtab_command)) {
            const struct symtab_command *st = (const struct symtab_command *)cmdPtr;
            symoff = st->symoff;
            nsyms = st->nsyms;
            stroff = st->stroff;
            strsize = st->strsize;
        } else if (lc->cmd == LC_DYLD_EXPORTS_TRIE && lc->cmdsize >= sizeof(struct linkedit_data_command)) {
            const struct linkedit_data_command *ed = (const struct linkedit_data_command *)cmdPtr;
            exportOff = ed->dataoff;
            exportSize = ed->datasize;
        } else if ((lc->cmd == LC_DYLD_INFO || lc->cmd == LC_DYLD_INFO_ONLY) &&
                   lc->cmdsize >= sizeof(struct dyld_info_command) && exportOff == 0) {
            const struct dyld_info_command *di = (const struct dyld_info_command *)cmdPtr;
            exportOff = di->export_off;
            exportSize = di->export_size;
        } else if (lc->cmd == LC_FUNCTION_STARTS && lc->cmdsize >= sizeof(struct linkedit_data_command)) {
            const struct linkedit_data_command *fs = (const struct linkedit_data_command *)cmdPtr;
            funcStartsOff = fs->dataoff;
            funcStartsSize = fs->datasize;
        }
        cmdPtr += lc->cmdsize;
    }

    if (!foundText) return @{};

    NSMutableArray<NSDictionary *> *rawSymbols = [NSMutableArray array];

    // 1. LC_SYMTAB
    if (symoff > 0 && nsyms > 0 && stroff > 0 && strsize > 0 &&
        (uint64_t)symoff + (uint64_t)nsyms * sizeof(struct nlist_64) <= sSize &&
        (uint64_t)stroff + (uint64_t)strsize <= sSize) {
        const struct nlist_64 *syms = (const struct nlist_64 *)(sb + symoff);
        const char *strtab = (const char *)(sb + stroff);
        for (uint32_t i = 0; i < nsyms; i++) {
            if ((syms[i].n_type & N_STAB) != 0) continue;
            if ((syms[i].n_type & N_TYPE) != N_SECT) continue;
            if (syms[i].n_value < textVMAddr || syms[i].n_value >= maxVMAddr) continue;
            uint32_t strx = syms[i].n_un.n_strx;
            if (strx == 0 || strx >= strsize) continue;
            const char *rawName = strtab + strx;
            size_t maxL = strsize - strx;
            size_t len = strnlen(rawName, maxL);
            if (len == 0) continue;
            if (rawName[0] == '_' && len > 1) {
                rawName++;
                len--;
            }
            NSString *name = [[NSString alloc] initWithBytes:rawName length:len encoding:NSUTF8StringEncoding];
            if (!name.length || [name isEqualToString:@"<redacted>"]) continue;
            [rawSymbols addObject:@{
                @"offset": @(syms[i].n_value - textVMAddr),
                @"name": name,
                @"source": @"symtab"
            }];
        }
    }

    // 2. LC_DYLD_EXPORTS_TRIE
    if (exportOff > 0 && exportSize > 0 && (uint64_t)exportOff + (uint64_t)exportSize <= sSize) {
        const uint8_t *trieStart = sb + exportOff;
        MCPWalkExportTrie(trieStart, trieStart + exportSize, trieStart, @"", 0, rawSymbols);
    }

    // 3. Objective-C __objc_classlist method addresses
    if (classlistOff > 0 && classlistSize >= 8 && classlistOff + classlistSize <= sSize) {
        size_t nClasses = (size_t)(classlistSize / 8);
        if (nClasses > 16384) nClasses = 16384;
        const uint64_t *clsPtrs = (const uint64_t *)(sb + classlistOff);
        for (size_t c = 0; c < nClasses; c++) {
            uint64_t clsVM = MCPDecodeOnDiskPointer(clsPtrs[c], isArm64e, textVMAddr, maxVMAddr);
            uint64_t clsOff = 0;
            if (!clsVM || !MCPVMAddrToSliceOffset(clsVM, segs, segCount, sSize, &clsOff)) continue;
            if (clsOff + 40 > sSize) continue;

            // objc_class: +0 isa, +8 superclass, +16 cache (16B), +32 bits/ro
            uint64_t rawIsa = *(const uint64_t *)(sb + clsOff + 0);
            uint64_t rawData = *(const uint64_t *)(sb + clsOff + 32);
            uint64_t roVM = MCPDecodeOnDiskPointer(rawData, isArm64e, textVMAddr, maxVMAddr) & ~7ULL;
            NSString *clsName = nil;
            if (roVM) {
                uint64_t roOff = 0;
                if (MCPVMAddrToSliceOffset(roVM, segs, segCount, sSize, &roOff) && roOff + 32 <= sSize) {
                    uint64_t nameVM = MCPDecodeOnDiskPointer(*(const uint64_t *)(sb + roOff + 24), isArm64e, textVMAddr, maxVMAddr);
                    if (nameVM) clsName = MCPReadCStringAtVMAddr(nameVM, sb, sSize, segs, segCount);
                }
                MCPExtractObjCMethodsFromClassRO(roVM, clsName, NO, isArm64e, textVMAddr, maxVMAddr, sb, sSize, segs, segCount, rawSymbols);
            }
            uint64_t metaVM = MCPDecodeOnDiskPointer(rawIsa, isArm64e, textVMAddr, maxVMAddr);
            uint64_t metaOff = 0;
            if (metaVM && MCPVMAddrToSliceOffset(metaVM, segs, segCount, sSize, &metaOff) && metaOff + 40 <= sSize) {
                uint64_t metaRawData = *(const uint64_t *)(sb + metaOff + 32);
                uint64_t metaROVM = MCPDecodeOnDiskPointer(metaRawData, isArm64e, textVMAddr, maxVMAddr) & ~7ULL;
                if (metaROVM) {
                    MCPExtractObjCMethodsFromClassRO(metaROVM, clsName, YES, isArm64e, textVMAddr, maxVMAddr, sb, sSize, segs, segCount, rawSymbols);
                }
            }
        }
    }

    // Deduplicate & sort symbols by ascending offset (preferring symtab / objc_metadata over export_trie at ties)
    NSMutableDictionary<NSNumber *, NSDictionary *> *byOffset = [NSMutableDictionary dictionaryWithCapacity:rawSymbols.count];
    for (NSDictionary *entry in rawSymbols) {
        NSNumber *offKey = entry[@"offset"];
        NSDictionary *existing = byOffset[offKey];
        if (!existing || [existing[@"source"] isEqualToString:@"export_trie"]) {
            byOffset[offKey] = entry;
        }
    }
    NSArray<NSNumber *> *sortedSymOffsets = [byOffset.allKeys sortedArrayUsingSelector:@selector(compare:)];

    // 4. Decode LC_FUNCTION_STARTS boundaries
    NSMutableArray<NSNumber *> *funcStarts = [NSMutableArray array];
    if (funcStartsOff > 0 && funcStartsSize > 0 && (uint64_t)funcStartsOff + (uint64_t)funcStartsSize <= sSize) {
        const uint8_t *p = sb + funcStartsOff;
        const uint8_t *end = p + funcStartsSize;
        uint64_t addr = 0;
        while (p < end) {
            BOOL ok = NO;
            uint64_t delta = MCPReadULEB128(&p, end, &ok);
            if (!ok || delta == 0) break;
            addr += delta;
            [funcStarts addObject:@(addr)];
        }
    }

    NSMutableDictionary<NSNumber *, NSDictionary *> *resolved = [NSMutableDictionary dictionaryWithCapacity:imageOffsets.count];
    for (NSNumber *queryNum in imageOffsets) {
        uint64_t targetOff = queryNum.unsignedLongLongValue;

        // Binary search in sortedSymOffsets for greatest symOff <= targetOff
        NSDictionary *bestSym = nil;
        uint64_t bestSymOff = 0;
        if (sortedSymOffsets.count > 0) {
            NSInteger lo = 0, hi = (NSInteger)sortedSymOffsets.count - 1, idx = -1;
            while (lo <= hi) {
                NSInteger mid = lo + (hi - lo) / 2;
                uint64_t val = sortedSymOffsets[(NSUInteger)mid].unsignedLongLongValue;
                if (val <= targetOff) {
                    idx = mid;
                    lo = mid + 1;
                } else {
                    hi = mid - 1;
                }
            }
            if (idx >= 0) {
                NSNumber *key = sortedSymOffsets[(NSUInteger)idx];
                bestSymOff = key.unsignedLongLongValue;
                bestSym = byOffset[key];
            }
        }

        // Binary search in funcStarts for greatest funcOff <= targetOff
        BOOL hasFuncStart = NO;
        uint64_t funcStartOff = 0;
        if (funcStarts.count > 0) {
            NSInteger lo = 0, hi = (NSInteger)funcStarts.count - 1, idx = -1;
            while (lo <= hi) {
                NSInteger mid = lo + (hi - lo) / 2;
                uint64_t val = funcStarts[(NSUInteger)mid].unsignedLongLongValue;
                if (val <= targetOff) {
                    idx = mid;
                    lo = mid + 1;
                } else {
                    hi = mid - 1;
                }
            }
            if (idx >= 0) {
                hasFuncStart = YES;
                funcStartOff = funcStarts[(NSUInteger)idx].unsignedLongLongValue;
            }
        }

        if (bestSym && (!hasFuncStart || bestSymOff >= funcStartOff)) {
            uint64_t delta = targetOff - bestSymOff;
            resolved[queryNum] = @{
                @"symbol": bestSym[@"name"],
                @"symbol_offset": @(delta),
                @"formatted": [NSString stringWithFormat:@"%@ + %llu", bestSym[@"name"], (unsigned long long)delta],
                @"source": bestSym[@"source"],
                @"exact_function": @YES,
                @"arch": sliceArch
            };
        } else if (hasFuncStart) {
            uint64_t funcDelta = targetOff - funcStartOff;
            NSString *subName = [NSString stringWithFormat:@"sub_%llx", (unsigned long long)(textVMAddr + funcStartOff)];
            NSMutableDictionary *entry = [@{
                @"symbol": subName,
                @"symbol_offset": @(funcDelta),
                @"formatted": [NSString stringWithFormat:@"%@ + %llu", subName, (unsigned long long)funcDelta],
                @"source": @"function_starts",
                @"exact_function": @YES,
                @"arch": sliceArch
            } mutableCopy];
            if (bestSym) {
                entry[@"nearest_named_symbol"] = bestSym[@"name"];
                entry[@"nearest_named_offset"] = @(targetOff - bestSymOff);
            }
            resolved[queryNum] = entry;
        } else if (bestSym && (targetOff - bestSymOff) <= 0x10000) {
            uint64_t delta = targetOff - bestSymOff;
            resolved[queryNum] = @{
                @"symbol": bestSym[@"name"],
                @"symbol_offset": @(delta),
                @"formatted": [NSString stringWithFormat:@"%@ + %llu", bestSym[@"name"], (unsigned long long)delta],
                @"source": bestSym[@"source"],
                @"exact_function": @NO,
                @"arch": sliceArch
            };
        }
    }

    return resolved;
}

#pragma mark - Seeded Frida/Gum Binary Scrubber

static uint64_t MCPXorshift64Star(uint64_t *state) {
    uint64_t x = *state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    return x * 0x2545F4914F6CDD1DULL;
}

static void MCPGenerateAlphaToken(uint64_t *rng, char *outBuf, size_t len) {
    // Use consonant/vowel-rich lowercase letters excluding forbidden substrings so generated tokens
    // are always valid C/GObject identifiers and never accidentally regenerate 'frida' or 'gum'.
    static const char alphabet[] = "bcdfhjklmnpqrstvwxyz";
    for (size_t i = 0; i < len; i++) {
        outBuf[i] = alphabet[MCPXorshift64Star(rng) % (sizeof(alphabet) - 1)];
    }
    outBuf[len] = '\0';
}

static BOOL MCPMatchCaseInsensitiveAt(const uint8_t *buf, size_t pos, size_t limit, const char *needle, size_t nlen) {
    if (pos + nlen > limit) return NO;
    for (size_t i = 0; i < nlen; i++) {
        if (tolower(buf[pos + i]) != (unsigned char)needle[i]) return NO;
    }
    return YES;
}

static void MCPApplyCasePreservingReplacement(uint8_t *dst, const char *replacement, size_t len) {
    for (size_t i = 0; i < len; i++) {
        char rep = replacement[i];
        if (!isalpha((unsigned char)rep)) {
            dst[i] = (uint8_t)rep;
        } else if (isupper(dst[i])) {
            dst[i] = (uint8_t)toupper((unsigned char)rep);
        } else {
            dst[i] = (uint8_t)tolower((unsigned char)rep);
        }
    }
}

NSDictionary *MCPScrubMachOBinaryAtPath(NSString *inputPath,
                                        NSString *outputPath,
                                        uint64_t seed,
                                        NSString **error) {
    if (error) *error = nil;
    if (!inputPath.length || !outputPath.length) {
        if (error) *error = @"inputPath and outputPath are required";
        return nil;
    }

    if (seed == 0) {
        arc4random_buf(&seed, sizeof(seed));
        if (seed == 0) seed = 0x9E3779B97F4A7C15ULL;
    }

    uint64_t rng = seed ^ 0xA5A5F0F05A5A0F0FULL;
    if (rng == 0) rng = 0x123456789ABCDEF1ULL;

    char repGumJsLoop[12] = {0}; // 11 chars: xxx-xx-xxxx
    char part1[4], part2[3], part3[5];
    MCPGenerateAlphaToken(&rng, part1, 3);
    MCPGenerateAlphaToken(&rng, part2, 2);
    MCPGenerateAlphaToken(&rng, part3, 4);
    snprintf(repGumJsLoop, sizeof(repGumJsLoop), "%s-%s-%s", part1, part2, part3);

    char repFrida[6] = {0};
    char repGmain[6] = {0};
    char repGdbus[6] = {0};
    char repGum[4] = {0};
    MCPGenerateAlphaToken(&rng, repFrida, 5);
    MCPGenerateAlphaToken(&rng, repGmain, 5);
    if (strcmp(repGmain, repFrida) == 0) repGmain[0] = (repGmain[0] == 'b') ? 'c' : 'b';
    MCPGenerateAlphaToken(&rng, repGdbus, 5);
    if (strcmp(repGdbus, repFrida) == 0 || strcmp(repGdbus, repGmain) == 0) repGdbus[0] = 'z';
    MCPGenerateAlphaToken(&rng, repGum, 3);

    struct stat st;
    mode_t mode = 0755;
    if (stat(inputPath.fileSystemRepresentation, &st) == 0) {
        mode = (st.st_mode & 07777) ?: 0755;
    }

    NSError *readErr = nil;
    NSData *origData = [NSData dataWithContentsOfFile:inputPath options:0 error:&readErr];
    if (!origData) {
        if (error) *error = readErr.localizedDescription ?: @"Cannot read dylib to scrub";
        return nil;
    }

    NSMutableData *mutable = [origData mutableCopy];
    uint8_t *bytes = (uint8_t *)mutable.mutableBytes;
    MCPMachOSliceRange slices[16];
    size_t sliceCount = 0;
    BOOL isFat = NO;
    if (!MCPCollectMachOSlices(bytes, mutable.length, slices, 16, &sliceCount, &isFat, error)) {
        return nil;
    }

    NSUInteger countGumJsLoop = 0;
    NSUInteger countFrida = 0;
    NSUInteger countGmain = 0;
    NSUInteger countGdbus = 0;
    NSUInteger countGum = 0;
    NSUInteger countIdDylib = 0;
    NSMutableArray<NSDictionary *> *sliceSummaries = [NSMutableArray arrayWithCapacity:sliceCount];

    for (size_t s = 0; s < sliceCount; s++) {
        uint8_t *sb = bytes + slices[s].offset;
        size_t sSize = (size_t)slices[s].size;
        struct mach_header_64 *hdr = (struct mach_header_64 *)sb;
        NSString *arch = MCPArchName(slices[s].cputype, slices[s].cpusubtype);

        NSUInteger sliceReplacements = 0;
        uint64_t cstringOff = 0, cstringSize = 0;

        uint8_t *cmdPtr = sb + sizeof(struct mach_header_64);
        uint8_t *cmdEnd = cmdPtr + hdr->sizeofcmds;
        for (uint32_t i = 0; i < hdr->ncmds && cmdPtr + sizeof(struct load_command) <= cmdEnd; i++) {
            struct load_command *lc = (struct load_command *)cmdPtr;
            if (lc->cmdsize < sizeof(struct load_command) || cmdPtr + lc->cmdsize > cmdEnd) break;

            if (lc->cmd == LC_ID_DYLIB && lc->cmdsize >= sizeof(struct dylib_command)) {
                struct dylib_command *dc = (struct dylib_command *)cmdPtr;
                uint32_t strOff = dc->dylib.name.offset;
                if (strOff < lc->cmdsize) {
                    uint8_t *idBuf = cmdPtr + strOff;
                    size_t idLen = strnlen((const char *)idBuf, lc->cmdsize - strOff);
                    for (size_t p = 0; p < idLen; ) {
                        if (MCPMatchCaseInsensitiveAt(idBuf, p, idLen, "frida", 5)) {
                            MCPApplyCasePreservingReplacement(idBuf + p, repFrida, 5);
                            countIdDylib++;
                            sliceReplacements++;
                            p += 5;
                        } else if (MCPMatchCaseInsensitiveAt(idBuf, p, idLen, "gum", 3) &&
                                   (p == 0 || !isalpha(idBuf[p - 1]) || isupper(idBuf[p]))) {
                            MCPApplyCasePreservingReplacement(idBuf + p, repGum, 3);
                            countIdDylib++;
                            sliceReplacements++;
                            p += 3;
                        } else {
                            p++;
                        }
                    }
                }
            } else if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
                struct segment_command_64 *seg = (struct segment_command_64 *)cmdPtr;
                if (strncmp(seg->segname, "__TEXT", 16) == 0) {
                    size_t maxSects = (lc->cmdsize - sizeof(struct segment_command_64)) / sizeof(struct section_64);
                    uint32_t nsects = seg->nsects < maxSects ? seg->nsects : (uint32_t)maxSects;
                    struct section_64 *sects = (struct section_64 *)(cmdPtr + sizeof(struct segment_command_64));
                    for (uint32_t k = 0; k < nsects; k++) {
                        if (strncmp(sects[k].sectname, "__cstring", 16) == 0) {
                            cstringOff = sects[k].offset;
                            cstringSize = sects[k].size;
                            break;
                        }
                    }
                }
            }
            cmdPtr += lc->cmdsize;
        }

        if (cstringOff > 0 && cstringSize > 0 && cstringOff + cstringSize <= sSize) {
            uint8_t *cs = sb + cstringOff;
            size_t limit = (size_t)cstringSize;
            size_t pos = 0;
            while (pos < limit) {
                if (cs[pos] == 0) {
                    pos++;
                    continue;
                }
                if (MCPMatchCaseInsensitiveAt(cs, pos, limit, "gum-js-loop", 11)) {
                    MCPApplyCasePreservingReplacement(cs + pos, repGumJsLoop, 11);
                    countGumJsLoop++;
                    sliceReplacements++;
                    pos += 11;
                } else if (MCPMatchCaseInsensitiveAt(cs, pos, limit, "frida", 5)) {
                    MCPApplyCasePreservingReplacement(cs + pos, repFrida, 5);
                    countFrida++;
                    sliceReplacements++;
                    pos += 5;
                } else if (MCPMatchCaseInsensitiveAt(cs, pos, limit, "gmain", 5)) {
                    MCPApplyCasePreservingReplacement(cs + pos, repGmain, 5);
                    countGmain++;
                    sliceReplacements++;
                    pos += 5;
                } else if (MCPMatchCaseInsensitiveAt(cs, pos, limit, "gdbus", 5)) {
                    MCPApplyCasePreservingReplacement(cs + pos, repGdbus, 5);
                    countGdbus++;
                    sliceReplacements++;
                    pos += 5;
                } else if (MCPMatchCaseInsensitiveAt(cs, pos, limit, "gum", 3) &&
                           pos > 0 && cs[pos - 1] == '-' &&
                           MCPMatchCaseInsensitiveAt(cs, pos, limit, "gum-", 4)) {
                    // Only scrub a standalone "gum-" token (e.g. a leftover "gum-*" thread/loop
                    // name), never the "Gum" prefix of GObject type-name strings such as
                    // "GumScript"/"GumInterceptor". Those names are resolved at runtime via
                    // g_type_from_name(); rewriting them (the old CamelCase/isupper rule did
                    // exactly that, 800+ times) makes GType lookup return 0 and the Gadget
                    // segfaults in its own initializer before its control socket binds.
                    MCPApplyCasePreservingReplacement(cs + pos, repGum, 3);
                    countGum++;
                    sliceReplacements++;
                    pos += 3;
                } else {
                    pos++;
                }
            }
        }

        [sliceSummaries addObject:@{
            @"arch": arch,
            @"cstring_offset": @(cstringOff),
            @"cstring_size": @(cstringSize),
            @"replacements": @(sliceReplacements)
        }];
    }

    if (!MCPWriteFreshVnodeFile(outputPath, mutable.bytes, mutable.length, mode, error)) {
        return nil;
    }

    NSUInteger totalReplacements = countGumJsLoop + countFrida + countGmain + countGdbus + countGum + countIdDylib;
    return @{
        @"input_path": inputPath,
        @"output_path": outputPath,
        @"seed": [NSString stringWithFormat:@"0x%016llx", (unsigned long long)seed],
        @"total_replacements": @(totalReplacements),
        @"counts": @{
            @"gum-js-loop": @(countGumJsLoop),
            @"frida": @(countFrida),
            @"gmain": @(countGmain),
            @"gdbus": @(countGdbus),
            @"gum": @(countGum),
            @"lc_id_dylib": @(countIdDylib)
        },
        @"token_map": @{
            @"gum-js-loop": [NSString stringWithUTF8String:repGumJsLoop],
            @"frida": [NSString stringWithUTF8String:repFrida],
            @"gmain": [NSString stringWithUTF8String:repGmain],
            @"gdbus": [NSString stringWithUTF8String:repGdbus],
            @"gum": [NSString stringWithUTF8String:repGum]
        },
        @"slices": sliceSummaries
    };
}
