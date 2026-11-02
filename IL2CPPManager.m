#import "IL2CPPManager.h"
#import "AppManager.h"
#import "MCPMachOUtil.h"
#import "MCPProcessUtil.h"
#import <stdint.h>
#import <string.h>

static const uint32_t kIL2CPPMetadataMagic = 0xFAB11BAFU;

typedef struct {
    uint32_t stringLiteralOffset;
    uint32_t stringLiteralSize;
    uint32_t stringLiteralDataOffset;
    uint32_t stringLiteralDataSize;
    uint32_t stringOffset;
    uint32_t stringSize;
    uint32_t methodsOffset;
    uint32_t methodsSize;
    uint32_t fieldsOffset;
    uint32_t fieldsSize;
    uint32_t typeDefinitionsOffset;
    uint32_t typeDefinitionsSize;
    uint32_t imagesOffset;
    uint32_t imagesSize;
    uint32_t assembliesOffset;
    uint32_t assembliesSize;
} MCPIL2CPPSections;

static BOOL MCPReadU32LE(const uint8_t *buf, size_t len, size_t off, uint32_t *outVal) {
    if (off + 4 > len) return NO;
    uint32_t v = 0;
    memcpy(&v, buf + off, 4);
    *outVal = CFSwapInt32LittleToHost(v);
    return YES;
}

static BOOL MCPReadI32LE(const uint8_t *buf, size_t len, size_t off, int32_t *outVal) {
    uint32_t u = 0;
    if (!MCPReadU32LE(buf, len, off, &u)) return NO;
    *outVal = (int32_t)u;
    return YES;
}

static BOOL MCPReadU16LE(const uint8_t *buf, size_t len, size_t off, uint16_t *outVal) {
    if (off + 2 > len) return NO;
    uint16_t v = 0;
    memcpy(&v, buf + off, 2);
    *outVal = CFSwapInt16LittleToHost(v);
    return YES;
}

static NSString *MCPIL2CPPReadCString(const uint8_t *buf,
                                      size_t len,
                                      uint32_t stringOffset,
                                      uint32_t stringSize,
                                      int32_t index) {
    if (index < 0 || (uint32_t)index >= stringSize) return @"";
    size_t start = (size_t)stringOffset + (size_t)index;
    size_t limit = (size_t)stringOffset + (size_t)stringSize;
    if (start >= len || limit > len) return @"";
    const uint8_t *p = buf + start;
    const uint8_t *end = memchr(p, '\0', limit - start);
    size_t slen = end ? (size_t)(end - p) : (limit - start);
    if (slen > 2048) slen = 2048;
    return [[NSString alloc] initWithBytes:p length:slen encoding:NSUTF8StringEncoding] ?: @"";
}

// Parse header section offsets across IL2CPP metadata versions 24..31.
static BOOL MCPParseIL2CPPSections(const uint8_t *buf,
                                   size_t len,
                                   uint32_t version,
                                   MCPIL2CPPSections *out,
                                   NSString **error) {
    memset(out, 0, sizeof(*out));
    if (len < 200) {
        if (error) *error = @"global-metadata.dat is truncated (< 200 bytes)";
        return NO;
    }

    // First 6 pairs are identical across v24..v31:
    // [8]: stringLiteral, [16]: stringLiteralData, [24]: string, [32]: events, [40]: properties, [48]: methods
    MCPReadU32LE(buf, len, 8,  &out->stringLiteralOffset);
    MCPReadU32LE(buf, len, 12, &out->stringLiteralSize);
    MCPReadU32LE(buf, len, 16, &out->stringLiteralDataOffset);
    MCPReadU32LE(buf, len, 20, &out->stringLiteralDataSize);
    MCPReadU32LE(buf, len, 24, &out->stringOffset);
    MCPReadU32LE(buf, len, 28, &out->stringSize);
    MCPReadU32LE(buf, len, 48, &out->methodsOffset);
    MCPReadU32LE(buf, len, 52, &out->methodsSize);
    MCPReadU32LE(buf, len, 88, &out->fieldsOffset);
    MCPReadU32LE(buf, len, 92, &out->fieldsSize);

    if (version >= 29) {
        // Verified on Unity 2021.3 / 2022.3 / Unity 6 (v29..v31):
        // [160]: typeDefinitions, [168]: images, [176]: assemblies
        MCPReadU32LE(buf, len, 160, &out->typeDefinitionsOffset);
        MCPReadU32LE(buf, len, 164, &out->typeDefinitionsSize);
        MCPReadU32LE(buf, len, 168, &out->imagesOffset);
        MCPReadU32LE(buf, len, 172, &out->imagesSize);
        MCPReadU32LE(buf, len, 176, &out->assembliesOffset);
        MCPReadU32LE(buf, len, 180, &out->assembliesSize);
    } else if (version >= 27) {
        // v27..v28 includes rgctxEntries (8 bytes) before typeDefinitions -> +8 shift vs v29
        MCPReadU32LE(buf, len, 168, &out->typeDefinitionsOffset);
        MCPReadU32LE(buf, len, 172, &out->typeDefinitionsSize);
        MCPReadU32LE(buf, len, 176, &out->imagesOffset);
        MCPReadU32LE(buf, len, 180, &out->imagesSize);
        MCPReadU32LE(buf, len, 184, &out->assembliesOffset);
        MCPReadU32LE(buf, len, 188, &out->assembliesSize);
    } else {
        // v24.x: [160] or [168] depending on v24.0 vs v24.2+ (globalMetadataHeader removed customAttributes shift)
        uint32_t candImgOff = 0, candImgSz = 0;
        MCPReadU32LE(buf, len, 176, &candImgOff);
        MCPReadU32LE(buf, len, 180, &candImgSz);
        if (candImgOff > 0 && candImgOff + candImgSz <= len && (candImgSz % 40) == 0 && candImgSz > 0) {
            MCPReadU32LE(buf, len, 168, &out->typeDefinitionsOffset);
            MCPReadU32LE(buf, len, 172, &out->typeDefinitionsSize);
            out->imagesOffset = candImgOff;
            out->imagesSize = candImgSz;
            MCPReadU32LE(buf, len, 184, &out->assembliesOffset);
            MCPReadU32LE(buf, len, 188, &out->assembliesSize);
        } else {
            MCPReadU32LE(buf, len, 160, &out->typeDefinitionsOffset);
            MCPReadU32LE(buf, len, 164, &out->typeDefinitionsSize);
            MCPReadU32LE(buf, len, 176, &out->imagesOffset);
            MCPReadU32LE(buf, len, 180, &out->imagesSize);
            MCPReadU32LE(buf, len, 184, &out->assembliesOffset);
            MCPReadU32LE(buf, len, 188, &out->assembliesSize);
        }
    }

    if ((size_t)out->stringOffset + (size_t)out->stringSize > len ||
        (size_t)out->typeDefinitionsOffset + (size_t)out->typeDefinitionsSize > len ||
        (size_t)out->imagesOffset + (size_t)out->imagesSize > len) {
        if (error) *error = @"global-metadata.dat section offsets exceed file size";
        return NO;
    }
    return YES;
}

@implementation IL2CPPManager

+ (instancetype)sharedInstance {
    static IL2CPPManager *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[IL2CPPManager alloc] init];
    });
    return instance;
}

- (NSDictionary *)dumpIL2CPPForBundleId:(NSString *)bundleId
                             imageFilter:(NSString *)imageFilter
                              typeFilter:(NSString *)typeFilter
                                maxTypes:(NSUInteger)maxTypes
                         maxStringLiterals:(NSUInteger)maxStringLiterals
                                  error:(NSString **)error {
    if (error) *error = nil;
    if (![bundleId isKindOfClass:[NSString class]] || !bundleId.length) {
        if (error) *error = @"bundle_id is required";
        return nil;
    }
    if (maxTypes == 0) maxTypes = 150;
    if (maxTypes > 1500) maxTypes = 1500;
    if (maxStringLiterals == 0) maxStringLiterals = 100;
    if (maxStringLiterals > 1000) maxStringLiterals = 1000;

    NSString *appErr = nil;
    NSDictionary *appInfo = [[AppManager sharedInstance] appInfoForBundleId:bundleId error:&appErr];
    if (!appInfo) {
        if (error) *error = appErr ?: [NSString stringWithFormat:@"App not found: %@", bundleId];
        return nil;
    }

    NSString *bundlePath = [appInfo[@"bundle_path"] isKindOfClass:[NSString class]] ? appInfo[@"bundle_path"] : nil;
    NSString *mainExec = [appInfo[@"executable_path"] isKindOfClass:[NSString class]] ? appInfo[@"executable_path"] : nil;
    if (!bundlePath.length) {
        if (error) *error = [NSString stringWithFormat:@"App %@ has no bundle_path", bundleId];
        return nil;
    }

    NSFileManager *fm = [NSFileManager defaultManager];

    // Locate global-metadata.dat
    NSArray<NSString *> *metaCandidates = @[
        [bundlePath stringByAppendingPathComponent:@"Data/Managed/Metadata/global-metadata.dat"],
        [bundlePath stringByAppendingPathComponent:@"Frameworks/UnityFramework.framework/Data/Managed/Metadata/global-metadata.dat"]
    ];
    NSString *metadataPath = nil;
    for (NSString *cand in metaCandidates) {
        if ([fm fileExistsAtPath:cand]) {
            metadataPath = cand;
            break;
        }
    }

    // Locate IL2CPP code binary (UnityFramework -> libil2cpp.dylib -> GameAssembly.dylib -> main executable)
    NSArray<NSString *> *binCandidates = @[
        [bundlePath stringByAppendingPathComponent:@"Frameworks/UnityFramework.framework/UnityFramework"],
        [bundlePath stringByAppendingPathComponent:@"Frameworks/libil2cpp.dylib"],
        [bundlePath stringByAppendingPathComponent:@"Frameworks/GameAssembly.dylib"],
        mainExec ?: @""
    ];
    NSString *il2cppBinaryPath = nil;
    for (NSString *cand in binCandidates) {
        if (cand.length > 0 && [fm fileExistsAtPath:cand]) {
            il2cppBinaryPath = cand;
            break;
        }
    }

    if (!metadataPath) {
        if (error) *error = [NSString stringWithFormat:@"App %@ is not a Unity IL2CPP build (Data/Managed/Metadata/global-metadata.dat not found in %@)", bundleId, bundlePath];
        return nil;
    }

    NSData *metaData = [NSData dataWithContentsOfFile:metadataPath options:NSDataReadingMappedIfSafe error:NULL];
    if (!metaData) {
        NSData *rootBytes = nil;
        BOOL truncated = NO;
        int code = -1;
        NSString *runErr = nil;
        if (MCPRunRootProcessData(@"/usr/libexec/ios-mcp/mcp-appmod",
                                  @[@"read-file", metadataPath, @"67108864"],
                                  30.0,
                                  64 * 1024 * 1024,
                                  &rootBytes,
                                  &truncated,
                                  &code,
                                  &runErr) && code == 0 && !truncated) {
            metaData = rootBytes;
        }
    }
    if (!metaData || metaData.length < 64) {
        if (error) *error = [NSString stringWithFormat:@"Cannot read global-metadata.dat at %@", metadataPath];
        return nil;
    }

    const uint8_t *buf = metaData.bytes;
    size_t len = metaData.length;
    uint32_t magic = 0, version = 0;
    MCPReadU32LE(buf, len, 0, &magic);
    MCPReadU32LE(buf, len, 4, &version);

    if (magic != kIL2CPPMetadataMagic) {
        if (error) *error = [NSString stringWithFormat:@"global-metadata.dat magic mismatch (got 0x%08x, expected 0xFAB11BAF — metadata may be encrypted/obfuscated)", magic];
        return nil;
    }
    if (version < 24 || version > 31) {
        if (error) *error = [NSString stringWithFormat:@"Unsupported IL2CPP metadata version %u (supported: 24..31)", version];
        return nil;
    }

    MCPIL2CPPSections sec;
    if (!MCPParseIL2CPPSections(buf, len, version, &sec, error)) {
        return nil;
    }

    // Inspect binary Mach-O slices & FairPlay encryption status (LC_ENCRYPTION_INFO_64 cryptid)
    NSDictionary *machInfo = il2cppBinaryPath ? MCPInspectMachOAtPath(il2cppBinaryPath, NULL) : nil;
    BOOL binaryEncrypted = NO;
    uint32_t binaryCryptId = 0;
    NSMutableArray<NSString *> *binaryArchs = [NSMutableArray array];
    NSMutableDictionary *textSegInfo = [NSMutableDictionary dictionary];

    if ([machInfo[@"slices"] isKindOfClass:[NSArray class]]) {
        for (NSDictionary *slice in (NSArray *)machInfo[@"slices"]) {
            if ([slice[@"arch"] isKindOfClass:[NSString class]]) {
                [binaryArchs addObject:slice[@"arch"]];
            }
            NSDictionary *enc = [slice[@"encryption"] isKindOfClass:[NSDictionary class]] ? slice[@"encryption"] : nil;
            if ([enc[@"encrypted"] boolValue]) {
                binaryEncrypted = YES;
                binaryCryptId = [enc[@"cryptid"] unsignedIntValue];
            }
            if ([slice[@"segments"] isKindOfClass:[NSArray class]]) {
                for (NSDictionary *seg in (NSArray *)slice[@"segments"]) {
                    if ([seg[@"name"] isEqualToString:@"__TEXT"]) {
                        textSegInfo[@"vmaddr"] = seg[@"vmaddr"] ?: @"0x0";
                        textSegInfo[@"vmsize"] = seg[@"vmsize"] ?: @0;
                    }
                }
            }
        }
    }

    // Struct strides by metadata version
    size_t imageStride = (version >= 24) ? 40 : 28;
    if (sec.imagesSize > 0 && (sec.imagesSize % 40) != 0 && (sec.imagesSize % 28) == 0) {
        imageStride = 28;
    }
    size_t typeStride = 88;
    if (version == 24 && (sec.typeDefinitionsSize % 88) != 0) {
        if ((sec.typeDefinitionsSize % 92) == 0) typeStride = 92;
        else if ((sec.typeDefinitionsSize % 100) == 0) typeStride = 100;
    }
    size_t methodStride = (version >= 31) ? 36 : ((version >= 27) ? 32 : 56);
    if (sec.methodsSize > 0 && (sec.methodsSize % methodStride) != 0) {
        if ((sec.methodsSize % 36) == 0) methodStride = 36;
        else if ((sec.methodsSize % 32) == 0) methodStride = 32;
        else if ((sec.methodsSize % 52) == 0) methodStride = 52;
    }
    size_t fieldStride = 12;

    size_t totalImages = imageStride ? (sec.imagesSize / imageStride) : 0;
    size_t totalTypes = typeStride ? (sec.typeDefinitionsSize / typeStride) : 0;
    size_t totalMethods = methodStride ? (sec.methodsSize / methodStride) : 0;
    size_t totalFields = fieldStride ? (sec.fieldsSize / fieldStride) : 0;
    size_t totalStringLiterals = sec.stringLiteralSize / 8;

    // 1. Parse Images (Managed Assemblies)
    NSMutableArray<NSDictionary *> *imagesOut = [NSMutableArray arrayWithCapacity:totalImages];
    NSMutableDictionary<NSNumber *, NSString *> *imageNameByTypeIdx = [NSMutableDictionary dictionary];

    for (size_t i = 0; i < totalImages; i++) {
        size_t off = (size_t)sec.imagesOffset + i * imageStride;
        int32_t nameIdx = -1, asmIdx = -1, typeStart = -1;
        uint32_t typeCount = 0, token = 0;
        MCPReadI32LE(buf, len, off + 0, &nameIdx);
        MCPReadI32LE(buf, len, off + 4, &asmIdx);
        MCPReadI32LE(buf, len, off + 8, &typeStart);
        MCPReadU32LE(buf, len, off + 12, &typeCount);
        if (imageStride >= 32) {
            MCPReadU32LE(buf, len, off + 28, &token);
        }
        NSString *imgName = MCPIL2CPPReadCString(buf, len, sec.stringOffset, sec.stringSize, nameIdx);
        [imagesOut addObject:@{
            @"index": @(i),
            @"name": imgName,
            @"assembly_index": @(asmIdx),
            @"type_start": @(typeStart),
            @"type_count": @(typeCount),
            @"token": [NSString stringWithFormat:@"0x%08x", token]
        }];
        if (typeStart >= 0) {
            for (uint32_t t = 0; t < typeCount && ((size_t)typeStart + t) < totalTypes; t++) {
                imageNameByTypeIdx[@((size_t)typeStart + t)] = imgName;
            }
        }
    }

    // 2. Parse TypeDefinitions, Methods, and Fields
    NSMutableArray<NSDictionary *> *typesOut = [NSMutableArray array];
    for (size_t tIdx = 0; tIdx < totalTypes && typesOut.count < maxTypes; tIdx++) {
        NSString *ownerImage = imageNameByTypeIdx[@(tIdx)] ?: @"";
        if (imageFilter.length > 0 &&
            [ownerImage rangeOfString:imageFilter options:NSCaseInsensitiveSearch].location == NSNotFound) {
            continue;
        }

        size_t tOff = (size_t)sec.typeDefinitionsOffset + tIdx * typeStride;
        int32_t nameIdx = -1, nsIdx = -1, flags = 0, fieldStart = -1, methodStart = -1;
        uint16_t methodCount = 0, propCount = 0, fieldCount = 0;
        uint32_t token = 0;

        MCPReadI32LE(buf, len, tOff + 0, &nameIdx);
        MCPReadI32LE(buf, len, tOff + 4, &nsIdx);

        if (typeStride == 88) {
            MCPReadI32LE(buf, len, tOff + 28, &flags);
            MCPReadI32LE(buf, len, tOff + 32, &fieldStart);
            MCPReadI32LE(buf, len, tOff + 36, &methodStart);
            MCPReadU16LE(buf, len, tOff + 64, &methodCount);
            MCPReadU16LE(buf, len, tOff + 66, &propCount);
            MCPReadU16LE(buf, len, tOff + 68, &fieldCount);
            MCPReadU32LE(buf, len, tOff + 84, &token);
        } else {
            MCPReadI32LE(buf, len, tOff + 32, &flags);
            MCPReadI32LE(buf, len, tOff + 36, &fieldStart);
            MCPReadI32LE(buf, len, tOff + 40, &methodStart);
            MCPReadU16LE(buf, len, tOff + 68, &methodCount);
            MCPReadU16LE(buf, len, tOff + 70, &propCount);
            MCPReadU16LE(buf, len, tOff + 72, &fieldCount);
            MCPReadU32LE(buf, len, tOff + typeStride - 4, &token);
        }

        NSString *typeName = MCPIL2CPPReadCString(buf, len, sec.stringOffset, sec.stringSize, nameIdx);
        NSString *nsName = MCPIL2CPPReadCString(buf, len, sec.stringOffset, sec.stringSize, nsIdx);
        NSString *fullName = nsName.length > 0 ? [NSString stringWithFormat:@"%@.%@", nsName, typeName] : typeName;

        if (typeFilter.length > 0 &&
            [fullName rangeOfString:typeFilter options:NSCaseInsensitiveSearch].location == NSNotFound) {
            continue;
        }

        // Methods of this TypeDefinition (cap 64 per type to keep MCP response bounded)
        NSMutableArray<NSDictionary *> *methodsList = [NSMutableArray array];
        if (methodStart >= 0 && methodCount > 0) {
            uint16_t mCap = MIN(methodCount, (uint16_t)64);
            for (uint16_t m = 0; m < mCap; m++) {
                size_t mIdx = (size_t)methodStart + m;
                if (mIdx >= totalMethods) break;
                size_t mOff = (size_t)sec.methodsOffset + mIdx * methodStride;
                int32_t mNameIdx = -1, retType = -1, paramStart = -1;
                uint32_t mToken = 0;
                uint16_t mFlags = 0, mParams = 0;
                MCPReadI32LE(buf, len, mOff + 0, &mNameIdx);
                MCPReadI32LE(buf, len, mOff + 8, &retType);
                if (methodStride == 36) {
                    // v31 layout verified on device
                    MCPReadI32LE(buf, len, mOff + 16, &paramStart);
                    MCPReadU32LE(buf, len, mOff + 24, &mToken);
                    MCPReadU16LE(buf, len, mOff + 28, &mFlags);
                    MCPReadU16LE(buf, len, mOff + 34, &mParams);
                } else if (methodStride == 32) {
                    // v27..v29 layout
                    MCPReadI32LE(buf, len, mOff + 12, &paramStart);
                    MCPReadU32LE(buf, len, mOff + 20, &mToken);
                    MCPReadU16LE(buf, len, mOff + 24, &mFlags);
                    MCPReadU16LE(buf, len, mOff + 30, &mParams);
                } else {
                    // v24 layout (56 bytes)
                    MCPReadI32LE(buf, len, mOff + 12, &paramStart);
                    MCPReadU32LE(buf, len, mOff + 44, &mToken);
                    MCPReadU16LE(buf, len, mOff + 48, &mFlags);
                    MCPReadU16LE(buf, len, mOff + 54, &mParams);
                }
                NSString *mName = MCPIL2CPPReadCString(buf, len, sec.stringOffset, sec.stringSize, mNameIdx);
                [methodsList addObject:@{
                    @"method_index": @(mIdx),
                    @"name": mName,
                    @"token": [NSString stringWithFormat:@"0x%08x", mToken],
                    @"flags": [NSString stringWithFormat:@"0x%04x", mFlags],
                    @"param_count": @(mParams),
                    @"return_type_index": @(retType)
                }];
            }
        }

        // Fields of this TypeDefinition (cap 64 per type)
        NSMutableArray<NSDictionary *> *fieldsList = [NSMutableArray array];
        if (fieldStart >= 0 && fieldCount > 0) {
            uint16_t fCap = MIN(fieldCount, (uint16_t)64);
            for (uint16_t f = 0; f < fCap; f++) {
                size_t fIdx = (size_t)fieldStart + f;
                if (fIdx >= totalFields) break;
                size_t fOff = (size_t)sec.fieldsOffset + fIdx * fieldStride;
                int32_t fNameIdx = -1, fWord1 = 0, fWord2 = 0;
                MCPReadI32LE(buf, len, fOff + 0, &fNameIdx);
                MCPReadI32LE(buf, len, fOff + 4, &fWord1);
                MCPReadI32LE(buf, len, fOff + 8, &fWord2);
                uint32_t fToken = (((uint32_t)fWord1 & 0xFF000000U) == 0x04000000U || ((uint32_t)fWord1 & 0xFF000000U) == 0x08000000U)
                    ? (uint32_t)fWord1 : (uint32_t)fWord2;
                int32_t fTypeIdx = (fToken == (uint32_t)fWord1) ? fWord2 : fWord1;
                NSString *fName = MCPIL2CPPReadCString(buf, len, sec.stringOffset, sec.stringSize, fNameIdx);
                [fieldsList addObject:@{
                    @"field_index": @(fIdx),
                    @"name": fName,
                    @"type_index": @(fTypeIdx),
                    @"token": [NSString stringWithFormat:@"0x%08x", fToken]
                }];
            }
        }

        [typesOut addObject:@{
            @"type_index": @(tIdx),
            @"image": ownerImage,
            @"namespace": nsName,
            @"name": typeName,
            @"full_name": fullName,
            @"token": [NSString stringWithFormat:@"0x%08x", token],
            @"flags": [NSString stringWithFormat:@"0x%08x", (uint32_t)flags],
            @"method_count": @(methodCount),
            @"field_count": @(fieldCount),
            @"property_count": @(propCount),
            @"methods": methodsList,
            @"fields": fieldsList
        }];
    }

    // 3. Parse String Literals sample
    NSMutableArray<NSDictionary *> *literalsOut = [NSMutableArray array];
    size_t litCap = MIN(totalStringLiterals, (size_t)maxStringLiterals);
    for (size_t lIdx = 0; lIdx < litCap; lIdx++) {
        size_t lOff = (size_t)sec.stringLiteralOffset + lIdx * 8;
        uint32_t sLen = 0;
        int32_t dataIdx = -1;
        if (!MCPReadU32LE(buf, len, lOff, &sLen) || !MCPReadI32LE(buf, len, lOff + 4, &dataIdx)) break;
        if (dataIdx < 0 || (uint64_t)dataIdx + (uint64_t)sLen > (uint64_t)sec.stringLiteralDataSize) continue;
        size_t dOff = (size_t)sec.stringLiteralDataOffset + (size_t)dataIdx;
        if (dOff + sLen > len) continue;
        NSUInteger previewLen = MIN((NSUInteger)sLen, (NSUInteger)256);
        NSString *val = [[NSString alloc] initWithBytes:(buf + dOff) length:previewLen encoding:NSUTF8StringEncoding] ?: @"";
        [literalsOut addObject:@{
            @"index": @(lIdx),
            @"length": @(sLen),
            @"value": val,
            @"truncated": @(sLen > 256)
        }];
    }

    NSString *codeGenNote = binaryEncrypted
        ? [NSString stringWithFormat:@"IL2CPP binary __TEXT is FairPlay encrypted on disk (LC_ENCRYPTION_INFO_64 cryptid=%u); metadata tokens/indices are fully dumped from global-metadata.dat, while on-disk CodeRegistration RVAs require decrypting __TEXT in memory first (e.g. via read_memory / frida_memory_scan while running).", binaryCryptId]
        : @"IL2CPP binary is unencrypted on disk (cryptid=0); metadata tokens, method/field indices, managed assemblies, and string literals extracted from global-metadata.dat.";

    return @{
        @"bundle_id": bundleId,
        @"metadata_path": metadataPath,
        @"metadata_size": @(len),
        @"metadata_magic": [NSString stringWithFormat:@"0x%08x", magic],
        @"metadata_version": @(version),
        @"il2cpp_binary_path": il2cppBinaryPath ?: @"",
        @"binary_architectures": binaryArchs,
        @"binary_fairplay_encrypted": @(binaryEncrypted),
        @"binary_cryptid": @(binaryCryptId),
        @"text_segment": textSegInfo,
        @"rva_status": binaryEncrypted ? @"unavailable_fairplay_encrypted_on_disk" : @"metadata_tokens_and_indices_extracted",
        @"note": codeGenNote,
        @"counts": @{
            @"images": @(totalImages),
            @"type_definitions": @(totalTypes),
            @"method_definitions": @(totalMethods),
            @"field_definitions": @(totalFields),
            @"string_literals": @(totalStringLiterals)
        },
        @"strides": @{
            @"image_stride": @(imageStride),
            @"type_stride": @(typeStride),
            @"method_stride": @(methodStride),
            @"field_stride": @(fieldStride)
        },
        @"images": imagesOut,
        @"returned_type_count": @(typesOut.count),
        @"types": typesOut,
        @"returned_string_literal_count": @(literalsOut.count),
        @"string_literals": literalsOut
    };
}

@end
