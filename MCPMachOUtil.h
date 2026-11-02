#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Inspect a thin or universal Mach-O file on disk (slices, segments, load dylibs, rpaths,
/// encryption info, UUID, code signature & embedded entitlements).
FOUNDATION_EXPORT NSDictionary * _Nullable MCPInspectMachOAtPath(NSString *path,
                                                                 NSString * _Nullable * _Nullable error);

/// Extract embedded entitlements dictionary and raw XML from a Mach-O's LC_CODE_SIGNATURE
/// (CSSLOT_ENTITLEMENTS / 0xfade7171) across slices. Returns @{@"entitlements": dict, @"xml": xmlString}.
FOUNDATION_EXPORT NSDictionary * _Nullable MCPExtractEntitlementsFromMachO(NSString *path,
                                                                           NSString * _Nullable * _Nullable error);

/// Inject an LC_LOAD_DYLIB load command into all 64-bit Mach-O slices of `binaryPath`.
/// Creates `<binaryPath>.mcp_orig` backup once before the first modification and writes to
/// a fresh vnode (temp file + unlink + rename) to avoid iOS kernel cs_blob page cache kills.
FOUNDATION_EXPORT NSDictionary * _Nullable MCPInjectLoadDylibInMachO(NSString *binaryPath,
                                                                     NSString *dylibInstallPath,
                                                                     NSString * _Nullable * _Nullable error);

/// Remove matching LC_LOAD_DYLIB / LC_LOAD_WEAK_DYLIB load command(s) from all 64-bit Mach-O
/// slices of `binaryPath`, or restore `<binaryPath>.mcp_orig` when `restoreOriginal` is YES.
/// Writes to a fresh vnode.
FOUNDATION_EXPORT NSDictionary * _Nullable MCPRemoveLoadDylibFromMachO(NSString *binaryPath,
                                                                       NSString * _Nullable dylibMatch,
                                                                       BOOL restoreOriginal,
                                                                       NSString * _Nullable * _Nullable error);

/// Best-effort on-device symbolication of image-relative offsets (`runtimeAddr - imageLoadAddr`)
/// against `binaryPath` using LC_SYMTAB, LC_DYLD_EXPORTS_TRIE / LC_DYLD_INFO, Objective-C
/// __objc_classlist method addresses, and LC_FUNCTION_STARTS boundaries (no external dSYM required).
FOUNDATION_EXPORT NSDictionary<NSNumber *, NSDictionary *> * _Nullable MCPSymbolicateOffsetsInMachO(
    NSString *binaryPath,
    NSString * _Nullable preferredArch,
    NSArray<NSNumber *> *imageOffsets,
    NSString * _Nullable * _Nullable error);

/// Deterministically scrub Frida/Gum signature tokens (`gum-js-loop`, `frida`, `gmain`, `gdbus`,
/// and prefix-bounded `gum`) inside `__TEXT,__cstring` and `LC_ID_DYLIB` across all slices of
/// `inputPath` using same-length alphabetic replacements derived from `seed`, writing to a
/// fresh vnode at `outputPath`.
FOUNDATION_EXPORT NSDictionary * _Nullable MCPScrubMachOBinaryAtPath(NSString *inputPath,
                                                                     NSString *outputPath,
                                                                     uint64_t seed,
                                                                     NSString * _Nullable * _Nullable error);

NS_ASSUME_NONNULL_END
