#import <Foundation/Foundation.h>

@interface BinaryInspector : NSObject

+ (instancetype)sharedInstance;

/// [Upgrade 01] Zero-Injection Out-of-Process FairPlay Decryptor & Clean .ipa Packager
- (NSDictionary *)decryptAppIPAForArgs:(NSDictionary *)args error:(NSString **)error;

/// [Upgrade 02] On-Device ARM64e Disassembler, CFG & Pseudo-C Decompiler
- (NSDictionary *)decompileFunctionForArgs:(NSDictionary *)args error:(NSString **)error;
- (NSDictionary *)decompileObjCMethodForArgs:(NSDictionary *)args error:(NSString **)error;
- (NSDictionary *)findXrefsForArgs:(NSDictionary *)args error:(NSString **)error;

/// [Upgrade 03] Zero-Memory-Patch ARM64 Hardware Debug Register (DBGBVR/DBGBCR) Hooking
- (NSDictionary *)hardwareBreakpointForArgs:(NSDictionary *)args error:(NSString **)error;

/// [Upgrade 05] Full Swift 5 Reflection, Type Reconstruction & Witness Table Mapper
- (NSDictionary *)dumpSwiftMetadataForArgs:(NSDictionary *)args error:(NSString **)error;

/// [Upgrade 08] Live In-Memory System Framework & Private API Extractor (dyld_shared_cache)
- (NSDictionary *)extractDyldSharedCacheForArgs:(NSDictionary *)args error:(NSString **)error;

/// [Upgrade 10] React Native Hermes Bytecode & Flutter Dart AOT Snapshot Inspector
- (NSDictionary *)inspectHermesFlutterForArgs:(NSDictionary *)args error:(NSString **)error;
- (NSDictionary *)inspectJsBundleForArgs:(NSDictionary *)args error:(NSString **)error;
- (NSDictionary *)decodeJsBundleForArgs:(NSDictionary *)args error:(NSString **)error;
- (NSDictionary *)listHermesDecodersForArgs:(NSDictionary *)args error:(NSString **)error;

@end
