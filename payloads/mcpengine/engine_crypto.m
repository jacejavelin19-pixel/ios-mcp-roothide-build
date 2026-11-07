#import "engine_rpc.h"
#include "fishhook.h"
#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonKeyDerivation.h>
#include <Security/Security.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <fcntl.h>
#include <libkern/OSByteOrder.h>
#include <mach-o/dyld.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static _Atomic int g_crypto_active = 0;
static _Atomic uint64_t g_crypto_seq = 0;
static pthread_mutex_t g_crypto_mutex = PTHREAD_MUTEX_INITIALIZER;
static NSMutableArray<NSDictionary *> *g_crypto_events = nil;
static NSMutableArray<NSDictionary *> *g_crypto_bound_slots = nil;

typedef struct {
    const void *ref;
    uint32_t op;
    uint32_t alg;
    uint32_t mode;
    uint32_t options;
    uint8_t key[64];
    size_t keyLen;
    uint8_t iv[32];
    BOOL hasIV;
    BOOL active;
} MECryptorContext;

#define ME_MAX_CRYPTOR_CTXS 64
static MECryptorContext g_cryptor_ctxs[ME_MAX_CRYPTOR_CTXS];

static NSString *MECryptoLogPath(void) {
    return [NSTemporaryDirectory() stringByAppendingPathComponent:@".mcp_crypto.jsonl"];
}

static NSString *MEBytesToHex(const void *bytes, size_t len, size_t maxBytes) {
    if (!bytes || len == 0) return @"";
    size_t n = MIN(len, maxBytes);
    const uint8_t *b = (const uint8_t *)bytes;
    NSMutableString *hex = [NSMutableString stringWithCapacity:n * 2];
    for (size_t i = 0; i < n; i++) {
        [hex appendFormat:@"%02x", b[i]];
    }
    return hex;
}

static NSString *MEBytesToPrintableUTF8(const void *bytes, size_t len, size_t maxBytes) {
    if (!bytes || len == 0) return nil;
    size_t n = MIN(len, maxBytes);
    const uint8_t *b = (const uint8_t *)bytes;
    for (size_t i = 0; i < n; i++) {
        uint8_t c = b[i];
        if (c < 0x20 && c != '\n' && c != '\r' && c != '\t') return nil;
        if (c > 0x7E) return nil;
    }
    return [[NSString alloc] initWithBytes:b length:n encoding:NSUTF8StringEncoding];
}

static NSArray<NSString *> *MECaptureBacktrace(unsigned maxFrames) {
    void *frames[16];
    int count = backtrace(frames, (int)MIN(maxFrames + 2, 16u));
    NSMutableArray<NSString *> *out = [NSMutableArray array];
    for (int i = 2; i < count; i++) {
        Dl_info info = {0};
        uintptr_t pc = (uintptr_t)frames[i] & 0x00007fffffffffffULL;
        if (dladdr((const void *)pc, &info) && info.dli_fname) {
            const char *slash = strrchr(info.dli_fname, '/');
            const char *img = slash ? (slash + 1) : info.dli_fname;
            uintptr_t off = pc - (uintptr_t)info.dli_fbase;
            if (info.dli_sname) {
                [out addObject:[NSString stringWithFormat:@"%s!%s (0x%llx, +0x%llx)",
                                img, info.dli_sname, (unsigned long long)pc, (unsigned long long)off]];
            } else {
                [out addObject:[NSString stringWithFormat:@"%s+0x%llx (0x%llx)",
                                img, (unsigned long long)off, (unsigned long long)pc]];
            }
        } else {
            [out addObject:MEHex(pc)];
        }
    }
    return out;
}

static NSString *MECCAlgName(CCAlgorithm alg, size_t keyLen) {
    switch (alg) {
        case kCCAlgorithmAES:
            if (keyLen == 16) return @"AES-128";
            if (keyLen == 24) return @"AES-192";
            if (keyLen == 32) return @"AES-256";
            return @"AES";
        case kCCAlgorithmDES: return @"DES";
        case kCCAlgorithm3DES: return @"3DES";
        case kCCAlgorithmCAST: return @"CAST";
        case kCCAlgorithmRC4: return @"RC4";
        case kCCAlgorithmRC2: return @"RC2";
        case kCCAlgorithmBlowfish: return @"Blowfish";
        default: return [NSString stringWithFormat:@"CCAlg(%u)", (unsigned)alg];
    }
}

static NSString *MECCModeName(CCMode mode, CCOptions options) {
    if (mode != 0) {
        switch (mode) {
            case kCCModeECB: return @"ECB";
            case kCCModeCBC: return @"CBC";
            case kCCModeCFB: return @"CFB";
            case kCCModeCTR: return @"CTR";
            case kCCModeOFB: return @"OFB";
            case kCCModeRC4: return @"RC4";
            case kCCModeCFB8: return @"CFB8";
            case 11: return @"GCM"; // kCCModeGCM
            default: break;
        }
    }
    return (options & kCCOptionECBMode) ? @"ECB" : @"CBC";
}

static NSString *MECCHmacAlgName(CCHmacAlgorithm alg) {
    switch (alg) {
        case kCCHmacAlgSHA1: return @"HMAC-SHA1";
        case kCCHmacAlgMD5: return @"HMAC-MD5";
        case kCCHmacAlgSHA256: return @"HMAC-SHA256";
        case kCCHmacAlgSHA384: return @"HMAC-SHA384";
        case kCCHmacAlgSHA512: return @"HMAC-SHA512";
        case kCCHmacAlgSHA224: return @"HMAC-SHA224";
        default: return [NSString stringWithFormat:@"HMAC(%u)", (unsigned)alg];
    }
}

static size_t MECCHmacDigestLength(CCHmacAlgorithm alg) {
    switch (alg) {
        case kCCHmacAlgSHA1: return 20;
        case kCCHmacAlgMD5: return 16;
        case kCCHmacAlgSHA224: return 28;
        case kCCHmacAlgSHA256: return 32;
        case kCCHmacAlgSHA384: return 48;
        case kCCHmacAlgSHA512: return 64;
        default: return 32;
    }
}

static void MERecordCryptoEvent(NSDictionary *event) {
    if (!atomic_load(&g_crypto_active) || !event) return;
    pthread_mutex_lock(&g_crypto_mutex);
    if (!g_crypto_events) g_crypto_events = [NSMutableArray array];
    if (g_crypto_events.count >= 512) {
        [g_crypto_events removeObjectAtIndex:0];
    }
    [g_crypto_events addObject:event];
    pthread_mutex_unlock(&g_crypto_mutex);

    NSData *json = [NSJSONSerialization dataWithJSONObject:event options:0 error:NULL];
    if (json.length) {
        int fd = open(MECryptoLogPath().fileSystemRepresentation, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
        if (fd >= 0) {
            write(fd, json.bytes, json.length);
            write(fd, "\n", 1);
            close(fd);
        }
    }
}

#pragma mark - Original Function Pointers

static CCCryptorStatus (*orig_CCCrypt)(CCOperation op, CCAlgorithm alg, CCOptions options,
                                       const void *key, size_t keyLength, const void *iv,
                                       const void *dataIn, size_t dataInLength,
                                       void *dataOut, size_t dataOutAvailable, size_t *dataOutMoved) = NULL;

static CCCryptorStatus (*orig_CCCryptorCreate)(CCOperation op, CCAlgorithm alg, CCOptions options,
                                               const void *key, size_t keyLength, const void *iv,
                                               CCCryptorRef *cryptorRef) = NULL;

static CCCryptorStatus (*orig_CCCryptorCreateWithMode)(CCOperation op, CCMode mode, CCAlgorithm alg,
                                                       CCPadding padding, const void *iv,
                                                       const void *key, size_t keyLength,
                                                       const void *tweak, size_t tweakLength,
                                                       int numRounds, CCModeOptions options,
                                                       CCCryptorRef *cryptorRef) = NULL;

static CCCryptorStatus (*orig_CCCryptorUpdate)(CCCryptorRef cryptorRef, const void *dataIn,
                                               size_t dataInLength, void *dataOut,
                                               size_t dataOutAvailable, size_t *dataOutMoved) = NULL;

static CCCryptorStatus (*orig_CCCryptorFinal)(CCCryptorRef cryptorRef, void *dataOut,
                                              size_t dataOutAvailable, size_t *dataOutMoved) = NULL;

static void (*orig_CCHmac)(CCHmacAlgorithm algorithm, const void *key, size_t keyLength,
                           const void *data, size_t dataLength, void *macOut) = NULL;

static int (*orig_CCKeyDerivationPBKDF)(CCPBKDFAlgorithm algorithm, const char *password,
                                        size_t passwordLen, const uint8_t *salt, size_t saltLen,
                                        CCPseudoRandomAlgorithm prf, unsigned rounds,
                                        uint8_t *derivedKey, size_t derivedKeyLen) = NULL;

static CFDataRef (*orig_SecKeyCreateEncryptedData)(SecKeyRef key, SecKeyAlgorithm algorithm,
                                                   CFDataRef plaintext, CFErrorRef *error) = NULL;

static CFDataRef (*orig_SecKeyCreateDecryptedData)(SecKeyRef key, SecKeyAlgorithm algorithm,
                                                   CFDataRef ciphertext, CFErrorRef *error) = NULL;

static CFDataRef (*orig_SecKeyCreateSignature)(SecKeyRef key, SecKeyAlgorithm algorithm,
                                               CFDataRef dataToSign, CFErrorRef *error) = NULL;

static int (*orig_EVP_CipherInit_ex)(void *ctx, const void *cipher, void *impl,
                                     const unsigned char *key, const unsigned char *iv, int enc) = NULL;

static int (*orig_EVP_EncryptUpdate)(void *ctx, unsigned char *out, int *outl,
                                     const unsigned char *in, int inl) = NULL;

static int (*orig_EVP_DecryptUpdate)(void *ctx, unsigned char *out, int *outl,
                                     const unsigned char *in, int inl) = NULL;

#pragma mark - Hook Implementations

static CCCryptorStatus hook_CCCrypt(CCOperation op, CCAlgorithm alg, CCOptions options,
                                    const void *key, size_t keyLength, const void *iv,
                                    const void *dataIn, size_t dataInLength,
                                    void *dataOut, size_t dataOutAvailable, size_t *dataOutMoved) {
    size_t localMoved = 0;
    size_t *movedPtr = dataOutMoved ? dataOutMoved : &localMoved;
    CCCryptorStatus status = orig_CCCrypt
        ? orig_CCCrypt(op, alg, options, key, keyLength, iv, dataIn, dataInLength, dataOut, dataOutAvailable, movedPtr)
        : kCCUnimplemented;

    if (atomic_load(&g_crypto_active) && MEDepth == 0) {
        MEDepth++;
        @try {
            uint64_t seq = atomic_fetch_add(&g_crypto_seq, 1) + 1;
            BOOL isEnc = (op == kCCEncrypt);
            const void *ptBuf = isEnc ? dataIn : dataOut;
            size_t ptLen = isEnc ? dataInLength : *movedPtr;
            const void *ctBuf = isEnc ? dataOut : dataIn;
            size_t ctLen = isEnc ? *movedPtr : dataInLength;
            size_t ivLen = (alg == kCCAlgorithmAES) ? 16 : 8;

            NSMutableDictionary *ev = [NSMutableDictionary dictionaryWithDictionary:@{
                @"id": @(seq),
                @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                @"primitive": @"CCCrypt",
                @"operation": isEnc ? @"encrypt" : @"decrypt",
                @"algorithm": MECCAlgName(alg, keyLength),
                @"mode": MECCModeName(0, options),
                @"key_bits": @(keyLength * 8),
                @"key_hex": MEBytesToHex(key, keyLength, 64),
                @"iv_hex": iv ? MEBytesToHex(iv, ivLen, 32) : @"",
                @"plaintext_size": @(ptLen),
                @"plaintext_hex": MEBytesToHex(ptBuf, ptLen, 1024),
                @"ciphertext_size": @(ctLen),
                @"ciphertext_hex": MEBytesToHex(ctBuf, ctLen, 1024),
                @"status": @(status),
                @"backtrace": MECaptureBacktrace(6)
            }];
            NSString *keyUtf8 = MEBytesToPrintableUTF8(key, keyLength, 64);
            if (keyUtf8.length) ev[@"key_utf8"] = keyUtf8;
            NSString *ptUtf8 = MEBytesToPrintableUTF8(ptBuf, ptLen, 2048);
            if (ptUtf8.length) ev[@"plaintext_utf8"] = ptUtf8;
            MERecordCryptoEvent(ev);
        } @catch (NSException *ignored) {}
        @finally { MEDepth--; }
    }
    return status;
}

static void METrackCryptor(const void *ref, uint32_t op, uint32_t alg, uint32_t mode, uint32_t options,
                           const void *key, size_t keyLen, const void *iv) {
    if (!ref) return;
    pthread_mutex_lock(&g_crypto_mutex);
    size_t slot = ((uintptr_t)ref >> 4) % ME_MAX_CRYPTOR_CTXS;
    MECryptorContext *ctx = &g_cryptor_ctxs[slot];
    ctx->ref = ref;
    ctx->op = op;
    ctx->alg = alg;
    ctx->mode = mode;
    ctx->options = options;
    ctx->keyLen = MIN(keyLen, sizeof(ctx->key));
    if (key && ctx->keyLen > 0) memcpy(ctx->key, key, ctx->keyLen);
    ctx->hasIV = (iv != NULL);
    if (iv) memcpy(ctx->iv, iv, 16);
    ctx->active = YES;
    pthread_mutex_unlock(&g_crypto_mutex);
}

static CCCryptorStatus hook_CCCryptorCreate(CCOperation op, CCAlgorithm alg, CCOptions options,
                                            const void *key, size_t keyLength, const void *iv,
                                            CCCryptorRef *cryptorRef) {
    CCCryptorStatus st = orig_CCCryptorCreate
        ? orig_CCCryptorCreate(op, alg, options, key, keyLength, iv, cryptorRef)
        : kCCUnimplemented;
    if (st == kCCSuccess && cryptorRef && *cryptorRef && atomic_load(&g_crypto_active)) {
        METrackCryptor(*cryptorRef, op, alg, 0, options, key, keyLength, iv);
    }
    return st;
}

static CCCryptorStatus hook_CCCryptorCreateWithMode(CCOperation op, CCMode mode, CCAlgorithm alg,
                                                    CCPadding padding, const void *iv,
                                                    const void *key, size_t keyLength,
                                                    const void *tweak, size_t tweakLength,
                                                    int numRounds, CCModeOptions options,
                                                    CCCryptorRef *cryptorRef) {
    CCCryptorStatus st = orig_CCCryptorCreateWithMode
        ? orig_CCCryptorCreateWithMode(op, mode, alg, padding, iv, key, keyLength, tweak, tweakLength, numRounds, options, cryptorRef)
        : kCCUnimplemented;
    if (st == kCCSuccess && cryptorRef && *cryptorRef && atomic_load(&g_crypto_active)) {
        METrackCryptor(*cryptorRef, op, alg, mode, options, key, keyLength, iv);
    }
    return st;
}

static CCCryptorStatus hook_CCCryptorUpdate(CCCryptorRef cryptorRef, const void *dataIn,
                                            size_t dataInLength, void *dataOut,
                                            size_t dataOutAvailable, size_t *dataOutMoved) {
    size_t localMoved = 0;
    size_t *movedPtr = dataOutMoved ? dataOutMoved : &localMoved;
    CCCryptorStatus st = orig_CCCryptorUpdate
        ? orig_CCCryptorUpdate(cryptorRef, dataIn, dataInLength, dataOut, dataOutAvailable, movedPtr)
        : kCCUnimplemented;

    if (st == kCCSuccess && atomic_load(&g_crypto_active) && MEDepth == 0 && dataInLength > 0) {
        MEDepth++;
        @try {
            MECryptorContext snap = {0};
            pthread_mutex_lock(&g_crypto_mutex);
            size_t slot = ((uintptr_t)cryptorRef >> 4) % ME_MAX_CRYPTOR_CTXS;
            if (g_cryptor_ctxs[slot].active && g_cryptor_ctxs[slot].ref == cryptorRef) {
                snap = g_cryptor_ctxs[slot];
            }
            pthread_mutex_unlock(&g_crypto_mutex);

            BOOL isEnc = (snap.op == kCCEncrypt);
            const void *ptBuf = isEnc ? dataIn : dataOut;
            size_t ptLen = isEnc ? dataInLength : *movedPtr;
            const void *ctBuf = isEnc ? dataOut : dataIn;
            size_t ctLen = isEnc ? *movedPtr : dataInLength;
            uint64_t seq = atomic_fetch_add(&g_crypto_seq, 1) + 1;

            NSMutableDictionary *ev = [NSMutableDictionary dictionaryWithDictionary:@{
                @"id": @(seq),
                @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                @"primitive": @"CCCryptorUpdate",
                @"operation": isEnc ? @"encrypt" : @"decrypt",
                @"algorithm": snap.active ? MECCAlgName(snap.alg, snap.keyLen) : @"AES",
                @"mode": snap.active ? MECCModeName(snap.mode, snap.options) : @"CBC/GCM",
                @"key_hex": snap.active ? MEBytesToHex(snap.key, snap.keyLen, 64) : @"",
                @"iv_hex": (snap.active && snap.hasIV) ? MEBytesToHex(snap.iv, 16, 16) : @"",
                @"plaintext_size": @(ptLen),
                @"plaintext_hex": MEBytesToHex(ptBuf, ptLen, 1024),
                @"ciphertext_size": @(ctLen),
                @"ciphertext_hex": MEBytesToHex(ctBuf, ctLen, 1024),
                @"backtrace": MECaptureBacktrace(5)
            }];
            NSString *ptUtf8 = MEBytesToPrintableUTF8(ptBuf, ptLen, 2048);
            if (ptUtf8.length) ev[@"plaintext_utf8"] = ptUtf8;
            MERecordCryptoEvent(ev);
        } @catch (NSException *ignored) {}
        @finally { MEDepth--; }
    }
    return st;
}

static CCCryptorStatus hook_CCCryptorFinal(CCCryptorRef cryptorRef, void *dataOut,
                                           size_t dataOutAvailable, size_t *dataOutMoved) {
    return orig_CCCryptorFinal
        ? orig_CCCryptorFinal(cryptorRef, dataOut, dataOutAvailable, dataOutMoved)
        : kCCUnimplemented;
}

static void hook_CCHmac(CCHmacAlgorithm algorithm, const void *key, size_t keyLength,
                        const void *data, size_t dataLength, void *macOut) {
    if (orig_CCHmac) {
        orig_CCHmac(algorithm, key, keyLength, data, dataLength, macOut);
    }
    if (atomic_load(&g_crypto_active) && MEDepth == 0) {
        MEDepth++;
        @try {
            uint64_t seq = atomic_fetch_add(&g_crypto_seq, 1) + 1;
            size_t macLen = MECCHmacDigestLength(algorithm);
            NSMutableDictionary *ev = [NSMutableDictionary dictionaryWithDictionary:@{
                @"id": @(seq),
                @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                @"primitive": @"CCHmac",
                @"operation": @"hmac_sign",
                @"algorithm": MECCHmacAlgName(algorithm),
                @"key_bits": @(keyLength * 8),
                @"key_hex": MEBytesToHex(key, keyLength, 128),
                @"input_size": @(dataLength),
                @"input_hex": MEBytesToHex(data, dataLength, 1024),
                @"mac_hex": MEBytesToHex(macOut, macLen, 64),
                @"backtrace": MECaptureBacktrace(6)
            }];
            NSString *keyUtf8 = MEBytesToPrintableUTF8(key, keyLength, 128);
            if (keyUtf8.length) ev[@"key_utf8"] = keyUtf8;
            NSString *msgUtf8 = MEBytesToPrintableUTF8(data, dataLength, 2048);
            if (msgUtf8.length) ev[@"input_utf8"] = msgUtf8;
            MERecordCryptoEvent(ev);
        } @catch (NSException *ignored) {}
        @finally { MEDepth--; }
    }
}

static int hook_CCKeyDerivationPBKDF(CCPBKDFAlgorithm algorithm, const char *password,
                                     size_t passwordLen, const uint8_t *salt, size_t saltLen,
                                     CCPseudoRandomAlgorithm prf, unsigned rounds,
                                     uint8_t *derivedKey, size_t derivedKeyLen) {
    int rc = orig_CCKeyDerivationPBKDF
        ? orig_CCKeyDerivationPBKDF(algorithm, password, passwordLen, salt, saltLen, prf, rounds, derivedKey, derivedKeyLen)
        : -1;
    if (rc == kCCSuccess && atomic_load(&g_crypto_active) && MEDepth == 0) {
        MEDepth++;
        @try {
            uint64_t seq = atomic_fetch_add(&g_crypto_seq, 1) + 1;
            NSMutableDictionary *ev = [NSMutableDictionary dictionaryWithDictionary:@{
                @"id": @(seq),
                @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                @"primitive": @"CCKeyDerivationPBKDF",
                @"operation": @"kdf_pbkdf2",
                @"algorithm": @"PBKDF2",
                @"prf": @(prf),
                @"rounds": @(rounds),
                @"password_hex": MEBytesToHex(password, passwordLen, 128),
                @"salt_hex": MEBytesToHex(salt, saltLen, 64),
                @"derived_key_bits": @(derivedKeyLen * 8),
                @"derived_key_hex": MEBytesToHex(derivedKey, derivedKeyLen, 64),
                @"backtrace": MECaptureBacktrace(6)
            }];
            NSString *pwUtf8 = MEBytesToPrintableUTF8(password, passwordLen, 128);
            if (pwUtf8.length) ev[@"password_utf8"] = pwUtf8;
            MERecordCryptoEvent(ev);
        } @catch (NSException *ignored) {}
        @finally { MEDepth--; }
    }
    return rc;
}

static CFDataRef hook_SecKeyCreateEncryptedData(SecKeyRef key, SecKeyAlgorithm algorithm,
                                                CFDataRef plaintext, CFErrorRef *error) {
    CFDataRef out = orig_SecKeyCreateEncryptedData
        ? orig_SecKeyCreateEncryptedData(key, algorithm, plaintext, error)
        : NULL;
    if (atomic_load(&g_crypto_active) && MEDepth == 0 && plaintext) {
        MEDepth++;
        @try {
            NSData *pt = (__bridge NSData *)plaintext;
            NSData *ct = (__bridge NSData *)out;
            uint64_t seq = atomic_fetch_add(&g_crypto_seq, 1) + 1;
            NSMutableDictionary *ev = [NSMutableDictionary dictionaryWithDictionary:@{
                @"id": @(seq),
                @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                @"primitive": @"SecKeyCreateEncryptedData",
                @"operation": @"asymmetric_encrypt",
                @"algorithm": algorithm ? ((__bridge NSString *)algorithm) : @"SecKey",
                @"plaintext_size": @(pt.length),
                @"plaintext_hex": MEBytesToHex(pt.bytes, pt.length, 1024),
                @"ciphertext_size": @(ct.length),
                @"ciphertext_hex": MEBytesToHex(ct.bytes, ct.length, 1024),
                @"backtrace": MECaptureBacktrace(6)
            }];
            NSString *ptUtf8 = MEBytesToPrintableUTF8(pt.bytes, pt.length, 2048);
            if (ptUtf8.length) ev[@"plaintext_utf8"] = ptUtf8;
            MERecordCryptoEvent(ev);
        } @catch (NSException *ignored) {}
        @finally { MEDepth--; }
    }
    return out;
}

static CFDataRef hook_SecKeyCreateDecryptedData(SecKeyRef key, SecKeyAlgorithm algorithm,
                                                CFDataRef ciphertext, CFErrorRef *error) {
    CFDataRef out = orig_SecKeyCreateDecryptedData
        ? orig_SecKeyCreateDecryptedData(key, algorithm, ciphertext, error)
        : NULL;
    if (atomic_load(&g_crypto_active) && MEDepth == 0 && ciphertext) {
        MEDepth++;
        @try {
            NSData *ct = (__bridge NSData *)ciphertext;
            NSData *pt = (__bridge NSData *)out;
            uint64_t seq = atomic_fetch_add(&g_crypto_seq, 1) + 1;
            NSMutableDictionary *ev = [NSMutableDictionary dictionaryWithDictionary:@{
                @"id": @(seq),
                @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                @"primitive": @"SecKeyCreateDecryptedData",
                @"operation": @"asymmetric_decrypt",
                @"algorithm": algorithm ? ((__bridge NSString *)algorithm) : @"SecKey",
                @"plaintext_size": @(pt.length),
                @"plaintext_hex": MEBytesToHex(pt.bytes, pt.length, 1024),
                @"ciphertext_size": @(ct.length),
                @"ciphertext_hex": MEBytesToHex(ct.bytes, ct.length, 1024),
                @"backtrace": MECaptureBacktrace(6)
            }];
            NSString *ptUtf8 = MEBytesToPrintableUTF8(pt.bytes, pt.length, 2048);
            if (ptUtf8.length) ev[@"plaintext_utf8"] = ptUtf8;
            MERecordCryptoEvent(ev);
        } @catch (NSException *ignored) {}
        @finally { MEDepth--; }
    }
    return out;
}

static CFDataRef hook_SecKeyCreateSignature(SecKeyRef key, SecKeyAlgorithm algorithm,
                                            CFDataRef dataToSign, CFErrorRef *error) {
    CFDataRef sig = orig_SecKeyCreateSignature
        ? orig_SecKeyCreateSignature(key, algorithm, dataToSign, error)
        : NULL;
    if (atomic_load(&g_crypto_active) && MEDepth == 0 && dataToSign) {
        MEDepth++;
        @try {
            NSData *msg = (__bridge NSData *)dataToSign;
            NSData *sigData = (__bridge NSData *)sig;
            uint64_t seq = atomic_fetch_add(&g_crypto_seq, 1) + 1;
            NSMutableDictionary *ev = [NSMutableDictionary dictionaryWithDictionary:@{
                @"id": @(seq),
                @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                @"primitive": @"SecKeyCreateSignature",
                @"operation": @"asymmetric_sign",
                @"algorithm": algorithm ? ((__bridge NSString *)algorithm) : @"SecKeySign",
                @"input_size": @(msg.length),
                @"input_hex": MEBytesToHex(msg.bytes, msg.length, 1024),
                @"signature_size": @(sigData.length),
                @"signature_hex": MEBytesToHex(sigData.bytes, sigData.length, 512),
                @"backtrace": MECaptureBacktrace(6)
            }];
            NSString *msgUtf8 = MEBytesToPrintableUTF8(msg.bytes, msg.length, 2048);
            if (msgUtf8.length) ev[@"input_utf8"] = msgUtf8;
            MERecordCryptoEvent(ev);
        } @catch (NSException *ignored) {}
        @finally { MEDepth--; }
    }
    return sig;
}

static int hook_EVP_CipherInit_ex(void *ctx, const void *cipher, void *impl,
                                  const unsigned char *key, const unsigned char *iv, int enc) {
    int rc = orig_EVP_CipherInit_ex ? orig_EVP_CipherInit_ex(ctx, cipher, impl, key, iv, enc) : 0;
    if (rc == 1 && atomic_load(&g_crypto_active) && (key || iv)) {
        METrackCryptor(ctx, (enc == 1) ? kCCEncrypt : kCCDecrypt, kCCAlgorithmAES, 0, 0, key, key ? 32 : 0, iv);
    }
    return rc;
}

static int hook_EVP_EncryptUpdate(void *ctx, unsigned char *out, int *outl,
                                  const unsigned char *in, int inl) {
    int localOut = 0;
    int *outPtr = outl ? outl : &localOut;
    int rc = orig_EVP_EncryptUpdate ? orig_EVP_EncryptUpdate(ctx, out, outPtr, in, inl) : 0;
    if (rc == 1 && atomic_load(&g_crypto_active) && MEDepth == 0 && inl > 0) {
        MEDepth++;
        @try {
            MECryptorContext snap = {0};
            pthread_mutex_lock(&g_crypto_mutex);
            size_t slot = ((uintptr_t)ctx >> 4) % ME_MAX_CRYPTOR_CTXS;
            if (g_cryptor_ctxs[slot].active && g_cryptor_ctxs[slot].ref == ctx) snap = g_cryptor_ctxs[slot];
            pthread_mutex_unlock(&g_crypto_mutex);

            uint64_t seq = atomic_fetch_add(&g_crypto_seq, 1) + 1;
            NSMutableDictionary *ev = [NSMutableDictionary dictionaryWithDictionary:@{
                @"id": @(seq),
                @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                @"primitive": @"EVP_EncryptUpdate",
                @"operation": @"encrypt",
                @"algorithm": @"BoringSSL_EVP",
                @"key_hex": snap.active ? MEBytesToHex(snap.key, snap.keyLen, 32) : @"",
                @"iv_hex": (snap.active && snap.hasIV) ? MEBytesToHex(snap.iv, 16, 16) : @"",
                @"plaintext_size": @(inl),
                @"plaintext_hex": MEBytesToHex(in, (size_t)inl, 1024),
                @"ciphertext_size": @(*outPtr),
                @"ciphertext_hex": MEBytesToHex(out, (size_t)*outPtr, 1024),
                @"backtrace": MECaptureBacktrace(5)
            }];
            NSString *ptUtf8 = MEBytesToPrintableUTF8(in, (size_t)inl, 2048);
            if (ptUtf8.length) ev[@"plaintext_utf8"] = ptUtf8;
            MERecordCryptoEvent(ev);
        } @catch (NSException *ignored) {}
        @finally { MEDepth--; }
    }
    return rc;
}

static int hook_EVP_DecryptUpdate(void *ctx, unsigned char *out, int *outl,
                                  const unsigned char *in, int inl) {
    int localOut = 0;
    int *outPtr = outl ? outl : &localOut;
    int rc = orig_EVP_DecryptUpdate ? orig_EVP_DecryptUpdate(ctx, out, outPtr, in, inl) : 0;
    if (rc == 1 && atomic_load(&g_crypto_active) && MEDepth == 0 && inl > 0) {
        MEDepth++;
        @try {
            MECryptorContext snap = {0};
            pthread_mutex_lock(&g_crypto_mutex);
            size_t slot = ((uintptr_t)ctx >> 4) % ME_MAX_CRYPTOR_CTXS;
            if (g_cryptor_ctxs[slot].active && g_cryptor_ctxs[slot].ref == ctx) snap = g_cryptor_ctxs[slot];
            pthread_mutex_unlock(&g_crypto_mutex);

            uint64_t seq = atomic_fetch_add(&g_crypto_seq, 1) + 1;
            NSMutableDictionary *ev = [NSMutableDictionary dictionaryWithDictionary:@{
                @"id": @(seq),
                @"timestamp": @([[NSDate date] timeIntervalSince1970]),
                @"primitive": @"EVP_DecryptUpdate",
                @"operation": @"decrypt",
                @"algorithm": @"BoringSSL_EVP",
                @"key_hex": snap.active ? MEBytesToHex(snap.key, snap.keyLen, 32) : @"",
                @"iv_hex": (snap.active && snap.hasIV) ? MEBytesToHex(snap.iv, 16, 16) : @"",
                @"plaintext_size": @(*outPtr),
                @"plaintext_hex": MEBytesToHex(out, (size_t)*outPtr, 1024),
                @"ciphertext_size": @(inl),
                @"ciphertext_hex": MEBytesToHex(in, (size_t)inl, 1024),
                @"backtrace": MECaptureBacktrace(5)
            }];
            NSString *ptUtf8 = MEBytesToPrintableUTF8(out, (size_t)*outPtr, 2048);
            if (ptUtf8.length) ev[@"plaintext_utf8"] = ptUtf8;
            MERecordCryptoEvent(ev);
        } @catch (NSException *ignored) {}
        @finally { MEDepth--; }
    }
    return rc;
}

static BOOL MECryptoShouldHookImage(const struct mach_header *hdr, const char *name) {
    if (!hdr || !name || hdr == MESelfHeader()) return NO;
    if (strstr(name, "libApple") || strstr(name, "libmcp") || strstr(name, "systemhook") ||
        strstr(name, "TweakLoader") || strstr(name, "/.jbroot-") || strstr(name, "/TweakInject/")) {
        return NO;
    }
    // Hook all app/framework images and Apple's CryptoKit/Security/Network consumers
    if (!strstr(name, "/System/Library/") && !strstr(name, "/usr/lib/") && !strstr(name, "/Developer/")) {
        return YES;
    }
    if (strstr(name, "CryptoKit") || strstr(name, "Security") || strstr(name, "Foundation")) {
        return YES;
    }
    return NO;
}

static NSDictionary *MECryptoSlotToDict(const mcp_slot_patch_t *p, NSString *imageName) {
    uint64_t newLE = OSSwapHostToLittleInt64((uint64_t)p->new_val);
    uint64_t origLE = OSSwapHostToLittleInt64((uint64_t)p->orig_val);
    NSString *newB64 = [[NSData dataWithBytes:&newLE length:sizeof(newLE)] base64EncodedStringWithOptions:0];
    NSString *origB64 = [[NSData dataWithBytes:&origLE length:sizeof(origLE)] base64EncodedStringWithOptions:0];
    return @{
        @"slot_address": MEHex(p->slot_addr),
        @"original_value": MEHex(p->orig_val),
        @"replacement_value": MEHex(p->new_val),
        @"bytes_base64": newB64 ?: @"",
        @"original_bytes_base64": origB64 ?: @"",
        @"symbol": @(p->symbol_name),
        @"section": @(p->section_name),
        @"auth_got": @(p->is_auth ? YES : NO),
        @"writable_in_proc": @(p->written_in_proc ? YES : NO),
        @"image": imageName ?: @""
    };
}

NSDictionary *MECrypto(NSString *op, NSDictionary *a) {
    if ([op isEqualToString:@"engine.trace_crypto"]) {
        BOOL clear = a[@"clear"] ? [a[@"clear"] boolValue] : NO;
        pthread_mutex_lock(&g_crypto_mutex);
        if (!g_crypto_events) g_crypto_events = [NSMutableArray array];
        if (!g_crypto_bound_slots) g_crypto_bound_slots = [NSMutableArray array];
        if (clear) {
            [g_crypto_events removeAllObjects];
            unlink(MECryptoLogPath().fileSystemRepresentation);
        }
        pthread_mutex_unlock(&g_crypto_mutex);

        if (!orig_CCCrypt) orig_CCCrypt = dlsym(RTLD_DEFAULT, "CCCrypt");
        if (!orig_CCCryptorCreate) orig_CCCryptorCreate = dlsym(RTLD_DEFAULT, "CCCryptorCreate");
        if (!orig_CCCryptorCreateWithMode) orig_CCCryptorCreateWithMode = dlsym(RTLD_DEFAULT, "CCCryptorCreateWithMode");
        if (!orig_CCCryptorUpdate) orig_CCCryptorUpdate = dlsym(RTLD_DEFAULT, "CCCryptorUpdate");
        if (!orig_CCCryptorFinal) orig_CCCryptorFinal = dlsym(RTLD_DEFAULT, "CCCryptorFinal");
        if (!orig_CCHmac) orig_CCHmac = dlsym(RTLD_DEFAULT, "CCHmac");
        if (!orig_CCKeyDerivationPBKDF) orig_CCKeyDerivationPBKDF = dlsym(RTLD_DEFAULT, "CCKeyDerivationPBKDF");
        if (!orig_SecKeyCreateEncryptedData) orig_SecKeyCreateEncryptedData = dlsym(RTLD_DEFAULT, "SecKeyCreateEncryptedData");
        if (!orig_SecKeyCreateDecryptedData) orig_SecKeyCreateDecryptedData = dlsym(RTLD_DEFAULT, "SecKeyCreateDecryptedData");
        if (!orig_SecKeyCreateSignature) orig_SecKeyCreateSignature = dlsym(RTLD_DEFAULT, "SecKeyCreateSignature");

        void *boring = dlopen("/usr/lib/libboringssl.dylib", RTLD_LAZY | RTLD_NOLOAD);
        if (!boring) boring = RTLD_DEFAULT;
        if (!orig_EVP_CipherInit_ex) orig_EVP_CipherInit_ex = dlsym(boring, "EVP_CipherInit_ex");
        if (!orig_EVP_EncryptUpdate) orig_EVP_EncryptUpdate = dlsym(boring, "EVP_EncryptUpdate");
        if (!orig_EVP_DecryptUpdate) orig_EVP_DecryptUpdate = dlsym(boring, "EVP_DecryptUpdate");

        struct mcp_rebinding rebindings[] = {
            {"CCCrypt", (void *)hook_CCCrypt, (void **)&orig_CCCrypt},
            {"CCCryptorCreate", (void *)hook_CCCryptorCreate, (void **)&orig_CCCryptorCreate},
            {"CCCryptorCreateWithMode", (void *)hook_CCCryptorCreateWithMode, (void **)&orig_CCCryptorCreateWithMode},
            {"CCCryptorUpdate", (void *)hook_CCCryptorUpdate, (void **)&orig_CCCryptorUpdate},
            {"CCCryptorFinal", (void *)hook_CCCryptorFinal, (void **)&orig_CCCryptorFinal},
            {"CCHmac", (void *)hook_CCHmac, (void **)&orig_CCHmac},
            {"CCKeyDerivationPBKDF", (void *)hook_CCKeyDerivationPBKDF, (void **)&orig_CCKeyDerivationPBKDF},
            {"SecKeyCreateEncryptedData", (void *)hook_SecKeyCreateEncryptedData, (void **)&orig_SecKeyCreateEncryptedData},
            {"SecKeyCreateDecryptedData", (void *)hook_SecKeyCreateDecryptedData, (void **)&orig_SecKeyCreateDecryptedData},
            {"SecKeyCreateSignature", (void *)hook_SecKeyCreateSignature, (void **)&orig_SecKeyCreateSignature},
            {"EVP_CipherInit_ex", (void *)hook_EVP_CipherInit_ex, (void **)&orig_EVP_CipherInit_ex},
            {"EVP_EncryptUpdate", (void *)hook_EVP_EncryptUpdate, (void **)&orig_EVP_EncryptUpdate},
            {"EVP_DecryptUpdate", (void *)hook_EVP_DecryptUpdate, (void **)&orig_EVP_DecryptUpdate}
        };

        atomic_store(&g_crypto_active, 1);

        NSMutableArray<NSDictionary *> *allSlots = [NSMutableArray array];
        NSMutableArray<NSDictionary *> *pendingSlots = [NSMutableArray array];
        NSUInteger patchedInProc = 0;
        uint32_t imgCount = _dyld_image_count();

        MEDepth++;
        @try {
            for (uint32_t i = 0; i < imgCount; i++) {
                const struct mach_header *hdr = _dyld_get_image_header(i);
                const char *name = _dyld_get_image_name(i);
                if (!MECryptoShouldHookImage(hdr, name)) continue;
                intptr_t slide = _dyld_get_image_vmaddr_slide(i);
                mcp_slot_collector_t collector = {0};
                mcp_rebind_symbols_image_collect(hdr, slide, MESelfHeader(),
                                                 rebindings, sizeof(rebindings) / sizeof(rebindings[0]),
                                                 &collector);
                NSString *imgName = name ? @(name) : @"";
                for (size_t k = 0; k < collector.count; k++) {
                    NSDictionary *slotDict = MECryptoSlotToDict(&collector.patches[k], imgName);
                    pthread_mutex_lock(&g_crypto_mutex);
                    [g_crypto_bound_slots addObject:slotDict];
                    pthread_mutex_unlock(&g_crypto_mutex);
                    [allSlots addObject:slotDict];
                    if (collector.patches[k].written_in_proc) patchedInProc++;
                    else [pendingSlots addObject:slotDict];
                }
                mcp_slot_collector_free(&collector);
            }
        } @finally {
            MEDepth--;
        }

        return @{
            @"tracing": @YES,
            @"pid": @(getpid()),
            @"log_path": MECryptoLogPath(),
            @"hooked_primitives": @[
                @"CCCrypt", @"CCCryptorCreate", @"CCCryptorCreateWithMode",
                @"CCCryptorUpdate", @"CCCryptorFinal", @"CCHmac",
                @"CCKeyDerivationPBKDF", @"SecKeyCreateEncryptedData",
                @"SecKeyCreateDecryptedData", @"SecKeyCreateSignature",
                @"EVP_CipherInit_ex", @"EVP_EncryptUpdate", @"EVP_DecryptUpdate"
            ],
            @"patched_in_proc": @(patchedInProc),
            @"slots": allSlots,
            @"pending_slots": pendingSlots
        };
    }

    if ([op isEqualToString:@"engine.get_crypto_events"]) {
        NSUInteger limit = MELimit(a, @"limit", 100, 1000);
        NSString *algFilter = [a[@"algorithm_filter"] isKindOfClass:[NSString class]] ? [a[@"algorithm_filter"] lowercaseString] : nil;
        NSString *opFilter = [a[@"operation_filter"] isKindOfClass:[NSString class]] ? [a[@"operation_filter"] lowercaseString] : nil;
        BOOL clear = [a[@"clear"] boolValue];

        pthread_mutex_lock(&g_crypto_mutex);
        NSArray<NSDictionary *> *snapshot = g_crypto_events ? [g_crypto_events copy] : @[];
        if (clear) {
            [g_crypto_events removeAllObjects];
            unlink(MECryptoLogPath().fileSystemRepresentation);
        }
        pthread_mutex_unlock(&g_crypto_mutex);

        NSMutableArray<NSDictionary *> *filtered = [NSMutableArray array];
        for (NSDictionary *ev in snapshot) {
            if (algFilter.length) {
                NSString *alg = [ev[@"algorithm"] isKindOfClass:[NSString class]] ? [ev[@"algorithm"] lowercaseString] : @"";
                if (![alg containsString:algFilter]) continue;
            }
            if (opFilter.length) {
                NSString *evOp = [ev[@"operation"] isKindOfClass:[NSString class]] ? [ev[@"operation"] lowercaseString] : @"";
                if (![evOp containsString:opFilter]) continue;
            }
            [filtered addObject:ev];
        }
        if (filtered.count > limit) {
            filtered = [[filtered subarrayWithRange:NSMakeRange(filtered.count - limit, limit)] mutableCopy];
        }

        return @{
            @"tracing": @(atomic_load(&g_crypto_active) ? YES : NO),
            @"count": @(filtered.count),
            @"total_buffered": @(snapshot.count),
            @"log_path": MECryptoLogPath(),
            @"events": filtered
        };
    }

    if ([op isEqualToString:@"engine.stop_crypto"]) {
        atomic_store(&g_crypto_active, 0);
        NSMutableArray<NSDictionary *> *restoreSlots = [NSMutableArray array];
        NSUInteger restoredInProc = 0;
        pthread_mutex_lock(&g_crypto_mutex);
        for (NSDictionary *slotDict in g_crypto_bound_slots) {
            uintptr_t slotAddr = MEWord(slotDict[@"slot_address"]);
            uintptr_t origVal = MEWord(slotDict[@"original_value"]);
            if (!slotAddr || !origVal) continue;
            if (mcp_write_raw_slot_in_proc(slotAddr, origVal)) {
                restoredInProc++;
            } else {
                [restoreSlots addObject:@{
                    @"slot_address": slotDict[@"slot_address"] ?: @"0x0",
                    @"original_value": slotDict[@"original_value"] ?: @"0x0",
                    @"bytes_base64": slotDict[@"original_bytes_base64"] ?: @""
                }];
            }
        }
        [g_crypto_bound_slots removeAllObjects];
        pthread_mutex_unlock(&g_crypto_mutex);

        return @{
            @"tracing": @NO,
            @"restored_in_proc": @(restoredInProc),
            @"restore_slots": restoreSlots
        };
    }

    return nil;
}
