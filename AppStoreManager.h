#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface AppStoreManager : NSObject

+ (instancetype)sharedInstance;

/// [Upgrade 37] Search the iOS App Store by keyword, bundle_id, or adam_id, resolve bundle_id <-> adamId,
/// and list all historical softwareVersionExternalIdentifiers (appExtVrsId) with semantic versions.
- (NSDictionary * _Nullable)searchAndVersionsWithArgs:(NSDictionary *)args
                                                error:(NSString * _Nullable * _Nullable)error;

/// [Upgrade 38] Zero-UI headless App Store acquisition & installation using StoreServices / AppStoreDaemon.
- (NSDictionary * _Nullable)installAppWithArgs:(NSDictionary *)args
                                         error:(NSString * _Nullable * _Nullable)error;

/// [Upgrade 39] MuffinStore historical version downgrade via buyParameters appExtVrsId injection
/// with automatic sandbox DataContainer preservation.
- (NSDictionary * _Nullable)downgradeAppWithArgs:(NSDictionary *)args
                                           error:(NSString * _Nullable * _Nullable)error;

/// [Upgrade 40] Automated multi-version pull, binary/framework/SDK security hardening diff,
/// and optimal version retention pipeline.
- (NSDictionary * _Nullable)autoRollbackAndDiffWithArgs:(NSDictionary *)args
                                                  error:(NSString * _Nullable * _Nullable)error;

@end

NS_ASSUME_NONNULL_END
