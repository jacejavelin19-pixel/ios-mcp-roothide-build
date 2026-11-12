#import <Foundation/Foundation.h>

@interface PlistPatchManager : NSObject

+ (instancetype)sharedInstance;
- (NSDictionary *)valueAtPath:(NSString *)path keypath:(NSString *)keypath error:(NSString **)error;
- (NSDictionary *)setValue:(id)value atPath:(NSString *)path keypath:(NSString *)keypath error:(NSString **)error;
- (NSDictionary *)setValue:(id)value atPath:(NSString *)path keypath:(NSString *)keypath options:(NSDictionary *)options error:(NSString **)error;

@end
