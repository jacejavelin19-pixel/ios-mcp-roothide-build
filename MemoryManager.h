#import <Foundation/Foundation.h>

@interface MemoryManager : NSObject

+ (instancetype)sharedInstance;
- (NSDictionary *)readPID:(pid_t)pid address:(uint64_t)address length:(NSUInteger)length error:(NSString **)error;
- (NSDictionary *)writePID:(pid_t)pid address:(uint64_t)address data:(NSData *)data error:(NSString **)error;
- (NSDictionary *)searchPID:(pid_t)pid data:(NSData *)data start:(uint64_t)start end:(uint64_t)end error:(NSString **)error;
- (NSDictionary *)listRegionsPID:(pid_t)pid limit:(NSUInteger)limit error:(NSString **)error;
- (NSDictionary *)dumpClassesPID:(pid_t)pid filter:(NSString *)filter limit:(NSUInteger)limit includeSystem:(BOOL)includeSystem error:(NSString **)error;

@end
