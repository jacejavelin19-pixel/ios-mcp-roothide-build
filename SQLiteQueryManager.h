#import <Foundation/Foundation.h>

@interface SQLiteQueryManager : NSObject

+ (instancetype)sharedInstance;
- (NSDictionary *)queryDatabaseAtPath:(NSString *)dbPath
                                  sql:(NSString *)sql
                                limit:(NSUInteger)limit
                                error:(NSString **)error;

@end
