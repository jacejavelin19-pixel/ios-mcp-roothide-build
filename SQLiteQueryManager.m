#import "SQLiteQueryManager.h"
#import "MCPProcessUtil.h"
#import <sqlite3.h>

@implementation SQLiteQueryManager

+ (instancetype)sharedInstance {
    static SQLiteQueryManager *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[SQLiteQueryManager alloc] init];
    });
    return instance;
}

- (NSDictionary *)queryDatabaseAtPath:(NSString *)dbPath
                                  sql:(NSString *)sql
                                limit:(NSUInteger)limit
                                error:(NSString **)error {
    if (error) *error = nil;
    if (![dbPath isKindOfClass:[NSString class]] || !dbPath.length) {
        if (error) *error = @"path is required";
        return nil;
    }
    if (limit == 0) limit = 200;
    if (limit > 2000) limit = 2000;

    NSString *effectiveSQL = [sql isKindOfClass:[NSString class]] && sql.length
        ? sql
        : @"SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name;";

    NSString *resolved = MCPResolvedJailbreakPath(dbPath);
    if (!resolved.length) resolved = dbPath;

    NSString *openPath = resolved;
    NSString *tempCopy = nil;

    sqlite3 *db = NULL;
    int rc = sqlite3_open_v2(openPath.fileSystemRepresentation, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, NULL);
    if (rc != SQLITE_OK) {
        if (db) { sqlite3_close(db); db = NULL; }
        // Privileged read fallback for root-owned or sandbox-restricted SQLite databases
        NSData *rootBytes = nil;
        BOOL truncated = NO;
        int exitCode = -1;
        NSString *runErr = nil;
        if (MCPRunRootProcessData(@"/usr/libexec/ios-mcp/mcp-appmod",
                                  @[@"read-file", resolved, @"67108864"],
                                  20.0,
                                  64 * 1024 * 1024,
                                  &rootBytes,
                                  &truncated,
                                  &exitCode,
                                  &runErr) && exitCode == 0 && rootBytes.length > 0 && !truncated) {
            NSString *workDir = @"/var/mobile/Library/Caches/ios-mcp-work";
            [[NSFileManager defaultManager] createDirectoryAtPath:workDir withIntermediateDirectories:YES attributes:nil error:nil];
            tempCopy = [workDir stringByAppendingPathComponent:[NSString stringWithFormat:@"sqlite-%@.db", [NSUUID UUID].UUIDString]];
            if ([rootBytes writeToFile:tempCopy options:NSDataWritingAtomic error:nil]) {
                openPath = tempCopy;
                rc = sqlite3_open_v2(openPath.fileSystemRepresentation, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, NULL);
            }
        }
    }

    if (rc != SQLITE_OK || !db) {
        NSString *msg = db ? [NSString stringWithUTF8String:sqlite3_errmsg(db)] : @"cannot open database";
        if (db) sqlite3_close(db);
        if (tempCopy) [[NSFileManager defaultManager] removeItemAtPath:tempCopy error:nil];
        if (error) *error = [NSString stringWithFormat:@"SQLite open failed for %@: %@", dbPath, msg ?: @"error"];
        return nil;
    }

    sqlite3_busy_timeout(db, 2000);
#ifdef SQLITE_DBCONFIG_DEFENSIVE
    sqlite3_db_config(db, SQLITE_DBCONFIG_DEFENSIVE, 1, NULL);
#endif

    @try {
        sqlite3_stmt *stmt = NULL;
        rc = sqlite3_prepare_v2(db, effectiveSQL.UTF8String, -1, &stmt, NULL);
        if (rc != SQLITE_OK || !stmt) {
            if (error) *error = [NSString stringWithFormat:@"SQLite prepare error: %s", sqlite3_errmsg(db)];
            return nil;
        }
        if (!sqlite3_stmt_readonly(stmt)) {
            sqlite3_finalize(stmt);
            if (error) *error = @"query_sqlite only permits read-only SELECT / PRAGMA statements";
            return nil;
        }

        int colCount = sqlite3_column_count(stmt);
        NSMutableArray<NSString *> *columns = [NSMutableArray arrayWithCapacity:(NSUInteger)MAX(0, colCount)];
        for (int c = 0; c < colCount; c++) {
            const char *cn = sqlite3_column_name(stmt, c);
            [columns addObject:(cn ? [NSString stringWithUTF8String:cn] : [NSString stringWithFormat:@"col_%d", c]) ?: @""];
        }

        NSMutableArray<NSDictionary *> *rows = [NSMutableArray array];
        BOOL truncatedRows = NO;
        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
            if (rows.count >= limit) {
                truncatedRows = YES;
                break;
            }
            NSMutableDictionary *row = [NSMutableDictionary dictionaryWithCapacity:(NSUInteger)MAX(0, colCount)];
            for (int c = 0; c < colCount; c++) {
                NSString *key = columns[(NSUInteger)c];
                int t = sqlite3_column_type(stmt, c);
                if (t == SQLITE_NULL) {
                    row[key] = [NSNull null];
                } else if (t == SQLITE_INTEGER) {
                    row[key] = @(sqlite3_column_int64(stmt, c));
                } else if (t == SQLITE_FLOAT) {
                    row[key] = @(sqlite3_column_double(stmt, c));
                } else if (t == SQLITE_TEXT) {
                    const unsigned char *txt = sqlite3_column_text(stmt, c);
                    int len = sqlite3_column_bytes(stmt, c);
                    NSString *str = (txt && len >= 0)
                        ? [[NSString alloc] initWithBytes:txt length:(NSUInteger)len encoding:NSUTF8StringEncoding]
                        : @"";
                    row[key] = str ?: @"";
                } else if (t == SQLITE_BLOB) {
                    const void *blob = sqlite3_column_blob(stmt, c);
                    int len = sqlite3_column_bytes(stmt, c);
                    NSData *bData = (blob && len > 0) ? [NSData dataWithBytes:blob length:(NSUInteger)MIN(len, 4096)] : [NSData data];
                    row[key] = @{
                        @"_sqlite_type": @"blob",
                        @"size": @(len),
                        @"base64_preview": [bData base64EncodedStringWithOptions:0] ?: @"",
                        @"truncated": @(len > 4096)
                    };
                }
            }
            [rows addObject:row];
        }
        sqlite3_finalize(stmt);

        if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
            if (error) *error = [NSString stringWithFormat:@"SQLite execution error: %s", sqlite3_errmsg(db)];
            return nil;
        }

        return @{
            @"path": dbPath,
            @"resolved_path": resolved,
            @"sql": effectiveSQL,
            @"columns": columns,
            @"row_count": @(rows.count),
            @"truncated": @(truncatedRows),
            @"rows": rows
        };
    } @finally {
        sqlite3_close(db);
        if (tempCopy) [[NSFileManager defaultManager] removeItemAtPath:tempCopy error:nil];
    }
}

@end
