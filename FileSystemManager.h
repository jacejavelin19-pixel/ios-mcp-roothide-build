#import <Foundation/Foundation.h>

/// Filesystem access for reverse-engineering workflows: list directories, read files
/// (text or binary via base64), and write files. Falls back to the mcp-root helper
/// when the sandboxed server process lacks permission (e.g. other apps' containers,
/// system paths). All paths are resolved through the jailbreak root prefix.
@interface FileSystemManager : NSObject

+ (instancetype)sharedInstance;

/// List directory entries. Returns a dict with "path" and "entries" (name/type/size/mode/mtime),
/// or nil with *error on failure.
- (NSDictionary *)listDirectoryAtPath:(NSString *)path
                                error:(NSString **)error;

/// Read a file. maxBytes caps the payload (0 = default). When the content is valid UTF-8
/// and not forced binary, returns encoding "utf8"; otherwise "base64".
/// Returns a dict with path/size/encoding/content/truncated, or nil with *error.
- (NSDictionary *)readFileAtPath:(NSString *)path
                        maxBytes:(NSUInteger)maxBytes
                     forceBinary:(BOOL)forceBinary
                           error:(NSString **)error;

/// Write a file. content is interpreted per encoding ("utf8" or "base64").
/// Returns a dict with path/bytes_written, or nil with *error.
- (NSDictionary *)writeFileAtPath:(NSString *)path
                          content:(NSString *)content
                         encoding:(NSString *)encoding
                            error:(NSString **)error;

/// Write a file honoring path-safety and write-approval guards.
- (NSDictionary *)writeFileWithArgs:(NSDictionary *)args
                              error:(NSString **)error;

/// Validate whether a target path is safe/approved for writing. Returns an approval-needed
/// dictionary in *approvalOut when write approval is required and not yet granted.
- (BOOL)validateWritePath:(NSString *)path
                  options:(NSDictionary *)options
              approvalOut:(NSDictionary **)approvalOut
                    error:(NSString **)error;

/// Read a chunk of a file starting at byte offset with given length.
- (NSDictionary *)readFileChunkAtPath:(NSString *)path
                               offset:(uint64_t)offset
                               length:(NSUInteger)length
                          forceBinary:(BOOL)forceBinary
                                error:(NSString **)error;

/// Tail the last N lines of a text/log file.
- (NSDictionary *)tailFileAtPath:(NSString *)path
                           lines:(NSUInteger)lines
                        maxBytes:(NSUInteger)maxBytes
                           error:(NSString **)error;

/// Compute cryptographic digests (SHA-256, SHA-1, MD5) of a file.
- (NSDictionary *)hashFileAtPath:(NSString *)path
                      algorithms:(NSArray<NSString *> *)algorithms
                           error:(NSString **)error;

/// Package a directory or file into a downloadable .zip / .tar.gz archive.
- (NSDictionary *)zipDirectoryAtPath:(NSString *)path
                          outputPath:(NSString *)outputPath
                               error:(NSString **)error;

/// Recursively search files by filename regex/substring and optional content pattern.
- (NSDictionary *)searchFilesAtPath:(NSString *)path
                            pattern:(NSString *)pattern
                     contentPattern:(NSString *)contentPattern
                           maxDepth:(NSUInteger)maxDepth
                         maxResults:(NSUInteger)maxResults
                              error:(NSString **)error;

/// Resolve a file for HTTP download. Returns the on-disk path the server can stream
/// (may be a temp copy staged via mcp-root for privileged sources), and whether it is temporary.
/// Returns nil with *error on failure.
- (NSString *)resolveDownloadPath:(NSString *)path
                      isTemporary:(BOOL *)isTemporary
                            error:(NSString **)error;

@end
