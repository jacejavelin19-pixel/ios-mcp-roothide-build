#import <Foundation/Foundation.h>

FOUNDATION_EXPORT NSString *MCPResolvedJailbreakPath(NSString *path);
FOUNDATION_EXPORT NSString *MCPBootstrapPathForRootHide(NSString *path);
FOUNDATION_EXPORT BOOL MCPIsExecutableFile(NSString *path);
FOUNDATION_EXPORT NSDictionary<NSString *, NSString *> *MCPJailbreakEnvironment(void);
FOUNDATION_EXPORT BOOL MCPRunProcess(NSString *launchPath,
                                     NSArray<NSString *> *arguments,
                                     NSDictionary<NSString *, NSString *> *environmentOverrides,
                                     NSTimeInterval timeout,
                                     NSUInteger maxOutputBytes,
                                     NSString **output,
                                     int *exitCode,
                                     NSString **errorMessage);

/// Like MCPRunProcess but captures raw stdout/stderr bytes instead of decoding to a string.
/// Required for reading binary files (plist/db/dumps) where UTF-8 decoding would corrupt data.
FOUNDATION_EXPORT BOOL MCPRunProcessData(NSString *launchPath,
                                         NSArray<NSString *> *arguments,
                                         NSDictionary<NSString *, NSString *> *environmentOverrides,
                                         NSTimeInterval timeout,
                                         NSUInteger maxOutputBytes,
                                         NSData **outputData,
                                         BOOL *truncated,
                                         int *exitCode,
                                         NSString **errorMessage);

/// Resolve the bundled setuid mcp-root helper path, or nil/empty when unavailable.
FOUNDATION_EXPORT NSString *MCPRootHelperPath(void);

/// Connect to the local unsandboxed mcp-helperd spawn broker (returns socket FD >= 0 or -1).
FOUNDATION_EXPORT int MCPConnectHelperDaemon(void);

/// Send a JSON control request (watchdog_arm, watchdog_disarm, spawn_detached, stop_detached) to mcp-helperd.
FOUNDATION_EXPORT NSDictionary *MCPHelperDaemonSendControlRequest(NSDictionary *request,
                                                                  NSTimeInterval timeout,
                                                                  NSString **errorMessage);

/// Run a command as root via the bundled mcp-root helper, capturing UTF-8 text output.
FOUNDATION_EXPORT BOOL MCPRunRootProcess(NSString *launchPath,
                                         NSArray<NSString *> *arguments,
                                         NSTimeInterval timeout,
                                         NSUInteger maxOutputBytes,
                                         NSString **output,
                                         int *exitCode,
                                         NSString **errorMessage);

/// Run a command as root via the bundled mcp-root helper, capturing raw bytes.
/// Returns NO (with errorMessage) when no privileged helper is available.
FOUNDATION_EXPORT BOOL MCPRunRootProcessData(NSString *launchPath,
                                             NSArray<NSString *> *arguments,
                                             NSTimeInterval timeout,
                                             NSUInteger maxOutputBytes,
                                             NSData **outputData,
                                             BOOL *truncated,
                                             int *exitCode,
                                             NSString **errorMessage);

FOUNDATION_EXPORT NSString *MCPJailbreakRoot(void);
FOUNDATION_EXPORT NSString *MCPSubPath(NSString *relPath);
FOUNDATION_EXPORT NSString *MCPCommandSearchPath(void);
FOUNDATION_EXPORT NSString *MCPReadCommandOutput(NSArray<NSString *> *cmdAndArgs,
                                                 NSTimeInterval timeout,
                                                 int *exitCodeOut);

