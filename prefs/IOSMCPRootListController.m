#import "IOSMCPRootListController.h"
#import "IOSMCPLocalization.h"
#import <Preferences/PSSpecifier.h>
#import <Preferences/PSTableCell.h>
#import <UIKit/UIKit.h>
#import <spawn.h>
#include <string.h>
#include <sys/stat.h>
#include <roothide.h>
#import "../IOSMCPPreferences.h"
#import "../MCPLogger.h"

@interface IOSMCPRootListController () <UIGestureRecognizerDelegate, UITextFieldDelegate>

@property (nonatomic, assign) BOOL serverRunning;
@property (nonatomic, assign) BOOL serverControlBusy;
@property (nonatomic, assign) NSUInteger serverStatusGeneration;
@property (nonatomic, strong) UITapGestureRecognizer *keyboardDismissTapGesture;
@property (nonatomic, weak) id<UITextFieldDelegate> originalPortTextFieldDelegate;

- (void)applyPortChangeFromPort:(uint16_t)previousPort toPort:(uint16_t)newPort;
- (void)configurePortTextField;
- (void)dismissKeyboardFromTap:(UITapGestureRecognizer *)gestureRecognizer;
- (void)fetchServerRunningOnPort:(uint16_t)port completion:(void (^)(BOOL running, NSError *error))completion;
- (void)installKeyboardDismissGestureIfNeeded;
- (BOOL)isPortTextField:(UITextField *)textField;
- (UILabel *)labelInView:(UIView *)view;
- (void)pollServerStatusExpectingRunning:(BOOL)expectedRunning
                                    port:(uint16_t)port
                              generation:(NSUInteger)generation
                            finalAttempt:(BOOL)finalAttempt;
- (UITableViewCell *)portPreferenceCell;
- (void)portTextFieldDidEndOnExit:(UITextField *)textField;
- (void)respringButtonTapped:(id)sender;
- (UITextField *)textFieldInView:(UIView *)view;
- (void)updateVisibleFooterText:(NSString *)text forSpecifier:(PSSpecifier *)specifier;
- (void)setServerControlBusyState:(BOOL)busy;

@end

static void IOSMCPAppendUInt16LE(NSMutableData *data, uint16_t value) {
    uint8_t bytes[2] = {
        (uint8_t)(value & 0xff),
        (uint8_t)((value >> 8) & 0xff)
    };
    [data appendBytes:bytes length:sizeof(bytes)];
}

static void IOSMCPAppendUInt32LE(NSMutableData *data, uint32_t value) {
    uint8_t bytes[4] = {
        (uint8_t)(value & 0xff),
        (uint8_t)((value >> 8) & 0xff),
        (uint8_t)((value >> 16) & 0xff),
        (uint8_t)((value >> 24) & 0xff)
    };
    [data appendBytes:bytes length:sizeof(bytes)];
}

static uint32_t IOSMCPCRC32(NSData *data) {
    uint32_t crc = 0xffffffffU;
    const uint8_t *bytes = data.bytes;
    for (NSUInteger index = 0; index < data.length; index++) {
        crc ^= bytes[index];
        for (int bit = 0; bit < 8; bit++) {
            crc = (crc >> 1) ^ (0xedb88320U & (uint32_t)(-(int32_t)(crc & 1)));
        }
    }
    return crc ^ 0xffffffffU;
}

static NSString *IOSMCPKillallPath(void) {
    NSArray<NSString *> *candidatePaths = @[
        jbroot(@"/usr/bin/killall") ?: @"",
        jbroot(@"/bin/killall") ?: @"",
        @"/usr/bin/killall",
        @"/bin/killall"
    ];
    NSFileManager *fileManager = [NSFileManager defaultManager];
    for (NSString *path in candidatePaths) {
        if (path.length == 0) continue;
        if ([fileManager isExecutableFileAtPath:path]) return path;
        struct stat st;
        const char *fsPath = path.fileSystemRepresentation;
        if (fsPath && stat(fsPath, &st) == 0 && S_ISREG(st.st_mode) && ((st.st_mode & 0111) != 0)) {
            return path;
        }
    }
    return nil;
}

static BOOL IOSMCPEnabledPreference(void) {
    CFPreferencesAppSynchronize((__bridge CFStringRef)IOS_MCP_PREFERENCES_DOMAIN);
    CFPropertyListRef value = CFPreferencesCopyAppValue((__bridge CFStringRef)IOS_MCP_ENABLED_PREFERENCE_KEY,
                                                        (__bridge CFStringRef)IOS_MCP_PREFERENCES_DOMAIN);
    if (!value) return YES;

    BOOL enabled = YES;
    CFTypeID typeID = CFGetTypeID(value);
    if (typeID == CFBooleanGetTypeID()) {
        enabled = CFBooleanGetValue((CFBooleanRef)value);
    } else if (typeID == CFNumberGetTypeID()) {
        int numericValue = 0;
        CFNumberGetValue((CFNumberRef)value, kCFNumberIntType, &numericValue);
        enabled = numericValue != 0;
    }
    CFRelease(value);
    return enabled;
}

@implementation IOSMCPRootListController

- (NSArray *)specifiers {
    if (!_specifiers) {
        _specifiers = [self loadSpecifiersFromPlistName:@"Root" target:self];
        // Root.plist supplies the source strings. Localize every visible property,
        // including custom-cell captions; preference keys/actions stay unchanged.
        for (PSSpecifier *specifier in _specifiers) {
            if (specifier.name.length) {
                specifier.name = IOSMCPLocalizedString(specifier.name);
                [specifier setProperty:specifier.name forKey:PSTitleKey];
            }
            for (NSString *property in @[PSFooterTextGroupKey, @"placeholder", @"caption"]) {
                id value = [specifier propertyForKey:property];
                if ([value isKindOfClass:NSString.class] && [value length]) {
                    [specifier setProperty:IOSMCPLocalizedString(value) forKey:property];
                }
            }
        }
    }

    return _specifiers;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    UIButton *respringButton = [UIButton buttonWithType:UIButtonTypeSystem];
    respringButton.frame = CGRectMake(0.0, 0.0, 52.0, 44.0);
    respringButton.contentHorizontalAlignment = UIControlContentHorizontalAlignmentRight;
    respringButton.titleLabel.font = [UIFont systemFontOfSize:17.0];
    UIColor *tintColor = self.navigationController.navigationBar.tintColor ?: self.view.tintColor;
    if (tintColor) {
        [respringButton setTitleColor:tintColor forState:UIControlStateNormal];
    }
    [respringButton setTitle:IOSMCPLocalizedString(@"Respring") forState:UIControlStateNormal];
    CGSize buttonSize = [respringButton sizeThatFits:CGSizeMake(CGFLOAT_MAX, 44.0)];
    respringButton.frame = CGRectMake(0.0, 0.0, MAX(52.0, ceil(buttonSize.width)), 44.0);
    [respringButton addTarget:self
                       action:@selector(respringButtonTapped:)
             forControlEvents:UIControlEventTouchUpInside];
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc] initWithCustomView:respringButton];
    [self installKeyboardDismissGestureIfNeeded];
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self refreshPromptText];
    [self refreshDebugLogFooter];
    [self refreshServerStatus];
    dispatch_async(dispatch_get_main_queue(), ^{
        [self configurePortTextField];
    });
}

- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    [self installKeyboardDismissGestureIfNeeded];
    [self configurePortTextField];
}

- (id)readPreferenceValue:(PSSpecifier *)specifier {
    NSString *key = [specifier propertyForKey:@"key"];
    if ([key isEqualToString:IOS_MCP_PORT_PREFERENCE_KEY]) {
        return [NSString stringWithFormat:@"%u", (unsigned int)IOSMCPConfiguredPort()];
    }

    return [super readPreferenceValue:specifier];
}

- (void)setPreferenceValue:(id)value specifier:(PSSpecifier *)specifier {
    NSString *key = [specifier propertyForKey:@"key"];
    if (![key isEqualToString:IOS_MCP_PORT_PREFERENCE_KEY]) {
        [super setPreferenceValue:value specifier:specifier];
        CFPreferencesAppSynchronize((__bridge CFStringRef)IOS_MCP_PREFERENCES_DOMAIN);
        if ([key isEqualToString:IOS_MCP_WAN_BRIDGE_ENABLED_KEY] ||
            [key isEqualToString:IOS_MCP_WAN_BRIDGE_HOST_KEY] ||
            [key isEqualToString:IOS_MCP_WAN_BRIDGE_PORT_KEY] ||
            [key isEqualToString:IOS_MCP_PREFER_CELLULAR_KEY]) {
            [self postNotification:IOS_MCP_DARWIN_NOTIFICATION_WAN_RELOAD];
            [self refreshPromptText];
        }
        return;
    }

    uint16_t previousPort = IOSMCPConfiguredPort();
    uint16_t newPort = IOS_MCP_DEFAULT_PORT;
    BOOL validPort = IOSMCPParsePortValue(value, &newPort);

    if (validPort && previousPort == newPort) {
        return;
    }

    CFPreferencesSetAppValue((__bridge CFStringRef)IOS_MCP_PORT_PREFERENCE_KEY,
                             (__bridge CFPropertyListRef)@(newPort),
                             (__bridge CFStringRef)IOS_MCP_PREFERENCES_DOMAIN);
    CFPreferencesAppSynchronize((__bridge CFStringRef)IOS_MCP_PREFERENCES_DOMAIN);

    [MCPLogger log:@"prefs_port updated previous=%u current=%u valid=%@",
     (unsigned int)previousPort,
     (unsigned int)newPort,
     validPort ? @"YES" : @"NO"];

    [self reloadSpecifier:specifier animated:NO];
    [self refreshPromptText];
    dispatch_async(dispatch_get_main_queue(), ^{
        [self configurePortTextField];
    });

    if (!validPort) {
        [self showAlertWithTitle:IOSMCPLocalizedString(@"Invalid Port")
                         message:[NSString stringWithFormat:IOSMCPLocalizedString(@"The port must be between %d and %d. It has been reset to the default port %d."),
                                  IOS_MCP_MIN_PORT,
                                  IOS_MCP_MAX_PORT,
                                  IOS_MCP_DEFAULT_PORT]];
    }

    if (previousPort != newPort && IOSMCPEnabledPreference()) {
        [self applyPortChangeFromPort:previousPort toPort:newPort];
    } else {
        [self refreshServerStatus];
    }
}

- (void)toggleServer:(PSSpecifier *)specifier {
    if (self.serverControlBusy) {
        [self deselectSpecifier:specifier];
        return;
    }

    BOOL shouldStart = !self.serverRunning;
    uint16_t port = IOSMCPConfiguredPort();
    NSUInteger generation = ++self.serverStatusGeneration;
    [self deselectSpecifier:specifier];
    [self setServerControlBusyState:YES];
    [self updateEnabledPreference:shouldStart];
    [self postNotification:shouldStart ? IOS_MCP_DARWIN_NOTIFICATION_START : IOS_MCP_DARWIN_NOTIFICATION_STOP];
    [self updateControlStatusText:shouldStart ? [NSString stringWithFormat:IOSMCPLocalizedString(@"Status: Starting on port %u..."), (unsigned int)port] : IOSMCPLocalizedString(@"Status: Stopping...")
                      buttonTitle:shouldStart ? IOSMCPLocalizedString(@"Starting...") : IOSMCPLocalizedString(@"Stopping...")
                    buttonEnabled:YES];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1000 * NSEC_PER_MSEC)),
                   dispatch_get_main_queue(), ^{
        [self pollServerStatusExpectingRunning:shouldStart
                                          port:port
                                    generation:generation
                                  finalAttempt:NO];
    });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3000 * NSEC_PER_MSEC)),
                   dispatch_get_main_queue(), ^{
        [self pollServerStatusExpectingRunning:shouldStart
                                          port:port
                                    generation:generation
                                  finalAttempt:YES];
    });
}

- (void)copyPrompt:(PSSpecifier *)specifier {
    NSString *prompt = [self codexPrompt];
    if (prompt.length == 0) {
        [self showAlertWithTitle:IOSMCPLocalizedString(@"Unable to Share") message:IOSMCPLocalizedString(@"Unable to generate the MCP prompt snippet.")];
        return;
    }

    [UIPasteboard generalPasteboard].string = prompt;
    UITableViewCell *sourceCell = [self cachedCellForSpecifier:specifier];
    [self deselectSpecifier:specifier];

    [MCPLogger log:@"prefs_share_prompt copied chars=%lu", (unsigned long)prompt.length];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(250 * NSEC_PER_MSEC)),
                   dispatch_get_main_queue(), ^{
        [self presentPromptShareSheetWithText:prompt sourceCell:sourceCell];
    });
}

- (void)shareDebugLogs:(PSSpecifier *)specifier {
    NSMutableArray<NSDictionary<NSString *, NSString *> *> *logFiles = [NSMutableArray array];
    NSArray<NSString *> *paths = [MCPLogger allLogFilePaths];
    for (NSUInteger index = 0; index < paths.count; index++) {
        NSString *title = IOSMCPLocalizedString(@"Current Log");
        if (index == 1) {
            title = IOSMCPLocalizedString(@"Previous Log");
        }
        [logFiles addObject:@{@"path": paths[index], @"title": title}];
    }

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSFileManager *fm = [NSFileManager defaultManager];
        NSString *shareRoot = [NSTemporaryDirectory() stringByAppendingPathComponent:
                               [NSString stringWithFormat:@"ios-mcp-debug-logs-%llu",
                                (unsigned long long)([[NSDate date] timeIntervalSince1970] * 1000)]];
        NSError *createError = nil;
        if (![fm createDirectoryAtPath:shareRoot
           withIntermediateDirectories:YES
                            attributes:nil
                                 error:&createError]) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [self showAlertWithTitle:IOSMCPLocalizedString(@"Unable to Share")
                                 message:createError.localizedDescription ?: IOSMCPLocalizedString(@"Unable to prepare the debug log files.")];
            });
            return;
        }

        __block BOOL hasLogFile = NO;
        NSMutableString *report = [NSMutableString stringWithString:
                                   IOSMCPLocalizedString(@"iOS MCP Debug Logs\n"
                                   @"Exported from iOS MCP Settings to troubleshoot service startup, HTTP requests, MCP tool calls, timing, and errors.\n\n")];
        for (NSDictionary<NSString *, NSString *> *entry in logFiles) {
            NSString *sourcePath = entry[@"path"];
            NSString *title = entry[@"title"];
            BOOL isDirectory = NO;
            if (![fm fileExistsAtPath:sourcePath isDirectory:&isDirectory] || isDirectory) {
                continue;
            }
            hasLogFile = YES;

            NSError *readError = nil;
            NSData *data = [NSData dataWithContentsOfFile:sourcePath
                                                  options:0
                                                    error:&readError];
            NSString *body = nil;
            if (!data) {
                body = [NSString stringWithFormat:IOSMCPLocalizedString(@"Unable to read the log file.\nError: %@\n"),
                        readError.localizedDescription ?: IOSMCPLocalizedString(@"Unknown error")];
            } else if (data.length > 0 && memchr(data.bytes, 0, data.length) != NULL) {
                body = [NSString stringWithFormat:IOSMCPLocalizedString(@"The log file contains non-displayable data; its raw contents were not exported.\nSize: %llu bytes\n"),
                        (unsigned long long)data.length];
            } else {
                body = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
                if (!body) {
                    body = [NSString stringWithFormat:IOSMCPLocalizedString(@"The log file is not valid UTF-8 text.\nSize: %llu bytes\n"),
                            (unsigned long long)data.length];
                } else if (body.length == 0) {
                    body = IOSMCPLocalizedString(@"The log file is empty.\n");
                }
            }

            [report appendFormat:IOSMCPLocalizedString(@"## %@\nPath: %@\n\n%@\n\n"),
             title ?: IOSMCPLocalizedString(@"Log"),
             sourcePath,
             body ?: @""];
        }

        NSString *destinationPath = [shareRoot stringByAppendingPathComponent:@"ios-mcp-debug-log.txt"];
        NSError *writeError = nil;
        BOOL wroteReport = [report writeToFile:destinationPath
                                    atomically:YES
                                      encoding:NSUTF8StringEncoding
                                         error:&writeError];

        // Package the raw log files into a zip archive for sharing.
        NSMutableArray<NSString *> *zipSources = [NSMutableArray array];
        for (NSDictionary<NSString *, NSString *> *entry in logFiles) {
            BOOL isDir = NO;
            if ([fm fileExistsAtPath:entry[@"path"] isDirectory:&isDir] && !isDir) {
                [zipSources addObject:entry[@"path"]];
            }
        }
        NSString *zipPath = [shareRoot stringByAppendingPathComponent:@"ios-mcp-debug-logs.zip"];
        BOOL zipped = zipSources.count > 0 && [self buildZipAtPath:zipPath fromFiles:zipSources];

        dispatch_async(dispatch_get_main_queue(), ^{
            if (!hasLogFile) {
                [self showAlertWithTitle:IOSMCPLocalizedString(@"No Logs")
                                 message:IOSMCPLocalizedString(@"There are no debug log files to share yet.")];
                return;
            }

            UITableViewCell *sourceCell = [self cachedCellForSpecifier:specifier];
            [self deselectSpecifier:specifier];

            if (zipped) {
                NSURL *zipURL = [NSURL fileURLWithPath:zipPath];
                [MCPLogger log:@"prefs_share_debug_logs prepared_zip file=%@ path=%@ files=%lu bytes=%llu",
                 zipPath.lastPathComponent ?: @"ios-mcp-debug-logs.zip",
                 zipPath,
                 (unsigned long)zipSources.count,
                 (unsigned long long)[[NSData dataWithContentsOfFile:zipPath] length]];
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(250 * NSEC_PER_MSEC)),
                               dispatch_get_main_queue(), ^{
                    [self presentDebugLogShareSheetWithZipURL:zipURL sourceCell:sourceCell];
                });
                return;
            }

            if (!wroteReport) {
                [self showAlertWithTitle:IOSMCPLocalizedString(@"Unable to Share")
                                 message:writeError.localizedDescription ?: IOSMCPLocalizedString(@"Unable to prepare the debug log files.")];
                return;
            }

            NSURL *reportURL = [NSURL fileURLWithPath:destinationPath];
            [MCPLogger log:@"prefs_share_debug_logs prepared file=%@ bytes=%llu",
             destinationPath.lastPathComponent ?: @"ios-mcp-debug-log.txt",
             (unsigned long long)[[NSData dataWithContentsOfFile:destinationPath] length]];
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(250 * NSEC_PER_MSEC)),
                           dispatch_get_main_queue(), ^{
                [self presentDebugLogShareSheetWithURL:reportURL sourceCell:sourceCell];
            });
        });
    });
}

// Built-in minimal ZIP writer using store mode.
- (BOOL)buildZipAtPath:(NSString *)zipPath fromFiles:(NSArray<NSString *> *)files {
    if (zipPath.length == 0 || files.count == 0) {
        return NO;
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    NSMutableData *zipData = [NSMutableData data];
    NSMutableArray<NSDictionary<NSString *, id> *> *centralEntries = [NSMutableArray array];

    for (NSString *sourcePath in files) {
        BOOL isDirectory = NO;
        if (![fm fileExistsAtPath:sourcePath isDirectory:&isDirectory] || isDirectory) {
            continue;
        }

        NSError *readError = nil;
        NSData *fileData = [NSData dataWithContentsOfFile:sourcePath options:0 error:&readError];
        if (!fileData) {
            [MCPLogger log:@"prefs_share_debug_logs zip_read_failed path=%@ error=%@",
             sourcePath,
             readError.localizedDescription ?: @"unknown"];
            return NO;
        }

        NSString *entryName = sourcePath.lastPathComponent ?: @"ios-mcp.log";
        NSData *entryNameData = [entryName dataUsingEncoding:NSUTF8StringEncoding];
        if (entryNameData.length == 0 || entryNameData.length > UINT16_MAX) {
            [MCPLogger log:@"prefs_share_debug_logs zip_invalid_entry_name path=%@ entry=%@",
             sourcePath,
             entryName ?: @"<nil>"];
            return NO;
        }

        if (fileData.length > UINT32_MAX || zipData.length > UINT32_MAX) {
            [MCPLogger log:@"prefs_share_debug_logs zip_file_too_large path=%@ bytes=%llu",
             sourcePath,
             (unsigned long long)fileData.length];
            return NO;
        }

        uint32_t crc = IOSMCPCRC32(fileData);
        uint32_t size = (uint32_t)fileData.length;
        uint32_t localOffset = (uint32_t)zipData.length;

        IOSMCPAppendUInt32LE(zipData, 0x04034b50);
        IOSMCPAppendUInt16LE(zipData, 20);
        IOSMCPAppendUInt16LE(zipData, 0);
        IOSMCPAppendUInt16LE(zipData, 0);
        IOSMCPAppendUInt16LE(zipData, 0);
        IOSMCPAppendUInt16LE(zipData, 0);
        IOSMCPAppendUInt32LE(zipData, crc);
        IOSMCPAppendUInt32LE(zipData, size);
        IOSMCPAppendUInt32LE(zipData, size);
        IOSMCPAppendUInt16LE(zipData, (uint16_t)entryNameData.length);
        IOSMCPAppendUInt16LE(zipData, 0);
        [zipData appendData:entryNameData];
        [zipData appendData:fileData];

        [centralEntries addObject:@{
            @"nameData": entryNameData,
            @"crc": @(crc),
            @"size": @(size),
            @"localOffset": @(localOffset)
        }];
    }

    if (centralEntries.count == 0) {
        [MCPLogger log:@"prefs_share_debug_logs zip_no_sources path=%@", zipPath];
        return NO;
    }

    if (centralEntries.count > UINT16_MAX || zipData.length > UINT32_MAX) {
        [MCPLogger log:@"prefs_share_debug_logs zip_too_large entries=%lu bytes=%llu",
         (unsigned long)centralEntries.count,
         (unsigned long long)zipData.length];
        return NO;
    }

    uint32_t centralOffset = (uint32_t)zipData.length;
    for (NSDictionary<NSString *, id> *entry in centralEntries) {
        NSData *entryNameData = entry[@"nameData"];
        uint32_t crc = [entry[@"crc"] unsignedIntValue];
        uint32_t size = [entry[@"size"] unsignedIntValue];
        uint32_t localOffset = [entry[@"localOffset"] unsignedIntValue];

        IOSMCPAppendUInt32LE(zipData, 0x02014b50);
        IOSMCPAppendUInt16LE(zipData, 20);
        IOSMCPAppendUInt16LE(zipData, 20);
        IOSMCPAppendUInt16LE(zipData, 0);
        IOSMCPAppendUInt16LE(zipData, 0);
        IOSMCPAppendUInt16LE(zipData, 0);
        IOSMCPAppendUInt16LE(zipData, 0);
        IOSMCPAppendUInt32LE(zipData, crc);
        IOSMCPAppendUInt32LE(zipData, size);
        IOSMCPAppendUInt32LE(zipData, size);
        IOSMCPAppendUInt16LE(zipData, (uint16_t)entryNameData.length);
        IOSMCPAppendUInt16LE(zipData, 0);
        IOSMCPAppendUInt16LE(zipData, 0);
        IOSMCPAppendUInt16LE(zipData, 0);
        IOSMCPAppendUInt16LE(zipData, 0);
        IOSMCPAppendUInt32LE(zipData, 0100644U << 16);
        IOSMCPAppendUInt32LE(zipData, localOffset);
        [zipData appendData:entryNameData];
    }

    if (zipData.length > UINT32_MAX) {
        [MCPLogger log:@"prefs_share_debug_logs zip_too_large entries=%lu bytes=%llu",
         (unsigned long)centralEntries.count,
         (unsigned long long)zipData.length];
        return NO;
    }

    uint32_t centralSize = (uint32_t)(zipData.length - centralOffset);
    IOSMCPAppendUInt32LE(zipData, 0x06054b50);
    IOSMCPAppendUInt16LE(zipData, 0);
    IOSMCPAppendUInt16LE(zipData, 0);
    IOSMCPAppendUInt16LE(zipData, (uint16_t)centralEntries.count);
    IOSMCPAppendUInt16LE(zipData, (uint16_t)centralEntries.count);
    IOSMCPAppendUInt32LE(zipData, centralSize);
    IOSMCPAppendUInt32LE(zipData, centralOffset);
    IOSMCPAppendUInt16LE(zipData, 0);

    NSError *writeError = nil;
    if (![zipData writeToFile:zipPath options:NSDataWritingAtomic error:&writeError]) {
        [MCPLogger log:@"prefs_share_debug_logs zip_write_failed path=%@ error=%@",
         zipPath,
         writeError.localizedDescription ?: @"unknown"];
        return NO;
    }

    BOOL ok = [[NSFileManager defaultManager] fileExistsAtPath:zipPath];
    unsigned long long bytes = ok ? (unsigned long long)[[NSData dataWithContentsOfFile:zipPath] length] : 0;
    [MCPLogger log:@"prefs_share_debug_logs zip_done ok=%@ files=%lu bytes=%llu path=%@",
     ok ? @"yes" : @"no",
     (unsigned long)centralEntries.count,
     bytes,
     zipPath];
    return ok;
}

- (void)deselectSpecifier:(PSSpecifier *)specifier {
    if (![self respondsToSelector:@selector(indexPathForSpecifier:)]) {
        return;
    }

    NSIndexPath *indexPath = [self indexPathForSpecifier:specifier];
    UITableView *tableView = self.table;
    if (indexPath && tableView) {
        [tableView deselectRowAtIndexPath:indexPath animated:YES];
    }
}

- (void)presentPromptShareSheetWithText:(NSString *)prompt sourceCell:(UITableViewCell *)sourceCell {
    if (prompt.length == 0) {
        [self showAlertWithTitle:IOSMCPLocalizedString(@"Unable to Share") message:IOSMCPLocalizedString(@"Unable to generate the MCP prompt snippet.")];
        return;
    }

    UIActivityViewController *activityController =
        [[UIActivityViewController alloc] initWithActivityItems:@[prompt]
                                         applicationActivities:nil];
    activityController.completionWithItemsHandler = ^(__unused UIActivityType activityType,
                                                      BOOL completed,
                                                      __unused NSArray *returnedItems,
                                                      NSError *activityError) {
        [MCPLogger log:@"prefs_share_prompt completed=%@ error=%@",
         completed ? @"yes" : @"no",
         activityError.localizedDescription ?: @"<nil>"];
    };

    UIViewController *presenter = self;
    while (presenter.presentedViewController && !presenter.presentedViewController.isBeingDismissed) {
        presenter = presenter.presentedViewController;
    }

    UIPopoverPresentationController *popover = activityController.popoverPresentationController;
    if (popover) {
        UIView *anchorView = (sourceCell && sourceCell.window) ? sourceCell.contentView : presenter.view;
        popover.sourceView = anchorView;
        popover.sourceRect = CGRectMake(CGRectGetMidX(anchorView.bounds),
                                        CGRectGetMidY(anchorView.bounds),
                                        1.0,
                                        1.0);
        popover.permittedArrowDirections = UIPopoverArrowDirectionAny;
    }

    [MCPLogger log:@"prefs_share_prompt presenting presenter=%@ popover=%@ chars=%lu",
     NSStringFromClass([presenter class]),
     popover ? @"yes" : @"no",
     (unsigned long)prompt.length];
    [presenter presentViewController:activityController
                           animated:YES
                         completion:^{
        [MCPLogger log:@"prefs_share_prompt presentation_completed"];
    }];
}

- (void)presentDebugLogShareSheetWithURL:(NSURL *)reportURL sourceCell:(UITableViewCell *)sourceCell {
    if (!reportURL) {
        [self showAlertWithTitle:IOSMCPLocalizedString(@"Unable to Share") message:IOSMCPLocalizedString(@"Unable to prepare the debug log files.")];
        return;
    }

    // Share the in-process text payload rather than a file URL to avoid cross-sandbox file coordination deadlocks in Preferences.app.
    NSString *shareText = [NSString stringWithContentsOfURL:reportURL
                                                   encoding:NSUTF8StringEncoding
                                                      error:NULL];
    if (shareText.length == 0) {
        [self showAlertWithTitle:IOSMCPLocalizedString(@"Unable to Share") message:IOSMCPLocalizedString(@"Unable to read the debug log contents.")];
        return;
    }

    UIActivityViewController *activityController =
        [[UIActivityViewController alloc] initWithActivityItems:@[shareText]
                                         applicationActivities:nil];
    activityController.completionWithItemsHandler = ^(__unused UIActivityType activityType,
                                                      BOOL completed,
                                                      __unused NSArray *returnedItems,
                                                      NSError *activityError) {
        [MCPLogger log:@"prefs_share_debug_logs completed=%@ error=%@",
         completed ? @"yes" : @"no",
         activityError.localizedDescription ?: @"<nil>"];
    };

    UIViewController *presenter = self;
    while (presenter.presentedViewController && !presenter.presentedViewController.isBeingDismissed) {
        presenter = presenter.presentedViewController;
    }

    UIPopoverPresentationController *popover = activityController.popoverPresentationController;
    if (popover) {
        UIView *anchorView = (sourceCell && sourceCell.window) ? sourceCell.contentView : presenter.view;
        popover.sourceView = anchorView;
        popover.sourceRect = CGRectMake(CGRectGetMidX(anchorView.bounds),
                                        CGRectGetMidY(anchorView.bounds),
                                        1.0,
                                        1.0);
        popover.permittedArrowDirections = UIPopoverArrowDirectionAny;
    }

    [MCPLogger log:@"prefs_share_debug_logs presenting presenter=%@ popover=%@ chars=%lu",
     NSStringFromClass([presenter class]),
     popover ? @"yes" : @"no",
     (unsigned long)shareText.length];
    [presenter presentViewController:activityController
                           animated:YES
                         completion:^{
        [MCPLogger log:@"prefs_share_debug_logs presentation_completed"];
    }];
}

- (void)presentDebugLogShareSheetWithZipURL:(NSURL *)zipURL sourceCell:(UITableViewCell *)sourceCell {
    // Share the ZIP archive via in-memory NSItemProvider data representation.
    NSData *zipData = zipURL ? [NSData dataWithContentsOfURL:zipURL] : nil;
    if (zipData.length == 0) {
        [self showAlertWithTitle:IOSMCPLocalizedString(@"Unable to Share") message:IOSMCPLocalizedString(@"Unable to read the debug log archive.")];
        return;
    }

    NSArray *activityItems = nil;
    if (@available(iOS 14.0, *)) {
        NSItemProvider *provider = [[NSItemProvider alloc] init];
        provider.suggestedName = @"ios-mcp-debug-logs";
        [provider registerDataRepresentationForTypeIdentifier:@"public.zip-archive"
                                                   visibility:NSItemProviderRepresentationVisibilityAll
                                                  loadHandler:^NSProgress * _Nullable(void (^completionHandler)(NSData *_Nullable, NSError *_Nullable)) {
            completionHandler(zipData, nil);
            return nil;
        }];
        activityItems = @[provider];
    } else {
        activityItems = @[zipData];
    }

    UIActivityViewController *activityController =
        [[UIActivityViewController alloc] initWithActivityItems:activityItems
                                         applicationActivities:nil];
    activityController.completionWithItemsHandler = ^(__unused UIActivityType activityType,
                                                      BOOL completed,
                                                      __unused NSArray *returnedItems,
                                                      NSError *activityError) {
        [MCPLogger log:@"prefs_share_debug_logs zip completed=%@ error=%@",
         completed ? @"yes" : @"no",
         activityError.localizedDescription ?: @"<nil>"];
    };

    UIViewController *presenter = self;
    while (presenter.presentedViewController && !presenter.presentedViewController.isBeingDismissed) {
        presenter = presenter.presentedViewController;
    }

    UIPopoverPresentationController *popover = activityController.popoverPresentationController;
    if (popover) {
        UIView *anchorView = (sourceCell && sourceCell.window) ? sourceCell.contentView : presenter.view;
        popover.sourceView = anchorView;
        popover.sourceRect = CGRectMake(CGRectGetMidX(anchorView.bounds),
                                        CGRectGetMidY(anchorView.bounds),
                                        1.0,
                                        1.0);
        popover.permittedArrowDirections = UIPopoverArrowDirectionAny;
    }

    [MCPLogger log:@"prefs_share_debug_logs zip presenting presenter=%@ popover=%@",
     NSStringFromClass([presenter class]),
     popover ? @"yes" : @"no"];
    [presenter presentViewController:activityController
                           animated:YES
                         completion:^{
        [MCPLogger log:@"prefs_share_debug_logs zip presentation_completed"];
    }];
}

- (void)clearDebugLogs:(PSSpecifier *)specifier {
    NSError *error = nil;
    if ([MCPLogger clearLogsWithError:&error]) {
        [self showAlertWithTitle:IOSMCPLocalizedString(@"Logs Cleared")
                         message:IOSMCPLocalizedString(@"The debug log files have been cleared.")];
        [self refreshDebugLogFooter];
        return;
    }

    [self showAlertWithTitle:IOSMCPLocalizedString(@"Unable to Clear Logs")
                     message:error.localizedDescription ?: IOSMCPLocalizedString(@"Unable to clear the debug log files.")];
}

- (void)respringButtonTapped:(id)sender {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:IOSMCPLocalizedString(@"Restart SpringBoard")
                                                                  message:IOSMCPLocalizedString(@"Restart SpringBoard? You will need to unlock the device again afterward.")
                                                           preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:IOSMCPLocalizedString(@"Cancel") style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:IOSMCPLocalizedString(@"Respring") style:UIAlertActionStyleDestructive handler:^(__unused UIAlertAction *action) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(300 * NSEC_PER_MSEC)), dispatch_get_main_queue(), ^{
            NSString *killallPath = IOSMCPKillallPath();
            if (!killallPath.length) {
                [MCPLogger log:@"prefs_respring failed reason=missing_killall"];
                [self showAlertWithTitle:IOSMCPLocalizedString(@"Unable to Restart") message:IOSMCPLocalizedString(@"The killall executable could not be found.")];
                return;
            }

            pid_t pid = 0;
            const char *argv[] = {"killall", "-9", "SpringBoard", NULL};
            int status = posix_spawn(&pid,
                                     killallPath.fileSystemRepresentation,
                                     NULL,
                                     NULL,
                                     (char *const *)argv,
                                     NULL);
            if (status != 0) {
                [MCPLogger log:@"prefs_respring failed status=%d error=%s", status, strerror(status)];
                [self showAlertWithTitle:IOSMCPLocalizedString(@"Unable to Restart")
                                 message:[NSString stringWithFormat:IOSMCPLocalizedString(@"Unable to execute killall: %s"), strerror(status)]];
                return;
            }

            [MCPLogger log:@"prefs_respring spawned pid=%d path=%@", pid, killallPath];
        });
    }]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)refreshServerStatus {
    NSUInteger generation = ++self.serverStatusGeneration;
    uint16_t port = IOSMCPConfiguredPort();
    [self setServerControlBusyState:YES];
    __weak typeof(self) weakSelf = self;
    [self fetchServerRunningOnPort:port completion:^(BOOL running, NSError *error) {
        __strong typeof(weakSelf) self = weakSelf;
        if (!self || generation != self.serverStatusGeneration || port != IOSMCPConfiguredPort()) {
            return;
        }

        self.serverRunning = running;
        NSString *stoppedText = (error.code == NSURLErrorTimedOut)
            ? [NSString stringWithFormat:IOSMCPLocalizedString(@"Status: No response on port %u"), (unsigned int)port]
            : [NSString stringWithFormat:IOSMCPLocalizedString(@"Status: Stopped (port %u)"), (unsigned int)port];
        [self updateControlStatusText:running ? [NSString stringWithFormat:IOSMCPLocalizedString(@"Status: Running (port %u)"), (unsigned int)port]
                                             : stoppedText
                          buttonTitle:running ? IOSMCPLocalizedString(@"Stop iOS MCP") : IOSMCPLocalizedString(@"Start iOS MCP")
                        buttonEnabled:YES];
        [self setServerControlBusyState:NO];
    }];
}

- (void)fetchServerRunningOnPort:(uint16_t)port completion:(void (^)(BOOL running, NSError *error))completion {
    NSURL *url = [NSURL URLWithString:[NSString stringWithFormat:@"http://127.0.0.1:%u/health", (unsigned int)port]];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    request.timeoutInterval = 5.0;
    request.cachePolicy = NSURLRequestReloadIgnoringLocalCacheData;

    NSURLSessionConfiguration *configuration = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    configuration.timeoutIntervalForRequest = 5.0;
    configuration.timeoutIntervalForResource = 6.0;

    NSURLSession *session = [NSURLSession sessionWithConfiguration:configuration];
    NSURLSessionDataTask *task = [session dataTaskWithRequest:request
                                            completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        BOOL running = [self isHealthyServerResponseData:data response:response error:error];
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) {
                completion(running, error);
            }
        });

        [session finishTasksAndInvalidate];
    }];
    [task resume];
}

- (void)pollServerStatusExpectingRunning:(BOOL)expectedRunning
                                    port:(uint16_t)port
                              generation:(NSUInteger)generation
                            finalAttempt:(BOOL)finalAttempt {
    if (generation != self.serverStatusGeneration || port != IOSMCPConfiguredPort()) {
        return;
    }

    __weak typeof(self) weakSelf = self;
    [self fetchServerRunningOnPort:port completion:^(BOOL running, NSError *error) {
        __strong typeof(weakSelf) self = weakSelf;
        if (!self || generation != self.serverStatusGeneration || port != IOSMCPConfiguredPort()) {
            return;
        }
        if (running != expectedRunning && !finalAttempt) {
            return;
        }

        // Finalizing invalidates the fallback poll that has not fired yet, or
        // any slower request from the same toggle operation.
        self.serverStatusGeneration++;
        self.serverRunning = running;
        NSString *stoppedText = (error.code == NSURLErrorTimedOut)
            ? [NSString stringWithFormat:IOSMCPLocalizedString(@"Status: No response on port %u"), (unsigned int)port]
            : [NSString stringWithFormat:IOSMCPLocalizedString(@"Status: Stopped (port %u)"), (unsigned int)port];
        [self updateControlStatusText:running ? [NSString stringWithFormat:IOSMCPLocalizedString(@"Status: Running (port %u)"), (unsigned int)port]
                                             : stoppedText
                          buttonTitle:running ? IOSMCPLocalizedString(@"Stop iOS MCP") : IOSMCPLocalizedString(@"Start iOS MCP")
                        buttonEnabled:YES];
        [self setServerControlBusyState:NO];
    }];
}

- (void)applyPortChangeFromPort:(uint16_t)previousPort toPort:(uint16_t)newPort {
    if (previousPort == newPort) {
        [MCPLogger log:@"prefs_port apply skipped unchanged current=%u",
         (unsigned int)newPort];
        [self refreshServerStatus];
        return;
    }

    [MCPLogger log:@"prefs_port applying running_change previous=%u current=%u",
     (unsigned int)previousPort,
     (unsigned int)newPort];

    NSUInteger generation = ++self.serverStatusGeneration;
    [self setServerControlBusyState:YES];
    [self updateControlStatusText:[NSString stringWithFormat:IOSMCPLocalizedString(@"Status: Switching to port %u..."), (unsigned int)newPort]
                      buttonTitle:IOSMCPLocalizedString(@"Switching...")
                    buttonEnabled:YES];
    // START is handled as a serialized restart in SpringBoard. Do not guess
    // when an asynchronous dispatch-source cancellation has closed the old fd.
    [self postNotification:IOS_MCP_DARWIN_NOTIFICATION_START];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1000 * NSEC_PER_MSEC)),
                   dispatch_get_main_queue(), ^{
        [self pollServerStatusExpectingRunning:YES
                                          port:newPort
                                    generation:generation
                                  finalAttempt:NO];
    });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3000 * NSEC_PER_MSEC)),
                   dispatch_get_main_queue(), ^{
        [self pollServerStatusExpectingRunning:YES
                                          port:newPort
                                    generation:generation
                                  finalAttempt:YES];
    });
}

- (void)configurePortTextField {
    UITableViewCell *cell = [self portPreferenceCell];
    UITextField *textField = [self textFieldInView:cell.contentView] ?: [self textFieldInView:cell];
    if (!textField) {
        return;
    }

    textField.keyboardType = UIKeyboardTypeNumbersAndPunctuation;
    textField.returnKeyType = UIReturnKeyDone;
    textField.enablesReturnKeyAutomatically = NO;
    textField.autocorrectionType = UITextAutocorrectionTypeNo;
    textField.autocapitalizationType = UITextAutocapitalizationTypeNone;
    if (textField.delegate != self) {
        self.originalPortTextFieldDelegate = textField.delegate;
        textField.delegate = self;
    }
    [textField removeTarget:self
                     action:@selector(portTextFieldDidEndOnExit:)
           forControlEvents:UIControlEventEditingDidEndOnExit];
    [textField addTarget:self
                  action:@selector(portTextFieldDidEndOnExit:)
        forControlEvents:UIControlEventEditingDidEndOnExit];
    [textField removeTarget:self
                     action:@selector(portTextFieldDidEndOnExit:)
           forControlEvents:UIControlEventPrimaryActionTriggered];
    [textField addTarget:self
                  action:@selector(portTextFieldDidEndOnExit:)
        forControlEvents:UIControlEventPrimaryActionTriggered];

    if (textField.isFirstResponder) {
        [textField reloadInputViews];
    }
}

- (void)dismissKeyboardFromTap:(UITapGestureRecognizer *)gestureRecognizer {
    if (gestureRecognizer.state == UIGestureRecognizerStateEnded) {
        [self.view endEditing:YES];
    }
}

- (BOOL)gestureRecognizer:(UIGestureRecognizer *)gestureRecognizer shouldReceiveTouch:(UITouch *)touch {
    if (gestureRecognizer != self.keyboardDismissTapGesture) {
        return YES;
    }

    UIView *view = touch.view;
    while (view) {
        if ([view isKindOfClass:[UITextField class]]) {
            return NO;
        }
        view = view.superview;
    }

    UITableViewCell *portCell = [self portPreferenceCell];
    if (portCell) {
        CGPoint pointInPortCell = [touch locationInView:portCell];
        if ([portCell pointInside:pointInPortCell withEvent:nil]) {
            return NO;
        }
    }

    view = touch.view;
    while (view) {
        if (view == portCell || view == portCell.contentView) {
            return NO;
        }
        view = view.superview;
    }
    return YES;
}

- (BOOL)gestureRecognizer:(UIGestureRecognizer *)gestureRecognizer
shouldRecognizeSimultaneouslyWithGestureRecognizer:(UIGestureRecognizer *)otherGestureRecognizer {
    return gestureRecognizer == self.keyboardDismissTapGesture || otherGestureRecognizer == self.keyboardDismissTapGesture;
}

- (void)installKeyboardDismissGestureIfNeeded {
    UIView *containerView = self.view;
    if (!containerView || self.keyboardDismissTapGesture) {
        return;
    }

    UITapGestureRecognizer *tapGesture =
        [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(dismissKeyboardFromTap:)];
    tapGesture.cancelsTouchesInView = NO;
    tapGesture.delegate = self;
    [containerView addGestureRecognizer:tapGesture];
    self.keyboardDismissTapGesture = tapGesture;
}

- (BOOL)isPortTextField:(UITextField *)textField {
    UITableViewCell *cell = [self portPreferenceCell];
    UITextField *portTextField = [self textFieldInView:cell.contentView] ?: [self textFieldInView:cell];
    return textField && textField == portTextField;
}

- (UITableViewCell *)portPreferenceCell {
    PSSpecifier *portSpecifier = [self specifierForID:@"httpPortField"];
    if (!portSpecifier) {
        return nil;
    }

    UITableViewCell *cell = [self cachedCellForSpecifier:portSpecifier];
    if (!cell && [self respondsToSelector:@selector(indexPathForSpecifier:)]) {
        NSIndexPath *indexPath = [self indexPathForSpecifier:portSpecifier];
        if (indexPath) {
            cell = [self.table cellForRowAtIndexPath:indexPath];
        }
    }
    return cell;
}

- (void)portTextFieldDidEndOnExit:(UITextField *)textField {
    [textField resignFirstResponder];
    [self.view endEditing:YES];
}

- (BOOL)textFieldShouldBeginEditing:(UITextField *)textField {
    id<UITextFieldDelegate> delegate = self.originalPortTextFieldDelegate;
    if ([self isPortTextField:textField] &&
        delegate &&
        delegate != self &&
        [delegate respondsToSelector:@selector(textFieldShouldBeginEditing:)]) {
        return [delegate textFieldShouldBeginEditing:textField];
    }
    return YES;
}

- (void)textFieldDidBeginEditing:(UITextField *)textField {
    id<UITextFieldDelegate> delegate = self.originalPortTextFieldDelegate;
    if ([self isPortTextField:textField] &&
        delegate &&
        delegate != self &&
        [delegate respondsToSelector:@selector(textFieldDidBeginEditing:)]) {
        [delegate textFieldDidBeginEditing:textField];
    }
}

- (BOOL)textFieldShouldEndEditing:(UITextField *)textField {
    if ([self isPortTextField:textField]) {
        return YES;
    }

    id<UITextFieldDelegate> delegate = self.originalPortTextFieldDelegate;
    if (delegate &&
        delegate != self &&
        [delegate respondsToSelector:@selector(textFieldShouldEndEditing:)]) {
        return [delegate textFieldShouldEndEditing:textField];
    }
    return YES;
}

- (void)textFieldDidEndEditing:(UITextField *)textField {
    id<UITextFieldDelegate> delegate = self.originalPortTextFieldDelegate;
    if ([self isPortTextField:textField] &&
        delegate &&
        delegate != self &&
        [delegate respondsToSelector:@selector(textFieldDidEndEditing:)]) {
        [delegate textFieldDidEndEditing:textField];
    }
}

- (BOOL)textFieldShouldReturn:(UITextField *)textField {
    if ([self isPortTextField:textField]) {
        [textField resignFirstResponder];
        [self.view endEditing:YES];
        return YES;
    }

    id<UITextFieldDelegate> delegate = self.originalPortTextFieldDelegate;
    if (delegate &&
        delegate != self &&
        [delegate respondsToSelector:@selector(textFieldShouldReturn:)]) {
        return [delegate textFieldShouldReturn:textField];
    }
    return YES;
}

- (UITextField *)textFieldInView:(UIView *)view {
    if ([view isKindOfClass:[UITextField class]]) {
        return (UITextField *)view;
    }

    for (UIView *subview in view.subviews) {
        UITextField *textField = [self textFieldInView:subview];
        if (textField) {
            return textField;
        }
    }
    return nil;
}

- (UILabel *)labelInView:(UIView *)view {
    if ([view isKindOfClass:[UILabel class]]) {
        return (UILabel *)view;
    }

    for (UIView *subview in view.subviews) {
        UILabel *label = [self labelInView:subview];
        if (label) {
            return label;
        }
    }
    return nil;
}

- (void)updateVisibleFooterText:(NSString *)text forSpecifier:(PSSpecifier *)specifier {
    NSInteger group = NSNotFound;
    NSInteger row = NSNotFound;
    if (!specifier || ![self getGroup:&group row:&row ofSpecifier:specifier] || group == NSNotFound) {
        return;
    }

    UITableView *tableView = self.table;
    UIView *footerView = [tableView footerViewForSection:group];
    UILabel *footerLabel = nil;
    if ([footerView isKindOfClass:[UITableViewHeaderFooterView class]]) {
        footerLabel = ((UITableViewHeaderFooterView *)footerView).textLabel;
    }
    footerLabel = footerLabel ?: [self labelInView:footerView];
    if (footerLabel && ![footerLabel.text isEqualToString:text]) {
        footerLabel.text = text;
        [footerView setNeedsLayout];
    }
}

- (void)setServerControlBusyState:(BOOL)busy {
    self.serverControlBusy = busy;

    PSSpecifier *toggleSpecifier = [self specifierForID:@"toggleServerButton"];
    NSNumber *enabledValue = [toggleSpecifier propertyForKey:PSEnabledKey];
    BOOL enabled = enabledValue ? enabledValue.boolValue : YES;
    PSTableCell *toggleCell = [self cachedCellForSpecifier:toggleSpecifier];
    if (toggleCell) {
        toggleCell.userInteractionEnabled = enabled && !busy;
    }
}

- (BOOL)isHealthyServerResponseData:(NSData *)data response:(NSURLResponse *)response error:(NSError *)error {
    if (error || !data) {
        return NO;
    }

    NSHTTPURLResponse *httpResponse = [response isKindOfClass:[NSHTTPURLResponse class]] ? (NSHTTPURLResponse *)response : nil;
    if (httpResponse.statusCode != 200) {
        return NO;
    }

    NSError *jsonError = nil;
    NSDictionary *payload = [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonError];
    if (jsonError) {
        return NO;
    }

    if (![payload isKindOfClass:[NSDictionary class]]) {
        return NO;
    }

    NSString *status = [payload[@"status"] isKindOfClass:[NSString class]] ? payload[@"status"] : nil;
    NSString *server = [payload[@"server"] isKindOfClass:[NSString class]] ? payload[@"server"] : nil;
    return [status isEqualToString:@"ok"] && [server isEqualToString:@"ios-mcp"];
}

- (void)refreshPromptText {
    PSSpecifier *promptSpecifier = [self specifierForID:@"codexPromptGroup"];
    if (!promptSpecifier) {
        return;
    }

    [promptSpecifier setProperty:[self codexPrompt] forKey:PSFooterTextGroupKey];
    [self reloadSpecifier:promptSpecifier animated:NO];
}

- (void)refreshDebugLogFooter {
    PSSpecifier *debugSpecifier = [self specifierForID:@"debugLogGroup"];
    if (!debugSpecifier) {
        return;
    }

    NSString *lastError = [MCPLogger lastLogError];
    NSString *footer = [NSString stringWithFormat:
                        IOSMCPLocalizedString(@"Log service startup, HTTP requests, MCP tool calls, timing, and errors to help troubleshoot issues. Screenshot contents, full UI trees, clipboard contents, typed text, and request bodies are not recorded.\n\nCurrent log: %@\nPrevious log: %@%@"),
                        [MCPLogger logFilePath],
                        [MCPLogger previousLogFilePath],
                        lastError.length ? [NSString stringWithFormat:IOSMCPLocalizedString(@"\nLast write error: %@"), lastError] : @""];
    [debugSpecifier setProperty:footer forKey:PSFooterTextGroupKey];
    [self reloadSpecifier:debugSpecifier animated:NO];
}

- (void)updateControlStatusText:(NSString *)statusText buttonTitle:(NSString *)buttonTitle buttonEnabled:(BOOL)buttonEnabled {
    PSSpecifier *groupSpecifier = [self specifierForID:@"serviceControlGroup"];
    PSSpecifier *toggleSpecifier = [self specifierForID:@"toggleServerButton"];

    if (groupSpecifier) {
        NSString *currentStatus = [groupSpecifier propertyForKey:PSFooterTextGroupKey];
        if (![currentStatus isEqualToString:statusText]) {
            [groupSpecifier setProperty:statusText forKey:PSFooterTextGroupKey];
            [self updateVisibleFooterText:statusText forSpecifier:toggleSpecifier];
        }
    }

    if (toggleSpecifier) {
        NSString *currentTitle = [toggleSpecifier propertyForKey:PSTitleKey] ?: toggleSpecifier.name;
        NSNumber *currentEnabledValue = [toggleSpecifier propertyForKey:PSEnabledKey];
        BOOL currentEnabled = currentEnabledValue ? currentEnabledValue.boolValue : YES;
        BOOL titleChanged = ![currentTitle isEqualToString:buttonTitle];
        BOOL enabledChanged = currentEnabled != buttonEnabled;

        toggleSpecifier.name = buttonTitle;
        [toggleSpecifier setProperty:buttonTitle forKey:PSTitleKey];
        [toggleSpecifier setProperty:@(buttonEnabled) forKey:PSEnabledKey];
        if (titleChanged || enabledChanged) {
            PSTableCell *toggleCell = [self cachedCellForSpecifier:toggleSpecifier];
            if (toggleCell) {
                [UIView performWithoutAnimation:^{
                    [toggleCell refreshCellContentsWithSpecifier:toggleSpecifier];
                    toggleCell.cellEnabled = buttonEnabled;
                    toggleCell.userInteractionEnabled = buttonEnabled && !self.serverControlBusy;
                    [toggleCell setNeedsLayout];
                    [toggleCell layoutIfNeeded];
                }];
            }
        }
    }
}

- (void)updateEnabledPreference:(BOOL)enabled {
    CFPreferencesSetAppValue((__bridge CFStringRef)IOS_MCP_ENABLED_PREFERENCE_KEY,
                             enabled ? kCFBooleanTrue : kCFBooleanFalse,
                             (__bridge CFStringRef)IOS_MCP_PREFERENCES_DOMAIN);
    CFPreferencesAppSynchronize((__bridge CFStringRef)IOS_MCP_PREFERENCES_DOMAIN);
}

- (void)postNotification:(CFStringRef)notificationName {
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                         notificationName,
                                         NULL,
                                         NULL,
                                         YES);
}

- (NSString *)codexPrompt {
    NSString *promptFormat = IOSMCPLocalizedString(@"MCP_PROMPT");
    NSString *basePrompt = [NSString stringWithFormat:
                            promptFormat,
                            IOSMCPServiceURLString(),
                            IOSMCPHealthURLString()];
    NSDictionary *net = IOSMCPNetworkInterfacesSummary();
    uint16_t port = IOSMCPConfiguredPort();
    NSString *wifiIp = [net[@"wifi_ipv4"] isKindOfClass:NSString.class] ? net[@"wifi_ipv4"] : @"";
    NSString *cellIpv4 = [net[@"cellular_ipv4"] isKindOfClass:NSString.class] ? net[@"cellular_ipv4"] : @"";
    NSString *cellIpv6 = [net[@"cellular_ipv6"] isKindOfClass:NSString.class] ? net[@"cellular_ipv6"] : @"";
    NSString *vpnIp = [net[@"vpn_tailscale_ipv4"] isKindOfClass:NSString.class] ? net[@"vpn_tailscale_ipv4"] : @"";
    NSString *bridgeHost = IOSMCPWanBridgeHost();
    uint16_t bridgePort = IOSMCPWanBridgePort();

    NSMutableString *extra = [NSMutableString stringWithString:@"\n\n[Wi-Fi + Cellular WAN Endpoints]"];
    if (wifiIp.length > 0) {
        [extra appendFormat:@"\n- Wi-Fi (en0): http://%@:%u/mcp", wifiIp, (unsigned int)port];
    }
    if (cellIpv4.length > 0 && ![cellIpv4 hasPrefix:@"192.0.0."]) {
        [extra appendFormat:@"\n- Cellular IPv4 (pdp_ip0): http://%@:%u/mcp", cellIpv4, (unsigned int)port];
    }
    if (cellIpv6.length > 0) {
        [extra appendFormat:@"\n- Cellular IPv6 (pdp_ip0): http://[%@]:%u/mcp", cellIpv6, (unsigned int)port];
    }
    if (vpnIp.length > 0) {
        [extra appendFormat:@"\n- Tailscale/VPN (utun): http://%@:%u/mcp", vpnIp, (unsigned int)port];
    }
    if (bridgeHost.length > 0 && IOSMCPWanBridgeEnabled()) {
        [extra appendFormat:@"\n- Remote Home-PC Bridge (%@:%u -> PC Local): http://127.0.0.1:8090/mcp", bridgeHost, (unsigned int)bridgePort];
    }
    return [basePrompt stringByAppendingString:extra];
}

- (NSDictionary *)readLatestNetworkResetReceipt {
    NSArray<NSString *> *paths = @[
        jbroot(@"/var/mobile/Library/ios-mcp/last_network_reset.json") ?: @"",
        @"/var/mobile/Library/ios-mcp/last_network_reset.json"
    ];
    for (NSString *path in paths) {
        if (!path.length) continue;
        NSData *data = [NSData dataWithContentsOfFile:path];
        if (!data.length) continue;
        id parsed = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
        if ([parsed isKindOfClass:[NSDictionary class]]) {
            return parsed;
        }
    }
    return nil;
}

- (void)pollNetworkResetReceiptSince:(NSTimeInterval)triggerTs
                             attempt:(NSInteger)attempt
                           specifier:(PSSpecifier *)specifier {
    NSDictionary *receipt = [self readLatestNetworkResetReceipt];
    NSTimeInterval ts = [receipt[@"timestamp"] respondsToSelector:@selector(doubleValue)] ? [receipt[@"timestamp"] doubleValue] : 0.0;
    if (receipt && ts >= (triggerTs - 1.5)) {
        NSString *defaultLabel = IOSMCPLocalizedString(@"Reset Wi-Fi / Cellular & Kill Tasks");
        if (specifier) {
            specifier.name = defaultLabel;
            [specifier setProperty:defaultLabel forKey:PSTitleKey];
            [specifier setProperty:@YES forKey:PSEnabledKey];
            [self reloadSpecifier:specifier animated:NO];
        }
        [self reloadSpecifiers];
        [self refreshPromptText];
        [self refreshServerStatus];

        NSInteger proxiesCleared = [receipt[@"proxies_cleared_count"] integerValue];
        NSInteger pinsCleared = [receipt[@"app_pins_cleared"] integerValue];
        NSInteger enginesUnloaded = [receipt[@"engines_unloaded_count"] integerValue];
        NSInteger tasksStopped = [receipt[@"watchdogs_cleared"] integerValue] + [receipt[@"detached_tasks_stopped"] integerValue];
        NSDictionary *cell = [receipt[@"cellular"] isKindOfClass:[NSDictionary class]] ? receipt[@"cellular"] : @{};
        BOOL wifiOn = [cell[@"wifi_enabled"] boolValue];
        BOOL apOff = ![cell[@"airplane_mode"] boolValue];

        NSString *msg = [NSString stringWithFormat:
                         IOSMCPLocalizedString(@"Network and MCP tasks reset.\n\n- Stuck proxies cleared: %ld\n- App egress pins cleared: %ld\n- Injected app hooks unloaded: %ld\n- Background tasks/watchdogs stopped: %ld\n- Wi-Fi: %@  |  Airplane Mode: %@"),
                         (long)proxiesCleared,
                         (long)pinsCleared,
                         (long)enginesUnloaded,
                         (long)tasksStopped,
                         wifiOn ? @"ON" : @"OFF",
                         apOff ? @"OFF" : @"ON"];
        [self showAlertWithTitle:IOSMCPLocalizedString(@"Network Reset Complete") message:msg];
        return;
    }

    if (attempt >= 20) {
        NSString *defaultLabel = IOSMCPLocalizedString(@"Reset Wi-Fi / Cellular & Kill Tasks");
        if (specifier) {
            specifier.name = defaultLabel;
            [specifier setProperty:defaultLabel forKey:PSTitleKey];
            [specifier setProperty:@YES forKey:PSEnabledKey];
            [self reloadSpecifier:specifier animated:NO];
        }
        [self showAlertWithTitle:IOSMCPLocalizedString(@"Reset Signal Sent")
                         message:IOSMCPLocalizedString(@"The recovery signal was sent to SpringBoard. If networking is still unresponsive, tap Respring in the top-right corner.")];
        return;
    }

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(400 * NSEC_PER_MSEC)),
                   dispatch_get_main_queue(), ^{
        [self pollNetworkResetReceiptSince:triggerTs attempt:attempt + 1 specifier:specifier];
    });
}

- (void)resetNetworkAndTasks:(PSSpecifier *)specifier {
    [self deselectSpecifier:specifier];
    UIAlertController *confirm = [UIAlertController alertControllerWithTitle:IOSMCPLocalizedString(@"Reset Wi-Fi / Cellular & Kill Tasks?")
                                                                     message:IOSMCPLocalizedString(@"This clears stuck Wi-Fi HTTP/HTTPS proxies, turns Airplane Mode off, restores Wi-Fi & Cellular Data, stops WAN/rotation tasks and watchdogs, clears all per-app egress pins, and unloads lingering AI-injected app hooks.")
                                                              preferredStyle:UIAlertControllerStyleAlert];
    [confirm addAction:[UIAlertAction actionWithTitle:IOSMCPLocalizedString(@"Cancel")
                                                style:UIAlertActionStyleCancel
                                              handler:nil]];
    __weak typeof(self) weakSelf = self;
    [confirm addAction:[UIAlertAction actionWithTitle:IOSMCPLocalizedString(@"Reset Everything")
                                                style:UIAlertActionStyleDestructive
                                              handler:^(__unused UIAlertAction *action) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) return;
        NSTimeInterval triggerTs = [[NSDate date] timeIntervalSince1970];
        if (specifier) {
            NSString *busyLabel = IOSMCPLocalizedString(@"Resetting Network & Tasks...");
            specifier.name = busyLabel;
            [specifier setProperty:busyLabel forKey:PSTitleKey];
            [specifier setProperty:@NO forKey:PSEnabledKey];
            [strongSelf reloadSpecifier:specifier animated:NO];
        }
        [strongSelf postNotification:IOS_MCP_DARWIN_NOTIFICATION_RESET_NETWORK];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(500 * NSEC_PER_MSEC)),
                       dispatch_get_main_queue(), ^{
            [strongSelf pollNetworkResetReceiptSince:triggerTs attempt:0 specifier:specifier];
        });
    }]];
    [self presentViewController:confirm animated:YES completion:nil];
}

- (void)showAlertWithTitle:(NSString *)title message:(NSString *)message {
    UIAlertController *alertController = [UIAlertController alertControllerWithTitle:title
                                                                             message:message
                                                                      preferredStyle:UIAlertControllerStyleAlert];
    [alertController addAction:[UIAlertAction actionWithTitle:IOSMCPLocalizedString(@"OK")
                                                        style:UIAlertActionStyleDefault
                                                      handler:nil]];
    [self presentViewController:alertController animated:YES completion:nil];
}

@end
