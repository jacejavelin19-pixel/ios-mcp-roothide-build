#import "IOSMCPLocalization.h"

@interface IOSMCPLocalizationAnchor : NSObject
@end
@implementation IOSMCPLocalizationAnchor
@end

NSString *IOSMCPLocalizedString(NSString *key) {
    if (!key.length) return @"";
    NSBundle *bundle = [NSBundle bundleForClass:IOSMCPLocalizationAnchor.class];
    NSString *englishPath = [bundle pathForResource:@"en" ofType:@"lproj"];
    NSBundle *english = englishPath ? [NSBundle bundleWithPath:englishPath] : bundle;
    return [english localizedStringForKey:key value:key table:nil] ?: key;
}
