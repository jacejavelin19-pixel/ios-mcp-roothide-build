override THEOS_PACKAGE_SCHEME :=
unexport THEOS_PACKAGE_SCHEME
export TARGET = iphone:clang:latest:15.0
export ARCHS = arm64 arm64e
export DEBUG = 0

include $(THEOS)/makefiles/common.mk
LIBRARY_NAME = libmcpengine
libmcpengine_FILES = engine.m engine_objc.m engine_native.m engine_mem.m engine_netcap.m engine_re.m engine_crypto.m engine_antifraud.m engine_webview.m engine_media_bio.m engine_social.m ../common/fishhook.c
libmcpengine_CFLAGS = -fobjc-arc -I../common -Wall -Wextra -Wno-unused-parameter -Wno-deprecated-declarations -Wno-unknown-warning-option -Wno-cast-function-type-mismatch
libmcpengine_FRAMEWORKS = Foundation UIKit CoreGraphics CFNetwork Network Security SystemConfiguration CoreMotion WebKit JavaScriptCore AVFoundation CoreMedia CoreVideo CoreImage CoreLocation LocalAuthentication AuthenticationServices AudioToolbox
libmcpengine_LIBRARIES = objc
libmcpengine_LDFLAGS = -Wl,-install_name,@executable_path/Frameworks/libmcpengine.dylib
libmcpengine_INSTALL_PATH = /usr/lib/ios-mcp
include $(THEOS_MAKE_PATH)/library.mk
