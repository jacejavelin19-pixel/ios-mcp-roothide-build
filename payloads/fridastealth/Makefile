override THEOS_PACKAGE_SCHEME :=
unexport THEOS_PACKAGE_SCHEME
export TARGET = iphone:clang:latest:15.0
export ARCHS = arm64 arm64e
export DEBUG = 0

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = libmcp_stealth
libmcp_stealth_FILES = stealth.m ../common/fishhook.c
libmcp_stealth_CFLAGS = -fobjc-arc -I../common -Wno-deprecated-declarations -Wno-unused-function -Wno-unused-variable
libmcp_stealth_FRAMEWORKS = Foundation UIKit
libmcp_stealth_LDFLAGS = -Wl,-install_name,@executable_path/Frameworks/libmcp_stealth.dylib
libmcp_stealth_INSTALL_PATH = /usr/lib/ios-mcp

include $(THEOS_MAKE_PATH)/library.mk
