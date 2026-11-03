ifeq ($(THEOS_PACKAGE_SCHEME),rootless)
    export TARGET = iphone:clang:latest:15.0
else ifeq ($(THEOS_PACKAGE_SCHEME),roothide)
    export TARGET = iphone:clang:latest:15.0
else
    export TARGET = iphone:clang:latest:13.0
endif
export ARCHS = arm64 arm64e
export DEBUG = 0

include $(THEOS)/makefiles/common.mk

TOOL_NAME = mcp-helperd
mcp-helperd_FILES = main.m
mcp-helperd_CFLAGS = -fobjc-arc -Wno-deprecated-declarations
mcp-helperd_FRAMEWORKS = Foundation
mcp-helperd_CODESIGN_FLAGS = -Sentitlements.plist
ifeq ($(THEOS_PACKAGE_SCHEME),roothide)
    mcp-helperd_CFLAGS += -DMCP_ROOTHIDE=1
    mcp-helperd_LIBRARIES = roothide
endif
mcp-helperd_INSTALL_PATH = /usr/libexec/ios-mcp

include $(THEOS_MAKE_PATH)/tool.mk
