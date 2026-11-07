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

TOOL_NAME = mcp-appstore
mcp-appstore_FILES = main.m
mcp-appstore_CFLAGS = -fobjc-arc -Wno-deprecated-declarations -Wno-unused-function -Wno-unknown-warning-option -Wno-cast-function-type-mismatch
mcp-appstore_FRAMEWORKS = Foundation Security CFNetwork
mcp-appstore_CODESIGN_FLAGS = -Sentitlements.plist
ifeq ($(THEOS_PACKAGE_SCHEME),roothide)
    mcp-appstore_CFLAGS += -DMCP_ROOTHIDE=1
    mcp-appstore_LIBRARIES = roothide
endif
mcp-appstore_INSTALL_PATH = /usr/libexec/ios-mcp

include $(THEOS_MAKE_PATH)/tool.mk
