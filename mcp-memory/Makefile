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

TOOL_NAME = mcp-memory
mcp-memory_FILES = main.m ../MemoryManager.m
mcp-memory_CFLAGS = -fobjc-arc -I..
mcp-memory_FRAMEWORKS = Foundation
mcp-memory_CODESIGN_FLAGS = -Sentitlements.plist
mcp-memory_INSTALL_PATH = /usr/libexec/ios-mcp

include $(THEOS_MAKE_PATH)/tool.mk
