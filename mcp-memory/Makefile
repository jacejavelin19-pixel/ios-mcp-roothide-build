ARCHS = arm64 arm64e
TARGET = iphone:clang:latest:15.0

include $(THEOS)/makefiles/common.mk

TOOL_NAME = mcp-memory
mcp-memory_FILES = main.m ../MemoryManager.m
mcp-memory_CFLAGS = -fobjc-arc -I..
mcp-memory_FRAMEWORKS = Foundation
mcp-memory_CODESIGN_FLAGS = -Sentitlements.plist
mcp-memory_INSTALL_PATH = /usr/libexec/ios-mcp

include $(THEOS_MAKE_PATH)/tool.mk
