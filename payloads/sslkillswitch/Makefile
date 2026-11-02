override THEOS_PACKAGE_SCHEME :=
unexport THEOS_PACKAGE_SCHEME
export TARGET = iphone:clang:latest:15.0
export ARCHS = arm64 arm64e
export DEBUG = 0

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = libmcp_sslks
libmcp_sslks_FILES = sslks.m ../common/fishhook.c
libmcp_sslks_CFLAGS = -fobjc-arc -I../common -Wno-deprecated-declarations
libmcp_sslks_FRAMEWORKS = Foundation Security CFNetwork
libmcp_sslks_LDFLAGS = -Wl,-install_name,@executable_path/Frameworks/libmcp_sslks.dylib
libmcp_sslks_INSTALL_PATH = /usr/lib/ios-mcp

include $(THEOS_MAKE_PATH)/library.mk
