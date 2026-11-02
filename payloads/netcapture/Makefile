override THEOS_PACKAGE_SCHEME :=
unexport THEOS_PACKAGE_SCHEME
export TARGET = iphone:clang:latest:15.0
export ARCHS = arm64 arm64e
export DEBUG = 0

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = libmcp_netcap
libmcp_netcap_FILES = netcap.m
libmcp_netcap_CFLAGS = -fobjc-arc -Wno-deprecated-declarations
libmcp_netcap_FRAMEWORKS = Foundation CFNetwork
libmcp_netcap_LDFLAGS = -Wl,-install_name,@executable_path/Frameworks/libmcp_netcap.dylib
libmcp_netcap_INSTALL_PATH = /usr/lib/ios-mcp

include $(THEOS_MAKE_PATH)/library.mk
