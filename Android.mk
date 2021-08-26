#############################################################################
#
# Copyright (c) 2012 - 2013 Samsung Electronics Co., Ltd
#
#############################################################################

ifeq ($(BOARD_WLAN_DEVICE),slsi)

LOCAL_PATH := $(call my-dir)

# Make the HAL library
# ============================================================
include $(CLEAR_VARS)

LOCAL_CFLAGS := -Wno-unused-parameter

LOCAL_HEADER_LIBRARIES := liblog_headers

LOCAL_C_INCLUDES += \
        system/core/include/ \
	external/libnl/include \
        $(call include-path-for, libhardware_legacy)/hardware_legacy \
        external/wpa_supplicant_8/src/drivers

LOCAL_SRC_FILES := \
	wifi_hal.cpp \
	rtt.cpp \
	common.cpp \
	cpp_bindings.cpp \
	gscan.cpp \
	link_layer_stats.cpp \
	wifi_offload.cpp \
	roam.cpp \
	wifi_logger.cpp \
	wifi_nan.cpp \
	wifi_nan_data_path.cpp

LOCAL_MODULE := libwifi-hal-slsi
LOCAL_VENDOR_MODULE := true

include $(BUILD_STATIC_LIBRARY)

endif
