
#include "wifi_hal.h"

#ifndef __WIFI_HAL_COMMON_H__
#define __WIFI_HAL_COMMON_H__

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG  "WifiHAL"

#include <log/log.h>
#include "nl80211_copy.h"
#include "sync.h"

#define SOCKET_BUFFER_SIZE      (32768U)
#define RECV_BUF_SIZE           (4096)
#define DEFAULT_EVENT_CB_SIZE   (64)
#define DEFAULT_CMD_SIZE        (64)
#define DOT11_OUI_LEN             3
#define WIFI_MAX_INFO_BUFFER_SIZE  41

#ifdef SLSI_WIFI_HAL_NL_ATTR_CONFIG
#define WIFI_HAL_ATTR_START 1
#define NLA_F_NESTED        (1 << 15)
#define NLA_F_NET_BYTEORDER (1 << 14)
#define NLA_TYPE_MASK       ~(NLA_F_NESTED | NLA_F_NET_BYTEORDER)
#else
#define WIFI_HAL_ATTR_START 0
#endif

typedef struct {
	int num_bssid;
	mac_addr bssids[MAX_BLACKLIST_BSSID];
} wifi_bssid_params;

/*
 Vendor OUI - This is a unique identifier that identifies organization. Lets
 code Android specific functions with Google OUI; although vendors can do more
 with their own OUI's as well.
 */

const uint32_t GOOGLE_OUI = 0x001A11;
const uint32_t SAMSUNG_OUI = 0x0000f0;

/* TODO: define vendor OUI here */

typedef enum {

    GSCAN_ATTRIBUTE_NUM_BUCKETS = 10,
    GSCAN_ATTRIBUTE_BASE_PERIOD,
    GSCAN_ATTRIBUTE_BUCKETS_BAND,
    GSCAN_ATTRIBUTE_BUCKET_ID,
    GSCAN_ATTRIBUTE_BUCKET_PERIOD,
    GSCAN_ATTRIBUTE_BUCKET_NUM_CHANNELS,
    GSCAN_ATTRIBUTE_BUCKET_CHANNELS,
    GSCAN_ATTRIBUTE_NUM_AP_PER_SCAN,
    GSCAN_ATTRIBUTE_REPORT_THRESHOLD,
    GSCAN_ATTRIBUTE_NUM_SCANS_TO_CACHE,
    GSCAN_ATTRIBUTE_REPORT_THRESHOLD_NUM_SCANS,
    GSCAN_ATTRIBUTE_BAND = GSCAN_ATTRIBUTE_BUCKETS_BAND,

    GSCAN_ATTRIBUTE_ENABLE_FEATURE = 20,
    GSCAN_ATTRIBUTE_SCAN_RESULTS_COMPLETE,              /* indicates no more results */
    GSCAN_ATTRIBUTE_REPORT_EVENTS,

    /* remaining reserved for additional attributes */
    GSCAN_ATTRIBUTE_NUM_OF_RESULTS = 30,
    GSCAN_ATTRIBUTE_SCAN_RESULTS,                       /* flat array of wifi_scan_result */
    GSCAN_ATTRIBUTE_NUM_CHANNELS,
    GSCAN_ATTRIBUTE_CHANNEL_LIST,
    GSCAN_ATTRIBUTE_SCAN_ID,
    GSCAN_ATTRIBUTE_SCAN_FLAGS,
    GSCAN_ATTRIBUTE_SCAN_BUCKET_BIT,

    /* remaining reserved for additional attributes */
    GSCAN_ATTRIBUTE_RSSI_SAMPLE_SIZE = 60,
    GSCAN_ATTRIBUTE_LOST_AP_SAMPLE_SIZE,
    GSCAN_ATTRIBUTE_MIN_BREACHING,
    GSCAN_ATTRIBUTE_SIGNIFICANT_CHANGE_BSSIDS,

    GSCAN_ATTRIBUTE_BUCKET_STEP_COUNT = 70,
    GSCAN_ATTRIBUTE_BUCKET_EXPONENT,
    GSCAN_ATTRIBUTE_BUCKET_MAX_PERIOD,

    GSCAN_ATTRIBUTE_NUM_BSSID,
    GSCAN_ATTRIBUTE_BLACKLIST_BSSID,

    GSCAN_ATTRIBUTE_MAX

} GSCAN_ATTRIBUTE;

/*
 This enum defines ranges for various commands; commands themselves
 can be defined in respective feature headers; i.e. find gscan command
 definitions in gscan.cpp
 */

typedef enum {
    /* don't use 0 as a valid subcommand */
    VENDOR_NL80211_SUBCMD_UNSPECIFIED,

    /* define all vendor startup commands between 0x0 and 0x0FFF */
    VENDOR_NL80211_SUBCMD_RANGE_START = 0x0001,
    VENDOR_NL80211_SUBCMD_RANGE_END   = 0x0FFF,

    /* define all GScan related commands between 0x1000 and 0x10FF */
    ANDROID_NL80211_SUBCMD_GSCAN_RANGE_START = 0x1000,
    ANDROID_NL80211_SUBCMD_GSCAN_RANGE_END   = 0x10FF,

    /* define all NearbyDiscovery related commands between 0x1100 and 0x11FF */
    ANDROID_NL80211_SUBCMD_NBD_RANGE_START = 0x1100,
    ANDROID_NL80211_SUBCMD_NBD_RANGE_END   = 0x11FF,

    /* define all RTT related commands between 0x1100 and 0x11FF */
    ANDROID_NL80211_SUBCMD_RTT_RANGE_START = 0x1100,
    ANDROID_NL80211_SUBCMD_RTT_RANGE_END   = 0x11FF,

    ANDROID_NL80211_SUBCMD_LSTATS_RANGE_START = 0x1200,
    ANDROID_NL80211_SUBCMD_LSTATS_RANGE_END   = 0x12FF,

    /* define all Logger related commands between 0x1400 and 0x14FF */
    ANDROID_NL80211_SUBCMD_DEBUG_RANGE_START = 0x1400,
    ANDROID_NL80211_SUBCMD_DEBUG_RANGE_END   = 0x14FF,

    /* define all wifi offload related commands between 0x1400 and 0x14FF */
    ANDROID_NL80211_SUBCMD_WIFI_OFFLOAD_RANGE_START = 0x1400,
    ANDROID_NL80211_SUBCMD_WIFI_OFFLOAD_RANGE_END   = 0x14FF,

    /* Range for NAN commands */
    ANDROID_NL80211_SUBCMD_NAN_RANGE_START = 0x1500,
    ANDROID_NL80211_SUBCMD_NAN_RANGE_END   = 0x15FF,
   /* This is reserved for future usage */

    /* define all APF related commands between 0x1600 and 0x16FF */
    ANDROID_NL80211_SUBCMD_APF_RANGE_START = 0x1600,
    ANDROID_NL80211_SUBCMD_APF_RANGE_END   = 0x16FF,

} ANDROID_VENDOR_SUB_COMMAND;

typedef enum {
    SLSI_NL80211_VENDOR_SUBCMD_GET_CAPABILITIES = ANDROID_NL80211_SUBCMD_GSCAN_RANGE_START,
    SLSI_NL80211_VENDOR_SUBCMD_GET_VALID_CHANNELS,
    SLSI_NL80211_VENDOR_SUBCMD_ADD_GSCAN,
    SLSI_NL80211_VENDOR_SUBCMD_DEL_GSCAN,
    SLSI_NL80211_VENDOR_SUBCMD_GET_SCAN_RESULTS,
    /**********Deprecated now due to fapi updates.Do not remove*/
    SLSI_NL80211_VENDOR_SUBCMD_SET_BSSID_HOTLIST,
    SLSI_NL80211_VENDOR_SUBCMD_RESET_BSSID_HOTLIST,
    SLSI_NL80211_VENDOR_SUBCMD_GET_HOTLIST_RESULTS,
    SLSI_NL80211_VENDOR_SUBCMD_SET_SIGNIFICANT_CHANGE,
    SLSI_NL80211_VENDOR_SUBCMD_RESET_SIGNIFICANT_CHANGE,
    /******************************************/
    SLSI_NL80211_VENDOR_SUBCMD_SET_GSCAN_OUI,
    SLSI_NL80211_VENDOR_SUBCMD_SET_NODFS,
    SLSI_NL80211_VENDOR_SUBCMD_START_KEEP_ALIVE_OFFLOAD,
    SLSI_NL80211_VENDOR_SUBCMD_STOP_KEEP_ALIVE_OFFLOAD,
    SLSI_NL80211_VENDOR_SUBCMD_SET_BSSID_BLACKLIST,
    SLSI_NL80211_VENDOR_SUBCMD_SET_EPNO_LIST,
    SLSI_NL80211_VENDOR_SUBCMD_SET_HS_LIST,
    SLSI_NL80211_VENDOR_SUBCMD_RESET_HS_LIST,
    SLSI_NL80211_VENDOR_SUBCMD_SET_RSSI_MONITOR,
    SLSI_NL80211_VENDOR_SUBCMD_LLS_SET_INFO,
    SLSI_NL80211_VENDOR_SUBCMD_LLS_GET_INFO,
    SLSI_NL80211_VENDOR_SUBCMD_LLS_CLEAR_INFO,
    SLSI_NL80211_VENDOR_SUBCMD_GET_FEATURE_SET,
    SLSI_NL80211_VENDOR_SUBCMD_SET_COUNTRY_CODE,
    SLSI_NL80211_VENDOR_SUBCMD_CONFIGURE_ND_OFFLOAD,
    SLSI_NL80211_VENDOR_SUBCMD_GET_ROAMING_CAPABILITIES,
    SLSI_NL80211_VENDOR_SUBCMD_SET_ROAMING_STATE,
    SLSI_NL80211_VENDOR_SUBCMD_SET_LATENCY_MODE,
    SLSI_NL80211_VENDOR_SUBCMD_GET_USABLE_CHANNELS,

    SLSI_NL80211_VENDOR_SUBCMD_NAN_ENABLE = ANDROID_NL80211_SUBCMD_NAN_RANGE_START,
    SLSI_NL80211_VENDOR_SUBCMD_NAN_DISABLE,
    SLSI_NL80211_VENDOR_SUBCMD_NAN_PUBLISH,
    SLSI_NL80211_VENDOR_SUBCMD_NAN_PUBLISHCANCEL,
    SLSI_NL80211_VENDOR_SUBCMD_NAN_SUBSCRIBE,
    SLSI_NL80211_VENDOR_SUBCMD_NAN_SUBSCRIBECANCEL,
    SLSI_NL80211_VENDOR_SUBCMD_NAN_TXFOLLOWUP,
    SLSI_NL80211_VENDOR_SUBCMD_NAN_CONFIG,
    SLSI_NL80211_VENDOR_SUBCMD_NAN_CAPABILITIES,
    SLSI_NL80211_VENDOR_SUBCMD_NAN_DATA_INTERFACE_CREATE,
    SLSI_NL80211_VENDOR_SUBCMD_NAN_DATA_INTERFACE_DELETE,
    SLSI_NL80211_VENDOR_SUBCMD_NAN_DATA_REQUEST_INITIATOR,
    SLSI_NL80211_VENDOR_SUBCMD_NAN_DATA_INDICATION_RESPONSE,
    SLSI_NL80211_VENDOR_SUBCMD_NAN_DATA_END,
    SLSI_NL80211_VENDOR_SUBCMD_RTT_GET_CAPABILITIES = ANDROID_NL80211_SUBCMD_RTT_RANGE_START,
    SLSI_NL80211_VENDOR_SUBCMD_RTT_RANGE_START,
    SLSI_NL80211_VENDOR_SUBCMD_RTT_RANGE_CANCEL,

    SLSI_NL80211_VENDOR_SUBCMD_APF_SET_FILTER = ANDROID_NL80211_SUBCMD_APF_RANGE_START,
    SLSI_NL80211_VENDOR_SUBCMD_APF_GET_CAPABILITIES,
    SLSI_NL80211_VENDOR_SUBCMD_APF_READ_FILTER
} WIFI_SUB_COMMAND;

typedef enum {
    /**********Deprecated now due to fapi updates.Do not remove*/
    GSCAN_EVENT_SIGNIFICANT_CHANGE_RESULTS ,
    GSCAN_EVENT_HOTLIST_RESULTS_FOUND,
    /******************************************/
    GSCAN_EVENT_SCAN_RESULTS_AVAILABLE,
    GSCAN_EVENT_FULL_SCAN_RESULTS,
    GSCAN_EVENT_COMPLETE_SCAN,
    /**********Deprecated now due to fapi updates.Do not remove*/
    GSCAN_EVENT_HOTLIST_RESULTS_LOST,
    /******************************************/
    WIFI_SUBCMD_KEY_MGMT_ROAM_AUTH, /* Handled by supplicant. not in Wifi-HAL */
    WIFI_HANGED_EVENT,
    WIFI_EPNO_EVENT,
    WIFI_HOTSPOT_MATCH,
    WIFI_RSSI_REPORT_EVENT = 10,
    ENHANCE_LOGGER_RING_EVENT,
    ENHANCE_LOGGER_MEM_DUMP_EVENT,
    /* NAN events start */
    SLSI_NAN_EVENT_RESPONSE = 13,
    SLSI_NAN_EVENT_PUBLISH_TERMINATED,
    SLSI_NAN_EVENT_MATCH,
    SLSI_NAN_EVENT_MATCH_EXPIRED,
    SLSI_NAN_EVENT_SUBSCRIBE_TERMINATED,
    SLSI_NAN_EVENT_FOLLOWUP,
    SLSI_NAN_EVENT_DISCOVERY_ENGINE,
    SLSI_NAN_EVENT_DISABLED = 20,
    SLSI_RTT_RESULT_EVENT,
    SLSI_RTT_EVENT_COMPLETE,
    WIFI_ACS_EVENT,            /* Handled by supplicant. not in Wifi-HAL */
    SLSI_NL80211_VENDOR_FORWARD_BEACON,
    SLSI_NL80211_VENDOR_FORWARD_BEACON_ABORT,
    SLSI_NAN_EVENT_TRANSMIT_FOLLOWUP_STATUS,
    /* NAN DATA PATH EVENTS*/
    SLSI_NAN_EVENT_NDP_REQ,
    SLSI_NAN_EVENT_NDP_CFM,
    SLSI_NAN_EVENT_NDP_END,
    WIFI_SUBSYSTEM_RESTART_EVENT = 33,
    SLSI_NL80211_VENDOR_NAN_INTERFACE_CREATED = 39,
    SLSI_NL80211_VENDOR_NAN_INTERFACE_DELETED

} WIFI_EVENT;

typedef void (*wifi_internal_event_handler) (wifi_handle handle, int events);

class WifiCommand;

typedef struct {
    int nl_cmd;
    uint32_t vendor_id;
    int vendor_subcmd;
    nl_recvmsg_msg_cb_t cb_func;
    void *cb_arg;
} cb_info;

typedef struct {
    wifi_request_id id;
    WifiCommand *cmd;
} cmd_info;

typedef struct {
    wifi_handle handle;                             // handle to wifi data
    char name[IFNAMSIZ+1];                                 // interface name + trailing null
    int  id;                                        // id to use when talking to driver
} interface_info;

typedef struct {

    struct nl_sock *cmd_sock;                       // command socket object
    struct nl_sock *event_sock;                     // event socket object
    int nl80211_family_id;                          // family id for 80211 driver
    int cleanup_socks[2];                           // sockets used to implement wifi_cleanup
    int ioctl_sock;

    bool in_event_loop;                             // Indicates that event loop is active
    bool clean_up;                                  // Indication to clean up the socket

    wifi_internal_event_handler event_handler;      // default event handler
    wifi_cleaned_up_handler cleaned_up_handler;     // socket cleaned up handler

    cb_info *event_cb;                              // event callbacks
    int num_event_cb;                               // number of event callbacks
    int alloc_event_cb;                             // number of allocated callback objects
    pthread_mutex_t cb_lock;                        // mutex for the event_cb access

    cmd_info *cmd;                                  // Outstanding commands
    int num_cmd;                                    // number of commands
    int alloc_cmd;                                  // number of commands allocated

    interface_info **interfaces;                    // array of interfaces
    int num_interfaces;                             // number of interfaces

    WifiCommand *nanCmd;

    // add other details
} hal_info;

wifi_error wifi_register_handler(wifi_handle handle, int cmd, nl_recvmsg_msg_cb_t func, void *arg);
wifi_error wifi_register_vendor_handler(wifi_handle handle,
            uint32_t id, int subcmd, nl_recvmsg_msg_cb_t func, void *arg);

void wifi_unregister_handler(wifi_handle handle, int cmd);
void wifi_unregister_vendor_handler(wifi_handle handle, uint32_t id, int subcmd);

wifi_error wifi_register_cmd(wifi_handle handle, int id, WifiCommand *cmd);
WifiCommand *wifi_unregister_cmd(wifi_handle handle, int id);
WifiCommand *wifi_get_cmd(wifi_handle handle, int id);
void wifi_unregister_cmd(wifi_handle handle, WifiCommand *cmd);
wifi_error wifi_cancel_cmd(wifi_request_id id, wifi_interface_handle iface);

interface_info *getIfaceInfo(wifi_interface_handle);
wifi_handle getWifiHandle(wifi_interface_handle handle);
hal_info *getHalInfo(wifi_handle handle);
hal_info *getHalInfo(wifi_interface_handle handle);
wifi_handle getWifiHandle(hal_info *info);
wifi_interface_handle getIfaceHandle(interface_info *info);

void wifi_set_nan_cmd(wifi_handle handle, WifiCommand *cmd);
void wifi_reset_nan_cmd(wifi_handle handle);
WifiCommand *wifi_get_nan_cmd(wifi_handle handle);
void wifi_log_hex2string(const u8 *hex_buffer, int length, char *hex_string);
void wifi_log_hex_buffer_debug(const char *pre_str, const char *post_str, const u8 *hex_buffer, int hex_len);
void wifi_log_hex_buffer_info(const char *pre_str, const char *post_str, const u8 *hex_buffer, int hex_len);
void wifi_log_hex_buffer_warn(const char *pre_str, const char *post_str, const u8 *hex_buffer, int hex_len);
void wifi_log_hex_buffer_error(const char *pre_str, const char *post_str, const u8 *hex_buffer, int hex_len);
void set_reset_in_progress(uint8_t value);
uint8_t is_reset_in_progress();

// some common macros

#define min(x, y)       ((x) < (y) ? (x) : (y))
#define max(x, y)       ((x) > (y) ? (x) : (y))

#define NULL_CHECK_RETURN(ptr, str, ret) \
    do { \
        if (!(ptr)) { \
            ALOGE("%s(): null pointer - #ptr (%s)\n", __FUNCTION__, str); \
            return ret; \
        } \
    } while (0)
#endif

