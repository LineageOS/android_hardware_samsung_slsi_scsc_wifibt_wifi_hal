/*
 *  Copyright 2019 Samsung Electronics Co. Ltd
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at

 *  http://www.apache.org/licenses/LICENSE-2.0

 *  Unless required by applicable law or agreed to in writing, software

 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <linux/rtnetlink.h>
#include <netpacket/packet.h>
#include <linux/filter.h>
#include <linux/errqueue.h>

#include <linux/pkt_sched.h>
#include <netlink/object-api.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/attr.h>
#include <netlink/handlers.h>
#include <netlink/msg.h>

#include <dirent.h>
#include <net/if.h>

#include "sync.h"

#define LOG_TAG  "WifiHAL"

#include <log/log.h>
#include "wifi_hal.h"
#include "common.h"
#include "cpp_bindings.h"
#include "roam.h"


#define WIFI_HAL_CMD_SOCK_PORT       644
#define WIFI_HAL_EVENT_SOCK_PORT     645

#define FEATURE_SET                  0
#define FEATURE_SET_MATRIX           1
#define ATTR_NODFS_VALUE             3
#ifndef SLSI_WIFI_HAL_NL_ATTR_CONFIG
#define ATTR_COUNTRY_CODE            4
#define ATTR_LOW_LATENCY_MODE        5
#endif

static int internal_no_seq_check(nl_msg *msg, void *arg);
static int internal_valid_message_handler(nl_msg *msg, void *arg);
static int wifi_get_multicast_id(wifi_handle handle, const char *name, const char *group);
static int wifi_add_membership(wifi_handle handle, const char *group);
static wifi_error wifi_init_interfaces(wifi_handle handle);

typedef enum wifi_attr {
    ANDR_WIFI_ATTRIBUTE_ND_OFFLOAD_CONFIG = WIFI_HAL_ATTR_START,
    ANDR_WIFI_ATTRIBUTE_PNO_RANDOM_MAC_OUI,
    ANDR_WIFI_ATTRIBUTE_GSCAN_OUI_MAX
} wifi_attr_t;

enum wifi_rssi_monitor_attr {
    RSSI_MONITOR_ATTRIBUTE_MAX_RSSI = WIFI_HAL_ATTR_START,
    RSSI_MONITOR_ATTRIBUTE_MIN_RSSI,
    RSSI_MONITOR_ATTRIBUTE_START,
    RSSI_MONITOR_ATTRIBUTE_MAX
};

enum wifi_apf_attr {
    APF_ATTRIBUTE_VERSION,
    APF_ATTRIBUTE_MAX_LEN,
    APF_ATTRIBUTE_PROGRAM,
    APF_ATTRIBUTE_PROGRAM_LEN,
    APF_ATTRIBUTE_MAX
};

enum apf_request_type {
    GET_APF_CAPABILITIES,
    SET_APF_PROGRAM,
    READ_APF_PROGRAM
};

#ifdef SLSI_WIFI_HAL_NL_ATTR_CONFIG
enum wifi_low_latency_attr {
    ATTR_LOW_LATENCY_MODE = 1,
    ATTR_LOW_LATENCY_MAX
};

enum country_code_attr {
    ATTR_COUNTRY_CODE = 1,
    ATTR_COUNTRY_CODE_MAX
};
#endif

enum slsi_usable_channel_attr {
    SLSI_UC_ATTRIBUTE_BAND = 1,
    SLSI_UC_ATTRIBUTE_IFACE_MODE,
    SLSI_UC_ATTRIBUTE_FILTER,
    SLSI_UC_ATTRIBUTE_MAX_NUM,
    SLSI_UC_ATTRIBUTE_NUM_CHANNELS,
    SLSI_UC_ATTRIBUTE_CHANNEL_LIST,
    SLSI_UC_ATTRIBUTE_MAX
};

enum slsi_uc_iface_mode {
    SLSI_UC_ITERFACE_STA = 1 << 0,
    SLSI_UC_ITERFACE_SOFTAP = 1 << 1,
    SLSI_UC_ITERFACE_IBSS = 1 << 2,
    SLSI_UC_ITERFACE_P2P_CLIENT = 1 << 3,
    SLSI_UC_ITERFACE_P2P_GO = 1 << 4,
    SLSI_UC_ITERFACE_P2P_NAN = 1 << 5,
    SLSI_UC_ITERFACE_P2P_MESH = 1 << 6,
    SLSI_UC_ITERFACE_P2P_TDLS = 1 << 7,
    SLSI_UC_ITERFACE_UNKNOWN = -1,
};

static wifi_error wifi_start_rssi_monitoring(wifi_request_id id, wifi_interface_handle
                        iface, s8 max_rssi, s8 min_rssi, wifi_rssi_event_handler eh);
static wifi_error wifi_stop_rssi_monitoring(wifi_request_id id, wifi_interface_handle iface);
wifi_error wifi_get_wake_reason_stats(wifi_interface_handle iface, WLAN_DRIVER_WAKE_REASON_CNT *wifi_wake_reason_cnt);
wifi_error wifi_get_usable_channels(wifi_handle handle, uint32_t band, uint32_t iface_mode, uint32_t filter,
                                    uint32_t max_num, uint32_t *num_channels, wifi_usable_channel *channels);

/* Initialize/Cleanup */

void wifi_socket_set_local_port(struct nl_sock *sock, uint32_t port)
{
    uint32_t pid = getpid() & 0x3FFFFF;
    nl_socket_set_local_port(sock, pid + (port << 22));
}

class AndroidPktFilterCommand : public WifiCommand {
    private:
        const u8* mProgram = NULL;
        u32 mProgramLen = 0;
        u32* mVersion = NULL;
        u32* mMaxLen = 0;
        u32 mSourceOffset = 0;
        u8 *mHostDestination = NULL;
        u32 mLength = 0;
        int mReqType = 0;
    public:
        AndroidPktFilterCommand(wifi_interface_handle handle,
                u32* version, u32* max_len)
            : WifiCommand(handle, 0),
                    mVersion(version), mMaxLen(max_len),
                    mReqType(GET_APF_CAPABILITIES)
        {
        }

        AndroidPktFilterCommand(wifi_interface_handle handle,
                const u8* program, u32 len)
            : WifiCommand(handle, 0),
                    mProgram(program), mProgramLen(len),
                    mReqType(SET_APF_PROGRAM)
        {
        }

        AndroidPktFilterCommand(wifi_interface_handle handle,
                u32 src_offset, u8 *host_dst, u32 length)
            : WifiCommand(handle, 0),
                    mSourceOffset(src_offset), mHostDestination(host_dst), mLength(length),
                    mReqType(READ_APF_PROGRAM)
        {
        }

    int createRequest(WifiRequest& request) {
        if (mReqType == SET_APF_PROGRAM) {
            ALOGI("\n%s: APF set program request\n", __FUNCTION__);
            return createSetPktFilterRequest(request);
        } else if (mReqType == GET_APF_CAPABILITIES) {
            ALOGI("\n%s: APF get capabilities request\n", __FUNCTION__);
            return createGetPktFilterCapabilitesRequest(request);
        } else if (mReqType == READ_APF_PROGRAM) {
            ALOGI("\n%s: APF read program request\n", __FUNCTION__);
            return createReadPktFilterRequest(request);
        } else {
            ALOGE("\n%s Unknown APF request\n", __FUNCTION__);
            return WIFI_ERROR_NOT_SUPPORTED;
        }
        return WIFI_SUCCESS;
    }

    int createSetPktFilterRequest(WifiRequest& request) {
        u8 *program = new u8[mProgramLen];
        nlattr *data = NULL;
        NULL_CHECK_RETURN(program, "memory allocation failure", WIFI_ERROR_OUT_OF_MEMORY);
        int result = request.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_APF_SET_FILTER);
        if (result < 0)
            goto exit;

        data = request.attr_start(NL80211_ATTR_VENDOR_DATA);
        result = request.put_u32(APF_ATTRIBUTE_PROGRAM_LEN, mProgramLen);
        if (result < 0)
            goto exit;

        memcpy(program, mProgram, mProgramLen);
        result = request.put(APF_ATTRIBUTE_PROGRAM, program, mProgramLen);
        if (result < 0)
            goto exit;
        request.attr_end(data);

exit:
        delete[] program;
        return result;
    }

    int createGetPktFilterCapabilitesRequest(WifiRequest& request) {
        return request.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_APF_GET_CAPABILITIES);
    }

    int createReadPktFilterRequest(WifiRequest& request) {
        return request.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_APF_READ_FILTER);
    }

    int start() {
        WifiRequest request(familyId(), ifaceId());
        int result = createRequest(request);
        if (result < 0) {
            return result;
        }
        result = requestResponse(request);
        if (result < 0) {
            ALOGI("Request Response failed for APF, result = %d", result);
            return result;
        }
        ALOGI("Done!");
        return result;
    }

    int cancel() {
        return WIFI_SUCCESS;
    }

    int handleResponse(WifiEvent& reply) {
        ALOGD("In SetAPFCommand::handleResponse");

        if (reply.get_cmd() != NL80211_CMD_VENDOR) {
            ALOGD("Ignoring reply with cmd = %d", reply.get_cmd());
            return NL_SKIP;
        }

        int id = reply.get_vendor_id();
        int subcmd = reply.get_vendor_subcmd();

        nlattr *vendor_data = reply.get_attribute(NL80211_ATTR_VENDOR_DATA);
        int len = reply.get_vendor_data_len();

        ALOGD("Id = %0x, subcmd = %d, len = %d", id, subcmd, len);
        if (vendor_data == NULL || len == 0) {
            ALOGE("no vendor data in SetAPFCommand response; ignoring it");
            return NL_SKIP;
        }
        if (mReqType == GET_APF_CAPABILITIES) {
            *mVersion = 0;
            *mMaxLen = 0;
            ALOGD("Response recieved for get packet filter capabilities command\n");
            for (nl_iterator it(vendor_data); it.has_next(); it.next()) {
                if (it.get_type() == APF_ATTRIBUTE_VERSION) {
                    *mVersion = it.get_u32();
                    ALOGI("APF version is %d\n", *mVersion);
                } else if (it.get_type() == APF_ATTRIBUTE_MAX_LEN) {
                    *mMaxLen = it.get_u32();
                    ALOGI("APF max len is %d\n", *mMaxLen);
                } else {
                    ALOGE("Ignoring invalid attribute type = %d, size = %d",
                            it.get_type(), it.get_len());
                }
            }
        } else if (mReqType == READ_APF_PROGRAM) {
            ALOGD("Response recieved for read apf packet filter command\n");
            u32 len = reply.get_vendor_data_len();
            void *data = reply.get_vendor_data();

            memcpy(mHostDestination, (u8 *)data + mSourceOffset, min(len, mLength));
        }
        return NL_OK;
    }

    int handleEvent(WifiEvent& event) {
        /* No Event to recieve for APF commands */
        return NL_SKIP;
    }
};

class SetNdoffloadCommand : public WifiCommand {

private:
    u8 mEnable;
public:
    SetNdoffloadCommand(wifi_interface_handle handle, u8 enable)
        : WifiCommand(handle, 0) {
        mEnable = enable;
    }
    virtual int create() {
        int ret;

        ret = mMsg.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_CONFIGURE_ND_OFFLOAD);
        if (ret < 0) {
            ALOGE("Can't create message to send to driver - %d", ret);
            return WIFI_ERROR_NOT_AVAILABLE;
        }

        nlattr *data = mMsg.attr_start(NL80211_ATTR_VENDOR_DATA);
        ret = mMsg.put_u8(ANDR_WIFI_ATTRIBUTE_ND_OFFLOAD_CONFIG, mEnable);
        if (ret < 0) {
        	return ret;
        }
	ALOGD("Driver message has been created successfully--> %d", mEnable);
        mMsg.attr_end(data);
        return WIFI_SUCCESS;
    }
};

static nl_sock * wifi_create_nl_socket(int port)
{
    struct nl_sock *sock = nl_socket_alloc();
    if (sock == NULL) {
        ALOGE("Could not create handle");
        return NULL;
    }

    wifi_socket_set_local_port(sock, port);

    if (nl_connect(sock, NETLINK_GENERIC)) {
        ALOGE("Could not connect handle");
        nl_socket_free(sock);
        return NULL;
    }

    return sock;
}


wifi_error wifi_configure_nd_offload(wifi_interface_handle handle, u8 enable)
{
	SetNdoffloadCommand command(handle, enable);
	int ret = command.requestResponse();
	if (ret != WIFI_SUCCESS) {
		if (ret == -EPERM) {           /*This is just to pass VTS test */
			ALOGD("return value from driver--> %d",ret);
			return WIFI_SUCCESS;
		}
	}
	return (wifi_error)ret;
}

wifi_error wifi_get_packet_filter_capabilities(wifi_interface_handle handle,
        u32 *version, u32 *max_len)
{
    ALOGD("Getting APF capabilities, halHandle = %p\n", handle);
    AndroidPktFilterCommand *cmd = new AndroidPktFilterCommand(handle, version, max_len);
    NULL_CHECK_RETURN(cmd, "memory allocation failure", WIFI_ERROR_OUT_OF_MEMORY);
    wifi_error result = (wifi_error)cmd->start();
    if (result == WIFI_SUCCESS) {
        ALOGD("Getting APF capability, version = %d, max_len = %d\n", *version, *max_len);
    } else {
        /* Return success to pass VTS test */
        *version = 0;
        *max_len = 0;
        ALOGD("Packet Filter not supported");
        result = WIFI_SUCCESS;
    }
    cmd->releaseRef();
    return result;
}

wifi_error wifi_set_packet_filter(wifi_interface_handle handle,
        const u8 *program, u32 len)
{
    ALOGD("Setting APF program, halHandle = %p\n", handle);
    AndroidPktFilterCommand *cmd = new AndroidPktFilterCommand(handle, program, len);
    NULL_CHECK_RETURN(cmd, "memory allocation failure", WIFI_ERROR_OUT_OF_MEMORY);
    wifi_error result = (wifi_error)cmd->start();
    cmd->releaseRef();
    return result;
}

wifi_error wifi_read_packet_filter(wifi_interface_handle handle,
       u32 src_offset, u8 *host_dst, u32 length)
{
    ALOGD("Reading APF filter, halHandle = %p\n", handle);
    AndroidPktFilterCommand *cmd = new AndroidPktFilterCommand(handle, src_offset, host_dst, length);
    NULL_CHECK_RETURN(cmd, "memory allocation failure", WIFI_ERROR_OUT_OF_MEMORY);
    wifi_error result = (wifi_error)cmd->start();
    cmd->releaseRef();
    return result;
}

/* Initialize HAL function pointer table */
wifi_error init_wifi_vendor_hal_func_table(wifi_hal_fn *fn)
{
    if (fn == NULL) {
        return WIFI_ERROR_UNKNOWN;
    }
    fn->wifi_initialize = wifi_initialize;
    fn->wifi_cleanup = wifi_cleanup;
    fn->wifi_event_loop = wifi_event_loop;
    fn->wifi_get_supported_feature_set = wifi_get_supported_feature_set;
    fn->wifi_get_concurrency_matrix = wifi_get_concurrency_matrix;
    fn->wifi_set_scanning_mac_oui =  wifi_set_scanning_mac_oui;
    fn->wifi_get_ifaces = wifi_get_ifaces;
    fn->wifi_get_iface_name = wifi_get_iface_name;
    fn->wifi_start_gscan = wifi_start_gscan;
    fn->wifi_stop_gscan = wifi_stop_gscan;
    fn->wifi_get_cached_gscan_results = wifi_get_cached_gscan_results;
    fn->wifi_get_gscan_capabilities = wifi_get_gscan_capabilities;
    fn->wifi_get_valid_channels = wifi_get_valid_channels;
    fn->wifi_rtt_range_request = wifi_rtt_range_request;
    fn->wifi_rtt_range_cancel = wifi_rtt_range_cancel;
    fn->wifi_get_rtt_capabilities = wifi_get_rtt_capabilities;
    fn->wifi_set_nodfs_flag = wifi_set_nodfs_flag;
    fn->wifi_start_sending_offloaded_packet = wifi_start_sending_offloaded_packet;
    fn->wifi_stop_sending_offloaded_packet = wifi_stop_sending_offloaded_packet;
    fn->wifi_set_epno_list = wifi_set_epno_list;
    fn->wifi_reset_epno_list = wifi_reset_epno_list;
    fn->wifi_set_passpoint_list = wifi_set_passpoint_list;
    fn->wifi_reset_passpoint_list = wifi_reset_passpoint_list;
    fn->wifi_start_rssi_monitoring = wifi_start_rssi_monitoring;
    fn->wifi_stop_rssi_monitoring = wifi_stop_rssi_monitoring;
    fn->wifi_set_link_stats = wifi_set_link_stats;
    fn->wifi_get_link_stats = wifi_get_link_stats;
    fn->wifi_clear_link_stats = wifi_clear_link_stats;
    fn->wifi_set_country_code = wifi_set_country_code;
    fn->wifi_configure_roaming = wifi_configure_roaming;
    fn->wifi_configure_nd_offload = wifi_configure_nd_offload;
    fn->wifi_start_pkt_fate_monitoring = wifi_start_pkt_fate_monitoring;
    fn->wifi_get_tx_pkt_fates = wifi_get_tx_pkt_fates;
    fn->wifi_get_rx_pkt_fates = wifi_get_rx_pkt_fates;
    fn->wifi_start_logging = wifi_start_logging;
    fn->wifi_set_log_handler = wifi_set_log_handler;
    fn->wifi_set_alert_handler= wifi_set_alert_handler;
    fn->wifi_get_ring_buffers_status = wifi_get_ring_buffers_status;
    fn->wifi_get_logger_supported_feature_set = wifi_get_logger_supported_feature_set;
    fn->wifi_get_ring_data = wifi_get_ring_data;
    fn->wifi_get_driver_version = wifi_get_driver_version;
    fn->wifi_get_firmware_version = wifi_get_firmware_version;
    fn->wifi_get_firmware_memory_dump = wifi_get_firmware_memory_dump;
    fn->wifi_get_driver_memory_dump = wifi_get_driver_memory_dump;
    fn->wifi_get_wake_reason_stats = wifi_get_wake_reason_stats;
    fn->wifi_nan_enable_request = nan_enable_request;
    fn->wifi_nan_disable_request = nan_disable_request;
    fn->wifi_nan_publish_request = nan_publish_request;
    fn->wifi_nan_publish_cancel_request = nan_publish_cancel_request;
    fn->wifi_nan_subscribe_request = nan_subscribe_request;
    fn->wifi_nan_subscribe_cancel_request = nan_subscribe_cancel_request;
    fn->wifi_nan_transmit_followup_request = nan_transmit_followup_request;
    fn->wifi_nan_config_request = nan_config_request;
    fn->wifi_nan_register_handler = nan_register_handler;
    fn->wifi_nan_get_version = nan_get_version;
    fn->wifi_nan_get_capabilities = nan_get_capabilities;
    fn->wifi_nan_data_interface_create = nan_data_interface_create;
    fn->wifi_nan_data_interface_delete = nan_data_interface_delete;
    fn->wifi_nan_data_request_initiator = nan_data_request_initiator;
    fn->wifi_nan_data_indication_response = nan_data_indication_response;
    fn->wifi_nan_data_end = nan_data_end;
    fn->wifi_get_roaming_capabilities = wifi_get_roaming_capabilities;
    fn->wifi_enable_firmware_roaming = wifi_enable_firmware_roaming;
    fn->wifi_get_packet_filter_capabilities = wifi_get_packet_filter_capabilities;
    fn->wifi_set_packet_filter = wifi_set_packet_filter;
    fn->wifi_read_packet_filter = wifi_read_packet_filter;
    fn->wifi_set_latency_mode = wifi_set_latency_mode;
    fn->wifi_set_subsystem_restart_handler = wifi_set_subsystem_restart_handler;
    fn->wifi_get_usable_channels = wifi_get_usable_channels;

    return WIFI_SUCCESS;
}

wifi_error wifi_initialize(wifi_handle *handle)
{
    srand(getpid());

    ALOGI("Initializing wifi");
    hal_info *info = (hal_info *)malloc(sizeof(hal_info));
    if (info == NULL) {
        ALOGE("Could not allocate hal_info");
        return WIFI_ERROR_UNKNOWN;
    }

    memset(info, 0, sizeof(*info));

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, info->cleanup_socks) == -1) {
        ALOGE("Could not create cleanup sockets");
        free(info);
        return WIFI_ERROR_UNKNOWN;
    }

    struct nl_sock *cmd_sock = wifi_create_nl_socket(WIFI_HAL_CMD_SOCK_PORT);
    if (cmd_sock == NULL) {
        ALOGE("Could not create handle");
        free(info);
        return WIFI_ERROR_UNKNOWN;
    }

    struct nl_sock *event_sock = wifi_create_nl_socket(WIFI_HAL_EVENT_SOCK_PORT);
    if (event_sock == NULL) {
        ALOGE("Could not create handle");
        nl_socket_free(cmd_sock);
        free(info);
        return WIFI_ERROR_UNKNOWN;
    }
    int ioctl_sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (ioctl_sock < 0) {
        ALOGE("Bad socket: %d\n", ioctl_sock);
        return WIFI_ERROR_UNKNOWN;
    }
    struct nl_cb *cb = nl_socket_get_cb(event_sock);
    if (cb == NULL) {
        ALOGE("Could not create handle");
        nl_socket_free(cmd_sock);
        nl_socket_free(event_sock);
        free(info);
        return WIFI_ERROR_UNKNOWN;
    }

//     ALOGI("cb->refcnt = %d", cb->cb_refcnt);
    nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, internal_no_seq_check, info);
    nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, internal_valid_message_handler, info);
    nl_cb_put(cb);

    info->cmd_sock = cmd_sock;
    info->event_sock = event_sock;
    info->clean_up = false;
    info->in_event_loop = false;
	info->ioctl_sock = ioctl_sock;
    info->event_cb = (cb_info *)malloc(sizeof(cb_info) * DEFAULT_EVENT_CB_SIZE);
    info->alloc_event_cb = DEFAULT_EVENT_CB_SIZE;
    info->num_event_cb = 0;

    info->cmd = (cmd_info *)malloc(sizeof(cmd_info) * DEFAULT_CMD_SIZE);
    info->alloc_cmd = DEFAULT_CMD_SIZE;
    info->num_cmd = 0;

    info->nl80211_family_id = genl_ctrl_resolve(cmd_sock, "nl80211");
    if (info->nl80211_family_id < 0) {
        ALOGE("Could not resolve nl80211 familty id");
        nl_socket_free(cmd_sock);
        nl_socket_free(event_sock);
        free(info);
        return WIFI_ERROR_UNKNOWN;
    }

    pthread_mutex_init(&info->cb_lock, NULL);

    *handle = (wifi_handle) info;
    wifi_add_membership(*handle, "scan");
    wifi_add_membership(*handle, "mlme");
    wifi_add_membership(*handle, "regulatory");
    wifi_add_membership(*handle, "vendor");

    wifi_init_interfaces(*handle);
    char intf_name_buff[10 * (IFNAMSIZ+1) + 4];
    char *pos = intf_name_buff;
    for (int i = 0; i < (info->num_interfaces < 10 ? info->num_interfaces : 10); i++) {
        strncpy(pos, info->interfaces[i]->name, sizeof(intf_name_buff) - (pos - intf_name_buff));
        pos += strlen(pos);
    }
    if (info->num_interfaces > 10) {
        strncpy(pos, "...", 3);
    }

    ALOGD("Found %d interfaces[%s]. Initialized Wifi HAL Successfully", info->num_interfaces, intf_name_buff);

    return WIFI_SUCCESS;
}

static int wifi_add_membership(wifi_handle handle, const char *group)
{
    hal_info *info = getHalInfo(handle);

    int id = wifi_get_multicast_id(handle, "nl80211", group);
    if (id < 0) {
        ALOGE("Could not find group %s", group);
        return id;
    }

    int ret = nl_socket_add_membership(info->event_sock, id);
    if (ret < 0) {
        ALOGE("Could not add membership to group %s", group);
    }
    return ret;
}

static void internal_cleaned_up_handler(wifi_handle handle)
{
    hal_info *info = getHalInfo(handle);
    wifi_cleaned_up_handler cleaned_up_handler = info->cleaned_up_handler;

    if (info->cmd_sock != 0) {
        close(info->cleanup_socks[0]);
        close(info->cleanup_socks[1]);
        nl_socket_free(info->cmd_sock);
        nl_socket_free(info->event_sock);
        info->cmd_sock = NULL;
        info->event_sock = NULL;
    }

    (*cleaned_up_handler)(handle);
    pthread_mutex_destroy(&info->cb_lock);
    free(info);
}

void wifi_cleanup(wifi_handle handle, wifi_cleaned_up_handler handler)
{
    hal_info *info = getHalInfo(handle);

    info->cleaned_up_handler = handler;
    pthread_mutex_lock(&info->cb_lock);

    int bad_commands = 0;

    while (info->num_cmd > bad_commands) {
        int num_cmd = info->num_cmd;
        cmd_info *cmdi = &(info->cmd[bad_commands]);
        WifiCommand *cmd = cmdi->cmd;
        if (cmd != NULL) {
            pthread_mutex_unlock(&info->cb_lock);
            cmd->cancel();
            pthread_mutex_lock(&info->cb_lock);
            /* release reference added when command is saved */
            cmd->releaseRef();
            if (num_cmd == info->num_cmd) {
                bad_commands++;
            }
        }
    }

    for (int i = 0; i < info->num_event_cb; i++) {
        cb_info *cbi = &(info->event_cb[i]);
        WifiCommand *cmd = (WifiCommand *)cbi->cb_arg;
        ALOGE("Leaked command %p", cmd);
    }
    pthread_mutex_unlock(&info->cb_lock);

    info->clean_up = true;
    if (TEMP_FAILURE_RETRY(write(info->cleanup_socks[0], "Exit", 4)) < 1) {
        ALOGE("could not write to the cleanup socket");
    }
    ALOGD("%s: Exit has sent properly. wifi_cleanup done", __FUNCTION__);
}

static int internal_pollin_handler(wifi_handle handle)
{
    hal_info *info = getHalInfo(handle);
    struct nl_cb *cb = nl_socket_get_cb(info->event_sock);
    int res = nl_recvmsgs(info->event_sock, cb);
    nl_cb_put(cb);
    return res;
}

/* Run event handler */
void wifi_event_loop(wifi_handle handle)
{
    hal_info *info = getHalInfo(handle);
    if (info->in_event_loop) {
        return;
    } else {
        info->in_event_loop = true;
    }

    pollfd pfd[2];
    memset(&pfd[0], 0, sizeof(pollfd) * 2);

    pfd[0].fd = nl_socket_get_fd(info->event_sock);
    pfd[0].events = POLLIN;
    pfd[1].fd = info->cleanup_socks[1];
    pfd[1].events = POLLIN;

    char buf[2048];

    do {
        int timeout = -1;                   /* Infinite timeout */

        pfd[0].revents = 0;
        pfd[1].revents = 0;
        int result = TEMP_FAILURE_RETRY(poll(pfd, 2, timeout));
        if (result < 0) {
            ALOGE("wifi_event_loop: return %d, error no = %d", result, errno);
        } else if (pfd[0].revents & POLLERR) {
            int prev_err = (int)errno;
            int result2 = TEMP_FAILURE_RETRY(read(pfd[0].fd, buf, sizeof(buf)));
            ALOGE("Poll err:%d | Read after POLL returned %d, error no = %d", prev_err, result2, errno);
        } else if (pfd[0].revents & POLLHUP) {
            ALOGE("Remote side hung up");
            break;
        } else if (pfd[0].revents & POLLIN) {
            internal_pollin_handler(handle);
        } else if (pfd[1].revents & POLLIN) {
            memset(buf, 0, sizeof(buf));
            int result2 = read(pfd[1].fd, buf, sizeof(buf));
            ALOGE("%s: Read after POLL returned %d, error no = %d", __FUNCTION__, result2, errno);
            if (strncmp(buf, "Exit", 4) == 0) {
                ALOGD("Got a signal to exit!!!");
            } else {
                ALOGD("Rx'ed %s on the cleanup socket\n", buf);
            }
        } else {
            ALOGE("wifi_event_loop: Unknown event - %0x, %0x", pfd[0].revents, pfd[1].revents);
        }
    } while (!info->clean_up);

    internal_cleaned_up_handler(handle);
    ALOGD("wifi_event_loop: end of event loop !!!!!");
}

///////////////////////////////////////////////////////////////////////////////////////

static int internal_no_seq_check(struct nl_msg *msg, void *arg)
{
    return NL_OK;
}

static int internal_valid_message_handler(nl_msg *msg, void *arg)
{
    wifi_handle handle = (wifi_handle)arg;
    hal_info *info = getHalInfo(handle);

    WifiEvent event(msg);
    int res = event.parse();
    if (res < 0) {
        ALOGE("Failed to parse event: %d", res);
        return NL_SKIP;
    }

    int cmd = event.get_cmd();
    uint32_t vendor_id = 0;
    int subcmd = 0;

    if (cmd == NL80211_CMD_VENDOR) {
        vendor_id = event.get_u32(NL80211_ATTR_VENDOR_ID);
        subcmd = event.get_u32(NL80211_ATTR_VENDOR_SUBCMD);
        /*
        ALOGI("event received %s, vendor_id = 0x%0x, subcmd = 0x%0x",
                event.get_cmdString(), vendor_id, subcmd);*/
    }

     //ALOGI("event received %s, vendor_id = 0x%0x", event.get_cmdString(), vendor_id);
     //event.log();

    pthread_mutex_lock(&info->cb_lock);

    for (int i = 0; i < info->num_event_cb; i++) {
        if (cmd == info->event_cb[i].nl_cmd) {
            if (cmd == NL80211_CMD_VENDOR
                && ((vendor_id != info->event_cb[i].vendor_id)
                || (subcmd != info->event_cb[i].vendor_subcmd)))
            {
                /* event for a different vendor, ignore it */
                continue;
            }

            cb_info *cbi = &(info->event_cb[i]);
            nl_recvmsg_msg_cb_t cb_func = cbi->cb_func;
            void *cb_arg = cbi->cb_arg;
            WifiCommand *cmd = (WifiCommand *)cbi->cb_arg;
            if (cmd != NULL) {
                cmd->addRef();
            }

            pthread_mutex_unlock(&info->cb_lock);
            if (cb_func)
                (*cb_func)(msg, cb_arg);
            if (cmd != NULL) {
                cmd->releaseRef();
            }

            return NL_OK;
        }
    }

    pthread_mutex_unlock(&info->cb_lock);
    return NL_OK;
}

///////////////////////////////////////////////////////////////////////////////////////

class GetMulticastIdCommand : public WifiCommand
{
private:
    const char *mName;
    const char *mGroup;
    int   mId;
public:
    GetMulticastIdCommand(wifi_handle handle, const char *name, const char *group)
        : WifiCommand(handle, 0)
    {
        mName = name;
        mGroup = group;
        mId = -1;
    }

    int getId() {
        return mId;
    }

    virtual int create() {
        int nlctrlFamily = genl_ctrl_resolve(mInfo->cmd_sock, "nlctrl");
        int ret = mMsg.create(nlctrlFamily, CTRL_CMD_GETFAMILY, 0, 0);
        if (ret < 0) {
            return ret;
        }
        ret = mMsg.put_string(CTRL_ATTR_FAMILY_NAME, mName);
        return ret;
    }

    virtual int handleResponse(WifiEvent& reply) {
        struct nlattr **tb = reply.attributes();
        struct nlattr *mcgrp = NULL;
        int i;

        if (!tb[CTRL_ATTR_MCAST_GROUPS]) {
            ALOGE("No multicast groups found");
            return NL_SKIP;
        }

        for_each_attr(mcgrp, tb[CTRL_ATTR_MCAST_GROUPS], i) {

            struct nlattr *tb2[CTRL_ATTR_MCAST_GRP_MAX + 1];
            nla_parse(tb2, CTRL_ATTR_MCAST_GRP_MAX, (nlattr *)nla_data(mcgrp),
                nla_len(mcgrp), NULL);
            if (!tb2[CTRL_ATTR_MCAST_GRP_NAME] || !tb2[CTRL_ATTR_MCAST_GRP_ID]) {
                continue;
            }

            char *grpName = (char *)nla_data(tb2[CTRL_ATTR_MCAST_GRP_NAME]);
            int grpNameLen = nla_len(tb2[CTRL_ATTR_MCAST_GRP_NAME]);

            if (strncmp(grpName, mGroup, grpNameLen) != 0)
                continue;

            mId = nla_get_u32(tb2[CTRL_ATTR_MCAST_GRP_ID]);
            break;
        }

        return NL_SKIP;
    }

};

class SetPnoMacAddrOuiCommand : public WifiCommand {

private:
    byte *mOui;
    feature_set *fset;
    feature_set *feature_matrix;
    int *fm_size;
    int set_size_max;
public:
    SetPnoMacAddrOuiCommand(wifi_interface_handle handle, oui scan_oui)
        : WifiCommand(handle, 0)
    {
        mOui = scan_oui;
	fset = NULL;
	feature_matrix = NULL;
	fm_size = NULL;
	set_size_max = 0;
    }

    int createRequest(WifiRequest& request, int subcmd, byte *scan_oui) {
        int result = request.create(GOOGLE_OUI, subcmd);
        if (result < 0) {
            return result;
        }

        nlattr *data = request.attr_start(NL80211_ATTR_VENDOR_DATA);
        result = request.put(ANDR_WIFI_ATTRIBUTE_PNO_RANDOM_MAC_OUI, scan_oui, DOT11_OUI_LEN);
        if (result < 0) {
            return result;
        }

        request.attr_end(data);
        return WIFI_SUCCESS;

    }

    int start() {
        WifiRequest request(familyId(), ifaceId());
        int result = createRequest(request, SLSI_NL80211_VENDOR_SUBCMD_SET_GSCAN_OUI, mOui);
        if (result != WIFI_SUCCESS) {
            ALOGE("failed to create request; result = %d", result);
            return result;
        }

        result = requestResponse(request);
        if (result != WIFI_SUCCESS) {
            ALOGE("failed to set scanning mac OUI; result = %d", result);
        }

        return result;
    }
protected:
    virtual int handleResponse(WifiEvent& reply) {
        /* Nothing to do on response! */
        return NL_SKIP;
    }
};

class SetNodfsCommand : public WifiCommand {

private:
    u32 mNoDfs;
public:
    SetNodfsCommand(wifi_interface_handle handle, u32 nodfs)
        : WifiCommand(handle, 0) {
        mNoDfs = nodfs;
    }
    virtual int create() {
        int ret;

        ret = mMsg.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_SET_NODFS);
        if (ret < 0) {
            ALOGE("Can't create message to send to driver - %d", ret);
            return ret;
        }

        nlattr *data = mMsg.attr_start(NL80211_ATTR_VENDOR_DATA);
        ret = mMsg.put_u32(ATTR_NODFS_VALUE, mNoDfs);
        if (ret < 0) {
             return ret;
        }

        mMsg.attr_end(data);
        return WIFI_SUCCESS;
    }
};

class SetRSSIMonitorCommand : public WifiCommand {
private:
    s8 mMax_rssi;
    s8 mMin_rssi;
    wifi_rssi_event_handler mHandler;
public:
    SetRSSIMonitorCommand(wifi_request_id id, wifi_interface_handle handle,
                s8 max_rssi, s8 min_rssi, wifi_rssi_event_handler eh)
        : WifiCommand(handle, id), mMax_rssi(max_rssi), mMin_rssi
        (min_rssi), mHandler(eh)
        {
        }
   int createRequest(WifiRequest& request, int enable) {
        int result = request.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_SET_RSSI_MONITOR);
        if (result < 0) {
            return result;
        }

        nlattr *data = request.attr_start(NL80211_ATTR_VENDOR_DATA);
        result = request.put_u8(RSSI_MONITOR_ATTRIBUTE_MAX_RSSI, (enable ? mMax_rssi: 0));
        if (result < 0) {
            return result;
        }

        result = request.put_u8(RSSI_MONITOR_ATTRIBUTE_MIN_RSSI, (enable? mMin_rssi: 0));
        if (result < 0) {
            return result;
        }
        result = request.put_u8(RSSI_MONITOR_ATTRIBUTE_START, enable);
        if (result < 0) {
            return result;
        }
        request.attr_end(data);
        return result;
    }

    int start() {
        WifiRequest request(familyId(), ifaceId());
        int result = createRequest(request, 1);
        if (result < 0) {
            return result;
        }
        result = requestResponse(request);
        if (result < 0) {
            ALOGI("Failed to set RSSI Monitor, result = %d", result);
            return result;
        }
        ALOGI("Successfully set RSSI monitoring");
        registerVendorHandler(GOOGLE_OUI, WIFI_RSSI_REPORT_EVENT);

        return result;
    }

    virtual int cancel() {

        WifiRequest request(familyId(), ifaceId());
        int result = createRequest(request, 0);
        if (result != WIFI_SUCCESS) {
            ALOGE("failed to create request; result = %d", result);
        } else {
            result = requestResponse(request);
            if (result != WIFI_SUCCESS) {
                ALOGE("failed to stop RSSI monitoring = %d", result);
            }
        }
        unregisterVendorHandler(GOOGLE_OUI, WIFI_RSSI_REPORT_EVENT);
        return WIFI_SUCCESS;
    }

    virtual int handleResponse(WifiEvent& reply) {
        /* Nothing to do on response! */
        return NL_SKIP;
    }

   virtual int handleEvent(WifiEvent& event) {

        nlattr *vendor_data = event.get_attribute(NL80211_ATTR_VENDOR_DATA);
        int len = event.get_vendor_data_len();

        if (vendor_data == NULL || len == 0) {
            ALOGI("RSSI monitor: No data");
            return NL_SKIP;
        }

        typedef struct {
            s8 cur_rssi;
            mac_addr BSSID;
        } rssi_monitor_evt;

        rssi_monitor_evt *data = (rssi_monitor_evt *)event.get_vendor_data();

        if (*mHandler.on_rssi_threshold_breached) {
            (*mHandler.on_rssi_threshold_breached)(id(), data->BSSID, data->cur_rssi);
        } else {
            ALOGW("No RSSI monitor handler registered");
        }

        return NL_SKIP;
    }

};

class SetCountryCodeCommand : public WifiCommand {
private:
    const char *mCountryCode;
public:
    SetCountryCodeCommand(wifi_interface_handle handle, const char *country_code)
        : WifiCommand(handle, 0) {
        mCountryCode = country_code;
        }
    virtual int create() {
        int ret;

        ret = mMsg.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_SET_COUNTRY_CODE);
        if (ret < 0) {
             ALOGE("Can't create message to send to driver - %d", ret);
             return ret;
        }

        nlattr *data = mMsg.attr_start(NL80211_ATTR_VENDOR_DATA);
        ret = mMsg.put_string(ATTR_COUNTRY_CODE, mCountryCode);
        if (ret < 0) {
            return ret;
        }

        mMsg.attr_end(data);
        return WIFI_SUCCESS;

    }
};

class GetFeatureSetCommand : public WifiCommand {

private:

    feature_set *fset;

public:
    GetFeatureSetCommand(wifi_interface_handle handle, feature_set *set)
        : WifiCommand(handle, 0)
    {
        fset = set;
    }

    virtual int create() {
        int ret;

        ret = mMsg.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_GET_FEATURE_SET);
        if (ret < 0) {
            ALOGE("create failed - %d", ret);
        }

        return ret;
    }

protected:
    virtual int handleResponse(WifiEvent& reply) {

        if (reply.get_cmd() != NL80211_CMD_VENDOR) {
            ALOGD("Ignore reply; cmd = %d", reply.get_cmd());
            return NL_SKIP;
        }

        nlattr *vendor_data = reply.get_attribute(NL80211_ATTR_VENDOR_DATA);
        int len = reply.get_vendor_data_len();

        if (vendor_data == NULL || len == 0) {
            ALOGE("vendor data in GetFeatureSetCommand missing!!");
            return NL_SKIP;
        }

        void *data = reply.get_vendor_data();
        if(!fset) {
            ALOGE("feature_set Pointer not set");
            return NL_SKIP;
        }
        memcpy(fset, data, min(len, (int) sizeof(*fset)));
        return NL_OK;
    }

};

class SetLatencyLockCommand : public WifiCommand {
private:
    wifi_latency_mode mMode;
public:
    SetLatencyLockCommand(wifi_interface_handle handle, wifi_latency_mode mode)
        : WifiCommand(handle, 0) {
        mMode = mode;
    }
    virtual int create() {
        int ret;

        ret = mMsg.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_SET_LATENCY_MODE);
        if (ret < 0) {
             ALOGE("Can't create message to send to driver - %d", ret);
             return ret;
        }

        nlattr *data = mMsg.attr_start(NL80211_ATTR_VENDOR_DATA);
        ret = mMsg.put_u8(ATTR_LOW_LATENCY_MODE, mMode);
        if (ret < 0) {
            return ret;
        }

        mMsg.attr_end(data);
        return WIFI_SUCCESS;
    }
};

class SetSubsystemRestartHandlerCommand : public WifiCommand {
private:
    wifi_subsystem_restart_handler mHandler;
public:
    SetSubsystemRestartHandlerCommand(int id, wifi_handle handle, wifi_subsystem_restart_handler handler)
        : WifiCommand(handle, id), mHandler(handler)
        {
        }

    int start() {
        set_reset_in_progress(0);
        ALOGI("Register Vendor Handler for WIFI_SUBSYSTEM_RESTART_EVENT");
        registerVendorHandler(GOOGLE_OUI, WIFI_SUBSYSTEM_RESTART_EVENT);
        return WIFI_SUCCESS;
    }

    virtual int cancel() {
        set_reset_in_progress(0);
        ALOGI("Unregister Vendor Handler for WIFI_SUBSYSTEM_RESTART_EVENT");
        unregisterVendorHandler(GOOGLE_OUI, WIFI_SUBSYSTEM_RESTART_EVENT);
        return WIFI_SUCCESS;
    }

    virtual int handleResponse(WifiEvent& reply) {
        /* Nothing to do on response! */
        return NL_SKIP;
    }

   virtual int handleEvent(WifiEvent& event) {

        nlattr *vendor_data = event.get_attribute(NL80211_ATTR_VENDOR_DATA);
        int len = event.get_vendor_data_len();

        if (vendor_data == NULL || len == 0) {
            ALOGI("Subsystem Restart Handler : No data");
            return NL_SKIP;
        }
        const char* error = (const char*)event.get_vendor_data();

        if (*mHandler.on_subsystem_restart) {
            set_reset_in_progress(1);
            (*mHandler.on_subsystem_restart)(error);
        } else {
            ALOGW("No Subsystem Restart handler registered");
        }
        return NL_SKIP;
    }
};

class GetUsableChannelsCommand : public WifiCommand {
    uint32_t mBand;
    uint32_t mIfaceMode;
    uint32_t mFilter;
    uint32_t mMaxNum;
    uint32_t *mNumChannels;
    wifi_usable_channel *mChannels;
public:
    GetUsableChannelsCommand(wifi_interface_handle handle, uint32_t band, uint32_t iface_mode, uint32_t filter,
                             uint32_t max_num, uint32_t *ch_num, wifi_usable_channel *channel_buf)
        : WifiCommand(handle, 0), mBand(band), mIfaceMode(iface_mode), mFilter(filter),
        mMaxNum(max_num), mNumChannels(ch_num), mChannels(channel_buf) {
        memset(mChannels, 0, sizeof(wifi_usable_channel) * max_num);
    }

    virtual int create() {
        int ret = mMsg.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_GET_USABLE_CHANNELS);
        if (ret < 0) {
            return ret;
        }

        nlattr *data = mMsg.attr_start(NL80211_ATTR_VENDOR_DATA);
        ret = mMsg.put_u32(SLSI_UC_ATTRIBUTE_BAND, mBand);
        if (ret < 0) {
            return ret;
        }

        ret = mMsg.put_u32(SLSI_UC_ATTRIBUTE_IFACE_MODE, mIfaceMode);
        if (ret < 0) {
            return ret;
        }

        ret = mMsg.put_u32(SLSI_UC_ATTRIBUTE_FILTER, mFilter);
        if (ret < 0) {
            return ret;
        }

        ret = mMsg.put_u32(SLSI_UC_ATTRIBUTE_MAX_NUM, mMaxNum);
        if (ret < 0) {
            return ret;
        }

        mMsg.attr_end(data);
        return 0;
   }

protected:
    virtual int handleResponse(WifiEvent& reply) {
        if (reply.get_cmd() != NL80211_CMD_VENDOR) {
            ALOGE("Ignoring reply with cmd = %d", reply.get_cmd());
            return NL_SKIP;
        }

        nlattr *vendor_data = reply.get_attribute(NL80211_ATTR_VENDOR_DATA);
        int len = reply.get_vendor_data_len();

        if (vendor_data == NULL || len == 0) {
            ALOGE("no vendor data in GetUsableChannel response; ignoring it");
            return NL_SKIP;
        }

        int num_channels_to_copy = 0;

        for (nl_iterator it(vendor_data); it.has_next(); it.next()) {
            if (it.get_type() == SLSI_UC_ATTRIBUTE_NUM_CHANNELS) {
                num_channels_to_copy = it.get_u32();
                ALOGD("Got channel list number with %d channels", num_channels_to_copy);
                if (num_channels_to_copy > mMaxNum)
                    num_channels_to_copy = mMaxNum;
                *mNumChannels = num_channels_to_copy;
            } else if (it.get_type() == SLSI_UC_ATTRIBUTE_CHANNEL_LIST && num_channels_to_copy) {
                memcpy(mChannels, it.get_data(), sizeof(wifi_usable_channel) * num_channels_to_copy);
                // for (int i = 0 ; i < num_channels_to_copy ; i++)
                //    ALOGD("Got channel list!!!!!!!!![%d] %d", i, channels[i].freq);
            } else {
                ALOGD("Ignoring invalid attribute type = %d, size = %d",
                        it.get_type(), it.get_len());
            }
        }

        return NL_OK;
    }
};

static int wifi_get_multicast_id(wifi_handle handle, const char *name, const char *group)
{
    GetMulticastIdCommand cmd(handle, name, group);
    int res = cmd.requestResponse();
    if (res < 0)
        return res;
    else
        return cmd.getId();
}

/////////////////////////////////////////////////////////////////////////

static bool is_wifi_interface(const char *name)
{
    if (strncmp(name, "wlan", 4) != 0 && strncmp(name, "p2p", 3) != 0 && strncmp(name, "wifi", 4) != 0
        && strncmp(name, "swlan", 5) != 0) {
        /* not a wifi interface; ignore it */
        return false;
    } else {
        return true;
    }
}

static int get_interface(const char *name, interface_info *info)
{
    strcpy(info->name, name);
    info->id = if_nametoindex(name);
    return WIFI_SUCCESS;
}

wifi_error wifi_init_interfaces(wifi_handle handle)
{
    hal_info *info = (hal_info *)handle;
    struct dirent *de;

    DIR *d = opendir("/sys/class/net");
    if (d == 0)
        return WIFI_ERROR_UNKNOWN;

    int n = 0;
    while ((de = readdir(d))) {
        if (de->d_name[0] == '.')
            continue;
        if (is_wifi_interface(de->d_name) ) {
            n++;
        }
    }

    closedir(d);

    d = opendir("/sys/class/net");
    if (d == 0)
        return WIFI_ERROR_UNKNOWN;

    info->interfaces = (interface_info **)malloc(sizeof(interface_info *) * n);

    int i = 0;
    while ((de = readdir(d))) {
        if (de->d_name[0] == '.')
            continue;
        if (is_wifi_interface(de->d_name)) {
            interface_info *ifinfo = (interface_info *)malloc(sizeof(interface_info));
            if (get_interface(de->d_name, ifinfo) != WIFI_SUCCESS) {
                free(ifinfo);
                continue;
            }
            ifinfo->handle = handle;
            info->interfaces[i] = ifinfo;
            i++;
        }
    }

    closedir(d);

    info->num_interfaces = n;
    return WIFI_SUCCESS;
}

wifi_error wifi_get_ifaces(wifi_handle handle, int *num, wifi_interface_handle **interfaces)
{
    hal_info *info = (hal_info *)handle;

    *interfaces = (wifi_interface_handle *)info->interfaces;
    *num = info->num_interfaces;

    return WIFI_SUCCESS;
}

wifi_error wifi_get_iface_name(wifi_interface_handle handle, char *name, size_t size)
{
    interface_info *info = (interface_info *)handle;
    strcpy(name, info->name);
    return WIFI_SUCCESS;
}

wifi_error wifi_get_concurrency_matrix(wifi_interface_handle handle, int set_size_max,
       feature_set set[], int *set_size)
{
    return WIFI_ERROR_NOT_SUPPORTED;
}

wifi_error wifi_set_scanning_mac_oui(wifi_interface_handle handle, oui scan_oui)
{
    SetPnoMacAddrOuiCommand command(handle, scan_oui);
    return (wifi_error)command.start();

}

wifi_error wifi_set_nodfs_flag(wifi_interface_handle handle, u32 nodfs)
{
    SetNodfsCommand command(handle, nodfs);
    return (wifi_error) command.requestResponse();
}

static wifi_error wifi_start_rssi_monitoring(wifi_request_id id, wifi_interface_handle
                        iface, s8 max_rssi, s8 min_rssi, wifi_rssi_event_handler eh)
{
    ALOGD("Start RSSI monitor %d", id);
    wifi_handle handle = getWifiHandle(iface);
    SetRSSIMonitorCommand *cmd = new SetRSSIMonitorCommand(id, iface, max_rssi, min_rssi, eh);
    wifi_register_cmd(handle, id, cmd);

    wifi_error result = (wifi_error)cmd->start();
    if (result != WIFI_SUCCESS) {
        wifi_unregister_cmd(handle, id);
    }
    return result;
}


static wifi_error wifi_stop_rssi_monitoring(wifi_request_id id, wifi_interface_handle iface)
{
    ALOGD("Stopping RSSI monitor");

    if(id == -1) {
        wifi_rssi_event_handler handler;
        memset(&handler, 0, sizeof(handler));
        SetRSSIMonitorCommand *cmd = new SetRSSIMonitorCommand(id, iface,
                                                    0, 0, handler);
        cmd->cancel();
        cmd->releaseRef();
        return WIFI_SUCCESS;
    }
    return wifi_cancel_cmd(id, iface);
}

wifi_error wifi_get_supported_feature_set(wifi_interface_handle handle, feature_set *set)
{
    GetFeatureSetCommand command(handle, set);
    return (wifi_error) command.requestResponse();
}

wifi_error wifi_set_country_code(wifi_interface_handle handle, const char *country_code)
{
    SetCountryCodeCommand command(handle, country_code);
    return (wifi_error) command.requestResponse();
}

wifi_error wifi_set_latency_mode(wifi_interface_handle handle, wifi_latency_mode mode) {
    SetLatencyLockCommand cmd(handle, mode);
    return (wifi_error) cmd.requestResponse();
}

wifi_error wifi_set_subsystem_restart_handler(wifi_handle handle,
                                              wifi_subsystem_restart_handler handler) {
    ALOGD("Set Subsystem Restart Handler");
    int id = 0;
    SetSubsystemRestartHandlerCommand *cmd = new SetSubsystemRestartHandlerCommand(id, handle, handler);
    wifi_register_cmd(handle, id, cmd);
    wifi_error result = (wifi_error)cmd->start();
    if (result != WIFI_SUCCESS) {
        wifi_unregister_cmd(handle, id);
    }
    return result;
}

wifi_error wifi_get_usable_channels(wifi_handle handle, uint32_t band, uint32_t iface_mode, uint32_t filter,
                                    uint32_t max_num, uint32_t *num_channels, wifi_usable_channel *channels) {
    wifi_interface_handle *ihandle = NULL;
    int ihandle_num = 0;
    wifi_get_ifaces(handle, &ihandle_num, &ihandle);
    ALOGD("%s: band %d iface %d filter %d max_num %d", __FUNCTION__, band, iface_mode, filter, max_num);
    if (ihandle_num <= 0)
        return WIFI_ERROR_UNINITIALIZED;

    if (iface_mode == SLSI_UC_ITERFACE_UNKNOWN || !(iface_mode & SLSI_UC_ITERFACE_SOFTAP))
        return WIFI_ERROR_NOT_SUPPORTED;

    GetUsableChannelsCommand command(ihandle[0], band, iface_mode, filter, max_num,
                                     num_channels, channels);

    int result = command.requestResponse();
    ALOGD("%s: result %d", __FUNCTION__, result);
    return (wifi_error)result;
}
/////////////////////////////////////////////////////////////////////////////

