
#include <stdint.h>
#include <stddef.h>
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
#include <netlink/handlers.h>

#include "sync.h"

#include <utils/Log.h>

#include "wifi_hal.h"
#include "common.h"
#include "cpp_bindings.h"

#define SLSI_WIFI_HAL_NAN_VERSION 1

#define CHECK_WIFI_STATUS_RETURN_FAIL(result, LOGSTR) \
    if (result != WIFI_SUCCESS) {\
        ALOGE(LOGSTR" [result:%d]", result);\
        return result;\
    }

#define CHECK_CONFIG_PUT_8_RETURN_FAIL(config, val, nan_attribute, request, result, FAIL_STR) \
    if (config) {\
        result = request.put_u8(nan_attribute, val); \
        if (result != WIFI_SUCCESS) {\
            ALOGE(FAIL_STR" [result:%d]", result);\
            return result;\
        }\
    }

#define CHECK_CONFIG_PUT_16_RETURN_FAIL(config, val, nan_attribute, request, result, FAIL_STR) \
    if (config) {\
        result = request.put_u16(nan_attribute, val); \
        if (result != WIFI_SUCCESS) {\
            ALOGE(FAIL_STR" [result:%d]", result);\
            return result;\
        }\
    }


#define CHECK_CONFIG_PUT_32_RETURN_FAIL(config, val, nan_attribute, request, result, FAIL_STR) \
    if (config) {\
        result = request.put_u32(nan_attribute, val); \
        if (result != WIFI_SUCCESS) {\
            ALOGE(FAIL_STR" [result:%d]", result);\
            return result;\
        }\
    }

#define CHECK_CONFIG_PUT_RETURN_FAIL(config, valptr, len, nan_attribute, request, result, FAIL_STR) \
    if (config) {\
        result = request.put(nan_attribute, valptr, len); \
        if (result != WIFI_SUCCESS) {\
            ALOGE(FAIL_STR" [result:%d]", result);\
            return result;\
        }\
    }

typedef enum {
    NAN_REQ_ATTR_MASTER_PREF,
    NAN_REQ_ATTR_CLUSTER_LOW,
    NAN_REQ_ATTR_CLUSTER_HIGH,
    NAN_REQ_ATTR_HOP_COUNT_LIMIT_VAL,
    NAN_REQ_ATTR_SID_BEACON_VAL,

    NAN_REQ_ATTR_SUPPORT_2G4_VAL,
    NAN_REQ_ATTR_SUPPORT_5G_VAL,

    NAN_REQ_ATTR_RSSI_CLOSE_2G4_VAL,
    NAN_REQ_ATTR_RSSI_MIDDLE_2G4_VAL,
    NAN_REQ_ATTR_RSSI_PROXIMITY_2G4_VAL,
    NAN_REQ_ATTR_BEACONS_2G4_VAL,
    NAN_REQ_ATTR_SDF_2G4_VAL,
    NAN_REQ_ATTR_CHANNEL_2G4_MHZ_VAL,
    NAN_REQ_ATTR_RSSI_PROXIMITY_VAL,


    NAN_REQ_ATTR_RSSI_CLOSE_5G_VAL,
    NAN_REQ_ATTR_RSSI_CLOSE_PROXIMITY_5G_VAL,
    NAN_REQ_ATTR_RSSI_MIDDLE_5G_VAL,
    NAN_REQ_ATTR_RSSI_PROXIMITY_5G_VAL,
    NAN_REQ_ATTR_BEACON_5G_VAL,
    NAN_REQ_ATTR_SDF_5G_VAL,
    NAN_REQ_ATTR_CHANNEL_5G_MHZ_VAL,

    NAN_REQ_ATTR_RSSI_WINDOW_SIZE_VAL,
    NAN_REQ_ATTR_OUI_VAL,
    NAN_REQ_ATTR_MAC_ADDR_VAL,
    NAN_REQ_ATTR_CLUSTER_VAL,
    NAN_REQ_ATTR_SOCIAL_CH_SCAN_DWELL_TIME,
    NAN_REQ_ATTR_SOCIAL_CH_SCAN_PERIOD,
    NAN_REQ_ATTR_RANDOM_FACTOR_FORCE_VAL,
    NAN_REQ_ATTR_HOP_COUNT_FORCE_VAL,
    NAN_REQ_ATTR_CONN_CAPABILITY_PAYLOAD_TX,
    NAN_REQ_ATTR_CONN_CAPABILITY_IBSS,
    NAN_REQ_ATTR_CONN_CAPABILITY_WFD,
    NAN_REQ_ATTR_CONN_CAPABILITY_WFDS,
    NAN_REQ_ATTR_CONN_CAPABILITY_TDLS,
    NAN_REQ_ATTR_CONN_CAPABILITY_MESH,
    NAN_REQ_ATTR_CONN_CAPABILITY_WLAN_INFRA,
    NAN_REQ_ATTR_DISCOVERY_ATTR_NUM_ENTRIES,
    NAN_REQ_ATTR_DISCOVERY_ATTR_VAL,
    NAN_REQ_ATTR_CONN_TYPE,
    NAN_REQ_ATTR_NAN_ROLE,
    NAN_REQ_ATTR_TRANSMIT_FREQ,
    NAN_REQ_ATTR_AVAILABILITY_DURATION,
    NAN_REQ_ATTR_AVAILABILITY_INTERVAL,
    NAN_REQ_ATTR_MESH_ID_LEN,
    NAN_REQ_ATTR_MESH_ID,
    NAN_REQ_ATTR_INFRASTRUCTURE_SSID_LEN,
    NAN_REQ_ATTR_INFRASTRUCTURE_SSID,
    NAN_REQ_ATTR_FURTHER_AVAIL_NUM_ENTRIES,
    NAN_REQ_ATTR_FURTHER_AVAIL_VAL,
    NAN_REQ_ATTR_FURTHER_AVAIL_ENTRY_CTRL,
    NAN_REQ_ATTR_FURTHER_AVAIL_CHAN_CLASS,
    NAN_REQ_ATTR_FURTHER_AVAIL_CHAN,
    NAN_REQ_ATTR_FURTHER_AVAIL_CHAN_MAPID,
    NAN_REQ_ATTR_FURTHER_AVAIL_INTERVAL_BITMAP,
    NAN_REQ_ATTR_PUBLISH_ID,
    NAN_REQ_ATTR_PUBLISH_TTL,
    NAN_REQ_ATTR_PUBLISH_PERIOD,
    NAN_REQ_ATTR_PUBLISH_TYPE,
    NAN_REQ_ATTR_PUBLISH_TX_TYPE,
    NAN_REQ_ATTR_PUBLISH_COUNT,
    NAN_REQ_ATTR_PUBLISH_SERVICE_NAME_LEN,
    NAN_REQ_ATTR_PUBLISH_SERVICE_NAME,
    NAN_REQ_ATTR_PUBLISH_MATCH_ALGO,
    NAN_REQ_ATTR_PUBLISH_SERVICE_INFO_LEN,
    NAN_REQ_ATTR_PUBLISH_SERVICE_INFO,
    NAN_REQ_ATTR_PUBLISH_RX_MATCH_FILTER_LEN,
    NAN_REQ_ATTR_PUBLISH_RX_MATCH_FILTER,
    NAN_REQ_ATTR_PUBLISH_TX_MATCH_FILTER_LEN,
    NAN_REQ_ATTR_PUBLISH_TX_MATCH_FILTER,
    NAN_REQ_ATTR_PUBLISH_RSSI_THRESHOLD_FLAG,
    NAN_REQ_ATTR_PUBLISH_CONN_MAP,
    NAN_REQ_ATTR_PUBLISH_RECV_IND_CFG,
    NAN_REQ_ATTR_SUBSCRIBE_ID,
    NAN_REQ_ATTR_SUBSCRIBE_TTL,
    NAN_REQ_ATTR_SUBSCRIBE_PERIOD,
    NAN_REQ_ATTR_SUBSCRIBE_TYPE,
    NAN_REQ_ATTR_SUBSCRIBE_RESP_FILTER_TYPE,
    NAN_REQ_ATTR_SUBSCRIBE_RESP_INCLUDE,
    NAN_REQ_ATTR_SUBSCRIBE_USE_RESP_FILTER,
    NAN_REQ_ATTR_SUBSCRIBE_SSI_REQUIRED,
    NAN_REQ_ATTR_SUBSCRIBE_MATCH_INDICATOR,
    NAN_REQ_ATTR_SUBSCRIBE_COUNT,
    NAN_REQ_ATTR_SUBSCRIBE_SERVICE_NAME_LEN,
    NAN_REQ_ATTR_SUBSCRIBE_SERVICE_NAME,
    NAN_REQ_ATTR_SUBSCRIBE_SERVICE_INFO_LEN,
    NAN_REQ_ATTR_SUBSCRIBE_SERVICE_INFO,
    NAN_REQ_ATTR_SUBSCRIBE_RX_MATCH_FILTER_LEN,
    NAN_REQ_ATTR_SUBSCRIBE_RX_MATCH_FILTER,
    NAN_REQ_ATTR_SUBSCRIBE_TX_MATCH_FILTER_LEN,
    NAN_REQ_ATTR_SUBSCRIBE_TX_MATCH_FILTER,
    NAN_REQ_ATTR_SUBSCRIBE_RSSI_THRESHOLD_FLAG,
    NAN_REQ_ATTR_SUBSCRIBE_CONN_MAP,
    NAN_REQ_ATTR_SUBSCRIBE_NUM_INTF_ADDR_PRESENT,
    NAN_REQ_ATTR_SUBSCRIBE_INTF_ADDR,
    NAN_REQ_ATTR_SUBSCRIBE_RECV_IND_CFG,
    NAN_REQ_ATTR_FOLLOWUP_ID,
    NAN_REQ_ATTR_FOLLOWUP_REQUESTOR_ID,
    NAN_REQ_ATTR_FOLLOWUP_ADDR,
    NAN_REQ_ATTR_FOLLOWUP_PRIORITY,
    NAN_REQ_ATTR_FOLLOWUP_SERVICE_NAME_LEN,
    NAN_REQ_ATTR_FOLLOWUP_SERVICE_NAME,
    NAN_REQ_ATTR_FOLLOWUP_TX_WINDOW,
    NAN_REQ_ATTR_FOLLOWUP_RECV_IND_CFG,
} NAN_REQ_ATTRIBUTES;

typedef enum {
	NAN_REPLY_ATTR_STATUS_TYPE,
	NAN_REPLY_ATTR_VALUE,
	NAN_REPLY_ATTR_RESPONSE_TYPE,
	NAN_REPLY_ATTR_PUBLISH_SUBSCRIBE_TYPE,
	NAN_REPLY_ATTR_CAP_MAX_CONCURRENT_CLUSTER,
	NAN_REPLY_ATTR_CAP_MAX_PUBLISHES,
	NAN_REPLY_ATTR_CAP_MAX_SUBSCRIBES,
	NAN_REPLY_ATTR_CAP_MAX_SERVICE_NAME_LEN,
	NAN_REPLY_ATTR_CAP_MAX_MATCH_FILTER_LEN,
	NAN_REPLY_ATTR_CAP_MAX_TOTAL_MATCH_FILTER_LEN,
	NAN_REPLY_ATTR_CAP_MAX_SERVICE_SPECIFIC_INFO_LEN,
	NAN_REPLY_ATTR_CAP_MAX_VSA_DATA_LEN,
	NAN_REPLY_ATTR_CAP_MAX_MESH_DATA_LEN,
	NAN_REPLY_ATTR_CAP_MAX_NDI_INTERFACES,
	NAN_REPLY_ATTR_CAP_MAX_NDP_SESSIONS,
	NAN_REPLY_ATTR_CAP_MAX_APP_INFO_LEN,
} NAN_RESP_ATTRIBUTES;

typedef enum {
    NAN_EVT_ATTR_MATCH_PUBLISH_SUBSCRIBE_ID,
    NAN_EVT_ATTR_MATCH_REQUESTOR_INSTANCE_ID,
    NAN_EVT_ATTR_MATCH_ADDR,
    NAN_EVT_ATTR_MATCH_SERVICE_SPECIFIC_INFO_LEN,
    NAN_EVT_ATTR_MATCH_SERVICE_SPECIFIC_INFO,
    NAN_EVT_ATTR_MATCH_SDF_MATCH_FILTER_LEN,
    NAN_EVT_ATTR_MATCH_SDF_MATCH_FILTER,
    NAN_EVT_ATTR_MATCH_MATCH_OCCURED_FLAG,
    NAN_EVT_ATTR_MATCH_OUT_OF_RESOURCE_FLAG,
    NAN_EVT_ATTR_MATCH_RSSI_VALUE,
/*CONN_CAPABILITY*/
    NAN_EVT_ATTR_MATCH_CONN_CAPABILITY_IS_WFD_SUPPORTED,
    NAN_EVT_ATTR_MATCH_CONN_CAPABILITY_IS_WFDS_SUPPORTED,
    NAN_EVT_ATTR_MATCH_CONN_CAPABILITY_IS_TDLS_SUPPORTED,
    NAN_EVT_ATTR_MATCH_CONN_CAPABILITY_IS_IBSS_SUPPORTED,
    NAN_EVT_ATTR_MATCH_CONN_CAPABILITY_IS_MESH_SUPPORTED,
    NAN_EVT_ATTR_MATCH_CONN_CAPABILITY_WLAN_INFRA_FIELD,
    NAN_EVT_ATTR_MATCH_NUM_RX_DISCOVERY_ATTR,
    NAN_EVT_ATTR_MATCH_RX_DISCOVERY_ATTR,
/*NANRECEIVEPOSTDISCOVERY DISCOVERY_ATTR,*/
    NAN_EVT_ATTR_MATCH_DISC_ATTR_TYPE,
    NAN_EVT_ATTR_MATCH_DISC_ATTR_ROLE,
    NAN_EVT_ATTR_MATCH_DISC_ATTR_DURATION,
    NAN_EVT_ATTR_MATCH_DISC_ATTR_AVAIL_INTERVAL_BITMAP,
    NAN_EVT_ATTR_MATCH_DISC_ATTR_MAPID,
    NAN_EVT_ATTR_MATCH_DISC_ATTR_ADDR,
    NAN_EVT_ATTR_MATCH_DISC_ATTR_MESH_ID_LEN,
    NAN_EVT_ATTR_MATCH_DISC_ATTR_MESH_ID,
    NAN_EVT_ATTR_MATCH_DISC_ATTR_INFRASTRUCTURE_SSID_LEN,
    NAN_EVT_ATTR_MATCH_DISC_ATTR_INFRASTRUCTURE_SSID_VAL,

    NAN_EVT_ATTR_MATCH_NUM_CHANS,
    NAN_EVT_ATTR_MATCH_FAMCHAN,
/*FAMCHAN[32],*/
    NAN_EVT_ATTR_MATCH_FAM_ENTRY_CONTROL,
    NAN_EVT_ATTR_MATCH_FAM_CLASS_VAL,
    NAN_EVT_ATTR_MATCH_FAM_CHANNEL,
    NAN_EVT_ATTR_MATCH_FAM_MAPID,
    NAN_EVT_ATTR_MATCH_FAM_AVAIL_INTERVAL_BITMAP,
    NAN_EVT_ATTR_MATCH_CLUSTER_ATTRIBUTE_LEN,
    NAN_EVT_ATTR_MATCH_CLUSTER_ATTRIBUTE,
    NAN_EVT_ATTR_PUBLISH_ID,
    NAN_EVT_ATTR_PUBLISH_REASON,
    NAN_EVT_ATTR_SUBSCRIBE_ID,
    NAN_EVT_ATTR_SUBSCRIBE_REASON,
    NAN_EVT_ATTR_DISABLED_REASON,
    NAN_EVT_ATTR_FOLLOWUP_PUBLISH_SUBSCRIBE_ID,
    NAN_EVT_ATTR_FOLLOWUP_REQUESTOR_INSTANCE_ID,
    NAN_EVT_ATTR_FOLLOWUP_ADDR,
    NAN_EVT_ATTR_FOLLOWUP_DW_OR_FAW,
    NAN_EVT_ATTR_FOLLOWUP_SERVICE_SPECIFIC_INFO_LEN,
    NAN_EVT_ATTR_FOLLOWUP_SERVICE_SPECIFIC_INFO,
    NAN_EVT_ATTR_DISCOVERY_ENGINE_EVT_TYPE	,
    NAN_EVT_ATTR_DISCOVERY_ENGINE_MAC_ADDR,
    NAN_EVT_ATTR_DISCOVERY_ENGINE_CLUSTER

} NAN_EVT_ATTRIBUTES;

class NanCommand : public WifiCommand {
    static NanCallbackHandler callbackEventHandler;
    int subscribeID[2];
    int publishID[2];
    int followupID[2];
    int version;
    NanCapabilities capabilities;

    void registerNanEvents(void) {
        registerVendorHandler(GOOGLE_OUI, SLSI_NAN_EVENT_PUBLISH_TERMINATED);
        registerVendorHandler(GOOGLE_OUI, SLSI_NAN_EVENT_MATCH);
        registerVendorHandler(GOOGLE_OUI, SLSI_NAN_EVENT_MATCH_EXPIRED);
        registerVendorHandler(GOOGLE_OUI, SLSI_NAN_EVENT_SUBSCRIBE_TERMINATED);
        registerVendorHandler(GOOGLE_OUI, SLSI_NAN_EVENT_FOLLOWUP);
        registerVendorHandler(GOOGLE_OUI, SLSI_NAN_EVENT_DISCOVERY_ENGINE);
    }

    void unregisterNanEvents(void) {
        unregisterVendorHandler(GOOGLE_OUI, SLSI_NAN_EVENT_PUBLISH_TERMINATED);
        unregisterVendorHandler(GOOGLE_OUI, SLSI_NAN_EVENT_MATCH);
        unregisterVendorHandler(GOOGLE_OUI, SLSI_NAN_EVENT_MATCH_EXPIRED);
        unregisterVendorHandler(GOOGLE_OUI, SLSI_NAN_EVENT_SUBSCRIBE_TERMINATED);
        unregisterVendorHandler(GOOGLE_OUI, SLSI_NAN_EVENT_FOLLOWUP);
        unregisterVendorHandler(GOOGLE_OUI, SLSI_NAN_EVENT_DISCOVERY_ENGINE);
    }

    int processResponse(WifiEvent &reply, NanResponseMsg *response) {
        NanCapabilities *capabilities = &response->body.nan_capabilities;
        nlattr *vendor_data = reply.get_attribute(NL80211_ATTR_VENDOR_DATA);
        //int len = reply.get_vendor_data_len();
        unsigned int val;

        for(nl_iterator nl_itr(vendor_data); nl_itr.has_next(); nl_itr.next()) {
            switch(nl_itr.get_type()) {
            case NAN_REPLY_ATTR_STATUS_TYPE:
                response->status = NanStatusType(nl_itr.get_u32());
                break;
            case NAN_REPLY_ATTR_VALUE:
                val = nl_itr.get_u32();
                if (val) {
                    strncpy(response->nan_error, "Lower_layer_error",NAN_ERROR_STR_LEN);
                }
                break;
            case NAN_REPLY_ATTR_RESPONSE_TYPE:
                response->response_type = NanResponseType(nl_itr.get_u32());
                break;
            case NAN_REPLY_ATTR_PUBLISH_SUBSCRIBE_TYPE:
                response->body.publish_response.publish_id = nl_itr.get_u16();
                break;
            case NAN_REPLY_ATTR_CAP_MAX_CONCURRENT_CLUSTER:
                capabilities->max_concurrent_nan_clusters = nl_itr.get_u32();
                break;
            case NAN_REPLY_ATTR_CAP_MAX_PUBLISHES:
                capabilities->max_publishes = nl_itr.get_u32();
                break;
            case NAN_REPLY_ATTR_CAP_MAX_SUBSCRIBES:
                capabilities->max_subscribes = nl_itr.get_u32();
                break;
            case NAN_REPLY_ATTR_CAP_MAX_SERVICE_NAME_LEN:
                capabilities->max_service_name_len = nl_itr.get_u32();
                break;
            case NAN_REPLY_ATTR_CAP_MAX_MATCH_FILTER_LEN:
                capabilities->max_match_filter_len = nl_itr.get_u32();
                break;
            case NAN_REPLY_ATTR_CAP_MAX_TOTAL_MATCH_FILTER_LEN:
                capabilities->max_total_match_filter_len = nl_itr.get_u32();
                break;
            case NAN_REPLY_ATTR_CAP_MAX_SERVICE_SPECIFIC_INFO_LEN:
                capabilities->max_service_specific_info_len = nl_itr.get_u32();
                break;
            case NAN_REPLY_ATTR_CAP_MAX_VSA_DATA_LEN:
                capabilities->max_vsa_data_len = nl_itr.get_u32();
                break;
            case NAN_REPLY_ATTR_CAP_MAX_MESH_DATA_LEN:
                capabilities->max_mesh_data_len = nl_itr.get_u32();
                break;
            case NAN_REPLY_ATTR_CAP_MAX_NDI_INTERFACES:
                capabilities->max_ndi_interfaces = nl_itr.get_u32();
                break;
            case NAN_REPLY_ATTR_CAP_MAX_NDP_SESSIONS:
                capabilities->max_ndp_sessions = nl_itr.get_u32();
                break;
            case NAN_REPLY_ATTR_CAP_MAX_APP_INFO_LEN:
                capabilities->max_app_info_len = nl_itr.get_u32();
                break;
            default :
                ALOGE("received unknown type(%d) in response", nl_itr.get_type());
                return NL_SKIP;
            }
        }
        this->capabilities = *capabilities;
        return NL_OK;
    }

    int processMatchEvent(WifiEvent &event) {
        NanMatchInd ind;
        memset(&ind,0,sizeof(NanMatchInd));
        int famchan_idx = 0, disc_idx = 0;
        nlattr *vendor_data = event.get_attribute(NL80211_ATTR_VENDOR_DATA);

        for(nl_iterator nl_itr(vendor_data); nl_itr.has_next(); nl_itr.next()) {
            switch(nl_itr.get_type()) {
            case NAN_EVT_ATTR_MATCH_PUBLISH_SUBSCRIBE_ID:
                ind.publish_subscribe_id = nl_itr.get_u16();
                break;
            case NAN_EVT_ATTR_MATCH_REQUESTOR_INSTANCE_ID:
                ind.requestor_instance_id = nl_itr.get_u32();
                break;
            case NAN_EVT_ATTR_MATCH_ADDR:
                memcpy(ind.addr, nl_itr.get_data(), NAN_MAC_ADDR_LEN);
                break;
            case NAN_EVT_ATTR_MATCH_SERVICE_SPECIFIC_INFO_LEN:
                ind.service_specific_info_len = nl_itr.get_u16();
                break;
            case NAN_EVT_ATTR_MATCH_SERVICE_SPECIFIC_INFO:
                memcpy(ind.service_specific_info, nl_itr.get_data(), ind.service_specific_info_len);
                break;
            case NAN_EVT_ATTR_MATCH_SDF_MATCH_FILTER_LEN:
                ind.sdf_match_filter_len = nl_itr.get_u16();
                break;
            case NAN_EVT_ATTR_MATCH_SDF_MATCH_FILTER:
                memcpy(ind.sdf_match_filter, nl_itr.get_data(), ind.sdf_match_filter_len);
                break;
            case NAN_EVT_ATTR_MATCH_MATCH_OCCURED_FLAG:
                ind.match_occured_flag = nl_itr.get_u8();
                break;
            case NAN_EVT_ATTR_MATCH_OUT_OF_RESOURCE_FLAG:
                ind.out_of_resource_flag = nl_itr.get_u8();
                break;
            case NAN_EVT_ATTR_MATCH_RSSI_VALUE:
                ind.rssi_value = nl_itr.get_u8();
                break;
            case NAN_EVT_ATTR_MATCH_CONN_CAPABILITY_IS_IBSS_SUPPORTED:
                ind.conn_capability.is_ibss_supported = nl_itr.get_u8();
                break;
            case NAN_EVT_ATTR_MATCH_CONN_CAPABILITY_IS_WFD_SUPPORTED:
                ind.conn_capability.is_wfd_supported = nl_itr.get_u8();
                break;
            case NAN_EVT_ATTR_MATCH_CONN_CAPABILITY_IS_WFDS_SUPPORTED:
                ind.conn_capability.is_wfds_supported = nl_itr.get_u8();
                break;
            case NAN_EVT_ATTR_MATCH_CONN_CAPABILITY_IS_TDLS_SUPPORTED:
                ind.conn_capability.is_tdls_supported = nl_itr.get_u8();
                break;
            case NAN_EVT_ATTR_MATCH_CONN_CAPABILITY_IS_MESH_SUPPORTED:
                ind.conn_capability.is_mesh_supported= nl_itr.get_u8();
                break;
            case NAN_EVT_ATTR_MATCH_CONN_CAPABILITY_WLAN_INFRA_FIELD:
                ind.conn_capability.wlan_infra_field = nl_itr.get_u8();
                break;
            case NAN_EVT_ATTR_MATCH_NUM_RX_DISCOVERY_ATTR:
                ind.num_rx_discovery_attr = nl_itr.get_u8();
                break;
            case NAN_EVT_ATTR_MATCH_RX_DISCOVERY_ATTR:
                NanReceivePostDiscovery *disc_attr;
                disc_attr = &ind.discovery_attr[disc_idx];
                disc_idx++;
                for(nl_iterator nl_nested_itr((struct nlattr *)nl_itr.get_data()); nl_nested_itr.has_next(); nl_nested_itr.next()) {
                    switch(nl_nested_itr.get_type()) {
                    case NAN_EVT_ATTR_MATCH_DISC_ATTR_TYPE:
                        disc_attr->type = (NanConnectionType)nl_nested_itr.get_u8();
                        break;
                    case NAN_EVT_ATTR_MATCH_DISC_ATTR_ROLE:
                        disc_attr->role = (NanDeviceRole)nl_nested_itr.get_u8();
                        break;
                    case NAN_EVT_ATTR_MATCH_DISC_ATTR_DURATION:
                        disc_attr->duration = (NanAvailDuration)nl_nested_itr.get_u8();
                        break;
                    case NAN_EVT_ATTR_MATCH_DISC_ATTR_AVAIL_INTERVAL_BITMAP:
                        disc_attr->avail_interval_bitmap = nl_nested_itr.get_u32();
                        break;
                    case NAN_EVT_ATTR_MATCH_DISC_ATTR_MAPID:
                        disc_attr->mapid = nl_nested_itr.get_u8();
                        break;
                    case NAN_EVT_ATTR_MATCH_DISC_ATTR_ADDR:
                        memcpy(disc_attr->addr, nl_nested_itr.get_data(), NAN_MAC_ADDR_LEN);
                        break;
                    case NAN_EVT_ATTR_MATCH_DISC_ATTR_MESH_ID_LEN:
                        disc_attr->mesh_id_len = nl_nested_itr.get_u8();
                        break;
                    case NAN_EVT_ATTR_MATCH_DISC_ATTR_MESH_ID:
                        memcpy(disc_attr->mesh_id, nl_nested_itr.get_data(), disc_attr->mesh_id_len);
                        break;
                    case NAN_EVT_ATTR_MATCH_DISC_ATTR_INFRASTRUCTURE_SSID_LEN:
                        disc_attr->infrastructure_ssid_len = nl_nested_itr.get_u16();
                        break;
                    case NAN_EVT_ATTR_MATCH_DISC_ATTR_INFRASTRUCTURE_SSID_VAL:
                        memcpy(disc_attr->infrastructure_ssid_val, nl_nested_itr.get_data(), disc_attr->infrastructure_ssid_len);
                        break;
                    }
                }
                break;
            case NAN_EVT_ATTR_MATCH_NUM_CHANS:
                ind.num_chans = nl_itr.get_u8();
                break;
            case NAN_EVT_ATTR_MATCH_FAMCHAN:
                NanFurtherAvailabilityChannel *famchan;
                famchan = &ind.famchan[famchan_idx];
                famchan_idx++;
                for(nl_iterator nl_nested_itr((struct nlattr *)nl_itr.get_data()); nl_nested_itr.has_next(); nl_nested_itr.next()) {
                    switch(nl_nested_itr.get_type()) {
                    case NAN_EVT_ATTR_MATCH_FAM_ENTRY_CONTROL:
                        famchan->entry_control = (NanAvailDuration)nl_nested_itr.get_u8();
                        break;
                    case NAN_EVT_ATTR_MATCH_FAM_CLASS_VAL:
                        famchan->class_val = nl_nested_itr.get_u8();
                        break;
                    case NAN_EVT_ATTR_MATCH_FAM_CHANNEL:
                        famchan->channel = nl_nested_itr.get_u8();
                        break;
                    case NAN_EVT_ATTR_MATCH_FAM_MAPID:
                        famchan->mapid = nl_nested_itr.get_u8();
                        break;
                    case NAN_EVT_ATTR_MATCH_FAM_AVAIL_INTERVAL_BITMAP:
                        famchan->avail_interval_bitmap = nl_nested_itr.get_u32();
                        break;
                    }
                }
            case NAN_EVT_ATTR_MATCH_CLUSTER_ATTRIBUTE_LEN:
                ind.cluster_attribute_len = nl_itr.get_u8();
                break;
            case NAN_EVT_ATTR_MATCH_CLUSTER_ATTRIBUTE:
                memcpy(ind.cluster_attribute, nl_itr.get_data(), ind.cluster_attribute_len);
                break;
            }
        }
        
        if (this->callbackEventHandler.EventMatch)
            this->callbackEventHandler.EventMatch(&ind);
        return NL_OK;
    }

    int processMatchExpiredEvent(WifiEvent &event) {
        NanMatchExpiredInd ind;
        memset(&ind,0,sizeof(NanMatchExpiredInd));

        for(nl_iterator nl_itr((struct nlattr *)event.get_vendor_data()); nl_itr.has_next(); nl_itr.next()) {
            switch(nl_itr.get_type()) {
            case NAN_EVT_ATTR_MATCH_PUBLISH_SUBSCRIBE_ID:
                ind.publish_subscribe_id = nl_itr.get_u16();
                break;
            case NAN_EVT_ATTR_MATCH_REQUESTOR_INSTANCE_ID:
                ind.requestor_instance_id = nl_itr.get_u32();
                break;
            default :
                ALOGE("processMatchExpiredEvent: unknown attribute(%d)", nl_itr.get_type());
                return NL_SKIP;
            }
        }

        if (callbackEventHandler.EventMatchExpired)
            callbackEventHandler.EventMatchExpired(&ind);

        return NL_OK;
    }

    int processPublishTerminatedEvent(WifiEvent &event) {
        NanPublishTerminatedInd ind;
        memset(&ind,0,sizeof(ind));

        for(nl_iterator nl_itr((struct nlattr *)event.get_vendor_data()); nl_itr.has_next(); nl_itr.next()) {
            switch(nl_itr.get_type()) {
            case NAN_EVT_ATTR_PUBLISH_ID:
                ind.publish_id = nl_itr.get_u16();
                break;
            case NAN_EVT_ATTR_PUBLISH_REASON:
                ind.reason = (NanStatusType)nl_itr.get_u32();
                break;
            default :
                ALOGE("processPublishTerminatedEvent: unknown attribute(%d)", nl_itr.get_type());
                return NL_SKIP;
            }
        }

        if (callbackEventHandler.EventPublishTerminated)
            callbackEventHandler.EventPublishTerminated(&ind);

        return NL_OK;

    }

    int processSubscribeTerminatedEvent(WifiEvent &event) {
        NanSubscribeTerminatedInd ind;
        memset(&ind,0,sizeof(ind));

        for(nl_iterator nl_itr((struct nlattr *)event.get_vendor_data()); nl_itr.has_next(); nl_itr.next()) {
            switch(nl_itr.get_type()) {
            case NAN_EVT_ATTR_SUBSCRIBE_ID:
                ind.subscribe_id = nl_itr.get_u16();
                break;
            case NAN_EVT_ATTR_SUBSCRIBE_REASON:
                ind.reason = (NanStatusType)nl_itr.get_u32();
                break;
            default :
                ALOGE("processSubscribeTerminatedEvent: unknown attribute(%d)", nl_itr.get_type());
                return NL_SKIP;
            }
        }

        if (callbackEventHandler.EventSubscribeTerminated)
            callbackEventHandler.EventSubscribeTerminated(&ind);

        return NL_OK;
    }

    int processFollowupEvent(WifiEvent &event) {
        NanFollowupInd ind;
        memset(&ind,0,sizeof(ind));

        for(nl_iterator nl_itr((struct nlattr *)event.get_vendor_data()); nl_itr.has_next(); nl_itr.next()) {
            switch(nl_itr.get_type()) {
            case NAN_EVT_ATTR_FOLLOWUP_PUBLISH_SUBSCRIBE_ID:
                ind.publish_subscribe_id = nl_itr.get_u16();
                break;
            case NAN_EVT_ATTR_FOLLOWUP_REQUESTOR_INSTANCE_ID:
                ind.requestor_instance_id = nl_itr.get_u32();
                break;
            case NAN_EVT_ATTR_FOLLOWUP_ADDR:
                memcpy(ind.addr, nl_itr.get_data(), NAN_MAC_ADDR_LEN);
                break;
            case NAN_EVT_ATTR_FOLLOWUP_DW_OR_FAW:
                ind.dw_or_faw = nl_itr.get_u8();
                break;
            case NAN_EVT_ATTR_FOLLOWUP_SERVICE_SPECIFIC_INFO_LEN:
                ind.service_specific_info_len = nl_itr.get_u16();
                break;
            case NAN_EVT_ATTR_FOLLOWUP_SERVICE_SPECIFIC_INFO:
                memcpy(ind.service_specific_info, nl_itr.get_data(), ind.service_specific_info_len);
                break;
            default :
                ALOGE("processNanDisabledEvent: unknown attribute(%d)", nl_itr.get_type());
                return NL_SKIP;
            }
        }

        if (callbackEventHandler.EventFollowup)
            callbackEventHandler.EventFollowup(&ind);

        return NL_OK;
    }

    int processNanDisabledEvent(WifiEvent &event) {
        NanDisabledInd ind;
        memset(&ind,0,sizeof(ind));

        for(nl_iterator nl_itr((struct nlattr *)event.get_vendor_data()); nl_itr.has_next(); nl_itr.next()) {
            switch(nl_itr.get_type()) {
            case NAN_EVT_ATTR_DISABLED_REASON:
                ind.reason = (NanStatusType)nl_itr.get_u32();
                break;
            default :
                ALOGE("processNanDisabledEvent: unknown attribute(%d)", nl_itr.get_type());
                return NL_SKIP;
            }
        }

        if (callbackEventHandler.EventDisabled)
            callbackEventHandler.EventDisabled(&ind);

        return NL_OK;
    }

    int processNanDiscoveryEvent(WifiEvent &event) {
        NanDiscEngEventInd ind;
        memset(&ind,0,sizeof(ind));
        u8 *addr = NULL;

        for(nl_iterator nl_itr((struct nlattr *)event.get_vendor_data()); nl_itr.has_next(); nl_itr.next()) {
            switch(nl_itr.get_type()) {
            case NAN_EVT_ATTR_DISCOVERY_ENGINE_EVT_TYPE:
                ind.event_type = (NanDiscEngEventType)nl_itr.get_u16();
                break;
            case NAN_EVT_ATTR_DISCOVERY_ENGINE_MAC_ADDR:
                addr = (u8 *)nl_itr.get_data();
                break;
            default :
                ALOGE("processNanDiscoveryEvent: unknown attribute(%d)", nl_itr.get_type());
                return NL_SKIP;
            }
        }
        if (addr) {
            if (ind.event_type == NAN_EVENT_ID_DISC_MAC_ADDR)
                memcpy(ind.data.mac_addr.addr, addr, NAN_MAC_ADDR_LEN);
            else
                memcpy(ind.data.cluster.addr, addr, NAN_MAC_ADDR_LEN);
        } else {
            ALOGE("processNanDiscoveryEvent: No Mac/cluster Address");
        }

        if (callbackEventHandler.EventDiscEngEvent)
            callbackEventHandler.EventDiscEngEvent(&ind);

        return NL_OK;
    }

public:
    NanCommand(wifi_interface_handle iface, int id)
        : WifiCommand(iface, id)
    {
        subscribeID[0] = 0;
        subscribeID[1] = 0;
        publishID[0] = 0;
        publishID[1] = 0;
        followupID[0] = 0;
        followupID[0] = 0;
        version = 0;
        memset(&capabilities, 0, sizeof(capabilities));
    }

    int enable(NanEnableRequest *msg) {
        ALOGD("Start NAN...");
        WifiRequest request(familyId(), ifaceId());

        int result = request.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_NAN_ENABLE);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "enable:Failed to create WifiRequest");

        nlattr *data = request.attr_start(NL80211_ATTR_VENDOR_DATA);
        if (!data) {
            ALOGE("enable: request.attr_start fail");
            return WIFI_ERROR_OUT_OF_MEMORY;
        }
        result = request.put_u8(NAN_REQ_ATTR_MASTER_PREF, msg->master_pref);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "enable:Failed to put master_pref");

        result = request.put_u16(NAN_REQ_ATTR_CLUSTER_LOW, msg->cluster_low);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "enable:Failed to put cluster_low");

        result = request.put_u16(NAN_REQ_ATTR_CLUSTER_HIGH, msg->cluster_high);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "enable:Failed to put cluster_high");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(msg->config_support_5g, msg->support_5g_val,
                    NAN_REQ_ATTR_SUPPORT_5G_VAL, request, result, "enable:Failed to put support_5g_val");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(msg->config_sid_beacon, msg->sid_beacon_val,
                    NAN_REQ_ATTR_SID_BEACON_VAL, request, result, "enable:Failed to put sid_beacon_val");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(msg->config_2dot4g_rssi_close, msg->rssi_close_2dot4g_val,
                    NAN_REQ_ATTR_RSSI_CLOSE_2G4_VAL, request, result, "enable:Failed to put rssi_close_2dot4g_val");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(msg->config_2dot4g_rssi_middle, msg->rssi_middle_2dot4g_val,
                    NAN_REQ_ATTR_RSSI_MIDDLE_2G4_VAL, request, result, "enable:Failed to put rssi_middle_2dot4g_val");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(msg->config_2dot4g_rssi_proximity, msg->rssi_proximity_2dot4g_val,
                    NAN_REQ_ATTR_RSSI_PROXIMITY_2G4_VAL, request, result, "enable:Failed to put rssi_proximity_2dot4g_val");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(msg->config_hop_count_limit, msg->hop_count_limit_val,
                    NAN_REQ_ATTR_HOP_COUNT_LIMIT_VAL, request, result, "enable:Failed to put hop_count_limit_val");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(msg->config_2dot4g_support, msg->support_2dot4g_val,
                    NAN_REQ_ATTR_SUPPORT_2G4_VAL, request, result, "enable:Failed to put support_2dot4g_val");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(msg->config_2dot4g_beacons, msg->beacon_2dot4g_val,
                    NAN_REQ_ATTR_BEACONS_2G4_VAL, request, result, "enable:Failed to put beacon_2dot4g_val");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(msg->config_2dot4g_sdf, msg->sdf_2dot4g_val,
                    NAN_REQ_ATTR_SDF_2G4_VAL, request, result, "enable:Failed to put sdf_2dot4g_val");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(msg->config_5g_beacons, msg->beacon_5g_val,
                    NAN_REQ_ATTR_BEACON_5G_VAL, request, result, "enable:Failed to put beacon_5g_val");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(msg->config_5g_sdf, msg->sdf_5g_val,
                    NAN_REQ_ATTR_SDF_5G_VAL, request, result, "enable:Failed to put sdf_5g_val");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(msg->config_5g_rssi_close, msg->rssi_close_5g_val,
                    NAN_REQ_ATTR_RSSI_CLOSE_5G_VAL, request, result, "enable:Failed to put rssi_close_5g_val");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(msg->config_5g_rssi_middle, msg->rssi_middle_5g_val,
                    NAN_REQ_ATTR_RSSI_MIDDLE_5G_VAL, request, result, "enable:Failed to put rssi_middle_5g_val");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(msg->config_5g_rssi_close_proximity, msg->rssi_close_proximity_5g_val,
                    NAN_REQ_ATTR_RSSI_CLOSE_PROXIMITY_5G_VAL, request, result, "enable:Failed to put rssi_close_proximity_5g_val");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(msg->config_rssi_window_size, msg->rssi_window_size_val,
                    NAN_REQ_ATTR_RSSI_WINDOW_SIZE_VAL, request, result, "enable:Failed to put rssi_window_size_val");

        CHECK_CONFIG_PUT_32_RETURN_FAIL(msg->config_oui, msg->oui_val,
                    NAN_REQ_ATTR_OUI_VAL, request, result, "enable:Failed to put oui_val");

        CHECK_CONFIG_PUT_RETURN_FAIL(msg->config_intf_addr, msg->intf_addr_val, NAN_MAC_ADDR_LEN,
                    NAN_REQ_ATTR_MAC_ADDR_VAL, request, result, "enable:Failed to put intf_addr_val");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(1, msg->config_cluster_attribute_val,
                    NAN_REQ_ATTR_CLUSTER_VAL, request, result, "enable:Failed to put config_cluster_attribute_val");

        CHECK_CONFIG_PUT_RETURN_FAIL(msg->config_scan_params, msg->scan_params_val.dwell_time, sizeof(msg->scan_params_val.dwell_time),
                    NAN_REQ_ATTR_SOCIAL_CH_SCAN_DWELL_TIME, request, result, "enable:Failed to put scan_params_val.dwell_time");

        CHECK_CONFIG_PUT_RETURN_FAIL(msg->config_scan_params, msg->scan_params_val.scan_period, sizeof(msg->scan_params_val.scan_period),
                    NAN_REQ_ATTR_SOCIAL_CH_SCAN_PERIOD, request, result, "enable:Failed to put scan_params_val.scan_period");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(msg->config_random_factor_force, msg->random_factor_force_val,
                    NAN_REQ_ATTR_RANDOM_FACTOR_FORCE_VAL, request, result, "enable:Failed to put random_factor_force_val");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(msg->config_hop_count_force, msg->hop_count_force_val,
                    NAN_REQ_ATTR_HOP_COUNT_FORCE_VAL, request, result, "enable:Failed to put hop_count_force_val");

        CHECK_CONFIG_PUT_32_RETURN_FAIL(msg->config_24g_channel, msg->channel_24g_val,
                    NAN_REQ_ATTR_CHANNEL_2G4_MHZ_VAL, request, result, "enable:Failed to put channel_24g_val");

        CHECK_CONFIG_PUT_32_RETURN_FAIL(msg->config_5g_channel, msg->channel_5g_val,
                    NAN_REQ_ATTR_CHANNEL_5G_MHZ_VAL, request, result, "enable:Failed to put channel_5g_val");

        request.attr_end(data);

        registerNanEvents();

        result = requestResponse(request);
        if (result != WIFI_SUCCESS) {
            ALOGE("failed to NAN; result = %d", result);
            unregisterNanEvents();
        } else {
            ALOGD("Start NAN...success");
        }
        return result;
    }

    int disable()
    {
        ALOGD("Stop NAN...");
        WifiRequest request(familyId(), ifaceId());

        unregisterNanEvents();

        int result = request.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_NAN_DISABLE);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "disable:Failed to create WifiRequest");
        result = requestResponse(request);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "disable:Failed to requestResponse");
        return result;
    }

    int config(NanConfigRequest *msg) {
        ALOGD("config...");
        WifiRequest request(familyId(), ifaceId());

        int result = request.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_NAN_CONFIG);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "config:Failed to create WifiRequest");

        nlattr *data = request.attr_start(NL80211_ATTR_VENDOR_DATA);
        if (!data) {
            ALOGE("config: request.attr_start fail");
            return WIFI_ERROR_OUT_OF_MEMORY;
        }

        CHECK_CONFIG_PUT_8_RETURN_FAIL(msg->config_sid_beacon, msg->sid_beacon,
                    NAN_REQ_ATTR_SID_BEACON_VAL, request, result, "config:Failed to put sid_beacon");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(msg->config_rssi_proximity, msg->rssi_proximity,
                    NAN_REQ_ATTR_RSSI_PROXIMITY_2G4_VAL, request, result, "config:Failed to put rssi_proximity");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(msg->config_master_pref, msg->master_pref,
                    NAN_REQ_ATTR_MASTER_PREF, request, result, "config:Failed to put master_pref");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(msg->config_5g_rssi_close_proximity, msg->rssi_close_proximity_5g_val,
                    NAN_REQ_ATTR_RSSI_CLOSE_PROXIMITY_5G_VAL, request, result, "config:Failed to put rssi_close_proximity_5g_val");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(msg->config_rssi_window_size, msg->rssi_window_size_val,
                    NAN_REQ_ATTR_RSSI_WINDOW_SIZE_VAL, request, result, "config:Failed to put rssi_window_size_val");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(1, msg->config_cluster_attribute_val,
                    NAN_REQ_ATTR_CLUSTER_VAL, request, result, "config:Failed to put config_cluster_attribute_val");

        CHECK_CONFIG_PUT_RETURN_FAIL(msg->config_scan_params, msg->scan_params_val.dwell_time, sizeof(msg->scan_params_val.dwell_time),
                    NAN_REQ_ATTR_SOCIAL_CH_SCAN_DWELL_TIME, request, result, "config:Failed to put scan_params_val.dwell_time");

        CHECK_CONFIG_PUT_RETURN_FAIL(msg->config_scan_params, msg->scan_params_val.scan_period, sizeof(msg->scan_params_val.scan_period),
                    NAN_REQ_ATTR_SOCIAL_CH_SCAN_PERIOD, request, result, "config:Failed to put scan_params_val.scan_period");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(msg->config_random_factor_force, msg->random_factor_force_val,
                    NAN_REQ_ATTR_RANDOM_FACTOR_FORCE_VAL, request, result, "config:Failed to put random_factor_force_val");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(msg->config_hop_count_force, msg->hop_count_force_val,
                    NAN_REQ_ATTR_HOP_COUNT_FORCE_VAL, request, result, "config:Failed to put hop_count_force_val");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(msg->config_conn_capability, msg->conn_capability_val.payload_transmit_flag,
                    NAN_REQ_ATTR_CONN_CAPABILITY_PAYLOAD_TX, request, result, "config:Failed to put payload_transmit_flag");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(msg->config_conn_capability, msg->conn_capability_val.is_wfd_supported,
                    NAN_REQ_ATTR_CONN_CAPABILITY_WFD, request, result, "config:Failed to put is_wfd_supported");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(msg->config_conn_capability, msg->conn_capability_val.is_wfds_supported,
                    NAN_REQ_ATTR_CONN_CAPABILITY_WFDS, request, result, "config:Failed to put is_wfds_supported");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(msg->config_conn_capability, msg->conn_capability_val.is_tdls_supported,
                    NAN_REQ_ATTR_CONN_CAPABILITY_TDLS, request, result, "config:Failed to put is_tdls_supported");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(msg->config_conn_capability, msg->conn_capability_val.is_ibss_supported,
                    NAN_REQ_ATTR_CONN_CAPABILITY_IBSS, request, result, "config:Failed to put is_ibss_supported");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(msg->config_conn_capability, msg->conn_capability_val.is_mesh_supported,
                    NAN_REQ_ATTR_CONN_CAPABILITY_MESH, request, result, "config:Failed to put is_mesh_supported");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(msg->config_conn_capability, msg->conn_capability_val.wlan_infra_field,
                    NAN_REQ_ATTR_CONN_CAPABILITY_WLAN_INFRA, request, result, "config:Failed to put wlan_infra_field");

        if (msg->num_config_discovery_attr) {
            CHECK_CONFIG_PUT_8_RETURN_FAIL(1, msg->num_config_discovery_attr,
                        NAN_REQ_ATTR_DISCOVERY_ATTR_NUM_ENTRIES, request, result, "config:Failed to put msg->num_config_discovery_attr");
            for (int i = 0; i < msg->num_config_discovery_attr; i++) {
                nlattr *nl_disc_attribute = request.attr_start(NAN_REQ_ATTR_DISCOVERY_ATTR_VAL);
                NanTransmitPostDiscovery *discovery_attr = &msg->discovery_attr_val[i];
                CHECK_CONFIG_PUT_8_RETURN_FAIL(1, discovery_attr->type,
                    NAN_REQ_ATTR_CONN_TYPE, request, result, "config:Failed to put discovery_attr->type");
                CHECK_CONFIG_PUT_8_RETURN_FAIL(1, discovery_attr->role,
                    NAN_REQ_ATTR_NAN_ROLE, request, result, "config:Failed to put discovery_attr->role");
                CHECK_CONFIG_PUT_8_RETURN_FAIL(1, discovery_attr->transmit_freq,
                    NAN_REQ_ATTR_TRANSMIT_FREQ, request, result, "config:Failed to put discovery_attr->transmit_freq");
                CHECK_CONFIG_PUT_8_RETURN_FAIL(1, discovery_attr->duration,
                    NAN_REQ_ATTR_AVAILABILITY_DURATION, request, result, "config:Failed to put discovery_attr->duration");
                CHECK_CONFIG_PUT_32_RETURN_FAIL(1, discovery_attr->avail_interval_bitmap,
                    NAN_REQ_ATTR_AVAILABILITY_INTERVAL, request, result, "config:Failed to put discovery_attr->avail_interval_bitmap");
                CHECK_CONFIG_PUT_RETURN_FAIL(1, discovery_attr->addr, NAN_MAC_ADDR_LEN,
                    NAN_REQ_ATTR_MAC_ADDR_VAL, request, result, "config:Failed to put discovery_attr->addr");
                CHECK_CONFIG_PUT_16_RETURN_FAIL(1, discovery_attr->mesh_id_len,
                    NAN_REQ_ATTR_MESH_ID_LEN, request, result, "config:Failed to put discovery_attr->mesh_id");
                CHECK_CONFIG_PUT_RETURN_FAIL(discovery_attr->mesh_id_len, discovery_attr->mesh_id, discovery_attr->mesh_id_len,
                    NAN_REQ_ATTR_MESH_ID, request, result, "config:Failed to put discovery_attr->mesh_id");
                CHECK_CONFIG_PUT_16_RETURN_FAIL(1, discovery_attr->infrastructure_ssid_len,
                    NAN_REQ_ATTR_INFRASTRUCTURE_SSID_LEN, request, result, "config:Failed to put discovery_attr->infrastructure_ssid_val");
                CHECK_CONFIG_PUT_RETURN_FAIL(discovery_attr->infrastructure_ssid_len, discovery_attr->infrastructure_ssid_val, discovery_attr->infrastructure_ssid_len,
                    NAN_REQ_ATTR_INFRASTRUCTURE_SSID, request, result, "config:Failed to put discovery_attr->infrastructure_ssid_val");
                request.attr_end(nl_disc_attribute);
            }
        }

        if (msg->config_fam) {
            CHECK_CONFIG_PUT_8_RETURN_FAIL(1, msg->fam_val.numchans,
                        NAN_REQ_ATTR_FURTHER_AVAIL_NUM_ENTRIES, request, result, "config:Failed to put msg->fam_val.numchans");
            for (int i = 0; i < msg->fam_val.numchans; i++) {
                nlattr *nl_fam_attribute = request.attr_start(NAN_REQ_ATTR_FURTHER_AVAIL_VAL);
                NanFurtherAvailabilityChannel *further_avail_chan = &msg->fam_val.famchan[i];
                CHECK_CONFIG_PUT_8_RETURN_FAIL(1, further_avail_chan->entry_control,
                            NAN_REQ_ATTR_FURTHER_AVAIL_ENTRY_CTRL, request, result, "config:Failed to put further_avail_chan->entry_control");
                CHECK_CONFIG_PUT_8_RETURN_FAIL(1, further_avail_chan->class_val,
                            NAN_REQ_ATTR_FURTHER_AVAIL_CHAN_CLASS, request, result, "config:Failed to put further_avail_chan->class_val");
                CHECK_CONFIG_PUT_8_RETURN_FAIL(1, further_avail_chan->channel,
                            NAN_REQ_ATTR_FURTHER_AVAIL_CHAN, request, result, "config:Failed to put further_avail_chan->channel");
                CHECK_CONFIG_PUT_8_RETURN_FAIL(1, further_avail_chan->mapid,
                            NAN_REQ_ATTR_FURTHER_AVAIL_CHAN_MAPID, request, result, "config:Failed to put further_avail_chan->mapid");
                CHECK_CONFIG_PUT_32_RETURN_FAIL(1, further_avail_chan->avail_interval_bitmap,
                            NAN_REQ_ATTR_FURTHER_AVAIL_INTERVAL_BITMAP, request, result, "config:Failed to put further_avail_chan->avail_interval_bitmap");
                request.attr_end(nl_fam_attribute);
            }
        }

        request.attr_end(data);
        result = requestResponse(request);
        if (result != WIFI_SUCCESS) {
            ALOGE("failed to set_config; result = %d", result);
        } else {
            ALOGD("config...success");
        }
        return result;
    }

    static int setCallbackHandler(NanCallbackHandler handlers) {
        callbackEventHandler = handlers;
        return WIFI_SUCCESS;
    }

    static int getVersion(NanVersion *version) {
        *version = SLSI_WIFI_HAL_NAN_VERSION;
        return WIFI_SUCCESS;
    }

    int publish(NanPublishRequest *msg) {
        ALOGD("publish...");
        WifiRequest request(familyId(), ifaceId());

        int result = request.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_NAN_PUBLISH);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "publish:Failed to create WifiRequest");

        nlattr *data = request.attr_start(NL80211_ATTR_VENDOR_DATA);
        if (!data) {
            ALOGE("publish: request.attr_start fail");
            return WIFI_ERROR_OUT_OF_MEMORY;
        }

        CHECK_CONFIG_PUT_16_RETURN_FAIL(msg->publish_id, msg->publish_id,
                NAN_REQ_ATTR_PUBLISH_ID, request, result, "publish:Failed to put msg->publish_id");

        CHECK_CONFIG_PUT_16_RETURN_FAIL(msg->ttl, msg->ttl,
                NAN_REQ_ATTR_PUBLISH_TTL, request, result, "publish:Failed to put msg->ttl");

        CHECK_CONFIG_PUT_16_RETURN_FAIL(1, msg->period,
                NAN_REQ_ATTR_PUBLISH_PERIOD, request, result, "publish:Failed to put msg->period");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(1, msg->publish_type,
                NAN_REQ_ATTR_PUBLISH_TYPE, request, result, "publish:Failed to put msg->publish_type");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(1, msg->tx_type,
                NAN_REQ_ATTR_PUBLISH_TX_TYPE, request, result, "publish:Failed to put msg->tx_type");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(1, msg->publish_count,
                NAN_REQ_ATTR_PUBLISH_COUNT, request, result, "publish:Failed to put msg->publish_count");

        CHECK_CONFIG_PUT_16_RETURN_FAIL(msg->service_name_len, msg->service_name_len,
                NAN_REQ_ATTR_PUBLISH_SERVICE_NAME_LEN, request, result, "publish:Failed to put msg->service_name_len");

        CHECK_CONFIG_PUT_RETURN_FAIL(msg->service_name_len, msg->service_name, msg->service_name_len,
                NAN_REQ_ATTR_PUBLISH_SERVICE_NAME, request, result, "publish:Failed to put msg->service_name");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(1, msg->publish_match_indicator,
                NAN_REQ_ATTR_PUBLISH_MATCH_ALGO, request, result, "publish:Failed to put msg->publish_match_indicator");

        CHECK_CONFIG_PUT_16_RETURN_FAIL(msg->service_specific_info_len, msg->service_specific_info_len,
                NAN_REQ_ATTR_PUBLISH_SERVICE_INFO_LEN, request, result, "publish:Failed to put msg->service_specific_info_len");

        CHECK_CONFIG_PUT_RETURN_FAIL(msg->service_specific_info_len, msg->service_specific_info, msg->service_specific_info_len,
                NAN_REQ_ATTR_PUBLISH_SERVICE_INFO, request, result, "publish:Failed to put msg->service_specific_info");

        CHECK_CONFIG_PUT_16_RETURN_FAIL(msg->rx_match_filter_len, msg->rx_match_filter_len,
                NAN_REQ_ATTR_PUBLISH_RX_MATCH_FILTER_LEN, request, result, "publish:Failed to put msg->rx_match_filter_len");

        CHECK_CONFIG_PUT_RETURN_FAIL(msg->rx_match_filter_len, msg->rx_match_filter, msg->rx_match_filter_len,
                NAN_REQ_ATTR_PUBLISH_RX_MATCH_FILTER, request, result, "publish:Failed to put msg->rx_match_filter");

        CHECK_CONFIG_PUT_16_RETURN_FAIL(msg->tx_match_filter_len, msg->tx_match_filter_len,
                NAN_REQ_ATTR_PUBLISH_TX_MATCH_FILTER_LEN, request, result, "publish:Failed to put msg->tx_match_filter_len");

        CHECK_CONFIG_PUT_RETURN_FAIL(msg->tx_match_filter_len, msg->tx_match_filter, msg->tx_match_filter_len,
                NAN_REQ_ATTR_PUBLISH_TX_MATCH_FILTER, request, result, "publish:Failed to put msg->tx_match_filter");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(1, msg->rssi_threshold_flag,
                NAN_REQ_ATTR_PUBLISH_RSSI_THRESHOLD_FLAG, request, result, "publish:Failed to put msg->rssi_threshold_flag");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(1, msg->connmap,
                NAN_REQ_ATTR_PUBLISH_CONN_MAP, request, result, "publish:Failed to put msg->connmap");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(1, msg->recv_indication_cfg,
                NAN_REQ_ATTR_PUBLISH_RECV_IND_CFG, request, result, "publish:Failed to put msg->recv_indication_cfg");

        request.attr_end(data);
        result = requestResponse(request);
        if (result != WIFI_SUCCESS) {
            ALOGE("failed to publish; result = %d", result);
        } else {
            ALOGD("publish...success");
        }
        return result;
    }

    int publishCancel(NanPublishCancelRequest *msg) {
        ALOGD("publishCancel...");
        WifiRequest request(familyId(), ifaceId());

        int result = request.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_NAN_PUBLISHCANCEL);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "publishCancel:Failed to create WifiRequest");

        nlattr *data = request.attr_start(NL80211_ATTR_VENDOR_DATA);
        if (!data) {
            ALOGE("publishCancel: request.attr_start fail");
            return WIFI_ERROR_OUT_OF_MEMORY;
        }

        CHECK_CONFIG_PUT_16_RETURN_FAIL(1, msg->publish_id,
                NAN_REQ_ATTR_PUBLISH_ID, request, result, "publishCancel:Failed to put msg->publish_id");

        request.attr_end(data);
        result = requestResponse(request);
        if (result != WIFI_SUCCESS) {
            ALOGE("failed to publishCancel; result = %d", result);
        } else {
            ALOGD("publishCancel...success");
        }
        return result;

    }

    int subscribe(NanSubscribeRequest *msg) {
        ALOGD("subscribe...");
        WifiRequest request(familyId(), ifaceId());

        int result = request.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_NAN_SUBSCRIBE);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "subscribe:Failed to create WifiRequest");

        nlattr *data = request.attr_start(NL80211_ATTR_VENDOR_DATA);
        if (!data) {
            ALOGE("subscribe: request.attr_start fail");
            return WIFI_ERROR_OUT_OF_MEMORY;
        }

        CHECK_CONFIG_PUT_16_RETURN_FAIL(msg->subscribe_id, msg->subscribe_id,
                NAN_REQ_ATTR_SUBSCRIBE_ID, request, result, "subscribe:Failed to put msg->publish_id");

        CHECK_CONFIG_PUT_16_RETURN_FAIL(1, msg->ttl,
                NAN_REQ_ATTR_SUBSCRIBE_TTL, request, result, "subscribe:Failed to put msg->ttl");

        CHECK_CONFIG_PUT_16_RETURN_FAIL(1, msg->period,
                NAN_REQ_ATTR_SUBSCRIBE_PERIOD, request, result, "subscribe:Failed to put msg->period");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(1, msg->subscribe_type,
                NAN_REQ_ATTR_SUBSCRIBE_TYPE, request, result, "subscribe:Failed to put msg->subscribe_type");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(1, msg->serviceResponseFilter,
                NAN_REQ_ATTR_SUBSCRIBE_RESP_FILTER_TYPE, request, result, "subscribe:Failed to put msg->serviceResponseFilter");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(1, msg->serviceResponseInclude,
                NAN_REQ_ATTR_SUBSCRIBE_RESP_INCLUDE, request, result, "subscribe:Failed to put msg->serviceResponseInclude");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(1, msg->useServiceResponseFilter,
                NAN_REQ_ATTR_SUBSCRIBE_USE_RESP_FILTER, request, result, "subscribe:Failed to put msg->useServiceResponseFilter");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(1, msg->ssiRequiredForMatchIndication,
                NAN_REQ_ATTR_SUBSCRIBE_SSI_REQUIRED, request, result, "subscribe:Failed to put msg->ssiRequiredForMatchIndication");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(1, msg->subscribe_match_indicator,
                NAN_REQ_ATTR_SUBSCRIBE_MATCH_INDICATOR, request, result, "subscribe:Failed to put msg->subscribe_match_indicator");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(1, msg->subscribe_count,
                NAN_REQ_ATTR_SUBSCRIBE_COUNT, request, result, "subscribe:Failed to put msg->subscribe_count");

        CHECK_CONFIG_PUT_16_RETURN_FAIL(msg->service_name_len, msg->service_name_len,
                NAN_REQ_ATTR_SUBSCRIBE_SERVICE_NAME_LEN, request, result, "subscribe:Failed to put msg->service_name_len");

        CHECK_CONFIG_PUT_RETURN_FAIL(msg->service_name_len, msg->service_name, msg->service_name_len,
                NAN_REQ_ATTR_SUBSCRIBE_SERVICE_NAME, request, result, "subscribe:Failed to put msg->service_name");

        CHECK_CONFIG_PUT_16_RETURN_FAIL(msg->service_specific_info_len, msg->service_specific_info_len,
                NAN_REQ_ATTR_SUBSCRIBE_SERVICE_INFO_LEN, request, result, "subscribe:Failed to put msg->service_specific_info_len");

        CHECK_CONFIG_PUT_RETURN_FAIL(msg->service_specific_info_len, msg->service_specific_info, msg->service_specific_info_len,
                NAN_REQ_ATTR_SUBSCRIBE_SERVICE_INFO, request, result, "subscribe:Failed to put msg->service_specific_info");

        CHECK_CONFIG_PUT_16_RETURN_FAIL(msg->rx_match_filter_len, msg->rx_match_filter_len,
                NAN_REQ_ATTR_SUBSCRIBE_RX_MATCH_FILTER_LEN, request, result, "subscribe:Failed to put msg->rx_match_filter_len");

        CHECK_CONFIG_PUT_RETURN_FAIL(msg->rx_match_filter_len, msg->rx_match_filter, msg->rx_match_filter_len,
                NAN_REQ_ATTR_SUBSCRIBE_RX_MATCH_FILTER, request, result, "subscribe:Failed to put msg->rx_match_filter");

        CHECK_CONFIG_PUT_16_RETURN_FAIL(msg->tx_match_filter_len, msg->tx_match_filter_len,
                NAN_REQ_ATTR_SUBSCRIBE_TX_MATCH_FILTER_LEN, request, result, "subscribe:Failed to put msg->tx_match_filter_len");

        CHECK_CONFIG_PUT_RETURN_FAIL(msg->tx_match_filter_len, msg->tx_match_filter, msg->tx_match_filter_len,
                NAN_REQ_ATTR_SUBSCRIBE_TX_MATCH_FILTER, request, result, "subscribe:Failed to put msg->tx_match_filter");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(1, msg->rssi_threshold_flag,
                NAN_REQ_ATTR_SUBSCRIBE_RSSI_THRESHOLD_FLAG, request, result, "subscribe:Failed to put msg->rssi_threshold_flag");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(1, msg->connmap,
                NAN_REQ_ATTR_SUBSCRIBE_CONN_MAP, request, result, "subscribe:Failed to put msg->connmap");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(msg->num_intf_addr_present, msg->num_intf_addr_present,
                NAN_REQ_ATTR_SUBSCRIBE_NUM_INTF_ADDR_PRESENT, request, result, "subscribe:Failed to put msg->num_intf_addr_present");

        CHECK_CONFIG_PUT_RETURN_FAIL(msg->num_intf_addr_present, msg->intf_addr, NAN_MAC_ADDR_LEN * msg->num_intf_addr_present,
                NAN_REQ_ATTR_SUBSCRIBE_INTF_ADDR, request, result, "subscribe:Failed to put msg->intf_addr");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(1, msg->recv_indication_cfg,
                NAN_REQ_ATTR_SUBSCRIBE_RECV_IND_CFG, request, result, "subscribe:Failed to put msg->recv_indication_cfg");

        request.attr_end(data);
        result = requestResponse(request);
        if (result != WIFI_SUCCESS) {
            ALOGE("failed to subscribe; result = %d", result);
        } else {
            ALOGD("subscribe...success");
        }
        return result;

    }

    int subscribeCancel(NanSubscribeCancelRequest *msg) {
        ALOGD("subscribeCancel...");
        WifiRequest request(familyId(), ifaceId());

        int result = request.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_NAN_SUBSCRIBECANCEL);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "subscribeCancel:Failed to create WifiRequest");

        nlattr *data = request.attr_start(NL80211_ATTR_VENDOR_DATA);
        if (!data) {
            ALOGE("subscribeCancel: request.attr_start fail");
            return WIFI_ERROR_OUT_OF_MEMORY;
        }

        CHECK_CONFIG_PUT_16_RETURN_FAIL(1, msg->subscribe_id,
                NAN_REQ_ATTR_SUBSCRIBE_ID, request, result, "subscribeCancel:Failed to put msg->subscribe_id");

        request.attr_end(data);
        result = requestResponse(request);
        if (result != WIFI_SUCCESS) {
            ALOGE("failed to subscribeCancel; result = %d", result);
        } else {
            ALOGD("subscribeCancel...success");
        }
        return result;
    }

    int followup(NanTransmitFollowupRequest *msg) {
        ALOGD("followup...");
        WifiRequest request(familyId(), ifaceId());

        int result = request.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_NAN_TXFOLLOWUP);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "followup:Failed to create WifiRequest");

        nlattr *data = request.attr_start(NL80211_ATTR_VENDOR_DATA);
        if (!data) {
            ALOGE("followup: request.attr_start fail");
            return WIFI_ERROR_OUT_OF_MEMORY;
        }

        CHECK_CONFIG_PUT_16_RETURN_FAIL(1, msg->publish_subscribe_id,
                NAN_REQ_ATTR_FOLLOWUP_ID, request, result, "followup:Failed to put msg->publish_subscribe_id");

        CHECK_CONFIG_PUT_32_RETURN_FAIL(1, msg->requestor_instance_id,
                NAN_REQ_ATTR_FOLLOWUP_REQUESTOR_ID, request, result, "followup:Failed to put msg->requestor_instance_id");

        CHECK_CONFIG_PUT_RETURN_FAIL(1, msg->addr, NAN_MAC_ADDR_LEN,
            NAN_REQ_ATTR_FOLLOWUP_ADDR, request, result, "followup:Failed to put msg->addr");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(1, msg->priority,
            NAN_REQ_ATTR_FOLLOWUP_PRIORITY, request, result, "followup:Failed to put msg->priority");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(1, msg->dw_or_faw,
            NAN_REQ_ATTR_FOLLOWUP_TX_WINDOW, request, result, "followup:Failed to put msg->dw_or_faw");

        CHECK_CONFIG_PUT_16_RETURN_FAIL(msg->service_specific_info_len, msg->service_specific_info_len,
            NAN_REQ_ATTR_FOLLOWUP_SERVICE_NAME_LEN, request, result, "followup:Failed to put msg->service_specific_info_len");

        CHECK_CONFIG_PUT_RETURN_FAIL(msg->service_specific_info_len, msg->service_specific_info, msg->service_specific_info_len,
            NAN_REQ_ATTR_FOLLOWUP_SERVICE_NAME, request, result, "followup:Failed to put msg->service_specific_info");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(1, msg->recv_indication_cfg,
            NAN_REQ_ATTR_FOLLOWUP_RECV_IND_CFG, request, result, "followup:Failed to put msg->recv_indication_cfg");

        request.attr_end(data);
        result = requestResponse(request);
        if (result != WIFI_SUCCESS) {
            ALOGE("failed to followup; result = %d", result);
        } else {
            ALOGD("followup...success");
        }
        return result;

    }

    int getCapabilities(void) {
        ALOGD("getCapabilities...");
        WifiRequest request(familyId(), ifaceId());

        int result = request.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_NAN_CAPABILITIES);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "getCapabilities:Failed to create WifiRequest");

        result = requestResponse(request);
        if (result != WIFI_SUCCESS) {
            ALOGE("failed to getCapabilities; result = %d", result);
        } else {
            ALOGD("getCapabilities...success");
        }
        return result;
    }

    int handleEvent(WifiEvent &event) {
        int ret;
        ALOGD("handleEvent...");

        if (event.get_cmd() != NL80211_CMD_VENDOR) {
            ALOGD("Ignoring event with cmd = %d", event.get_cmd());
            return NL_SKIP;
        }

        int id = event.get_vendor_id();
        int subcmd = event.get_vendor_subcmd();

        ALOGI("Id = %0x, subcmd = %d", id, subcmd);

        switch(subcmd) {
        case SLSI_NAN_EVENT_MATCH:
            ret = processMatchEvent(event);
            break;
        case SLSI_NAN_EVENT_MATCH_EXPIRED:
            ret = processMatchExpiredEvent(event);
            break;
        case SLSI_NAN_EVENT_PUBLISH_TERMINATED:
            ret = processPublishTerminatedEvent(event);
            break;
        case SLSI_NAN_EVENT_SUBSCRIBE_TERMINATED:
            ret = processSubscribeTerminatedEvent(event);
            break;
        case SLSI_NAN_EVENT_FOLLOWUP:
            ret = processFollowupEvent(event);
            break;
        case SLSI_NAN_EVENT_DISABLED:
            ret = processNanDisabledEvent(event);
            break;
        case SLSI_NAN_EVENT_DISCOVERY_ENGINE:
            ret = processNanDiscoveryEvent(event);
            break;

        }

        return NL_OK;
    }

    int handleResponse(WifiEvent &reply) {
        ALOGD("handleResponse...");

        if (reply.get_cmd() != NL80211_CMD_VENDOR) {
            ALOGD("Ignoring reply with cmd = %d", reply.get_cmd());
            return NL_SKIP;
        }

        int vendorId = reply.get_vendor_id();
        int subcmd = reply.get_vendor_subcmd();

        ALOGI("Id = %0x, subcmd = %d", vendorId, subcmd);

        NanResponseMsg response;
        memset(&response, 0, sizeof(response));

        if (processResponse(reply, &response) == NL_SKIP)
            return NL_SKIP;

        if (callbackEventHandler.NotifyResponse)
            callbackEventHandler.NotifyResponse(id(), &response);
        return NL_OK;
    }
};

NanCallbackHandler NanCommand::callbackEventHandler;

NanCommand *nan_get_object(transaction_id id,
                              wifi_interface_handle iface) {
    wifi_handle handle = getWifiHandle(iface);
    NanCommand *nanRequest = (NanCommand *)wifi_get_cmd(handle, id);
    if (!nanRequest) {
        nanRequest = new NanCommand(iface, id);
        if (!nanRequest){
            ALOGE("Could not alloc NanCommand");
            return NULL;
        }
    }
    return nanRequest;
}

wifi_error nan_enable_request(transaction_id id,
                              wifi_interface_handle iface,
                              NanEnableRequest *msg) {
    wifi_handle handle = getWifiHandle(iface);
    wifi_error ret;

    NanCommand *nanRequest = new NanCommand(iface, id);
    if (!nanRequest) {
        ALOGE("nan_enable_request:: Unable to create NanCommand");
        return WIFI_ERROR_OUT_OF_MEMORY;
    }

    wifi_register_cmd(handle, id, nanRequest);
    ret = (wifi_error)nanRequest->enable(msg);
    if (ret != WIFI_SUCCESS) {
        wifi_unregister_cmd(handle, id);
        delete nanRequest;
    }
    return ret;
}

/*  Disable NAN functionality. */
wifi_error nan_disable_request(transaction_id id, wifi_interface_handle iface) {
    NanCommand *nanRequest = nan_get_object(id, iface);
    wifi_error ret;

    if (!nanRequest) {
        return WIFI_ERROR_OUT_OF_MEMORY;
    }
    ret = (wifi_error)nanRequest->disable();
    delete nanRequest;
    return ret;
}

/*  Publish request to advertize a service. */
wifi_error nan_publish_request(transaction_id id,
                               wifi_interface_handle iface,
                               NanPublishRequest *msg) {
    NanCommand *nanRequest = nan_get_object(id, iface);
    if (!nanRequest) {
        return WIFI_ERROR_OUT_OF_MEMORY;
    }
    return (wifi_error)nanRequest->publish(msg);
}

/*  Cancel previous publish requests. */
wifi_error nan_publish_cancel_request(transaction_id id,
                                      wifi_interface_handle iface,
                                      NanPublishCancelRequest *msg) {
    NanCommand *nanRequest = nan_get_object(id, iface);
    if (!nanRequest) {
        return WIFI_ERROR_OUT_OF_MEMORY;
    }
    return (wifi_error)nanRequest->publishCancel(msg);
}

/*  Subscribe request to search for a service. */
wifi_error nan_subscribe_request(transaction_id id,
                                 wifi_interface_handle iface,
                                 NanSubscribeRequest *msg) {
    NanCommand *nanRequest = nan_get_object(id, iface);
    if (!nanRequest) {
        return WIFI_ERROR_OUT_OF_MEMORY;
    }
    return (wifi_error)nanRequest->subscribe(msg);
}

/*  Cancel previous subscribe requests. */
wifi_error nan_subscribe_cancel_request(transaction_id id,
                                        wifi_interface_handle iface,
                                        NanSubscribeCancelRequest *msg) {
    NanCommand *nanRequest = nan_get_object(id, iface);
    if (!nanRequest) {
        return WIFI_ERROR_OUT_OF_MEMORY;
    }
    return (wifi_error)nanRequest->subscribeCancel(msg);
}

/*  NAN transmit follow up request. */
wifi_error nan_transmit_followup_request(transaction_id id,
                                         wifi_interface_handle iface,
                                         NanTransmitFollowupRequest *msg) {
    NanCommand *nanRequest = nan_get_object(id, iface);
    if (!nanRequest) {
        return WIFI_ERROR_OUT_OF_MEMORY;
    }
    return (wifi_error)nanRequest->followup(msg);
}

/* NAN configuration request. */
wifi_error nan_config_request(transaction_id id,
                              wifi_interface_handle iface,
                              NanConfigRequest *msg) {
    NanCommand *nanRequest = nan_get_object(id, iface);
    if (!nanRequest) {
        return WIFI_ERROR_OUT_OF_MEMORY;
    }
    return (wifi_error)nanRequest->config(msg);
}

/* Register NAN callbacks. */
wifi_error nan_register_handler(wifi_interface_handle iface,
                                NanCallbackHandler handlers) {
    return (wifi_error)NanCommand::setCallbackHandler(handlers);
}

/*  Get NAN HAL version. */
wifi_error nan_get_version(wifi_handle handle,
                           NanVersion *version) {
    return (wifi_error)NanCommand::getVersion(version);
}

/*  Get NAN capabilities. */
wifi_error nan_get_capabilities(transaction_id id,
                                wifi_interface_handle iface) {
    NanCommand *nanRequest = nan_get_object(id, iface);
    if (!nanRequest) {
        return WIFI_ERROR_OUT_OF_MEMORY;
    }
    return (wifi_error)nanRequest->getCapabilities();
}

