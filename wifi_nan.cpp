
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
#include "nan_data.h"
#include "nan_common.h"

#define SLSI_WIFI_HAL_NAN_VERSION 1

class NanCommand : public WifiCommand {
    static NanCallbackHandler callbackEventHandler;
    int subscribeID[2];
    int publishID[2];
    int followupID[2];
    int version;
    NanCapabilities capabilities;
    NanDataCommand  datacmd;

    void registerNanEvents(void) {
        registerVendorHandler(GOOGLE_OUI, SLSI_NAN_EVENT_PUBLISH_TERMINATED);
        registerVendorHandler(GOOGLE_OUI, SLSI_NAN_EVENT_MATCH);
        registerVendorHandler(GOOGLE_OUI, SLSI_NAN_EVENT_MATCH_EXPIRED);
        registerVendorHandler(GOOGLE_OUI, SLSI_NAN_EVENT_SUBSCRIBE_TERMINATED);
        registerVendorHandler(GOOGLE_OUI, SLSI_NAN_EVENT_FOLLOWUP);
        registerVendorHandler(GOOGLE_OUI, SLSI_NAN_EVENT_DISCOVERY_ENGINE);
        registerVendorHandler(GOOGLE_OUI, SLSI_NAN_EVENT_TRANSMIT_FOLLOWUP_STATUS);
        registerVendorHandler(GOOGLE_OUI, SLSI_NAN_EVENT_NDP_REQ);
        registerVendorHandler(GOOGLE_OUI, SLSI_NAN_EVENT_NDP_CFM);
        registerVendorHandler(GOOGLE_OUI, SLSI_NAN_EVENT_NDP_END);
    }

    void unregisterNanEvents(void) {
        unregisterVendorHandler(GOOGLE_OUI, SLSI_NAN_EVENT_PUBLISH_TERMINATED);
        unregisterVendorHandler(GOOGLE_OUI, SLSI_NAN_EVENT_MATCH);
        unregisterVendorHandler(GOOGLE_OUI, SLSI_NAN_EVENT_MATCH_EXPIRED);
        unregisterVendorHandler(GOOGLE_OUI, SLSI_NAN_EVENT_SUBSCRIBE_TERMINATED);
        unregisterVendorHandler(GOOGLE_OUI, SLSI_NAN_EVENT_FOLLOWUP);
        unregisterVendorHandler(GOOGLE_OUI, SLSI_NAN_EVENT_DISCOVERY_ENGINE);
        unregisterVendorHandler(GOOGLE_OUI, SLSI_NAN_EVENT_TRANSMIT_FOLLOWUP_STATUS);
        unregisterVendorHandler(GOOGLE_OUI, SLSI_NAN_EVENT_NDP_REQ);
        unregisterVendorHandler(GOOGLE_OUI, SLSI_NAN_EVENT_NDP_CFM);
        unregisterVendorHandler(GOOGLE_OUI, SLSI_NAN_EVENT_NDP_END);
    }

    static const u8 *getEventName(int event) {
        switch(event) {
        case SLSI_NAN_EVENT_RESPONSE:
            return (const u8 *)"SLSI_NAN_EVENT_RESPONSE";
        case SLSI_NAN_EVENT_PUBLISH_TERMINATED:
            return (const u8 *)"SLSI_NAN_EVENT_PUBLISH_TERMINATED";
        case SLSI_NAN_EVENT_MATCH:
            return (const u8 *)"SLSI_NAN_EVENT_MATCH";
        case SLSI_NAN_EVENT_MATCH_EXPIRED:
            return (const u8 *)"SLSI_NAN_EVENT_MATCH_EXPIRED";
        case SLSI_NAN_EVENT_SUBSCRIBE_TERMINATED:
            return (const u8 *)"SLSI_NAN_EVENT_SUBSCRIBE_TERMINATED";
        case SLSI_NAN_EVENT_FOLLOWUP:
            return (const u8 *)"SLSI_NAN_EVENT_FOLLOWUP";
        case SLSI_NAN_EVENT_DISCOVERY_ENGINE:
            return (const u8 *)"SLSI_NAN_EVENT_DISCOVERY_ENGINE";
        case SLSI_NAN_EVENT_DISABLED:
            return (const u8 *)"SLSI_NAN_EVENT_DISABLED";
        case SLSI_NAN_EVENT_TRANSMIT_FOLLOWUP_STATUS:
            return (const u8 *)"SLSI_NAN_EVENT_TRANSMIT_FOLLOWUP_STATUS";
        case SLSI_NAN_EVENT_NDP_REQ:
            return (const u8 *)"SLSI_NAN_EVENT_NDP_REQ";
        case SLSI_NAN_EVENT_NDP_CFM:
            return (const u8 *)"SLSI_NAN_EVENT_NDP_CFM";
        case SLSI_NAN_EVENT_NDP_END:
            return (const u8 *)"SLSI_NAN_EVENT_NDP_END";
        default:
            return (const u8 *)"UNKNOWN event";
        }
        return (const u8 *)"UNKNOWN event";
    }

    int processResponse(WifiEvent &reply, NanResponseMsg *response) {
        NanCapabilities *capabilities = &response->body.nan_capabilities;
        nlattr *vendor_data = reply.get_attribute(NL80211_ATTR_VENDOR_DATA);
        unsigned int val;
        transaction_id id = 0;

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
            case NAN_REPLY_ATTR_NDP_INSTANCE_ID:
                response->body.data_request_response.ndp_instance_id = nl_itr.get_u32();
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

            case NAN_REPLY_ATTR_CAP_MAX_QUEUED_TRANSMIT_FOLLOWUP_MGS:
                capabilities->max_queued_transmit_followup_msgs = nl_itr.get_u32();
                break;
            case NAN_REPLY_ATTR_CAP_MAX_NDP_SUPPORTED_BANDS:
                capabilities->ndp_supported_bands = nl_itr.get_u32();
                break;
            case NAN_REPLY_ATTR_CAP_MAX_CIPHER_SUITES_SUPPORTED:
                capabilities->cipher_suites_supported = nl_itr.get_u32();
                break;
            case NAN_REPLY_ATTR_CAP_MAX_SCID_LEN:
                capabilities->max_scid_len = nl_itr.get_u32();
                break;
            case NAN_REPLY_ATTR_CAP_NDP_SECURITY_SUPPORTED:
                capabilities->is_ndp_security_supported = (bool)nl_itr.get_u32();
                break;
            case NAN_REPLY_ATTR_CAP_MAX_SDEA_SERVICE_SPECIFIC_INFO_LEN:
                capabilities->max_sdea_service_specific_info_len = nl_itr.get_u32();
                break;
            case NAN_REPLY_ATTR_CAP_MAX_SUBSCRIBE_ADDRESS:
                capabilities->max_subscribe_address = nl_itr.get_u32();
                break;
            case NAN_REPLY_ATTR_CAP_NDPE_ATTR_SUPPORTED:
                capabilities->ndpe_attr_supported = nl_itr.get_u32();
                break;
            case NAN_REPLY_ATTR_HAL_TRANSACTION_ID:
                id = nl_itr.get_u16();
                break;
            default :
                ALOGE("received unknown type(%d) in response", nl_itr.get_type());
                return -1;
            }
        }
        this->capabilities = *capabilities;
        return id;
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
                break;
            case NAN_EVT_ATTR_MATCH_CLUSTER_ATTRIBUTE_LEN:
                ind.cluster_attribute_len = nl_itr.get_u8();
                break;
            case NAN_EVT_ATTR_MATCH_CLUSTER_ATTRIBUTE:
                memcpy(ind.cluster_attribute, nl_itr.get_data(), ind.cluster_attribute_len);
                break;
            case NAN_EVT_ATTR_SDEA_LEN:
                ind.sdea_service_specific_info_len = nl_itr.get_u16();
                break;
            case NAN_EVT_ATTR_SDEA:
                memcpy(ind.sdea_service_specific_info, nl_itr.get_data(), ind.sdea_service_specific_info_len);
                break;
            case NAN_EVT_ATTR_SCID_LEN:
                ind.scid_len = nl_itr.get_u32();
                break;
            case NAN_EVT_ATTR_SCID:
                memcpy(ind.scid, nl_itr.get_data(), ind.scid_len);
                break;
            case NAN_EVT_ATTR_SDEA_PARAM_CONFIG_NAN_DATA_PATH:
                ind.peer_sdea_params.config_nan_data_path = nl_itr.get_u8();
                break;
            case NAN_EVT_ATTR_SDEA_PARAM_NDP_TYPE:
                ind.peer_sdea_params.ndp_type = (NdpType)nl_itr.get_u8();
                break;
            case NAN_EVT_ATTR_SDEA_PARAM_SECURITY_CONFIG:
                ind.peer_sdea_params.security_cfg = (NanDataPathSecurityCfgStatus)nl_itr.get_u8();
                break;
            case NAN_EVT_ATTR_SDEA_PARAM_RANGE_STATE:
                ind.peer_sdea_params.ranging_state = (NanRangingState)nl_itr.get_u8();
                break;
            case NAN_EVT_ATTR_SDEA_PARAM_RANGE_REPORT:
                ind.peer_sdea_params.range_report = (NanRangeReport)nl_itr.get_u8();
                break;
            case NAN_EVT_ATTR_SDEA_PARAM_QOS_CFG:
                ind.peer_sdea_params.qos_cfg = (NanQosCfgStatus)nl_itr.get_u8();
                break;
            case NAN_EVT_ATTR_RANGE_MEASUREMENT_MM:
                ind.range_info.range_measurement_mm = nl_itr.get_u32();
                break;
            case NAN_EVT_ATTR_RANGEING_EVENT_TYPE:
                ind.range_info.ranging_event_type = nl_itr.get_u32();
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
        nlattr *vendor_data = event.get_attribute(NL80211_ATTR_VENDOR_DATA);
        memset(&ind,0,sizeof(ind));

        for(nl_iterator nl_itr(vendor_data); nl_itr.has_next(); nl_itr.next()) {
            switch(nl_itr.get_type()) {
            case NAN_EVT_ATTR_PUBLISH_ID:
                ind.publish_id = nl_itr.get_u16();
                break;
            case NAN_EVT_ATTR_PUBLISH_REASON:
                ind.reason = (NanStatusType)nl_itr.get_u32();
                break;
            case NAN_EVT_ATTR_STATUS:
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
        nlattr *vendor_data = event.get_attribute(NL80211_ATTR_VENDOR_DATA);
        memset(&ind,0,sizeof(ind));

        for(nl_iterator nl_itr(vendor_data); nl_itr.has_next(); nl_itr.next()) {
            switch(nl_itr.get_type()) {
            case NAN_EVT_ATTR_SUBSCRIBE_ID:
                ind.subscribe_id = nl_itr.get_u16();
                break;
            case NAN_EVT_ATTR_SUBSCRIBE_REASON:
                ind.reason = (NanStatusType)nl_itr.get_u32();
                break;
            case NAN_EVT_ATTR_STATUS:
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
        nlattr *vendor_data = event.get_attribute(NL80211_ATTR_VENDOR_DATA);
        memset(&ind,0,sizeof(ind));

        for(nl_iterator nl_itr(vendor_data); nl_itr.has_next(); nl_itr.next()) {
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
            case NAN_EVT_ATTR_SDEA_LEN:
                ind.sdea_service_specific_info_len = nl_itr.get_u16();
                break;
            case NAN_EVT_ATTR_SDEA:
                memcpy(ind.sdea_service_specific_info, nl_itr.get_data(), ind.sdea_service_specific_info_len);
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
        nlattr *vendor_data = event.get_attribute(NL80211_ATTR_VENDOR_DATA);
        for(nl_iterator nl_itr(vendor_data); nl_itr.has_next(); nl_itr.next()) {
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
        nlattr *vendor_data = event.get_attribute(NL80211_ATTR_VENDOR_DATA);
        for(nl_iterator nl_itr(vendor_data); nl_itr.has_next(); nl_itr.next()) {
            switch(nl_itr.get_type()) {
            case NAN_EVT_ATTR_DISCOVERY_ENGINE_EVT_TYPE:
                ind.event_type = (NanDiscEngEventType)nl_itr.get_u16();
                break;
            case NAN_EVT_ATTR_DISCOVERY_ENGINE_MAC_ADDR:
                addr = (u8 *)nl_itr.get_data();
                break;
            case NAN_EVT_ATTR_STATUS:
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

    int processNanFollowupStatus(WifiEvent &event) {
        NanTransmitFollowupInd ind;
        memset(&ind,0,sizeof(ind));
        nlattr *vendor_data = event.get_attribute(NL80211_ATTR_VENDOR_DATA);
        for(nl_iterator nl_itr(vendor_data); nl_itr.has_next(); nl_itr.next()) {
            if (nl_itr.get_type() == NAN_EVT_ATTR_STATUS) {
                ind.reason = (NanStatusType)nl_itr.get_u16();
            } else if(nl_itr.get_type() == NAN_EVT_ATTR_HAL_TRANSACTION_ID) {
                ind.id = nl_itr.get_u16();
            }else {
                ALOGE("processNanFollowupStatus: unknown attribute(%d)", nl_itr.get_type());
                return NL_SKIP;
            }
        }

        if (callbackEventHandler.EventTransmitFollowup)
            callbackEventHandler.EventTransmitFollowup(&ind);

        return NL_OK;
    }

    int putSdeaParams(NanSdeaCtrlParams *sdea_params, WifiRequest *request)
    {
        int result;

        if (!sdea_params->config_nan_data_path)
            return 0;

        result = request->put_u8(NAN_REQ_ATTR_SDEA_PARAM_NDP_TYPE, sdea_params->ndp_type);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "enable:Failed to put SDEA PARAM ndp_type");

        result = request->put_u8(NAN_REQ_ATTR_SDEA_PARAM_SECURITY_CFG, sdea_params->security_cfg);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "enable:Failed to put SDEA PARAM security_cfg");

        result = request->put_u8(NAN_REQ_ATTR_SDEA_PARAM_RANGING_STATE, sdea_params->ranging_state);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "enable:Failed to put SDEA PARAM ranging_state");

        result = request->put_u8(NAN_REQ_ATTR_SDEA_PARAM_RANGE_REPORT, sdea_params->range_report);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "enable:Failed to put SDEA PARAM range_report");

        result = request->put_u8(NAN_REQ_ATTR_SDEA_PARAM_QOS_CFG, sdea_params->qos_cfg);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "enable:Failed to put SDEA PARAM qos_cfg");

        return result;
    }

    int putRangingCfg(NanRangingCfg *ranging_cfg, WifiRequest *request)
    {
        int result;

        result = request->put_u32(NAN_REQ_ATTR_RANGING_CFG_INTERVAL, ranging_cfg->ranging_interval_msec);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "enable:Failed to put Ranging CFG ranging_interval_msec");

        result = request->put_u32(NAN_REQ_ATTR_RANGING_CFG_INDICATION, ranging_cfg->config_ranging_indications);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "enable:Failed to put Ranging CFG config_ranging_indications");

        result = request->put_u32(NAN_REQ_ATTR_RANGING_CFG_INGRESS_MM, ranging_cfg->distance_ingress_mm);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "enable:Failed to put Ranging CFG distance_ingress_mm");

        result = request->put_u32(NAN_REQ_ATTR_RANGING_CFG_EGRESS_MM, ranging_cfg->distance_egress_mm);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "enable:Failed to put Ranging CFG distance_egress_mm");

        return result;
    }

    int putRangeResponseCfg(NanRangeResponseCfg *range_resp_cfg, WifiRequest *request)
    {
        int result;

        result = request->put_u16(NAN_REQ_ATTR_RANGE_RESPONSE_CFG_PUBLISH_ID, range_resp_cfg->publish_id);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "Failed to put range response cfg::publish_id");

        result = request->put_u32(NAN_REQ_ATTR_RANGE_RESPONSE_CFG_REQUESTOR_ID, range_resp_cfg->requestor_instance_id);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "Failed to put range response cfg::requestor_instance_id");

        result = request->put_addr(NAN_REQ_ATTR_RANGE_RESPONSE_CFG_PEER_ADDR, range_resp_cfg->peer_addr);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "Failed to put range response cfg::peer_addr");

        result = request->put_u16(NAN_REQ_ATTR_RANGE_RESPONSE_CFG_RANGING_RESPONSE, range_resp_cfg->ranging_response);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "Failed to put range response cfg::ranging_response");

        return result;
    }

public:
    NanCommand(wifi_interface_handle iface, int id)
        : WifiCommand(iface, id), datacmd()
    {
        subscribeID[0] = 0;
        subscribeID[1] = 0;
        publishID[0] = 0;
        publishID[1] = 0;
        followupID[0] = 0;
        followupID[1] = 0;

        version = 0;
        memset(&capabilities, 0, sizeof(capabilities));
    }

    int enable(transaction_id id, NanEnableRequest *msg) {
        ALOGD("NAN enable id:%d", id);
        WifiRequest request(familyId(), ifaceId());

        int result = request.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_NAN_ENABLE);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "enable:Failed to create WifiRequest");

        nlattr *data = request.attr_start(NL80211_ATTR_VENDOR_DATA);
        if (!data) {
            ALOGE("enable: request.attr_start fail");
            return WIFI_ERROR_OUT_OF_MEMORY;
        }
        /* Valid master pref values are 2-254 */
        int master_pref;
        if (msg->master_pref < 2)
            master_pref = 2;
        else if (msg->master_pref > 254)
            master_pref = 254;
        else
            master_pref = msg->master_pref;
        result = request.put_u8(NAN_REQ_ATTR_MASTER_PREF, master_pref);
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

        CHECK_CONFIG_PUT_8_RETURN_FAIL(msg->config_subscribe_sid_beacon, msg->subscribe_sid_beacon_val,
                    NAN_REQ_ATTR_SUBSCRIBE_SID_BEACON_VAL, request, result, "enable:Failed to put subscribe_sid_beacon_val");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(msg->config_dw.config_2dot4g_dw_band, msg->config_dw.dw_2dot4g_interval_val,
                    NAN_REQ_ATTR_DW_2G4_INTERVAL, request, result, "enable:Failed to put dw_2dot4g_interval_val");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(msg->config_dw.config_5g_dw_band, msg->config_dw.dw_5g_interval_val,
                    NAN_REQ_ATTR_DW_5G_INTERVAL, request, result, "enable:Failed to put dw_5g_interval_val");

        CHECK_CONFIG_PUT_32_RETURN_FAIL(msg->config_disc_mac_addr_randomization, msg->disc_mac_addr_rand_interval_sec,
                    NAN_REQ_ATTR_DISC_MAC_ADDR_RANDOM_INTERVAL, request, result, "enable:Failed to put disc_mac_addr_rand_interval_sec");

        CHECK_CONFIG_PUT_32_RETURN_FAIL(msg->config_ndpe_attr, msg->use_ndpe_attr,
                    NAN_REQ_ATTR_USE_NDPE_ATTR, request, result, "enable:Failed to put use_ndpe_attr");

        CHECK_CONFIG_PUT_16_RETURN_FAIL(1, id, NAN_REQ_ATTR_HAL_TRANSACTION_ID, request, result, "enable:Failed to put transaction id");

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

    int disable(transaction_id id)
    {
        ALOGD("NAN disable id:%d", id);
        WifiRequest request(familyId(), ifaceId());

        unregisterNanEvents();

        int result = request.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_NAN_DISABLE);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "disable:Failed to create WifiRequest");

        nlattr *data = request.attr_start(NL80211_ATTR_VENDOR_DATA);
        if (!data) {
            ALOGE("enable: request.attr_start fail");
            return WIFI_ERROR_OUT_OF_MEMORY;
        }
        CHECK_CONFIG_PUT_16_RETURN_FAIL(1, id, NAN_REQ_ATTR_HAL_TRANSACTION_ID, request, result, "disable:Failed to put transaction id");
        request.attr_end(data);
        result = requestResponse(request);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "disable:Failed to requestResponse");
        return result;
    }

    int config(transaction_id id, NanConfigRequest *msg) {
        ALOGD("NAN config id:%d", id);
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

        CHECK_CONFIG_PUT_8_RETURN_FAIL(msg->config_subscribe_sid_beacon, msg->subscribe_sid_beacon_val,
                    NAN_REQ_ATTR_SUBSCRIBE_SID_BEACON_VAL, request, result, "config:Failed to put subscribe_sid_beacon_val");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(msg->config_dw.config_2dot4g_dw_band, msg->config_dw.dw_2dot4g_interval_val,
                    NAN_REQ_ATTR_DW_2G4_INTERVAL, request, result, "config:Failed to put dw_2dot4g_interval_val");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(msg->config_dw.config_5g_dw_band, msg->config_dw.dw_5g_interval_val,
                    NAN_REQ_ATTR_DW_5G_INTERVAL, request, result, "config:Failed to put dw_5g_interval_val");

        CHECK_CONFIG_PUT_8_RETURN_FAIL(msg->config_disc_mac_addr_randomization, msg->disc_mac_addr_rand_interval_sec,
                    NAN_REQ_ATTR_DISC_MAC_ADDR_RANDOM_INTERVAL, request, result, "config:Failed to put disc_mac_addr_rand_interval_sec");

        CHECK_CONFIG_PUT_32_RETURN_FAIL(msg->config_ndpe_attr, msg->use_ndpe_attr,
                    NAN_REQ_ATTR_USE_NDPE_ATTR, request, result, "config:Failed to put use_ndpe_attr");

        CHECK_CONFIG_PUT_16_RETURN_FAIL(1, id, NAN_REQ_ATTR_HAL_TRANSACTION_ID, request, result, "config:Failed to put transaction id");

        request.attr_end(data);
        result = requestResponse(request);
        if (result != WIFI_SUCCESS) {
            ALOGE("failed to set_config; result = %d", result);
        } else {
            ALOGD("NAN config...success");
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

    int publish(transaction_id id, NanPublishRequest *msg) {
        ALOGD("NAN publish transId:%d publishId:%d publishType:%d", id, msg->publish_id, msg->publish_type);
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

        CHECK_CONFIG_PUT_16_RETURN_FAIL(1, msg->sdea_service_specific_info_len,
                NAN_REQ_ATTR_PUBLISH_SDEA_LEN, request, result, "publish:Failed to put msg->sdea_service_specific_info_len");

        CHECK_CONFIG_PUT_RETURN_FAIL(msg->sdea_service_specific_info_len, msg->sdea_service_specific_info, msg->sdea_service_specific_info_len,
                NAN_REQ_ATTR_PUBLISH_SDEA, request, result, "publish:Failed to put msg->sdea_service_specific_info");

        result = request.put_u8(NAN_REQ_ATTR_RANGING_AUTO_RESPONSE, msg->ranging_auto_response);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "publish:Failed to put ranging_auto_response");

        result = putSdeaParams(&msg->sdea_params, &request);
        if (result != 0)
            return result;
        result = putRangingCfg(&msg->ranging_cfg, &request);
        if (result != 0)
            return result;
        result = NanDataCommand::putSecurityInfo(msg->cipher_type, &msg->key_info, msg->scid_len, msg->scid, &request);
        if (result != 0)
            return result;
        result = putRangeResponseCfg(&msg->range_response_cfg, &request);
        if (result != 0)
            return result;

        CHECK_CONFIG_PUT_16_RETURN_FAIL(1, id, NAN_REQ_ATTR_HAL_TRANSACTION_ID, request, result, "publish:Failed to put transaction id");

        request.attr_end(data);
        result = requestResponse(request);
        if (result != WIFI_SUCCESS) {
            ALOGE("failed to publish; result = %d", result);
        } else {
            ALOGD("NAN publish...success");
        }
        return result;
    }

    int publishCancel(transaction_id id, NanPublishCancelRequest *msg) {
        ALOGD("NAN publishCancel transId:%d, publish_id:%d", id, msg->publish_id);
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

        CHECK_CONFIG_PUT_16_RETURN_FAIL(1, id, NAN_REQ_ATTR_HAL_TRANSACTION_ID, request, result, "publishCancel:Failed to put transaction id");

        request.attr_end(data);
        result = requestResponse(request);
        if (result != WIFI_SUCCESS) {
            ALOGE("failed to publishCancel; result = %d", result);
        } else {
            ALOGD("NAN publishCancel...success");
        }
        return result;

    }

    int subscribe(transaction_id id, NanSubscribeRequest *msg) {
        ALOGD("NAN subscribe trans_id:%d subscribe_id:%d subscribetype:%d", id, msg->subscribe_id, msg->subscribe_type);
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

        CHECK_CONFIG_PUT_16_RETURN_FAIL(1, msg->sdea_service_specific_info_len,
                NAN_REQ_ATTR_PUBLISH_SDEA_LEN, request, result, "subscribe:Failed to put msg->sdea_service_specific_info_len");

        CHECK_CONFIG_PUT_RETURN_FAIL(msg->sdea_service_specific_info_len, msg->sdea_service_specific_info, msg->sdea_service_specific_info_len,
                NAN_REQ_ATTR_PUBLISH_SDEA, request, result, "subscribe:Failed to put msg->sdea_service_specific_info");

        result = request.put_u8(NAN_REQ_ATTR_RANGING_AUTO_RESPONSE, msg->ranging_auto_response);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "subscribe:Failed to put ranging_auto_response");

        result = putSdeaParams(&msg->sdea_params, &request);
        if (result != 0)
            return result;
        result = putRangingCfg(&msg->ranging_cfg, &request);
        if (result != 0)
            return result;
        result = NanDataCommand::putSecurityInfo(msg->cipher_type, &msg->key_info, msg->scid_len, msg->scid, &request);
        if (result != 0)
            return result;
        result = putRangeResponseCfg(&msg->range_response_cfg, &request);
        if (result != 0)
            return result;

        CHECK_CONFIG_PUT_16_RETURN_FAIL(1, id, NAN_REQ_ATTR_HAL_TRANSACTION_ID, request, result, "subscribe:Failed to put transaction id");

        request.attr_end(data);
        result = requestResponse(request);
        if (result != WIFI_SUCCESS) {
            ALOGE("failed to subscribe; result = %d", result);
        } else {
            ALOGD("NAN subscribe...success");
        }
        return result;

    }

    int subscribeCancel(transaction_id id, NanSubscribeCancelRequest *msg) {
        ALOGD("NAN subscribeCancel transId:%d subscribeId:%d", id, msg->subscribe_id);
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

        CHECK_CONFIG_PUT_16_RETURN_FAIL(1, id, NAN_REQ_ATTR_HAL_TRANSACTION_ID, request, result, "subscribeCancel:Failed to put transaction id");

        request.attr_end(data);
        result = requestResponse(request);
        if (result != WIFI_SUCCESS) {
            ALOGE("failed to subscribeCancel; result = %d", result);
        } else {
            ALOGD("NAN subscribeCancel...success");
        }
        return result;
    }

    int followup(transaction_id id, NanTransmitFollowupRequest *msg) {
        ALOGD("NAN followup transid:%d pub/subId:%d reqInstId:%d", id, msg->publish_subscribe_id, msg->requestor_instance_id);
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

        CHECK_CONFIG_PUT_16_RETURN_FAIL(1, msg->sdea_service_specific_info_len,
                NAN_REQ_ATTR_PUBLISH_SDEA_LEN, request, result, "publish:Failed to put msg->sdea_service_specific_info_len");

        CHECK_CONFIG_PUT_RETURN_FAIL(msg->sdea_service_specific_info_len, msg->sdea_service_specific_info, msg->sdea_service_specific_info_len,
                NAN_REQ_ATTR_PUBLISH_SDEA, request, result, "publish:Failed to put msg->sdea_service_specific_info");

        CHECK_CONFIG_PUT_16_RETURN_FAIL(1, id, NAN_REQ_ATTR_HAL_TRANSACTION_ID, request, result, "followup:Failed to put transaction id");

        request.attr_end(data);
        result = requestResponse(request);
        if (result != WIFI_SUCCESS) {
            ALOGE("failed to followup; result = %d", result);
        } else {
            ALOGD("NAN followup...success");
        }
        return result;

    }

    int getCapabilities(transaction_id id) {
        ALOGD("NAN getCapabilities transId:%d", id);
        WifiRequest request(familyId(), ifaceId());

        int result = request.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_NAN_CAPABILITIES);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "getCapabilities:Failed to create WifiRequest");

        nlattr *data = request.attr_start(NL80211_ATTR_VENDOR_DATA);
        if (!data) {
            ALOGE("enable: request.attr_start fail");
            return WIFI_ERROR_OUT_OF_MEMORY;
        }
        CHECK_CONFIG_PUT_16_RETURN_FAIL(1, id, NAN_REQ_ATTR_HAL_TRANSACTION_ID, request, result, "getCapabilities:Failed to put transaction id");
        request.attr_end(data);
        result = requestResponse(request);
        if (result != WIFI_SUCCESS) {
            ALOGE("failed to getCapabilities; result = %d", result);
        } else {
            ALOGD("NAN getCapabilities...success");
        }
        return result;
    }

    int handleEvent(WifiEvent &event) {
        int ret;

        if (event.get_cmd() != NL80211_CMD_VENDOR) {
            ALOGD("NAN %s Ignoring event with cmd = %d", __func__, event.get_cmd());
            return NL_SKIP;
        }

        int id = event.get_vendor_id();
        int subcmd = event.get_vendor_subcmd();

        ALOGI("NAN %s Id = 0x%x, subcmd = %s(0x%x)", __func__, id, getEventName(subcmd), subcmd);

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
        case SLSI_NAN_EVENT_TRANSMIT_FOLLOWUP_STATUS:
            ret = processNanFollowupStatus(event);
            break;
        default:
            return datacmd.handleEvent(event, callbackEventHandler);
        }

        return NL_OK;
    }

    int handleResponse(WifiEvent &reply) {
        if (reply.get_cmd() != NL80211_CMD_VENDOR) {
            ALOGD("NAN %s Ignoring reply with cmd = %d", __func__, reply.get_cmd());
            return NL_SKIP;
        }

        NanResponseMsg response;
        memset(&response, 0, sizeof(response));

        transaction_id id = processResponse(reply, &response);
        if ( id < 0)
            return NL_SKIP;

        ALOGD("NAN %s transId:%d status:%d, response:%d", __func__, id, response.status, response.response_type);
        if (callbackEventHandler.NotifyResponse)
            callbackEventHandler.NotifyResponse(id, &response);
        return NL_OK;
    }

    int dataPathReq(u16 id, void *data, int subcmd) {
        int result;
        WifiRequest request(familyId(), ifaceId());

        ALOGI("NAN DATA-PATH req subcmd:%s(0x%x) transaction_id:%d", datacmd.getCmdName(subcmd), subcmd, id);

        result = datacmd.getDataPathNLMsg(id, data, subcmd, request);
        if (result != WIFI_SUCCESS) {
            return result;
        }
        result = requestResponse(request);
        if (result != WIFI_SUCCESS) {
            ALOGE("NAN DATA-PATH req subcmd:%s(0x%x)...failed(%d)", datacmd.getCmdName(subcmd), subcmd, result);
            unregisterNanEvents();
        } else {
            datacmd.requestSuccess(id, data, subcmd);
            ALOGD("NAN DATA-PATH req subcmd:%s(0x%x)...success", datacmd.getCmdName(subcmd), subcmd);
        }
        return result;
    }
};

NanCallbackHandler NanCommand::callbackEventHandler;

NanCommand *nan_get_object(transaction_id id,
                              wifi_interface_handle iface) {
    wifi_handle handle = getWifiHandle(iface);
    NanCommand *nanRequest = (NanCommand *)wifi_get_nan_cmd(handle);
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

    wifi_set_nan_cmd(handle, nanRequest);
    ret = (wifi_error)nanRequest->enable(id, msg);
    if (ret != WIFI_SUCCESS) {
        wifi_reset_nan_cmd(handle);
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
    ret = (wifi_error)nanRequest->disable(id);
    wifi_reset_nan_cmd(getWifiHandle(iface));
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
    return (wifi_error)nanRequest->publish(id, msg);
}

/*  Cancel previous publish requests. */
wifi_error nan_publish_cancel_request(transaction_id id,
                                      wifi_interface_handle iface,
                                      NanPublishCancelRequest *msg) {
    NanCommand *nanRequest = nan_get_object(id, iface);
    if (!nanRequest) {
        return WIFI_ERROR_OUT_OF_MEMORY;
    }
    return (wifi_error)nanRequest->publishCancel(id, msg);
}

/*  Subscribe request to search for a service. */
wifi_error nan_subscribe_request(transaction_id id,
                                 wifi_interface_handle iface,
                                 NanSubscribeRequest *msg) {
    NanCommand *nanRequest = nan_get_object(id, iface);
    if (!nanRequest) {
        return WIFI_ERROR_OUT_OF_MEMORY;
    }
    return (wifi_error)nanRequest->subscribe(id, msg);
}

/*  Cancel previous subscribe requests. */
wifi_error nan_subscribe_cancel_request(transaction_id id,
                                        wifi_interface_handle iface,
                                        NanSubscribeCancelRequest *msg) {
    NanCommand *nanRequest = nan_get_object(id, iface);
    if (!nanRequest) {
        return WIFI_ERROR_OUT_OF_MEMORY;
    }
    return (wifi_error)nanRequest->subscribeCancel(id, msg);
}

/*  NAN transmit follow up request. */
wifi_error nan_transmit_followup_request(transaction_id id,
                                         wifi_interface_handle iface,
                                         NanTransmitFollowupRequest *msg) {
    NanCommand *nanRequest = nan_get_object(id, iface);
    if (!nanRequest) {
        return WIFI_ERROR_OUT_OF_MEMORY;
    }
    return (wifi_error)nanRequest->followup(id, msg);
}

/* NAN configuration request. */
wifi_error nan_config_request(transaction_id id,
                              wifi_interface_handle iface,
                              NanConfigRequest *msg) {
    NanCommand *nanRequest = nan_get_object(id, iface);
    if (!nanRequest) {
        return WIFI_ERROR_OUT_OF_MEMORY;
    }
    return (wifi_error)nanRequest->config(id, msg);
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
    return (wifi_error)nanRequest->getCapabilities(id);
}

wifi_error nan_data_interface_create(transaction_id id,
                                     wifi_interface_handle iface,
                                     char* iface_name) {
    NanCommand *nanRequest = nan_get_object(id, iface);
    if (!nanRequest) {
        return WIFI_ERROR_OUT_OF_MEMORY;
    }
    return (wifi_error)nanRequest->dataPathReq(id, iface_name,
                SLSI_NL80211_VENDOR_SUBCMD_NAN_DATA_INTERFACE_CREATE);
}

wifi_error nan_data_interface_delete(transaction_id id,
                                     wifi_interface_handle iface,
                                     char* iface_name) {
    NanCommand *nanRequest = nan_get_object(id, iface);
    if (!nanRequest) {
        return WIFI_ERROR_OUT_OF_MEMORY;
    }
    return (wifi_error)nanRequest->dataPathReq(id, iface_name,
                SLSI_NL80211_VENDOR_SUBCMD_NAN_DATA_INTERFACE_DELETE);

}

wifi_error nan_data_request_initiator(transaction_id id,
                                      wifi_interface_handle iface,
                                      NanDataPathInitiatorRequest* msg) {
    NanCommand *nanRequest = nan_get_object(id, iface);
    if (!nanRequest) {
        return WIFI_ERROR_OUT_OF_MEMORY;
    }
    return (wifi_error)nanRequest->dataPathReq(id, msg,
                SLSI_NL80211_VENDOR_SUBCMD_NAN_DATA_REQUEST_INITIATOR);

}

wifi_error nan_data_indication_response(transaction_id id,
                                        wifi_interface_handle iface,
                                        NanDataPathIndicationResponse* msg) {
    NanCommand *nanRequest = nan_get_object(id, iface);
    if (!nanRequest) {
        return WIFI_ERROR_OUT_OF_MEMORY;
    }
    return (wifi_error)nanRequest->dataPathReq(id, msg,
                SLSI_NL80211_VENDOR_SUBCMD_NAN_DATA_INDICATION_RESPONSE);

}

wifi_error nan_data_end(transaction_id id,
                        wifi_interface_handle iface,
                        NanDataPathEndRequest* msg) {
    NanCommand *nanRequest = nan_get_object(id, iface);
    if (!nanRequest) {
        return WIFI_ERROR_OUT_OF_MEMORY;
    }
    return (wifi_error)nanRequest->dataPathReq(id, msg,
                SLSI_NL80211_VENDOR_SUBCMD_NAN_DATA_END);

}

