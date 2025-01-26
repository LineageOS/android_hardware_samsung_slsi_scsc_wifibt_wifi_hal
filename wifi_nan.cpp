
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

#include <log/log.h>

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
    u8 mac[NAN_MAC_ADDR_LEN];

    void registerNanEvents(void) {
        ALOGD("Registering NAN events");
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
        registerVendorHandler(SAMSUNG_OUI, SLSI_NL80211_VENDOR_NAN_INTERFACE_CREATED);
        registerVendorHandler(SAMSUNG_OUI, SLSI_NL80211_VENDOR_NAN_INTERFACE_DELETED);
    }

    void unregisterNanEvents(void) {
        ALOGD("Unregistering NAN events");
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
        unregisterVendorHandler(SAMSUNG_OUI, SLSI_NL80211_VENDOR_NAN_INTERFACE_CREATED);
        unregisterVendorHandler(SAMSUNG_OUI, SLSI_NL80211_VENDOR_NAN_INTERFACE_DELETED);
    }

    static const u8 *getResponseName(int resp) {
        switch(resp) {
        case NAN_RESPONSE_ENABLED:
            return (const u8 *)"ENABLED";
        case NAN_RESPONSE_DISABLED:
            return (const u8 *)"DISABLED";
        case NAN_RESPONSE_PUBLISH:
            return (const u8 *)"PUBLISH";
        case NAN_RESPONSE_PUBLISH_CANCEL:
            return (const u8 *)"PUB-CANCEL";
        case NAN_RESPONSE_TRANSMIT_FOLLOWUP:
            return (const u8 *)"TXFOLLOWUP";
        case NAN_RESPONSE_SUBSCRIBE:
            return (const u8 *)"SUB";
        case NAN_RESPONSE_SUBSCRIBE_CANCEL:
            return (const u8 *)"SUB-CANCEL";
        case NAN_RESPONSE_STATS:
            return (const u8 *)"STATS";
        case NAN_RESPONSE_CONFIG:
            return (const u8 *)"CONFIG";
        case NAN_RESPONSE_TCA:
            return (const u8 *)"TCA";
        case NAN_RESPONSE_ERROR:
            return (const u8 *)"ERROR";
        case NAN_RESPONSE_BEACON_SDF_PAYLOAD:
            return (const u8 *)"BEACON_SDF_PAYLOAD";
        case NAN_GET_CAPABILITIES:
            return (const u8 *)"CAPABILITIES";
        case NAN_DP_INTERFACE_CREATE:
            return (const u8 *)"IFCREATE";
        case NAN_DP_INTERFACE_DELETE:
            return (const u8 *)"IFDELETE";
        case NAN_DP_INITIATOR_RESPONSE:
            return (const u8 *)"NDP_INITIATOR";
        case NAN_DP_RESPONDER_RESPONSE:
            return (const u8 *)"NDP_RESPONDER";
        case NAN_DP_END:
            return (const u8 *)"NDP_END";
        default:
            return (const u8 *)"UNKNOWN response";
        }
        return (const u8 *)"UNKNOWN response";
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
                if (response->response_type == NAN_RESPONSE_SUBSCRIBE)
                    response->body.subscribe_response.subscribe_id = nl_itr.get_u16();
                else
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
            case NAN_EVT_ATTR_DISCOVERY_ENGINE_MAC_ADDR:
                memcpy(this->mac, nl_itr.get_data(),NAN_MAC_ADDR_LEN);
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

        ALOGD("[NAN][NA][Match][Ind]:Received[pub_sub_id:%d, requestor_instance_id:%d, addr:%02x:*:*:*:%02x:%02x]\n"
              "[service_specific_info_len:%d, sdfMF_len:%d]\n", ind.publish_subscribe_id, ind.requestor_instance_id,
              ind.addr[0], ind.addr[4], ind.addr[5], ind.service_specific_info_len, ind.sdf_match_filter_len);
        wifi_log_hex_buffer_debug("service_specific_info:", NULL,
                                           ind.service_specific_info, ind.service_specific_info_len);
        wifi_log_hex_buffer_debug("sdf_match_filter:", NULL, ind.sdf_match_filter,
                                           ind.sdf_match_filter_len);
        ALOGD("Continued..[match_occured_flag:%d, out_of_resource_flag:%d, rssi:%d, is_ibss:%d, is_wfd:%d]\n"
              "[is_wfds:%d, is_tdls:%d, is_mesh:%d, wlan_infra_field:%d, num_rx_discovery_attr:%d]\n",
              ind.match_occured_flag, ind.out_of_resource_flag, ind.rssi_value, ind.conn_capability.is_ibss_supported,
              ind.conn_capability.is_wfd_supported, ind.conn_capability.is_wfds_supported, ind.conn_capability.is_tdls_supported,
              ind.conn_capability.is_mesh_supported, ind.conn_capability.wlan_infra_field, ind.num_rx_discovery_attr);
        ALOGD("Continued..[cluster_attribute_len:%d, sdea_service_specific_info_len:%d, scid_len:%d, config_nan_data_path:%d, ndpType:%d]\n"
              "[security_cfg:%d, ranging_state:%d, range_report:%d, qos_cfg:%d, range_measurement_mm:%d, ranging_eventType:%d]\n",
              ind.cluster_attribute_len, ind.sdea_service_specific_info_len, ind.scid_len, ind.peer_sdea_params.config_nan_data_path,
              ind.peer_sdea_params.ndp_type, ind.peer_sdea_params.security_cfg, ind.peer_sdea_params.ranging_state,
              ind.peer_sdea_params.range_report,
              ind.peer_sdea_params.qos_cfg, ind.range_info.range_measurement_mm, ind.range_info.ranging_event_type);
        wifi_log_hex_buffer_debug("sdea_service_specific_info:", NULL,
                                           ind.sdea_service_specific_info, ind.sdea_service_specific_info_len);
        for (int i = 0; i < disc_idx; i++) {
            NanReceivePostDiscovery *disc_attr;
            disc_attr = &ind.discovery_attr[i];
            ALOGD("Discovery_attr[%d]:[type:%d, role:%d, duration:%d, avail_interval_bitmap:%d, mapId:%d, addr:%02x:*:*:*:%02x:%02x]\n"
                  "[meshId_len:%d, meshId:%d%d%d.., infrastructure_ssid_len:%d, infrastructure_ssid:%.*s]\n",
                  i, disc_attr->type, disc_attr->role, disc_attr->duration, disc_attr->avail_interval_bitmap, disc_attr->mapid,
                  disc_attr->addr[0], disc_attr->addr[4], disc_attr->addr[5],
                  disc_attr->mesh_id_len, disc_attr->mesh_id[0], disc_attr->mesh_id[1], disc_attr->mesh_id[2], disc_attr->infrastructure_ssid_len,
                  disc_attr->infrastructure_ssid_len > 20 ? 20 : disc_attr->infrastructure_ssid_len, disc_attr->infrastructure_ssid_val);
        }
        for (int i = 0; i < famchan_idx; i++) {
            NanFurtherAvailabilityChannel *famchan;
            famchan = &ind.famchan[i];
            ALOGD("FAMCHAN_attr[%d]:[entry_control:%d, class:%d, channel:%d, mapId:%d, avail_interval_bitmap:%d]\n",
                  i, famchan->entry_control, famchan->class_val, famchan->channel, famchan->mapid, famchan->avail_interval_bitmap);
        }
        if (this->callbackEventHandler.EventMatch)
            this->callbackEventHandler.EventMatch(&ind);
        return NL_OK;
    }

    int processMatchExpiredEvent(WifiEvent &event) {
        NanMatchExpiredInd ind;
        nlattr *vendor_data = event.get_attribute(NL80211_ATTR_VENDOR_DATA);
        memset(&ind,0,sizeof(NanMatchExpiredInd));

        for(nl_iterator nl_itr(vendor_data); nl_itr.has_next(); nl_itr.next()) {
            switch(nl_itr.get_type()) {
            case NAN_EVT_ATTR_MATCH_PUBLISH_SUBSCRIBE_ID:
                ind.publish_subscribe_id = nl_itr.get_u16();
                break;
            case NAN_EVT_ATTR_MATCH_REQUESTOR_INSTANCE_ID:
                ind.requestor_instance_id = nl_itr.get_u32();
                break;
            default :
                ALOGE("processMatchExpiredEvent: unknown attribute(%d)", nl_itr.get_type());
            }
        }

        ALOGD("[NAN][NA][Match_Expired][Ind]:Received[pub_sub_id:%d, requestor_instance_id:%d]\n", ind.publish_subscribe_id, ind.requestor_instance_id);
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

        ALOGD("[NAN][NA][PUB-TERMINATED][Ind]:Received[publish_id:%d, reason:%d]\n", ind.publish_id, ind.reason);
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

        ALOGD("[NAN][NA][SUB-TERMINATED][Ind]:Received[subscribe_id:%d, reason:%d]\n", ind.subscribe_id, ind.reason);
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

        ALOGD("[NAN][NA][FOLLOWUP][Ind]:Received[pub_sub_id:%d, requestor_instance_id:%d, addr:%02x:*:*:*:%02x:%02x, dw_or_faw:%d]\n"
              "[service_specific_info_len:%d, sdea_service_specific_info_len:%d]\n",
              ind.publish_subscribe_id, ind.requestor_instance_id, ind.addr[0], ind.addr[4], ind.addr[5], ind.dw_or_faw,
              ind.service_specific_info_len, ind.sdea_service_specific_info_len);
        wifi_log_hex_buffer_debug("service_specific_info:", NULL,
                                           ind.service_specific_info, ind.service_specific_info_len);
        wifi_log_hex_buffer_debug("sdea_service_specific_info:", NULL,
                                           ind.sdea_service_specific_info, ind.sdea_service_specific_info_len);
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

        ALOGD("[NAN][NA][DISABLED][Ind]:Received[reason:%d]\n", ind.reason);
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
            if (ind.event_type == NAN_EVENT_ID_DISC_MAC_ADDR) {
                memcpy(ind.data.mac_addr.addr, addr, NAN_MAC_ADDR_LEN);
                memcpy(this->mac, addr, NAN_MAC_ADDR_LEN);
            } else {
                memcpy(ind.data.cluster.addr, addr, NAN_MAC_ADDR_LEN);
            }
        } else {
            ALOGE("processNanDiscoveryEvent: No Mac/cluster Address");
        }
        ALOGD("[NAN][NA][DISCOVERY][Ind]:Received[eventType:%d, Disc_mac_addr:%02x:*:*:*:%02x:%02x, ClusterAddr:%02x:%02x:%02x:%02x:%02x:%02x]\n",
              ind.event_type, ind.data.mac_addr.addr[0], ind.data.mac_addr.addr[4], ind.data.mac_addr.addr[5],
              ind.data.cluster.addr[0], ind.data.cluster.addr[1], ind.data.cluster.addr[2],
              ind.data.cluster.addr[3],ind.data.cluster.addr[4], ind.data.cluster.addr[5]);
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

        ALOGD("[NAN][%d][FOLLOWUP_STATUS][Ind]:Received[reason:%d]\n", ind.id, ind.reason);
        if (callbackEventHandler.EventTransmitFollowup)
            callbackEventHandler.EventTransmitFollowup(&ind);

        return NL_OK;
    }

    int processNanInterfaceDeleted(WifiEvent &event) {
        NanResponseMsg response;
        memset(&response, 0, sizeof(response));
        transaction_id id = 0;

        nlattr *vendor_data = event.get_attribute(NL80211_ATTR_VENDOR_DATA);
        for(nl_iterator nl_itr(vendor_data); nl_itr.has_next(); nl_itr.next()) {
            if (nl_itr.get_type() == NAN_EVT_ATTR_STATUS) {
                response.status = (NanStatusType)nl_itr.get_u16();
            } else if(nl_itr.get_type() == NAN_EVT_ATTR_HAL_TRANSACTION_ID) {
                id = nl_itr.get_u16();
            }else {
                ALOGE("processNanINterfaceDeleted : unknown attribute(%d)", nl_itr.get_type());
                return NL_SKIP;
            }
        }
        response.response_type = NAN_DP_INTERFACE_DELETE;
        ALOGD("[NAN][Interface Deleted]Event]:Received[Status:%d]\n", response.status);
        if (callbackEventHandler.NotifyResponse)
            callbackEventHandler.NotifyResponse(id, &response);

        return NL_OK;
    }

    int processNanInterfaceCreated(WifiEvent &event) {
        NanResponseMsg response;
        memset(&response, 0, sizeof(response));
        transaction_id id = 0;

        nlattr *vendor_data = event.get_attribute(NL80211_ATTR_VENDOR_DATA);
        for(nl_iterator nl_itr(vendor_data); nl_itr.has_next(); nl_itr.next()) {
            if (nl_itr.get_type() == NAN_EVT_ATTR_STATUS) {
                response.status = (NanStatusType)nl_itr.get_u16();
            } else if(nl_itr.get_type() == NAN_EVT_ATTR_HAL_TRANSACTION_ID) {
                id = nl_itr.get_u16();
            }else {
                ALOGE("processNanINterfaceDeleted : unknown attribute(%d)", nl_itr.get_type());
                return NL_SKIP;
            }
        }
        response.response_type = NAN_DP_INTERFACE_CREATE;
        ALOGD("[NAN][Interface Created]Event]:Received[Status:%d]\n", response.status);
        if (callbackEventHandler.NotifyResponse)
            callbackEventHandler.NotifyResponse(id, &response);

        return NL_OK;
    }
    int putSdeaParams(NanSdeaCtrlParams *sdea_params, WifiRequest *request)
    {
        int result;

        if (sdea_params->config_nan_data_path) {
            result = request->put_u8(NAN_REQ_ATTR_SDEA_PARAM_NDP_TYPE, sdea_params->ndp_type);
            CHECK_WIFI_STATUS_RETURN_FAIL(result, "enable:Failed to put SDEA PARAM ndp_type");

            result = request->put_u8(NAN_REQ_ATTR_SDEA_PARAM_SECURITY_CFG, sdea_params->security_cfg);
            CHECK_WIFI_STATUS_RETURN_FAIL(result, "enable:Failed to put SDEA PARAM security_cfg");
        }
        result = request->put_u8(NAN_REQ_ATTR_SDEA_PARAM_RANGING_STATE, sdea_params->ranging_state);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "enable:Failed to put SDEA PARAM ranging_state");

        result = request->put_u8(NAN_REQ_ATTR_SDEA_PARAM_RANGE_REPORT, sdea_params->range_report);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "enable:Failed to put SDEA PARAM range_report");

        result = request->put_u8(NAN_REQ_ATTR_SDEA_PARAM_QOS_CFG, sdea_params->qos_cfg);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "enable:Failed to put SDEA PARAM qos_cfg");

        ALOGD("Send[Sdea Params: ndpType:%d, security_cfg:%d, ranging_state:%d, range_report:%d, qos_cfg:%d]\n",
              sdea_params->ndp_type, sdea_params->security_cfg, sdea_params->ranging_state, sdea_params->range_report, sdea_params->qos_cfg);
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

        ALOGD("Send[Ranging cfg: ranging_interval_msec:%d, config_ranging_indications:%d, distance_ingress_mm:%d, distance_egress_mm:%d]\n",
              ranging_cfg->ranging_interval_msec, ranging_cfg->config_ranging_indications, ranging_cfg->distance_ingress_mm, ranging_cfg->distance_egress_mm);
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

        ALOGD("Send[RangeResponseCfg publish_id:%d, requestor_instance_id:%d, peerAddr:%02x:*:*:*:%02x:%02x, ranging_resp:%d]\n",
              range_resp_cfg->publish_id, range_resp_cfg->requestor_instance_id, range_resp_cfg->peer_addr[0],
              range_resp_cfg->peer_addr[4], range_resp_cfg->peer_addr[5],
              range_resp_cfg->ranging_response);
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
        memset(mac, 0, NAN_MAC_ADDR_LEN);
    }

    int enable(transaction_id id, NanEnableRequest *msg) {
        WifiRequest request(familyId(), ifaceId());

        int result = request.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_NAN_ENABLE);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "enable:Failed to create WifiRequest");

        nlattr *data = request.attr_start(NL80211_ATTR_VENDOR_DATA);
        if (!data) {
            ALOGE("NAN enable: request.attr_start fail");
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
        CHECK_CONFIG_PUT_16_RETURN_FAIL(1, id, NAN_REQ_ATTR_HAL_TRANSACTION_ID, request, result, "enable:Failed to put transaction id");

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

        CHECK_CONFIG_PUT_8_RETURN_FAIL(msg->config_disc_mac_addr_randomization, msg->config_disc_mac_addr_randomization,
                    NAN_REQ_ATTR_CONFIG_DISC_MAC_ADDR_RANDOM, request, result, "enable:Failed to put config_disc_mac_addr_rand_interval_sec");

        CHECK_CONFIG_PUT_32_RETURN_FAIL(msg->config_disc_mac_addr_randomization, msg->disc_mac_addr_rand_interval_sec,
                    NAN_REQ_ATTR_DISC_MAC_ADDR_RANDOM_INTERVAL, request, result, "enable:Failed to put disc_mac_addr_rand_interval_sec");

        CHECK_CONFIG_PUT_32_RETURN_FAIL(msg->config_ndpe_attr, msg->use_ndpe_attr,
                    NAN_REQ_ATTR_USE_NDPE_ATTR, request, result, "enable:Failed to put use_ndpe_attr");

        CHECK_CONFIG_PUT_32_RETURN_FAIL(msg->config_discovery_beacon_int, msg->discovery_beacon_interval,
                    NAN_REQ_ATTR_DISCOVERY_BEACON_INT, request, result, "config:Failed to put discovery_beacon_interval");

        CHECK_CONFIG_PUT_32_RETURN_FAIL(msg->config_nss, msg->nss,
                    NAN_REQ_ATTR_NSS, request, result, "config:Failed to put nss");

        CHECK_CONFIG_PUT_32_RETURN_FAIL(msg->config_enable_ranging, msg->enable_ranging,
                    NAN_REQ_ATTR_ENABLE_RANGING, request, result, "config:Failed to put enable_ranging");

        CHECK_CONFIG_PUT_32_RETURN_FAIL(msg->config_dw_early_termination, msg->enable_dw_termination,
                    NAN_REQ_ATTR_DW_EARLY_TERMINATION, request, result, "config:Failed to put enable_dw_termination");

        request.attr_end(data);
        ALOGD("[NAN][%d][ENABLE][req]::Sent[Mpref:%d, cluster_low:%d, cluster_high:%d, support5g:%d, sid_beaconl:%d, rssiC24g:%d, rssiM5g:%d, rssiCP5g:%d]\n"
              "[rssi_window_size:%d, oui:%d, intf_addr:%02x:*:*:*:%02x:%02x, config_cluster_attribute:%d, dwell_time:%d,%d,%d, scan_period:%d,%d,%d, random_factor_force:%d, hop_count_force:%d]\n"
              "[chan24g:%d, chan5g:%d, subscribe_sid_beacon:%d, dw24gInterval:%d, dw5gInterval:%d, config_disc_mac_addr_randomization:%d, disc_mac_addr_rand_interval_sec:%d, use_ndpe_attr:%d]\n",
              id, master_pref, msg->cluster_low, msg->cluster_high, msg->support_5g_val, msg->sid_beacon_val, msg->rssi_close_2dot4g_val,
              msg->rssi_middle_5g_val, msg->rssi_close_proximity_5g_val, msg->rssi_window_size_val, msg->oui_val, msg->intf_addr_val[0],
              msg->intf_addr_val[4], msg->intf_addr_val[5], msg->config_cluster_attribute_val, msg->scan_params_val.dwell_time[0],
              msg->scan_params_val.dwell_time[1], msg->scan_params_val.dwell_time[2], msg->scan_params_val.scan_period[0],
              msg->scan_params_val.scan_period[1], msg->scan_params_val.scan_period[2], msg->random_factor_force_val, msg->hop_count_force_val,
              msg->channel_24g_val, msg->channel_5g_val, msg->subscribe_sid_beacon_val, msg->config_dw.dw_2dot4g_interval_val,
              msg->config_dw.dw_5g_interval_val, msg->config_disc_mac_addr_randomization, msg->disc_mac_addr_rand_interval_sec, msg->use_ndpe_attr);
        ALOGD("Continued..[discovery_beacon_interval:%d, nss:%d, enable_ranging:%d, enable_dw_termination:%d]\n",
              msg->discovery_beacon_interval, msg->nss, msg->enable_ranging, msg->enable_dw_termination);
        registerNanEvents();
        result = requestResponse(request);
        if (result != WIFI_SUCCESS) {
            ALOGE("[NAN][%d][ENABLE][req]::Failed[result:%d]\n", id, result);
            unregisterNanEvents();
        }
        return result;
    }

    int disable(transaction_id id)
    {
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
        ALOGD("[NAN][%d][DISABLE][req]:Sent\n", id);
        result = requestResponse(request);
        if (result != WIFI_SUCCESS) {
            ALOGE("[NAN][%d][DISABLE][req]::Failed[result:%d]\n", id, result);
        }
        return result;
    }

    int config(transaction_id id, NanConfigRequest *msg) {
        WifiRequest request(familyId(), ifaceId());

        int result = request.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_NAN_CONFIG);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "config:Failed to create WifiRequest");

        nlattr *data = request.attr_start(NL80211_ATTR_VENDOR_DATA);
        if (!data) {
            ALOGE("config: request.attr_start fail");
            return WIFI_ERROR_OUT_OF_MEMORY;
        }

        CHECK_CONFIG_PUT_16_RETURN_FAIL(1, id, NAN_REQ_ATTR_HAL_TRANSACTION_ID, request, result, "config:Failed to put transaction id");

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

        CHECK_CONFIG_PUT_8_RETURN_FAIL(msg->config_disc_mac_addr_randomization, msg->config_disc_mac_addr_randomization,
                    NAN_REQ_ATTR_CONFIG_DISC_MAC_ADDR_RANDOM, request, result, "enable:Failed to put config_disc_mac_addr_rand_interval_sec");

        CHECK_CONFIG_PUT_32_RETURN_FAIL(msg->config_disc_mac_addr_randomization, msg->disc_mac_addr_rand_interval_sec,
                    NAN_REQ_ATTR_DISC_MAC_ADDR_RANDOM_INTERVAL, request, result, "config:Failed to put disc_mac_addr_rand_interval_sec");

        CHECK_CONFIG_PUT_32_RETURN_FAIL(msg->config_ndpe_attr, msg->use_ndpe_attr,
                    NAN_REQ_ATTR_USE_NDPE_ATTR, request, result, "config:Failed to put use_ndpe_attr");

        CHECK_CONFIG_PUT_32_RETURN_FAIL(msg->config_discovery_beacon_int, msg->discovery_beacon_interval,
                    NAN_REQ_ATTR_DISCOVERY_BEACON_INT, request, result, "config:Failed to put discovery_beacon_interval");

        CHECK_CONFIG_PUT_32_RETURN_FAIL(msg->config_nss, msg->nss,
                    NAN_REQ_ATTR_NSS, request, result, "config:Failed to put nss");

        CHECK_CONFIG_PUT_32_RETURN_FAIL(msg->config_enable_ranging, msg->enable_ranging,
                    NAN_REQ_ATTR_ENABLE_RANGING, request, result, "config:Failed to put enable_ranging");

        CHECK_CONFIG_PUT_32_RETURN_FAIL(msg->config_dw_early_termination, msg->enable_dw_termination,
                    NAN_REQ_ATTR_DW_EARLY_TERMINATION, request, result, "config:Failed to put enable_dw_termination");


        request.attr_end(data);

        ALOGD("[NAN][%d][CONFIG][req]::Sent[sid_beacon:%d, rssiP:%d, master_pref:%d, rssiCP5g:%d, rssi_window_size:%d]\n"
              "[config_cluster_attribute:%d, dwell_time:%d,%d,%d, scan_period:%d,%d,%d, random_factor_force:%d, hop_count_force:%d]\n"
              "[payload_transmit_flag%d, is_wfd:%d, is_wfds:%d, is_tdls:%d, is_ibss:%d, is_mesh:%d, wlan_infra_field:%d]\n"
              "[num_config_discovery_attr:%d]\n",
              id, msg->sid_beacon, msg->rssi_proximity, msg->master_pref, msg->rssi_close_proximity_5g_val, msg->rssi_window_size_val,
              msg->config_cluster_attribute_val, msg->scan_params_val.dwell_time[0], msg->scan_params_val.dwell_time[1],
              msg->scan_params_val.dwell_time[2], msg->scan_params_val.scan_period[0], msg->scan_params_val.scan_period[1],
              msg->scan_params_val.scan_period[2], msg->random_factor_force_val, msg->hop_count_force_val, msg->conn_capability_val.payload_transmit_flag,
              msg->conn_capability_val.is_wfd_supported, msg->conn_capability_val.is_wfds_supported, msg->conn_capability_val.is_tdls_supported,
              msg->conn_capability_val.is_ibss_supported, msg->conn_capability_val.is_mesh_supported, msg->conn_capability_val.wlan_infra_field,
              msg->num_config_discovery_attr);
        if (msg->num_config_discovery_attr)
            for (int i = 0; i < msg->num_config_discovery_attr; i++) {
                NanTransmitPostDiscovery *discovery_attr = &msg->discovery_attr_val[i];
                ALOGD("Continued...Sent[discovery_attr: type:%d, role:%d, transmit_freq:%d, duration:%d, avail_interval_bitmap:%d, addr:%02x:*:*:*:%02x:%02x, meshId_len:%d]\n"
                      "[meshId:%.*s, infrastructure_ssid_len:%d, infrastructure_ssid:%.*s]\n",
                      discovery_attr->type, discovery_attr->role, discovery_attr->transmit_freq, discovery_attr->duration, discovery_attr->avail_interval_bitmap, discovery_attr->addr[0],
                      discovery_attr->addr[4], discovery_attr->addr[5], discovery_attr->mesh_id_len,
                      discovery_attr->mesh_id_len > 20 ? 20 : discovery_attr->mesh_id_len, discovery_attr->mesh_id, discovery_attr->infrastructure_ssid_len,
                      discovery_attr->infrastructure_ssid_len > 20 ? 20 : discovery_attr->infrastructure_ssid_len, discovery_attr->infrastructure_ssid_val);
            }
        if (msg->config_fam) {
            ALOGD("Continued...Sent[numchans:%d]\n", msg->fam_val.numchans);
            for (int i = 0; i < msg->fam_val.numchans; i++) {
                NanFurtherAvailabilityChannel *further_avail_chan = &msg->fam_val.famchan[i];
                ALOGD("[further_avail_chan entry_control:%d, class_val:%d, channel:%d, mapid:%d, avail_interval_bitmap:%d]\n",
                      further_avail_chan->entry_control, further_avail_chan->class_val, further_avail_chan->channel,
                      further_avail_chan->mapid, further_avail_chan->avail_interval_bitmap);
            }
        }
        ALOGD("Continued...Sent[subscribe_sid_beacon:%d, dw24gInterval:%d, dw5gInterval:%d, disc_mac_addr_rand_interval_sec:%d, use_ndpe_attr:%d]\n"
              "[discovery_beacon_interval:%d, nss:%d, enable_dw_termination:%d, enable_ranging:%d, config_disc_mac_addr_randomization:%d]\n",
              msg->subscribe_sid_beacon_val, msg->config_dw.dw_2dot4g_interval_val, msg->config_dw.dw_5g_interval_val,
              msg->disc_mac_addr_rand_interval_sec, msg->use_ndpe_attr, msg->discovery_beacon_interval, msg->nss,
              msg->enable_dw_termination, msg->enable_ranging, msg->config_disc_mac_addr_randomization);

        result = requestResponse(request);
        if (result != WIFI_SUCCESS) {
            ALOGE("[NAN][%d][CONFIG][req]::Failed[result:%d]\n", id, result);
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
        WifiRequest request(familyId(), ifaceId());

        int result = request.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_NAN_PUBLISH);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "publish:Failed to create WifiRequest");

        nlattr *data = request.attr_start(NL80211_ATTR_VENDOR_DATA);
        if (!data) {
            ALOGE("publish: request.attr_start fail");
            return WIFI_ERROR_OUT_OF_MEMORY;
        }

        CHECK_CONFIG_PUT_16_RETURN_FAIL(1, id, NAN_REQ_ATTR_HAL_TRANSACTION_ID, request, result, "publish:Failed to put transaction id");

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

        request.attr_end(data);

        ALOGD("[NAN][%d][PUB][req]::Sent[pubId:%d pubType:%d, TTL:%d, period:%d, txType:%d, pubCount:%d, service_len:%d, service:%.*s]\n"
              "[publish_match_indicator:%d, service_specific_info_len:%d, rxMF_len:%d]\n"
              "[txMF_len:%d, rssi_threshold_flag:%d, connmap:%d, recv_indication_cfg:%d, sdea_service_specific_info_len:%d]\n"
              "[ranging_auto_response:%d]\n", id, msg->publish_id, msg->publish_type, msg->ttl, msg->period,
              msg->tx_type, msg->publish_count, msg->service_name_len, msg->service_name_len > 20 ? 20 : msg->service_name_len,
              msg->service_name, msg->publish_match_indicator, msg->service_specific_info_len,
              msg->rx_match_filter_len, msg->tx_match_filter_len, msg->rssi_threshold_flag, msg->connmap,
              msg->recv_indication_cfg, msg->sdea_service_specific_info_len, msg->ranging_auto_response);

        wifi_log_hex_buffer_debug("rx_match_filter:", NULL, msg->rx_match_filter,
                                           msg->rx_match_filter_len);
        wifi_log_hex_buffer_debug("tx_match_filter:", NULL, msg->tx_match_filter,
                                           msg->tx_match_filter_len);
        wifi_log_hex_buffer_debug("service_specific_info:", NULL, msg->service_specific_info,
                                           msg->service_specific_info_len);
        wifi_log_hex_buffer_debug("sdea_service_specific_info:", NULL,
                                           msg->sdea_service_specific_info, msg->sdea_service_specific_info_len);
        result = requestResponse(request);
        if (result != WIFI_SUCCESS) {
            ALOGE("[NAN][%d][PUB][req]::Failed[result:%d]\n", id, result);
        }
        return result;
    }

    int publishCancel(transaction_id id, NanPublishCancelRequest *msg) {
        WifiRequest request(familyId(), ifaceId());

        if (is_reset_in_progress())
            return WIFI_SUCCESS;

        int result = request.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_NAN_PUBLISHCANCEL);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "publishCancel:Failed to create WifiRequest");

        nlattr *data = request.attr_start(NL80211_ATTR_VENDOR_DATA);
        if (!data) {
            ALOGE("publishCancel: request.attr_start fail");
            return WIFI_ERROR_OUT_OF_MEMORY;
        }

        CHECK_CONFIG_PUT_16_RETURN_FAIL(1, id, NAN_REQ_ATTR_HAL_TRANSACTION_ID, request, result, "publishCancel:Failed to put transaction id");

        CHECK_CONFIG_PUT_16_RETURN_FAIL(1, msg->publish_id,
                NAN_REQ_ATTR_PUBLISH_ID, request, result, "publishCancel:Failed to put msg->publish_id");

        request.attr_end(data);
        ALOGD("[NAN][%d][PUB-CANCEL][req]::Sent[pubId:%d]\n", id, msg->publish_id);
        result = requestResponse(request);
        if (result != WIFI_SUCCESS) {
            ALOGE("[NAN][%d][PUB-CANCEL][req]::Failed[result:%d]\n", id, result);
        }
        return result;

    }

    int subscribe(transaction_id id, NanSubscribeRequest *msg) {
        WifiRequest request(familyId(), ifaceId());

        int result = request.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_NAN_SUBSCRIBE);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "subscribe:Failed to create WifiRequest");

        nlattr *data = request.attr_start(NL80211_ATTR_VENDOR_DATA);
        if (!data) {
            ALOGE("subscribe: request.attr_start fail");
            return WIFI_ERROR_OUT_OF_MEMORY;
        }

        CHECK_CONFIG_PUT_16_RETURN_FAIL(1, id, NAN_REQ_ATTR_HAL_TRANSACTION_ID, request, result, "subscribe:Failed to put transaction id");

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

        request.attr_end(data);

        ALOGD("[NAN][%d][SUB][req]::Sent[subId:%d, subType:%d, TTL:%d, period:%d, serviceRespFilter:%d, serviceRespInclude:%d, useServiceRespFilter:%d, ssiRequiredForMatchIndication:%d, sub_match_indicator:%d]\n"
              "[subCount:%d, service_len:%d, service:%.*s, service_specific_info_len:%d, rxMF_len:%d]\n"
              "[txMF_len:%drssi_threshold_flag:%d, connmap:%d, num_intf_addr_present:%d, recv_indication_cfg:%d, sdea_service_specific_info_len:%d]\n"
              "[ranging_auto_resp:%d]\n", id, msg->subscribe_id, msg->subscribe_type, msg->ttl, msg->period,
              msg->serviceResponseFilter, msg->serviceResponseInclude, msg->useServiceResponseFilter, msg->ssiRequiredForMatchIndication,
              msg->subscribe_match_indicator, msg->subscribe_count, msg->service_name_len,
              msg->service_name_len > 20 ? 20 : msg->service_name_len, msg->service_name, msg->service_specific_info_len,
              msg->rx_match_filter_len, msg->tx_match_filter_len,
              msg->rssi_threshold_flag, msg->connmap, msg->num_intf_addr_present, msg->recv_indication_cfg,
              msg->sdea_service_specific_info_len, msg->ranging_auto_response);
        wifi_log_hex_buffer_debug("rx_match_filter:", NULL, msg->rx_match_filter,
                                           msg->rx_match_filter_len);
        wifi_log_hex_buffer_debug("tx_match_filter:", NULL, msg->tx_match_filter,
                                           msg->tx_match_filter_len);
        wifi_log_hex_buffer_debug("service_specific_info:", NULL, msg->service_specific_info,
                                           msg->service_specific_info_len);
        wifi_log_hex_buffer_debug("sdea_service_specific_info:", NULL,
                                           msg->sdea_service_specific_info, msg->sdea_service_specific_info_len);
        result = requestResponse(request);
        if (result != WIFI_SUCCESS) {
            ALOGE("[NAN][%d][SUB][req]::Failed[result:%d]\n", id, result);
        }
        return result;

    }

    int subscribeCancel(transaction_id id, NanSubscribeCancelRequest *msg) {
        WifiRequest request(familyId(), ifaceId());

        if (is_reset_in_progress())
            return WIFI_SUCCESS;

        int result = request.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_NAN_SUBSCRIBECANCEL);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "subscribeCancel:Failed to create WifiRequest");

        nlattr *data = request.attr_start(NL80211_ATTR_VENDOR_DATA);
        if (!data) {
            ALOGE("subscribeCancel: request.attr_start fail");
            return WIFI_ERROR_OUT_OF_MEMORY;
        }

        CHECK_CONFIG_PUT_16_RETURN_FAIL(1, id, NAN_REQ_ATTR_HAL_TRANSACTION_ID, request, result, "subscribeCancel:Failed to put transaction id");

        CHECK_CONFIG_PUT_16_RETURN_FAIL(1, msg->subscribe_id,
                NAN_REQ_ATTR_SUBSCRIBE_ID, request, result, "subscribeCancel:Failed to put msg->subscribe_id");

        request.attr_end(data);
        ALOGD("[NAN][%d][SUB-CANCEL][req]::Sent[subId:%d]\n", id, msg->subscribe_id);
        result = requestResponse(request);
        if (result != WIFI_SUCCESS) {
            ALOGE("[NAN][%d][SUB-CANCEL][req]::Failed[result:%d]\n", id, result);
        }
        return result;
    }

    int followup(transaction_id id, NanTransmitFollowupRequest *msg) {
        WifiRequest request(familyId(), ifaceId());

        int result = request.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_NAN_TXFOLLOWUP);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "followup:Failed to create WifiRequest");

        nlattr *data = request.attr_start(NL80211_ATTR_VENDOR_DATA);
        if (!data) {
            ALOGE("followup: request.attr_start fail");
            return WIFI_ERROR_OUT_OF_MEMORY;
        }

        CHECK_CONFIG_PUT_16_RETURN_FAIL(1, id, NAN_REQ_ATTR_HAL_TRANSACTION_ID, request, result, "followup:Failed to put transaction id");

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

        request.attr_end(data);
        ALOGD("[NAN][%d][TXFOLLOWUP][req]::Sent[pub/subId:%d reqInstId:%d, addr:%02x:*:*:*:%02x:%02x, priority:%d, dw_or_faw:%d, service_specific_info_len:%d]\n"
              "[recv_indication_cfg:%d, sdea_service_specific_info_len:%d]\n",
              id, msg->publish_subscribe_id, msg->requestor_instance_id, msg->addr[0], msg->addr[4], msg->addr[5],
              msg->priority, msg->dw_or_faw, msg->service_specific_info_len,
              msg->recv_indication_cfg, msg->sdea_service_specific_info_len);
        wifi_log_hex_buffer_debug("service_specific_info:", NULL, msg->service_specific_info,
                                           msg->service_specific_info_len);
        wifi_log_hex_buffer_debug("sdea_service_specific_info:", NULL,
                                           msg->sdea_service_specific_info, msg->sdea_service_specific_info_len);
        result = requestResponse(request);
        if (result != WIFI_SUCCESS) {
            ALOGE("[NAN][%d][TXFOLLOWUP][req]::Failed[result:%d]\n", id, result);
        }
        return result;

    }

    int getCapabilities(transaction_id id) {
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
        ALOGD("[NAN][%d][CAPABILITIES][req]::Sent\n", id);
        result = requestResponse(request);
       if (result != WIFI_SUCCESS) {
            ALOGE("[NAN][%d][CAPABILITIES][req]::Failed[result:%d]\n", id, result);
        }
        return result;
    }

    int handleEvent(WifiEvent &event) {
        int ret;

        if (event.get_cmd() != NL80211_CMD_VENDOR) {
            ALOGD("NAN %s Ignoring event with cmd = %d", __func__, event.get_cmd());
            return NL_SKIP;
        }

        int subcmd = event.get_vendor_subcmd();

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
        case SLSI_NL80211_VENDOR_NAN_INTERFACE_CREATED:
            ret = processNanInterfaceCreated(event);
            break;
        case SLSI_NL80211_VENDOR_NAN_INTERFACE_DELETED:
            ret = processNanInterfaceDeleted(event);
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
        if (response.response_type == NAN_RESPONSE_PUBLISH) {
            if (response.status == NAN_STATUS_SUCCESS)
                ALOGD("[NAN][%d][%s][resp]:SUCCESS[publish_id:%d]", id, getResponseName(response.response_type),
                      response.body.publish_response.publish_id);
            else
                ALOGD("[NAN][%d][%s][resp]:FAIL[publish_id:%d status:%d]", id, getResponseName(response.response_type),
                      response.body.publish_response.publish_id, response.status);
        } else if (response.response_type == NAN_RESPONSE_SUBSCRIBE) {
            if (response.status == NAN_STATUS_SUCCESS)
                ALOGD("[NAN][%d][%s][resp]:SUCCESS[subscribe_id:%d]", id, getResponseName(response.response_type),
                      response.body.subscribe_response.subscribe_id);
            else
                ALOGD("[NAN][%d][%s][resp]:FAIL[subscribe_id:%d status:%d]", id, getResponseName(response.response_type),
                      response.body.subscribe_response.subscribe_id, response.status);
        } else {
            if (response.status == NAN_STATUS_SUCCESS)
                ALOGD("[NAN][%d][%s][resp]:SUCCESS", id, getResponseName(response.response_type));
            else
                ALOGD("[NAN][%d][%s][resp]:FAIL[status:%d]", id, getResponseName(response.response_type),
                      response.status);
        }
        if (response.response_type == NAN_RESPONSE_ENABLED) {
            NanDiscEngEventInd ind;
            memset(&ind,0,sizeof(ind));
            ind.event_type = NAN_EVENT_ID_DISC_MAC_ADDR;
            memcpy(ind.data.mac_addr.addr, this->mac, NAN_MAC_ADDR_LEN);
            if (callbackEventHandler.EventDiscEngEvent)
                callbackEventHandler.EventDiscEngEvent(&ind);
        }
        if (callbackEventHandler.NotifyResponse)
            callbackEventHandler.NotifyResponse(id, &response);
        return NL_OK;
    }

    int dataPathReq(u16 id, void *data, int subcmd) {
        int result;
        WifiRequest request(familyId(), ifaceId());

        ALOGD("[NAN][%d][%s][req]:: Sent", id, datacmd.getCmdName(subcmd));
        if (subcmd == SLSI_NL80211_VENDOR_SUBCMD_NAN_DATA_INTERFACE_DELETE)
            linuxSetIfaceFlags((char *)data, 0);
        result = datacmd.getDataPathNLMsg(id, data, subcmd, request);
        if (result != WIFI_SUCCESS) {
            return result;
        }
        result = requestResponse(request);
        if (result != WIFI_SUCCESS) {
            ALOGE("[NAN][%d][%s][req]:: Failed[result:%d]", id, datacmd.getCmdName(subcmd), result);
        } else {
            datacmd.requestSuccess(id, data, subcmd);
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
        ALOGE("[NAN][%d][ENABLE][req]:: Failed[Create Command]\n", id);
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
        ALOGE("[NAN][%d][DISABLE][req]:: Failed[Create Command]\n", id);
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
        ALOGE("[NAN][%d][PUB][req]:: Failed[Create Command]\n", id);
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
        ALOGE("[NAN][%d][PUB-CANCEL][req]:: Failed[Create Command]\n", id);
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
        ALOGE("[NAN][%d][SUB][req]:: Failed[Create Command]\n", id);
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
        ALOGE("[NAN][%d][SUB-CANCEL][req]:: Failed[Create Command]\n", id);
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
        ALOGE("[NAN][%d][TXFOLLOWUP][req]:: Failed[Create Command]\n", id);
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
        ALOGE("[NAN][%d][CONFIG][req]:: Failed[Create Command]\n", id);
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
        ALOGE("[NAN][%d][CAPABILITIES][req]:: Failed[Out of memory]\n", id);
        return WIFI_ERROR_OUT_OF_MEMORY;
    }
    return (wifi_error)nanRequest->getCapabilities(id);
}

wifi_error nan_data_interface_create(transaction_id id,
                                     wifi_interface_handle iface,
                                     char* iface_name) {
    NanCommand *nanRequest = nan_get_object(id, iface);
    if (!nanRequest) {
        ALOGE("[NAN][%d][DATA_IF_ADD][req]:: Failed[Out of memory]\n", id);
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
        ALOGE("[NAN][%d][DATA_IF_DEL][req]:: Failed[Out of memory]\n", id);
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
        ALOGE("[NAN][%d][DATA_REQ][req]:: Failed[Out of memory]\n", id);
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
        ALOGE("[NAN][%d][DATA_RES][req]:: Failed[Out of memory]\n", id);
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
        ALOGE("[NAN][%d][DATA_END][req]:: Failed[Out of memory]\n", id);
        return WIFI_ERROR_OUT_OF_MEMORY;
    }
    return (wifi_error)nanRequest->dataPathReq(id, msg,
                SLSI_NL80211_VENDOR_SUBCMD_NAN_DATA_END);

}

