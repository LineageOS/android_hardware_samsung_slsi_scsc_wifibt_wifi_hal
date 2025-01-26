
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

nlattr *NanDataCommand::newNlVendorMsg(int subcmd, WifiRequest &request) {
    int result = request.create(GOOGLE_OUI, subcmd);
    if (result != WIFI_SUCCESS) {
        ALOGE("newNlVendorMsg:Failed to create WifiRequest (%d)", result);
        return NULL;
    }

    nlattr *data = request.attr_start(NL80211_ATTR_VENDOR_DATA);
    if (!data) {
        ALOGE("newNlVendorMsg: request.attr_start fail");
        return NULL;
    }
    return data;
}

int NanDataCommand::dataInterfaceCreateDelete(u16 id, char *ifaceName, int subcmd, WifiRequest &request) {
    int result;
    nlattr *data = newNlVendorMsg(subcmd, request);
    if (!data)
        return WIFI_ERROR_OUT_OF_MEMORY;

    CHECK_CONFIG_PUT_16_RETURN_FAIL(1, id, NAN_REQ_ATTR_HAL_TRANSACTION_ID, request, result, "dataInterfacecreateDelete:Failed to put transaction id");

    result = request.put_u8(NAN_REQ_ATTR_DATA_INTERFACE_NAME_LEN, strlen(ifaceName));
    CHECK_WIFI_STATUS_RETURN_FAIL(result, "Failed to put ifaceName_len");
    result = request.put(NAN_REQ_ATTR_DATA_INTERFACE_NAME, ifaceName, strlen(ifaceName));
    CHECK_WIFI_STATUS_RETURN_FAIL(result, "Failed to put ifaceName");

    request.attr_end(data);
    ALOGD("Send[IfaceNamelen:%d, IfaceName:%.*s]\n", (int)strlen(ifaceName), strlen(ifaceName) > 20 ? 20 : (int)strlen(ifaceName), ifaceName);
    return WIFI_SUCCESS;
}

int NanDataCommand::dataRequestInitiate(u16 id, NanDataPathInitiatorRequest* msg, WifiRequest &request) {
    int result;
    nlattr *data = newNlVendorMsg(SLSI_NL80211_VENDOR_SUBCMD_NAN_DATA_REQUEST_INITIATOR, request);
    if (!data)
        return WIFI_ERROR_OUT_OF_MEMORY;
    CHECK_CONFIG_PUT_16_RETURN_FAIL(1, id, NAN_REQ_ATTR_HAL_TRANSACTION_ID, request, result, "dataRequestInitiate:Failed to put transaction id");
    result = request.put_u32(NAN_REQ_ATTR_REQ_INSTANCE_ID, msg->requestor_instance_id);
    CHECK_WIFI_STATUS_RETURN_FAIL(result, "Failed to put req_instance_id");
    result = request.put_u8(NAN_REQ_ATTR_CHAN_REQ_TYPE, msg->channel_request_type);
    CHECK_WIFI_STATUS_RETURN_FAIL(result, "Failed to put channel_request_type");
    result = request.put_u32(NAN_REQ_ATTR_CHAN, msg->channel);
    CHECK_WIFI_STATUS_RETURN_FAIL(result, "Failed to put channel");
    result = request.put(NAN_REQ_ATTR_MAC_ADDR_VAL, msg->peer_disc_mac_addr, NAN_MAC_ADDR_LEN);
    CHECK_WIFI_STATUS_RETURN_FAIL(result, "Failed to put peer_disc_mac_addr");
    result = request.put_u8(NAN_REQ_ATTR_DATA_INTERFACE_NAME_LEN, IFNAMSIZ+1);
    CHECK_WIFI_STATUS_RETURN_FAIL(result, "Failed to put ifaceName_len");
    result = request.put(NAN_REQ_ATTR_DATA_INTERFACE_NAME, msg->ndp_iface, IFNAMSIZ+1);
    CHECK_WIFI_STATUS_RETURN_FAIL(result, "Failed to put ndp_iface");
    result = request.put_u8(NAN_REQ_ATTR_SDEA_PARAM_SECURITY_CFG, msg->ndp_cfg.security_cfg);
    CHECK_WIFI_STATUS_RETURN_FAIL(result, "Failed to put security_cfg");
    result = request.put_u8(NAN_REQ_ATTR_SDEA_PARAM_QOS_CFG, msg->ndp_cfg.qos_cfg);
    CHECK_WIFI_STATUS_RETURN_FAIL(result, "Failed to put qos_cfg");
    if(msg->app_info.ndp_app_info_len){
        result = request.put_u16(NAN_REQ_ATTR_APP_INFO_LEN, msg->app_info.ndp_app_info_len);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "Failed to put ndp_app_info_len");
        result = request.put(NAN_REQ_ATTR_APP_INFO, msg->app_info.ndp_app_info, msg->app_info.ndp_app_info_len);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "Failed to put ndp_app_info");
    }
    if (msg->service_name_len) {
        result = request.put_u32(NAN_REQ_ATTR_SERVICE_NAME_LEN, msg->service_name_len);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "Failed to put service_name_len");
        result = request.put(NAN_REQ_ATTR_SERVICE_NAME, msg->service_name, msg->service_name_len);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "Failed to put req_instance_id");
    }
    result =  putSecurityInfo(msg->cipher_type, &msg->key_info, 0, NULL, &request);

    request.attr_end(data);
    ALOGD("Send[requestor_instance_id:%d, chan_requestType:%d, channel:%d, peer_disc_mac_addr:%02x:*:*:*:%02x:%02x, ndp_iface:%s, security_cfg:%d]\n"
          "[qos_cfg:%d, ndp_app_info_len:%d, service_len:%d, service:%.*s]\n",
          msg->requestor_instance_id, msg->channel_request_type, msg->channel, msg->peer_disc_mac_addr[0],
          msg->peer_disc_mac_addr[4], msg->peer_disc_mac_addr[5], msg->ndp_iface, msg->ndp_cfg.security_cfg,
          msg->ndp_cfg.qos_cfg, msg->app_info.ndp_app_info_len,
          msg->service_name_len, msg->service_name_len > 20 ? 20 : msg->service_name_len, msg->service_name);
    wifi_log_hex_buffer_debug("ndp_app_info:", NULL, msg->app_info.ndp_app_info, msg->app_info.ndp_app_info_len);
    return result;
}

int NanDataCommand::dataIndicationResponse(u16 id, NanDataPathIndicationResponse* msg, WifiRequest &request) {
    int result;
    nlattr *data = newNlVendorMsg(SLSI_NL80211_VENDOR_SUBCMD_NAN_DATA_INDICATION_RESPONSE, request);
    if (!data)
        return WIFI_ERROR_OUT_OF_MEMORY;
    CHECK_CONFIG_PUT_16_RETURN_FAIL(1, id, NAN_REQ_ATTR_HAL_TRANSACTION_ID, request, result, "dataIndicationResponse:Failed to put transaction id");

    result = request.put_u32(NAN_REQ_ATTR_NDP_INSTANCE_ID, msg->ndp_instance_id);
    CHECK_WIFI_STATUS_RETURN_FAIL(result, "Failed to put ndp_instance_id");
    result = request.put_u8(NAN_REQ_ATTR_DATA_INTERFACE_NAME_LEN, IFNAMSIZ+1);
    CHECK_WIFI_STATUS_RETURN_FAIL(result, "Failed to put ifaceName_len");
    result = request.put(NAN_REQ_ATTR_DATA_INTERFACE_NAME, msg->ndp_iface, IFNAMSIZ+1);
    CHECK_WIFI_STATUS_RETURN_FAIL(result, "Failed to put ndp_iface");
    result = request.put_u8(NAN_REQ_ATTR_SDEA_PARAM_SECURITY_CFG, msg->ndp_cfg.security_cfg);
    CHECK_WIFI_STATUS_RETURN_FAIL(result, "Failed to put security_cfg");
    result = request.put_u8(NAN_REQ_ATTR_SDEA_PARAM_QOS_CFG, msg->ndp_cfg.qos_cfg);
    CHECK_WIFI_STATUS_RETURN_FAIL(result, "Failed to put qos_cfg");
    if(msg->app_info.ndp_app_info_len){
        result = request.put_u16(NAN_REQ_ATTR_APP_INFO_LEN, msg->app_info.ndp_app_info_len);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "Failed to put ndp_app_info_len");
        result = request.put(NAN_REQ_ATTR_APP_INFO, msg->app_info.ndp_app_info, msg->app_info.ndp_app_info_len);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "Failed to put ndp_app_info");
    }
    result = request.put_u8(NAN_REQ_ATTR_NDP_RESPONSE_CODE, msg->rsp_code);
    CHECK_WIFI_STATUS_RETURN_FAIL(result, "Failed to put rsp_code");
    if (msg->service_name_len) {
        result = request.put_u32(NAN_REQ_ATTR_SERVICE_NAME_LEN, msg->service_name_len);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "Failed to put service_name_len");
        result = request.put(NAN_REQ_ATTR_SERVICE_NAME, msg->service_name, msg->service_name_len);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "Failed to put req_instance_id");
    }
    result =  putSecurityInfo(msg->cipher_type, &msg->key_info, 0, NULL, &request);

    request.attr_end(data);
    ALOGD("Send[ndp_instance_id:%d, ndp_iface:%s, security_cfg:%d, qos_cfg:%d, ndp_app_info_len:%d]\n"
          "[rsp_code:%d, service_len:%d, service:%.*s]\n", msg->ndp_instance_id, msg->ndp_iface, msg->ndp_cfg.security_cfg,
          msg->ndp_cfg.qos_cfg, msg->app_info.ndp_app_info_len,
          msg->rsp_code, msg->service_name_len, msg->service_name_len > 20 ? 20 : msg->service_name_len, msg->service_name);
    wifi_log_hex_buffer_debug("ndp_app_info:", NULL, msg->app_info.ndp_app_info, msg->app_info.ndp_app_info_len);
    return result;
}

int NanDataCommand::dataEnd(u16 id, NanDataPathEndRequest* msg, WifiRequest &request) {
    int result, i;
    nlattr *data = newNlVendorMsg(SLSI_NL80211_VENDOR_SUBCMD_NAN_DATA_END, request);
    if (!data)
        return WIFI_ERROR_UNKNOWN;
    CHECK_CONFIG_PUT_16_RETURN_FAIL(1, id, NAN_REQ_ATTR_HAL_TRANSACTION_ID, request, result, "dataEnd:Failed to put transaction id");

    for(i=0; i<msg->num_ndp_instances; i++) {
        result = request.put_u32(NAN_REQ_ATTR_NDP_INSTANCE_ID, msg->ndp_instance_id[i]);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "Failed to put ndp_instance_id");
        ALOGD("Send[ndp_instance_id:%d]\n", msg->ndp_instance_id[i]);
    }

    request.attr_end(data);
    return result;
}

void NanDataCommand::dataInterfaceCreated(char *ifaceName) {
    int i;
    for(i=0; i<SLSI_NAN_MAX_NDP; i++)
        if (m_ifaceName[i][0] == 0) {
            strncpy(ifaceName, m_ifaceName[i], IFNAMSIZ);
            m_data_iface_count++;
            return;
        }
}

void NanDataCommand::dataInterfaceDeleted(char *ifaceName) {
    int i;
    for(i=0; i<SLSI_NAN_MAX_NDP; i++)
        if (strncmp(m_ifaceName[i], ifaceName, IFNAMSIZ)== 0) {
            memset(m_ifaceName[i], 0, IFNAMSIZ);
            m_data_iface_count--;
            return;
        }
}

void NanDataCommand::dataRequestInitiateSuccess(NanDataPathInitiatorRequest *msg) {
    int i;
    for(i=0; i<SLSI_NAN_MAX_NDP; i++)
        if(m_ndp_instance_id[i] == 0) {
            m_ndp_instance_id[i] = msg->requestor_instance_id;
            m_ndp_count++;
            return;
        }
}

void NanDataCommand::dataIndicationResponseSuccess(NanDataPathIndicationResponse *msg) {
    int i;
    for(i=0; i<SLSI_NAN_MAX_NDP; i++)
        if(m_ndp_instance_id[i] == 0) {
            m_ndp_instance_id[i] = msg->ndp_instance_id;
            m_ndp_count++;
            return;
        }
}

void NanDataCommand::dataEndSuccess(NanDataPathEndRequest *msg) {
    int i, j;
    for(i=0; i<msg->num_ndp_instances; i++)
        for(j=0; j<SLSI_NAN_MAX_NDP; j++)
            if(m_ndp_instance_id[j] == msg->ndp_instance_id[i]) {
                m_ndp_instance_id[j] = 0;
                m_ndp_count--;
            }
}

void NanDataCommand::processNdpChannelInfo(nlattr *nl_data, NanChannelInfo &channel_info) {
    for(nl_iterator nl_itr(nl_data); nl_itr.has_next(); nl_itr.next()) {
        switch(nl_itr.get_type()) {
        case NAN_EVT_ATTR_CHANNEL:
            channel_info.channel = nl_itr.get_u32();
            break;
        case NAN_EVT_ATTR_CHANNEL_BW:
            channel_info.bandwidth = nl_itr.get_u32();
            break;
        case NAN_EVT_ATTR_CHANNEL_NSS:
            channel_info.nss = nl_itr.get_u32();
            break;
        }
    }
}
int NanDataCommand::processNdpReqEvent(WifiEvent &event, NanCallbackHandler &callbackEventHandler) {
    NanDataPathRequestInd ind;
    memset(&ind,0,sizeof(NanDataPathRequestInd));
    nlattr *vendor_data = event.get_attribute(NL80211_ATTR_VENDOR_DATA);

    for(nl_iterator nl_itr(vendor_data); nl_itr.has_next(); nl_itr.next()) {
        switch(nl_itr.get_type()) {
        case NAN_EVT_ATTR_SERVICE_INSTANCE_ID:
            ind.service_instance_id = nl_itr.get_u16();
            break;
        case NAN_EVT_ATTR_MATCH_ADDR:
            memcpy(ind.peer_disc_mac_addr, nl_itr.get_data(), ETHER_ADDR_LEN);
            break;
        case NAN_EVT_ATTR_NDP_INSTANCE_ID:
            ind.ndp_instance_id = nl_itr.get_u32();
            break;
        case NAN_EVT_ATTR_SDEA_PARAM_SECURITY_CONFIG:
            ind.ndp_cfg.security_cfg = (NanDataPathSecurityCfgStatus)nl_itr.get_u32();
            break;
        case NAN_EVT_ATTR_SDEA_PARAM_QOS_CFG:
            ind.ndp_cfg.qos_cfg = (NanDataPathQosCfg)nl_itr.get_u32();
            break;
        case NAN_EVT_ATTR_APP_INFO_LEN:
            ind.app_info.ndp_app_info_len = nl_itr.get_u16();
            break;
        case NAN_EVT_ATTR_APP_INFO:
            memcpy(ind.app_info.ndp_app_info, nl_itr.get_data(), ind.app_info.ndp_app_info_len);
            break;
        }
    }

    ALOGD("[NAN][NA][NDP_REQ][Ind]:Received[service_instance_id:%d, match_addr:%02x:*:*:*:%02x:%02x, ndp_instance_id:%d, security_cfg:%d]\n"
          "[qos_cfg:%d, ndp_app_info_len:%d]\n",
          ind.service_instance_id, ind.peer_disc_mac_addr[0],
          ind.peer_disc_mac_addr[4], ind.peer_disc_mac_addr[5], ind.ndp_instance_id, ind.ndp_cfg.security_cfg, ind.ndp_cfg.qos_cfg,
          ind.app_info.ndp_app_info_len);
    wifi_log_hex_buffer_debug("ndp_app_info:", NULL, ind.app_info.ndp_app_info, ind.app_info.ndp_app_info_len);
    if(callbackEventHandler.EventDataRequest)
        callbackEventHandler.EventDataRequest(&ind);
    return NL_OK;
}

int NanDataCommand::processNdpCfmEvent(WifiEvent &event, NanCallbackHandler &callbackEventHandler) {
    NanDataPathConfirmInd ind;
    memset(&ind,0,sizeof(NanDataPathConfirmInd));
    nlattr *vendor_data = event.get_attribute(NL80211_ATTR_VENDOR_DATA);

    for(nl_iterator nl_itr(vendor_data); nl_itr.has_next(); nl_itr.next()) {
        switch(nl_itr.get_type()) {
        case NAN_EVT_ATTR_NDP_INSTANCE_ID:
            ind.ndp_instance_id = nl_itr.get_u32();
            break;
        case NAN_EVT_ATTR_MATCH_ADDR:
            memcpy(ind.peer_ndi_mac_addr, nl_itr.get_data(), ETHER_ADDR_LEN);
            break;
        case NAN_EVT_ATTR_APP_INFO_LEN:
            ind.app_info.ndp_app_info_len = nl_itr.get_u16();
            break;
        case NAN_EVT_ATTR_APP_INFO:
            memcpy(ind.app_info.ndp_app_info, nl_itr.get_data(), ind.app_info.ndp_app_info_len);
            break;
        case NAN_EVT_ATTR_NDP_RSP_CODE:
            ind.rsp_code = (NanDataPathResponseCode)nl_itr.get_u32();
            break;
        case NAN_EVT_ATTR_STATUS_CODE:
            ind.reason_code = (NanStatusType)nl_itr.get_u32();
            break;
        case NAN_EVT_ATTR_CHANNEL_INFO:
            if (ind.num_channels < NAN_MAX_CHANNEL_INFO_SUPPORTED)
                processNdpChannelInfo(nl_itr.get(), ind.channel_info[ind.num_channels++]);
            break;
        }
    }
    ALOGD("[NAN][NA][NDP_CFM][Ind]:Received[ndp_instance_id:%d, match_addr:%02x:*:*:*:%02x:%02x, ndp_app_info_len:%d]\n"
          "[rsp_code:%d, reason_code:%d]\n", ind.ndp_instance_id, ind.peer_ndi_mac_addr[0],
          ind.peer_ndi_mac_addr[4], ind.peer_ndi_mac_addr[5], ind.app_info.ndp_app_info_len,
          ind.rsp_code, ind.reason_code);
    wifi_log_hex_buffer_debug("ndp_app_info:", NULL, ind.app_info.ndp_app_info, ind.app_info.ndp_app_info_len);
    if (ind.num_channels >= 1 && ind.num_channels <= NAN_MAX_CHANNEL_INFO_SUPPORTED)
        ALOGD("Continued..[channel:%d, bandwidth:%d, nss:%d]\n", ind.channel_info[ind.num_channels - 1].channel,
              ind.channel_info[ind.num_channels - 1].bandwidth, ind.channel_info[ind.num_channels - 1].nss);
    if(callbackEventHandler.EventDataConfirm)
        callbackEventHandler.EventDataConfirm(&ind);
    return NL_OK;
}

int NanDataCommand::processNdpEndEvent(WifiEvent &event, NanCallbackHandler &callbackEventHandler) {
    NanDataPathEndInd *end_ind;
    char ndp_list_str[SLSI_NAN_MAX_NDP * 6];
    int slen = 0;

    end_ind = (NanDataPathEndInd *) malloc(sizeof(*end_ind) + (SLSI_NAN_MAX_NDP * sizeof(NanDataPathId)));
    if (!end_ind) {
        ALOGE("Could not allocate end_ind");
        return WIFI_ERROR_UNKNOWN;
    }
    memset(end_ind,0,(sizeof(NanDataPathEndInd) + (SLSI_NAN_MAX_NDP * sizeof(NanDataPathId))));
    nlattr *vendor_data = event.get_attribute(NL80211_ATTR_VENDOR_DATA);

    memset(ndp_list_str, '\0', sizeof(ndp_list_str));
    for(nl_iterator nl_itr(vendor_data); nl_itr.has_next(); nl_itr.next()) {
        if (nl_itr.get_type() == NAN_EVT_ATTR_NDP_INSTANCE_ID) {
            end_ind->ndp_instance_id[end_ind->num_ndp_instances] = nl_itr.get_u32();
            end_ind->num_ndp_instances++;
            slen =  snprintf(ndp_list_str + slen, SLSI_NAN_MAX_NDP * 6 - slen, "%d ",
                             end_ind->ndp_instance_id[end_ind->num_ndp_instances - 1]);
        }
    }
    if (end_ind->num_ndp_instances > 0)
        ALOGD("[NAN][NA][NDP_END][Ind]:Received[ndp_instance_id:%s]\n", ndp_list_str);
    else
        ALOGD("[NAN][NA][NDP_END][Ind]:Received[0 ndp_ids]\n");
    if(callbackEventHandler.EventDataEnd)
        callbackEventHandler.EventDataEnd(end_ind);
    free(end_ind);
    return NL_OK;
}

NanDataCommand::NanDataCommand() {
    memset(m_ndp_instance_id, 0, sizeof(m_ndp_instance_id));
    memset(m_ifaceName, 0, sizeof(m_ifaceName));
    m_ndp_count = 0;
    m_data_iface_count = 0;
    m_max_ndp_sessions = 0;
}

int NanDataCommand::getDataPathNLMsg(u16 id, void *data, int subcmd, WifiRequest &request) {
    switch (subcmd) {
    case SLSI_NL80211_VENDOR_SUBCMD_NAN_DATA_INTERFACE_CREATE:
        return dataInterfaceCreateDelete(id, (char *)data, subcmd, request);
    case SLSI_NL80211_VENDOR_SUBCMD_NAN_DATA_INTERFACE_DELETE:
        return dataInterfaceCreateDelete(id, (char *)data, subcmd, request);
    case SLSI_NL80211_VENDOR_SUBCMD_NAN_DATA_REQUEST_INITIATOR:
        return dataRequestInitiate(id, (NanDataPathInitiatorRequest *)data, request);
    case SLSI_NL80211_VENDOR_SUBCMD_NAN_DATA_INDICATION_RESPONSE:
        return dataIndicationResponse(id, (NanDataPathIndicationResponse *)data, request);
    case SLSI_NL80211_VENDOR_SUBCMD_NAN_DATA_END:
        return dataEnd(id, (NanDataPathEndRequest *)data, request);
    default:
        ALOGE("unknown subcmd :0x%x", subcmd);
    }
    return WIFI_ERROR_UNKNOWN;
}

void NanDataCommand::requestSuccess(u16 id, void *data, int subcmd) {
    switch (subcmd) {
    case SLSI_NL80211_VENDOR_SUBCMD_NAN_DATA_INTERFACE_CREATE:
        dataInterfaceCreated((char *)data);
        break;
    case SLSI_NL80211_VENDOR_SUBCMD_NAN_DATA_INTERFACE_DELETE:
        dataInterfaceDeleted((char *)data);
        break;
    case SLSI_NL80211_VENDOR_SUBCMD_NAN_DATA_REQUEST_INITIATOR:
        dataRequestInitiateSuccess((NanDataPathInitiatorRequest *)data);
        break;
    case SLSI_NL80211_VENDOR_SUBCMD_NAN_DATA_INDICATION_RESPONSE:
        dataIndicationResponseSuccess((NanDataPathIndicationResponse *)data);
        break;
    case SLSI_NL80211_VENDOR_SUBCMD_NAN_DATA_END:
        dataEndSuccess((NanDataPathEndRequest *)data);
        break;
    }
}

int NanDataCommand::handleEvent(WifiEvent &event, NanCallbackHandler &callbackEventHandler) {
    int subcmd = event.get_vendor_subcmd();
    int id = event.get_vendor_id();

    switch (subcmd) {
    case SLSI_NAN_EVENT_NDP_REQ:
        return processNdpReqEvent(event, callbackEventHandler);
    case SLSI_NAN_EVENT_NDP_CFM:
        return processNdpCfmEvent(event, callbackEventHandler);
    case SLSI_NAN_EVENT_NDP_END:
        return processNdpEndEvent(event, callbackEventHandler);
    default:
        ALOGI("NAN %s, Id = 0x%x, subcmd = Unknown Event(0x%x)", __func__, id, subcmd);
        return NL_OK;
    }
}

void NanDataCommand::setMaxNdpSessions(int max_ndp) {
    m_max_ndp_sessions = max_ndp > SLSI_NAN_MAX_NDP ? SLSI_NAN_MAX_NDP : max_ndp;
}

int NanDataCommand::putSecurityInfo(u32 cipher, NanSecurityKeyInfo *key_info, u32 scid_len, u8 *scid, WifiRequest *request)
{
    int result;

    result = request->put_u32(NAN_REQ_ATTR_CIPHER_TYPE, cipher);
    CHECK_WIFI_STATUS_RETURN_FAIL(result, "enable:Failed to put cipher_type");

    result = request->put_u32(NAN_REQ_ATTR_SECURITY_KEY_TYPE, key_info->key_type);
    CHECK_WIFI_STATUS_RETURN_FAIL(result, "enable:Failed to put cipher_type");

    if (key_info->key_type == NAN_SECURITY_KEY_INPUT_PMK) {
        result = request->put_u32(NAN_REQ_ATTR_SECURITY_PMK_LEN, key_info->body.pmk_info.pmk_len);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "enable:Failed to put key_info->body.pmk_info.pmk_len");
        result = request->put(NAN_REQ_ATTR_SECURITY_PMK, key_info->body.pmk_info.pmk, key_info->body.pmk_info.pmk_len);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "enable:Failed to put key_info->body.pmk_info.pmk");
    } else {
        result = request->put_u32(NAN_REQ_ATTR_SECURITY_PASSPHRASE_LEN, key_info->body.passphrase_info.passphrase_len);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "enable:Failed to put key_info->body.passphrase_info.passphrase_len");
        result = request->put(NAN_REQ_ATTR_SECURITY_PASSPHRASE, key_info->body.passphrase_info.passphrase,
                            key_info->body.passphrase_info.passphrase_len);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "enable:Failed to put key_info->body.passphrase_info.passphrase");
    }

    result = request->put_u32(NAN_REQ_ATTR_SCID_LEN, scid_len);
    CHECK_WIFI_STATUS_RETURN_FAIL(result, "enable:Failed to put scid_len");
    if (scid_len) {
        result = request->put(NAN_REQ_ATTR_SCID, scid, scid_len);
        CHECK_WIFI_STATUS_RETURN_FAIL(result, "enable:Failed to put scid");
    }
    if (key_info->key_type == NAN_SECURITY_KEY_INPUT_PMK)
        ALOGD("Continued...Send[cipher:%d, keyType:PMK, pmk_len:%d, scid_len:%d, scid:%.*s]\n", cipher, key_info->body.pmk_info.pmk_len,
              scid_len, scid_len > 20 ? 20 : scid_len, scid);
    else
        ALOGD("Continued...Send[cipher:%d, keyType:Passphrase, Passphrase_len:%d, scid_len:%d, scid:%.*s]\n", cipher,
              key_info->body.passphrase_info.passphrase_len, scid_len, scid_len > 20 ? 20 : scid_len, scid);
    return result;
}

const u8 *NanDataCommand::getCmdName(int cmd){
    switch(cmd) {
    case SLSI_NL80211_VENDOR_SUBCMD_NAN_DATA_INTERFACE_CREATE:
        return (const u8 *)"IFCREATE";
    case SLSI_NL80211_VENDOR_SUBCMD_NAN_DATA_INTERFACE_DELETE:
        return (const u8 *)"IFDELETE";
    case SLSI_NL80211_VENDOR_SUBCMD_NAN_DATA_REQUEST_INITIATOR:
        return (const u8 *)"NDP_INITIATOR";
    case SLSI_NL80211_VENDOR_SUBCMD_NAN_DATA_INDICATION_RESPONSE:
        return (const u8 *)"NDP_RESPONDER";
    case SLSI_NL80211_VENDOR_SUBCMD_NAN_DATA_END:
        return (const u8 *)"NDP_END";
    default:
        return (const u8 *)"UNKNOWN CMD";
    }
    return (const u8 *)"UNKNOWN CMD";
}

