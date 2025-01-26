#include <stdint.h>
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

typedef enum {

    LSTATS_ATTRIBUTE_SET_MPDU_SIZE_THRESHOLD = 1,
    LSTATS_ATTRIBUTE_SET_AGGR_STATISTICS_GATHERING,
    LSTATS_ATTRIBUTE_CLEAR_STOP_REQUEST_MASK,
    LSTATS_ATTRIBUTE_CLEAR_STOP_REQUEST,

    LSTATS_ATTRIBUTE_MAX

} LSTATS_ATTRIBUTE;

class LinkLayerStatsCommand : public WifiCommand
{
    wifi_link_layer_params mParams;
    u32 mStatsClearReqMask;
    u32 *mStatsClearRspMask;
    u8 mStopReq;
    u8 *mStopRsp;
public:
    LinkLayerStatsCommand(wifi_interface_handle handle, wifi_link_layer_params params)
        : WifiCommand(handle, 0), mParams(params)
    {
        mStatsClearReqMask = 0;
        mStatsClearRspMask = 0;
        mStopReq = 0 ;
        mStopRsp = NULL;

    }

    LinkLayerStatsCommand(wifi_interface_handle handle,
        u32 stats_clear_req_mask, u32 *stats_clear_rsp_mask, u8 stop_req, u8 *stop_rsp)
        : WifiCommand(handle, 0), mStatsClearReqMask(stats_clear_req_mask), mStatsClearRspMask(stats_clear_rsp_mask),
        mStopReq(stop_req), mStopRsp(stop_rsp)
    {
        memset(&mParams,0,sizeof(wifi_link_layer_params));
    }

    int createSetRequest(WifiRequest& request) {
        int result = request.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_LLS_SET_INFO);
        if (result < 0) {
            return result;
        }

        nlattr *data = request.attr_start(NL80211_ATTR_VENDOR_DATA);

        result = request.put_u32(LSTATS_ATTRIBUTE_SET_MPDU_SIZE_THRESHOLD, mParams.mpdu_size_threshold);
        if (result < 0) {
            return result;
        }

        result = request.put_u32(LSTATS_ATTRIBUTE_SET_AGGR_STATISTICS_GATHERING, mParams.aggressive_statistics_gathering);
        if (result < 0) {
            return result;
        }
        request.attr_end(data);
        return result;
    }

    int createClearRequest(WifiRequest& request) {
        int result = request.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_LLS_CLEAR_INFO);
        if (result < 0) {
            return result;
        }
        nlattr *data = request.attr_start(NL80211_ATTR_VENDOR_DATA);

        result = request.put_u32(LSTATS_ATTRIBUTE_CLEAR_STOP_REQUEST_MASK, mStatsClearReqMask);
        if (result < 0) {
            return result;
        }

        result = request.put_u32(LSTATS_ATTRIBUTE_CLEAR_STOP_REQUEST, mStopReq);
        if (result < 0) {
            return result;
        }
        request.attr_end(data);
        return result;
    }

    int start() {
        ALOGD("Starting Link Layer Statistics measurement (%d, %d)", mParams.mpdu_size_threshold, mParams.aggressive_statistics_gathering);
        WifiRequest request(familyId(), ifaceId());
        int result = createSetRequest(request);
        if (result < 0) {
            ALOGE("failed to set Link Layer Statistics (result:%d)", result);
            return result;
        }

        result = requestResponse(request);
        if (result < 0) {
            ALOGE("failed to Set Link Layer Statistics (result:%d)", result);
            return result;
        }

        return result;
    }

    virtual int clear() {
        ALOGD("Clearing Link Layer Statistics (%d, %d)", mStatsClearReqMask, mStopReq);
        WifiRequest request(familyId(), ifaceId());
        int result = createClearRequest(request);
        if (result < 0) {
            ALOGE("failed to clear Link Layer Statistics (result:%d)", result);
            return result;
        }

        result = requestResponse(request);
        if (result < 0) {
            ALOGE("failed to clear Link Layer Statistics (result:%d)", result);
            return result;
        }

        return result;
    }

    virtual int handleResponse(WifiEvent& reply) {
        /* Nothing to do on response! */
        return NL_SKIP;
    }
};


wifi_error wifi_set_link_stats(wifi_interface_handle iface, wifi_link_layer_params params)
{
    LinkLayerStatsCommand *command = new LinkLayerStatsCommand(iface, params);
    wifi_error result = (wifi_error)command->start();
    if (result != WIFI_SUCCESS) {
        ALOGE("failed to Set link layer stats (result:%d)", result);
    }
    return result;
}

wifi_error wifi_clear_link_stats(wifi_interface_handle iface,
        u32 stats_clear_req_mask, u32 *stats_clear_rsp_mask, u8 stop_req, u8 *stop_rsp)
{
    LinkLayerStatsCommand *command = new LinkLayerStatsCommand(iface, stats_clear_req_mask, stats_clear_rsp_mask, stop_req, stop_rsp);
    wifi_error result = (wifi_error)command->clear();
    if (result != WIFI_SUCCESS) {
        ALOGE("failed to Clear link layer stats (result:%d)", result);
        *stats_clear_rsp_mask = 0;
        *stop_rsp = 0;
    } else {
        *stats_clear_rsp_mask = stats_clear_req_mask;
        *stop_rsp = stop_req;
    }
    return result;
}


class GetLinkStatsCommand : public WifiCommand
{
    wifi_stats_result_handler mHandler;
    wifi_interface_handle iface;
public:
    GetLinkStatsCommand(wifi_interface_handle iface, wifi_stats_result_handler handler)
        : WifiCommand(iface, 0), mHandler(handler)
    {
        this->iface = iface;
    }

    virtual int create() {
        int ret = mMsg.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_LLS_GET_INFO);
        if (ret < 0) {
            ALOGE("Failed to create %x - %d", SLSI_NL80211_VENDOR_SUBCMD_LLS_GET_INFO, ret);
            return ret;
        }

        return ret;
    }

protected:
    virtual int handleResponse(WifiEvent& reply) {
        if (reply.get_cmd() != NL80211_CMD_VENDOR) {
            ALOGD("Ignoring reply with cmd = %d", reply.get_cmd());
            return NL_SKIP;
        }
        int id = reply.get_vendor_id();
        u8 *data = (u8 *)reply.get_vendor_data();
        int num_radios = 0, i = 0;
        num_radios = data[0];
        data += sizeof(data[0]);

        // assuming max peers is 16
        wifi_iface_stat *iface_stat = (wifi_iface_stat *) malloc(sizeof(wifi_iface_stat) + sizeof(wifi_peer_info) * 16);
        wifi_iface_stat *iface_stat2;
        iface_stat2 = iface_stat;
        if (!iface_stat) {
            ALOGE("Memory alloc failed for iface_stat in response handler!!!");
            return NL_SKIP;
        }

        // max channel is 39 (14 2.4GHz and 25 5GHz)
        wifi_radio_stat *radio_stat = (wifi_radio_stat *) malloc((num_radios * sizeof(wifi_radio_stat)) + sizeof(wifi_channel_stat) * 39);
        wifi_radio_stat *radio_stat2;
        radio_stat2 = radio_stat;
        if (!radio_stat) {
            ALOGE("Memory alloc failed for radio_stat in response handler!!!");
            free(iface_stat);
            return NL_SKIP;
        }

        /* Data sent from driver does not contain num_tx_levels and tx_time per level. So copy
         * radio data in two parts - 1st part until num_tx_levels and 2nd part from rx_time.
         * channel data is copied separately
         */
        int radio_data_len1,radio_data_len2;
        radio_data_len1 = (u8 *)&(radio_stat->num_tx_levels) - (u8*)radio_stat;
        radio_data_len2 = (u8 *)(radio_stat->channels) - (u8*)&(radio_stat->rx_time);

        int iface_data_len1;
        iface_data_len1 = (u8 *)&(iface_stat->peer_info) - (u8*)iface_stat;

        //kernel is 64 bit. if userspace is 64 bit, typecastting buffer works else, make corrections
        if (sizeof(iface_stat->iface) == 8) {
            memcpy(iface_stat2, data, iface_data_len1);
            data += iface_data_len1;

            for (i = 0; i < iface_stat2->num_peers; i++) {
                memcpy(&iface_stat2->peer_info[i].type, data, sizeof(wifi_peer_type));
                data += sizeof(wifi_peer_type);
                memcpy(iface_stat2->peer_info[i].peer_mac_address, data, (sizeof(u8) * 6));
                data += (sizeof(u8) * 6) + 2; //for allignment skip 2 bytes
                memcpy(&iface_stat2->peer_info[i].capabilities, data, sizeof(u32));
                data += sizeof(u32);
                memcpy(&iface_stat2->peer_info[i].num_rate, data, sizeof(u32));
                data += sizeof(u32);
            }
        } else {
            /* for 64 bit kernel ad 32 bit user space, there is 4 byte extra at the begining and another 4 byte pad after 80 bytes
             * so remove first 4 and 81-84 bytes from NL buffer.*/
            data += 4;
            memcpy(iface_stat, data, 80);
            data += 80 + 4; //for allignment skip 4 bytes
            memcpy(((u8 *)iface_stat) + 80, data, sizeof(wifi_iface_stat) - 80);
            data += sizeof(wifi_iface_stat) - 80;
            for (i = 0; i < iface_stat->num_peers; i++) {
                memcpy(&iface_stat->peer_info[i].type, data, sizeof(wifi_peer_type));
                data += sizeof(wifi_peer_type);
                memcpy(iface_stat->peer_info[i].peer_mac_address, data, (sizeof(u8) * 6));
                data += (sizeof(u8) * 6) + 2; //for allignment skip 2 bytes
                memcpy(&iface_stat->peer_info[i].capabilities, data, sizeof(u32));
                data += sizeof(u32);
                memcpy(&iface_stat->peer_info[i].num_rate, data, sizeof(u32));
                data += sizeof(u32);
            }
        }

        for (i = 0; i < num_radios; i++) {
            memcpy(radio_stat2, data, radio_data_len1);
            data += radio_data_len1;
            memcpy(&radio_stat2->rx_time, data, radio_data_len2);
            data += radio_data_len2;
            memcpy(radio_stat2->channels, data, sizeof(wifi_channel_stat)* radio_stat2->num_channels);
            radio_stat2->num_tx_levels = 0;
            radio_stat2->tx_time_per_levels = NULL;
            data += sizeof(wifi_channel_stat)* radio_stat2->num_channels;
            radio_stat2=(wifi_radio_stat *) ((u8 *)radio_stat2+ sizeof(wifi_radio_stat) +
                        (sizeof(wifi_channel_stat) * radio_stat2->num_channels ));
        }
        iface_stat->iface = iface;
        (*mHandler.on_link_stats_results)(id, iface_stat, num_radios, radio_stat);
        free(iface_stat);
        free(radio_stat);
        return NL_OK;
    }
};

wifi_error wifi_get_link_stats(wifi_request_id id,
        wifi_interface_handle iface, wifi_stats_result_handler handler)
{
    GetLinkStatsCommand command(iface, handler);
    return (wifi_error) command.requestResponse();
}


