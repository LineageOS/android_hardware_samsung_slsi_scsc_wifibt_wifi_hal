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

typedef enum {
    EPNO_ATTRIBUTE_MINIMUM_5G_RSSI = WIFI_HAL_ATTR_START,
    EPNO_ATTRIBUTE_MINIMUM_2G_RSSI,
    EPNO_ATTRIBUTE_INITIAL_SCORE_MAX,
    EPNO_ATTRIBUTE_CUR_CONN_BONUS,
    EPNO_ATTRIBUTE_SAME_NETWORK_BONUS,
    EPNO_ATTRIBUTE_SECURE_BONUS,
    EPNO_ATTRIBUTE_5G_BONUS,
    EPNO_ATTRIBUTE_SSID_NUM,
    EPNO_ATTRIBUTE_SSID_LIST,
    EPNO_ATTRIBUTE_SSID,
    EPNO_ATTRIBUTE_SSID_LEN,
    EPNO_ATTRIBUTE_FLAGS,
    EPNO_ATTRIBUTE_AUTH,
    EPNO_ATTRIBUTE_MAX
} EPNO_ATTRIBUTE;

typedef enum {
    EPNO_ATTRIBUTE_HS_PARAM_LIST = WIFI_HAL_ATTR_START,
    EPNO_ATTRIBUTE_HS_NUM,
    EPNO_ATTRIBUTE_HS_ID,
    EPNO_ATTRIBUTE_HS_REALM,
    EPNO_ATTRIBUTE_HS_CONSORTIUM_IDS,
    EPNO_ATTRIBUTE_HS_PLMN,
    EPNO_ATTRIBUTE_HS_MAX
} EPNO_HS_ATTRIBUTE;


class GetCapabilitiesCommand : public WifiCommand
{
    wifi_gscan_capabilities *mCapabilities;
public:
    GetCapabilitiesCommand(wifi_interface_handle iface, wifi_gscan_capabilities *capabitlites)
        : WifiCommand(iface, 0), mCapabilities(capabitlites)
    {
        memset(mCapabilities, 0, sizeof(*mCapabilities));
    }

    virtual int create() {
        int ret = mMsg.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_GET_CAPABILITIES);
        if (ret < 0) {
            ALOGE("NL message creation failed");
            return ret;
        }

        return ret;
    }

protected:
    virtual int handleResponse(WifiEvent& reply) {

        if (reply.get_cmd() != NL80211_CMD_VENDOR) {
            ALOGE("Ignoring reply with cmd = %d", reply.get_cmd());
            return NL_SKIP;
        }

        void *data = reply.get_vendor_data();
        int len = reply.get_vendor_data_len();

        memcpy(mCapabilities, data, min(len, (int) sizeof(*mCapabilities)));

        return NL_OK;
    }
};


wifi_error wifi_get_gscan_capabilities(wifi_interface_handle handle,
        wifi_gscan_capabilities *capabilities)
{
    GetCapabilitiesCommand command(handle, capabilities);
    return (wifi_error) command.requestResponse();
}

class GetChannelListCommand : public WifiCommand
{
    wifi_channel *channels;
    int max_channels;
    int *num_channels;
    int band;
public:
    GetChannelListCommand(wifi_interface_handle iface, wifi_channel *channel_buf, int *ch_num,
        int num_max_ch, int band)
        : WifiCommand(iface, 0), channels(channel_buf), max_channels(num_max_ch), num_channels(ch_num),
        band(band)
    {
        memset(channels, 0, sizeof(wifi_channel) * max_channels);
    }
    virtual int create() {
        int ret = mMsg.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_GET_VALID_CHANNELS);
        if (ret < 0) {
            return ret;
        }

        nlattr *data = mMsg.attr_start(NL80211_ATTR_VENDOR_DATA);
        ret = mMsg.put_u32(GSCAN_ATTRIBUTE_BAND, band);
        if (ret < 0) {
            return ret;
        }

        mMsg.attr_end(data);

        return ret;
    }

protected:
    virtual int handleResponse(WifiEvent& reply) {

        if (reply.get_cmd() != NL80211_CMD_VENDOR) {
            ALOGE("Ignoring reply with cmd = %d", reply.get_cmd());
            return NL_SKIP;
        }

        int num_channels_to_copy = 0;

        nlattr *vendor_data = reply.get_attribute(NL80211_ATTR_VENDOR_DATA);
        int len = reply.get_vendor_data_len();

        if (vendor_data == NULL || len == 0) {
            ALOGE("no vendor data in GetChannelList response; ignoring it");
            return NL_SKIP;
        }

        for (nl_iterator it(vendor_data); it.has_next(); it.next()) {
            if (it.get_type() == GSCAN_ATTRIBUTE_NUM_CHANNELS) {
                num_channels_to_copy = it.get_u32();
                /*ALOGD("Got channel list with %d channels", num_channels_to_copy);*/
                if(num_channels_to_copy > max_channels)
                    num_channels_to_copy = max_channels;
                *num_channels = num_channels_to_copy;
            } else if (it.get_type() == GSCAN_ATTRIBUTE_CHANNEL_LIST && num_channels_to_copy) {
                memcpy(channels, it.get_data(), sizeof(int) * num_channels_to_copy);
            } else {
                ALOGW("Ignoring invalid attribute type = %d, size = %d",
                        it.get_type(), it.get_len());
            }
        }

        return NL_OK;
    }
};

wifi_error wifi_get_valid_channels(wifi_interface_handle handle,
        int band, int max_channels, wifi_channel *channels, int *num_channels)
{
    GetChannelListCommand command(handle, channels, num_channels,
                                        max_channels, band);
    return (wifi_error) command.requestResponse();
}
/////////////////////////////////////////////////////////////////////////////

/* helper functions */

/*
static int parseScanResults(wifi_scan_result *results, int num, nlattr *attr)
{
    memset(results, 0, sizeof(wifi_scan_result) * num);

    int i = 0;
    for (nl_iterator it(attr); it.has_next() && i < num; it.next(), i++) {

        nlattr *sc_data = (nlattr *) it.get_data();
        wifi_scan_result *result = results + i;

        for (nl_iterator it2(sc_data); it2.has_next(); it2.next()) {
            int type = it2.get_type();
            if (type == GSCAN_ATTRIBUTE_SSID) {
                strncpy(result->ssid, (char *) it2.get_data(), it2.get_len());
                result->ssid[it2.get_len()] = 0;
            } else if (type == GSCAN_ATTRIBUTE_BSSID) {
                memcpy(result->bssid, (byte *) it2.get_data(), sizeof(mac_addr));
            } else if (type == GSCAN_ATTRIBUTE_TIMESTAMP) {
                result->ts = it2.get_u64();
            } else if (type == GSCAN_ATTRIBUTE_CHANNEL) {
                result->ts = it2.get_u16();
            } else if (type == GSCAN_ATTRIBUTE_RSSI) {
                result->rssi = it2.get_u8();
            } else if (type == GSCAN_ATTRIBUTE_RTT) {
                result->rtt = it2.get_u64();
            } else if (type == GSCAN_ATTRIBUTE_RTTSD) {
                result->rtt_sd = it2.get_u64();
            }
        }

    }

    if (i >= num) {
        ALOGE("Got too many results; skipping some");
    }

    return i;
}
*/

int createFeatureRequest(WifiRequest& request, int subcmd) {

    int result = request.create(GOOGLE_OUI, subcmd);
    if (result < 0) {
        return result;
    }

    return WIFI_SUCCESS;
}

class ScanCommand : public WifiCommand
{
    wifi_scan_cmd_params *mParams;
    wifi_scan_result_handler mHandler;
    static unsigned mGlobalFullScanBuckets;
public:
    ScanCommand(wifi_interface_handle iface, int id, wifi_scan_cmd_params *params,
                wifi_scan_result_handler handler)
        : WifiCommand(iface, id), mParams(params), mHandler(handler)
    { }

    int createSetupRequest(WifiRequest& request) {
        int result = request.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_ADD_GSCAN);
        if (result < 0) {
            return result;
        }

        nlattr *data = request.attr_start(NL80211_ATTR_VENDOR_DATA);
        result = request.put_u32(GSCAN_ATTRIBUTE_BASE_PERIOD, mParams->base_period);
        if (result < 0) {
            return result;
        }

        result = request.put_u32(GSCAN_ATTRIBUTE_NUM_AP_PER_SCAN, mParams->max_ap_per_scan);
        if (result < 0) {
            return result;
        }

        result = request.put_u32(GSCAN_ATTRIBUTE_REPORT_THRESHOLD, mParams->report_threshold_percent);
        if (result < 0) {
            return result;
        }

        result = request.put_u32(GSCAN_ATTRIBUTE_REPORT_THRESHOLD_NUM_SCANS, mParams->report_threshold_num_scans);
        if (result < 0) {
            return result;
        }

        result = request.put_u32(GSCAN_ATTRIBUTE_NUM_BUCKETS, mParams->num_buckets);
        if (result < 0) {
            return result;
        }

        for (int i = 0; i < mParams->num_buckets; i++) {
            nlattr * bucket = request.attr_start(i);    // next bucket
            result = request.put_u32(GSCAN_ATTRIBUTE_BUCKET_ID, mParams->buckets[i].bucket);
            if (result < 0) {
                return result;
            }
            result = request.put_u32(GSCAN_ATTRIBUTE_BUCKET_PERIOD, mParams->buckets[i].period);
            if (result < 0) {
                return result;
            }
            result = request.put_u32(GSCAN_ATTRIBUTE_BUCKETS_BAND,
                    mParams->buckets[i].band);
            if (result < 0) {
                return result;
            }

            if (mParams->buckets[i].report_events == 0) {
                mParams->buckets[i].report_events = REPORT_EVENTS_EACH_SCAN;
            }
            result = request.put_u32(GSCAN_ATTRIBUTE_REPORT_EVENTS,
                    mParams->buckets[i].report_events);
            if (result < 0) {
                return result;
            }

            result = request.put_u32(GSCAN_ATTRIBUTE_BUCKET_NUM_CHANNELS,
                    mParams->buckets[i].num_channels);
            if (result < 0) {
                return result;
            }

            result = request.put_u32(GSCAN_ATTRIBUTE_BUCKET_EXPONENT,
                    mParams->buckets[i].base);
            if (result < 0) {
                return result;
            }

            result = request.put_u32(GSCAN_ATTRIBUTE_BUCKET_MAX_PERIOD,
                    mParams->buckets[i].max_period);
            if (result < 0) {
                return result;
            }

            result = request.put_u32(GSCAN_ATTRIBUTE_BUCKET_STEP_COUNT,
                    mParams->buckets[i].step_count);
            if (result < 0) {
                return result;
            }

            if (mParams->buckets[i].num_channels) {
                nlattr *channels = request.attr_start(GSCAN_ATTRIBUTE_BUCKET_CHANNELS);
                for (int j = 0; j < mParams->buckets[i].num_channels; j++) {
                    result = request.put_u32(j, mParams->buckets[i].channels[j].channel);
                    if (result < 0) {
                        return result;
                    }
                }
                request.attr_end(channels);
            }

            request.attr_end(bucket);
        }

        request.attr_end(data);
        return WIFI_SUCCESS;
    }

    int createStartRequest(WifiRequest& request) {
        return createFeatureRequest(request, SLSI_NL80211_VENDOR_SUBCMD_ADD_GSCAN);
    }

    int createStopRequest(WifiRequest& request) {
        return createFeatureRequest(request, SLSI_NL80211_VENDOR_SUBCMD_DEL_GSCAN);
    }

    int start() {
        ALOGD("starting Gscan");
        WifiRequest request(familyId(), ifaceId());
        int result = createSetupRequest(request);
        if (result != WIFI_SUCCESS) {
            ALOGE("failed to create setup request; result = %d", result);
            return result;
        }

        registerVendorHandler(GOOGLE_OUI, GSCAN_EVENT_SCAN_RESULTS_AVAILABLE);
        registerVendorHandler(GOOGLE_OUI, GSCAN_EVENT_COMPLETE_SCAN);

        int nBuckets = 0;
        for (int i = 0; i < mParams->num_buckets; i++) {
            if (mParams->buckets[i].report_events & REPORT_EVENTS_FULL_RESULTS) {
                nBuckets++;
            }
        }

        if (nBuckets != 0) {
           ALOGI("Full scan requested with nBuckets = %d", nBuckets);
           registerVendorHandler(GOOGLE_OUI, GSCAN_EVENT_FULL_SCAN_RESULTS);
        }
        result = requestResponse(request);
        if (result != WIFI_SUCCESS) {
            ALOGE("failed to start scan; result = %d", result);
            unregisterVendorHandler(GOOGLE_OUI, GSCAN_EVENT_COMPLETE_SCAN);
            unregisterVendorHandler(GOOGLE_OUI, GSCAN_EVENT_SCAN_RESULTS_AVAILABLE);
            return result;
        }


        return result;
    }

    virtual int cancel() {
        ALOGD("Stopping Gscan");

        WifiRequest request(familyId(), ifaceId());
        int result = createStopRequest(request);
        if (result != WIFI_SUCCESS) {
            ALOGE("failed to create stop request; result = %d", result);
        } else {
            result = requestResponse(request);
            if (result != WIFI_SUCCESS) {
                ALOGE("failed to stop scan; result = %d", result);
            }
        }

        unregisterVendorHandler(GOOGLE_OUI, GSCAN_EVENT_COMPLETE_SCAN);
        unregisterVendorHandler(GOOGLE_OUI, GSCAN_EVENT_SCAN_RESULTS_AVAILABLE);
        unregisterVendorHandler(GOOGLE_OUI, GSCAN_EVENT_FULL_SCAN_RESULTS);

        return WIFI_SUCCESS;
    }

    virtual int handleResponse(WifiEvent& reply) {
        /* Nothing to do on response! */
        return NL_SKIP;
    }

    virtual int handleEvent(WifiEvent& event) {
        //event.log();

        nlattr *vendor_data = event.get_attribute(NL80211_ATTR_VENDOR_DATA);
        unsigned int len = event.get_vendor_data_len();
        int event_id = event.get_vendor_subcmd();

        if(event_id == GSCAN_EVENT_COMPLETE_SCAN) {
            if (vendor_data == NULL || len != 4) {
                ALOGE("Scan complete type not mentioned!");
                return NL_SKIP;
            }
            wifi_scan_event evt_type;

            evt_type = (wifi_scan_event) event.get_u32(NL80211_ATTR_VENDOR_DATA);
            if(*mHandler.on_scan_event)
                (*mHandler.on_scan_event)(id(), evt_type);
        } else if(event_id == GSCAN_EVENT_FULL_SCAN_RESULTS) {
            uint32_t bucket_scanned = 0;
            wifi_scan_result *scan_result = NULL;
            for (nl_iterator it(vendor_data); it.has_next(); it.next()) {
                if (it.get_type() == GSCAN_ATTRIBUTE_SCAN_BUCKET_BIT) {
                    bucket_scanned = it.get_u32();
                } else if (it.get_type() == GSCAN_ATTRIBUTE_SCAN_RESULTS) {
                    if (it.get_len() >= (int)sizeof(*scan_result))
                        scan_result = (wifi_scan_result *)it.get_data();
                }
            }
            if (scan_result) {
                if(*mHandler.on_full_scan_result)
                    (*mHandler.on_full_scan_result)(id(), scan_result, bucket_scanned);
/*
                    ALOGD("%-32s\t", scan_result->ssid);
                    ALOGD("%02x:%02x:%02x:%02x:%02x:%02x ", scan_result->bssid[0], scan_result->bssid[1],
                            scan_result->bssid[2], scan_result->bssid[3], scan_result->bssid[4], scan_result->bssid[5]);
                    ALOGD("%d\t", scan_result->rssi);
                    ALOGD("%d\t", scan_result->channel);
                    ALOGD("%lld\t", scan_result->ts);
                    ALOGD("%lld\t", scan_result->rtt);
                    ALOGD("%lld\n", scan_result->rtt_sd);
*/
            }
        }
        return NL_SKIP;
    }
};

unsigned ScanCommand::mGlobalFullScanBuckets = 0;

wifi_error wifi_start_gscan(
        wifi_request_id id,
        wifi_interface_handle iface,
        wifi_scan_cmd_params params,
        wifi_scan_result_handler handler)
{
    wifi_handle handle = getWifiHandle(iface);

    ScanCommand *cmd = new ScanCommand(iface, id, &params, handler);
    wifi_register_cmd(handle, id, cmd);
    return (wifi_error)cmd->start();
}

wifi_error wifi_stop_gscan(wifi_request_id id, wifi_interface_handle iface)
{
    wifi_handle handle = getWifiHandle(iface);

    if(id == -1) {
        wifi_scan_result_handler handler;
        wifi_scan_cmd_params dummy_params;
        memset(&handler, 0, sizeof(handler));

        ScanCommand *cmd = new ScanCommand(iface, id, &dummy_params, handler);
        cmd->cancel();
        cmd->releaseRef();
        return WIFI_SUCCESS;
    }


    WifiCommand *cmd = wifi_unregister_cmd(handle, id);
    if (cmd) {
        cmd->cancel();
        cmd->releaseRef();
        return WIFI_SUCCESS;
    }

    return WIFI_ERROR_INVALID_ARGS;
}

class GetScanResultsCommand : public WifiCommand {
    wifi_cached_scan_results *mScans;
    int mMax;
    int *mNum;
    int mRetrieved;
    byte mFlush;
    int mCompleted;
    static const int MAX_RESULTS = 320;
    wifi_scan_result mScanResults[MAX_RESULTS];
    int mNextScanResult;
public:
    GetScanResultsCommand(wifi_interface_handle iface, byte flush,
            wifi_cached_scan_results *results, int max, int *num)
        : WifiCommand(iface, -1), mScans(results), mMax(max), mNum(num),
                mRetrieved(0), mFlush(flush), mCompleted(0)
    {
        memset(mScanResults,0,sizeof(mScanResults));
        mNextScanResult = 0;
    }

    int createRequest(WifiRequest& request, int num, byte flush) {
        int result = request.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_GET_SCAN_RESULTS);
        if (result < 0) {
            return result;
        }

        nlattr *data = request.attr_start(NL80211_ATTR_VENDOR_DATA);
        result = request.put_u32(GSCAN_ATTRIBUTE_NUM_OF_RESULTS, num);
        if (result < 0) {
            return result;
        }

        request.attr_end(data);
        return WIFI_SUCCESS;
    }

    int execute() {
        WifiRequest request(familyId(), ifaceId());

        for (int i = 0; i < 10 && mRetrieved < mMax; i++) {
            int result = createRequest(request, (mMax - mRetrieved), mFlush);
            if (result < 0) {
                ALOGE("failed to create request");
                return result;
            }

            int prev_retrieved = mRetrieved;

            result = requestResponse(request);

            if (result != WIFI_SUCCESS) {
                ALOGE("failed to retrieve scan results; result = %d", result);
                return result;
            }

            if (mRetrieved == prev_retrieved || mCompleted) {
                /* no more items left to retrieve */
                break;
            }

            request.destroy();
        }

        ALOGE("GetScanResults read %d results", mRetrieved);
        *mNum = mRetrieved;
        return WIFI_SUCCESS;
    }

    virtual int handleResponse(WifiEvent& reply) {

        if (reply.get_cmd() != NL80211_CMD_VENDOR) {
            ALOGE("Ignoring reply with cmd = %d", reply.get_cmd());
            return NL_SKIP;
        }

        nlattr *vendor_data = reply.get_attribute(NL80211_ATTR_VENDOR_DATA);
        int len = reply.get_vendor_data_len();

        if (vendor_data == NULL || len == 0) {
            ALOGE("no vendor data in GetScanResults response; ignoring it");
            return NL_SKIP;
        }

        for (nl_iterator it(vendor_data); it.has_next(); it.next()) {
            if (it.get_type() == GSCAN_ATTRIBUTE_SCAN_RESULTS_COMPLETE) {
                mCompleted = it.get_u8();
                //ALOGD("retrieved mCompleted flag : %d", mCompleted);
            } else if (it.get_type() == GSCAN_ATTRIBUTE_SCAN_RESULTS || it.get_type() == 0) {
                int scan_id = 0, flags = 0, num = 0;
                for (nl_iterator it2(it.get()); it2.has_next(); it2.next()) {
                    if (it2.get_type() == GSCAN_ATTRIBUTE_SCAN_ID) {
                        scan_id = it2.get_u32();
                        //ALOGD("retrieved scan_id : 0x%0x", scan_id);
                    } else if (it2.get_type() == GSCAN_ATTRIBUTE_SCAN_FLAGS) {
                        flags = it2.get_u8();
                        //ALOGD("retrieved scan_flags : 0x%0x", flags);
                    } else if (it2.get_type() == GSCAN_ATTRIBUTE_NUM_OF_RESULTS) {
                        num = it2.get_u32();
                        //ALOGD("retrieved num_results: %d", num);
                    } else if (it2.get_type() == GSCAN_ATTRIBUTE_SCAN_RESULTS) {
                        if (mRetrieved >= mMax) {
                            ALOGW("Stored %d scans, ignoring excess results", mRetrieved);
                            break;
                        }
                        num = it2.get_len() / sizeof(wifi_scan_result);
                        num = min(MAX_RESULTS - mNextScanResult, num);
                        num = min((int)MAX_AP_CACHE_PER_SCAN, num);
                        memcpy(mScanResults + mNextScanResult, it2.get_data(),
                                sizeof(wifi_scan_result) * num);
                        /*
                        wifi_scan_result *results = (wifi_scan_result *)it2.get_data();
                        for (int i = 0; i < num; i++) {
                            wifi_scan_result *result = results + i;
                            ALOGD("%02d  %-32s  %02x:%02x:%02x:%02x:%02x:%02x  %04d", i,
                                result->ssid, result->bssid[0], result->bssid[1], result->bssid[2],
                                result->bssid[3], result->bssid[4], result->bssid[5],
                                result->rssi);
                        }*/
                        mScans[mRetrieved].scan_id = scan_id;
                        mScans[mRetrieved].flags = flags;
                        mScans[mRetrieved].num_results = num;
                        //ALOGD("Setting result of scan_id : 0x%0x", mScans[mRetrieved].scan_id);
                        memcpy(mScans[mRetrieved].results,
                                &(mScanResults[mNextScanResult]), num * sizeof(wifi_scan_result));
                        mNextScanResult += num;
                        mRetrieved++;
                    } else {
                        ALOGW("Ignoring invalid attribute type = %d, size = %d",
                                it.get_type(), it.get_len());
                    }
                }
            } else {
                ALOGW("Ignoring invalid attribute type = %d, size = %d",
                        it.get_type(), it.get_len());
            }
        }

        return NL_OK;
    }
};

wifi_error wifi_get_cached_gscan_results(wifi_interface_handle iface, byte flush,
        int max, wifi_cached_scan_results *results, int *num) {
    GetScanResultsCommand *cmd = new GetScanResultsCommand(iface, flush, results, max, num);
    return (wifi_error)cmd->execute();
}

/////////////////////////////////////////////////////////////////////////////
class ePNOCommand : public WifiCommand
{
private:
    wifi_epno_params  *epno_params;
    wifi_epno_handler mHandler;
    wifi_scan_result  mResults;
public:
    ePNOCommand(wifi_interface_handle handle, int id,
            wifi_epno_params *params, wifi_epno_handler handler)
        : WifiCommand(handle, id), mHandler(handler)
    {
        epno_params = params;
        memset(&mResults,0,sizeof(wifi_scan_result));
    }

    int createSetupRequest(WifiRequest& request) {
        int result = request.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_SET_EPNO_LIST);
        if (result < 0) {
            return result;
        }

        nlattr *data = request.attr_start(NL80211_ATTR_VENDOR_DATA);
        if (epno_params == NULL) {
            result = request.put_u8(EPNO_ATTRIBUTE_SSID_NUM, 0);
            if (result < 0) {
                return result;
            }
            request.attr_end(data);
            return result;
        }
        result = request.put_u16(EPNO_ATTRIBUTE_MINIMUM_5G_RSSI, epno_params->min5GHz_rssi);
        if (result < 0) {
            return result;
        }
        result = request.put_u16(EPNO_ATTRIBUTE_MINIMUM_2G_RSSI, epno_params->min24GHz_rssi);
        if (result < 0) {
            return result;
        }
        result = request.put_u16(EPNO_ATTRIBUTE_INITIAL_SCORE_MAX, epno_params->initial_score_max);
        if (result < 0) {
            return result;
        }
        result = request.put_u8(EPNO_ATTRIBUTE_CUR_CONN_BONUS, epno_params->current_connection_bonus);
        if (result < 0) {
            return result;
        }
        result = request.put_u8(EPNO_ATTRIBUTE_SAME_NETWORK_BONUS, epno_params->same_network_bonus);
        if (result < 0) {
            return result;
        }
        result = request.put_u8(EPNO_ATTRIBUTE_SECURE_BONUS, epno_params->secure_bonus);
        if (result < 0) {
            return result;
        }
        result = request.put_u8(EPNO_ATTRIBUTE_5G_BONUS, epno_params->band5GHz_bonus);
        if (result < 0) {
            return result;
        }
        result = request.put_u8(EPNO_ATTRIBUTE_SSID_NUM, epno_params->num_networks);
        if (result < 0) {
            return result;
        }

       ALOGI("ePNO [min5GHz_rssi:%d min24GHz_rssi:%d initial_score_max:%d current_connection_bonus:%d same_network_bonus:%d secure_bonus:%d band5GHz_bonus:%d num_networks:%d]",
         epno_params->min5GHz_rssi,
         epno_params->min24GHz_rssi,
         epno_params->initial_score_max,
         epno_params->current_connection_bonus,
         epno_params->same_network_bonus,
         epno_params->secure_bonus,
         epno_params->band5GHz_bonus,
         epno_params->num_networks);

        struct nlattr * attr = request.attr_start(EPNO_ATTRIBUTE_SSID_LIST);
        for (int i = 0; i < epno_params->num_networks; i++) {
            nlattr *attr2 = request.attr_start(i);
            if (attr2 == NULL) {
                return WIFI_ERROR_OUT_OF_MEMORY;
            }
            result = request.put_u16(EPNO_ATTRIBUTE_FLAGS, epno_params->networks[i].flags);
            if (result < 0) {
                return result;
            }
            result = request.put_u8(EPNO_ATTRIBUTE_AUTH, epno_params->networks[i].auth_bit_field);
            if (result < 0) {
                return result;
            }
            result = request.put_u8(EPNO_ATTRIBUTE_SSID_LEN, strlen(epno_params->networks[i].ssid));
            if (result < 0) {
                return result;
            }
            result = request.put(EPNO_ATTRIBUTE_SSID, epno_params->networks[i].ssid, strlen(epno_params->networks[i].ssid));
            if (result < 0) {
                return result;
            }
            request.attr_end(attr2);
        }

        request.attr_end(attr);
        request.attr_end(data);
        return result;
    }

    int start() {
        ALOGI("ePNO num_network=%d", epno_params ? epno_params->num_networks : 0);
        WifiRequest request(familyId(), ifaceId());
        int result = createSetupRequest(request);
        if (result < 0) {
            return result;
        }

        result = requestResponse(request);
        if (result < 0) {
            ALOGI("Failed: ePNO setup request, result = %d", result);
            unregisterVendorHandler(GOOGLE_OUI, WIFI_EPNO_EVENT);
            return result;
        }

        if (epno_params) {
            registerVendorHandler(GOOGLE_OUI, WIFI_EPNO_EVENT);
        }
        return result;
    }

    virtual int cancel() {
        /* unregister event handler */
        unregisterVendorHandler(GOOGLE_OUI, WIFI_EPNO_EVENT);
        return 0;
    }

    virtual int handleResponse(WifiEvent& reply) {
        /* Nothing to do on response! */
        return NL_SKIP;
    }

    virtual int handleEvent(WifiEvent& event) {
        // event.log();

        nlattr *vendor_data = event.get_attribute(NL80211_ATTR_VENDOR_DATA);
        int len = event.get_vendor_data_len();

        if (vendor_data == NULL || len == 0) {
            ALOGI("No scan results found");
            return NL_SKIP;
        }


        mResults = *(wifi_scan_result *) event.get_vendor_data();
        if (*mHandler.on_network_found)
            (*mHandler.on_network_found)(id(), 1, &mResults);
        return NL_SKIP;
    }
};

wifi_error wifi_set_epno_list(wifi_request_id id,
                              wifi_interface_handle iface,
                              const wifi_epno_params *epno_params,
                              wifi_epno_handler handler)
{
    wifi_handle handle = getWifiHandle(iface);
    ePNOCommand *cmd = new ePNOCommand(iface, id, (wifi_epno_params *)epno_params, handler);
    wifi_register_cmd(handle, id, cmd);
    wifi_error result = (wifi_error)cmd->start();
    if (result != WIFI_SUCCESS) {
        wifi_unregister_cmd(handle, id);
    }
    return result;
}

wifi_error wifi_reset_epno_list(wifi_request_id id, wifi_interface_handle iface)
{
    wifi_handle handle = getWifiHandle(iface);
    wifi_epno_handler handler;

    handler.on_network_found = NULL;
    ePNOCommand *cmd = new ePNOCommand(iface, id, NULL, handler);
    wifi_register_cmd(handle, id, cmd);
    wifi_error result = (wifi_error)cmd->start();
    if (result != WIFI_SUCCESS) {
        wifi_unregister_cmd(handle, id);
    }
    return result;
}

class HsListCommand : public WifiCommand
{
    int num_hs;
    wifi_passpoint_network *mNetworks;
    wifi_passpoint_event_handler mHandler;
public:
    HsListCommand(wifi_request_id id, wifi_interface_handle iface,
        int num, wifi_passpoint_network *hs_list, wifi_passpoint_event_handler handler)
        : WifiCommand(iface, id), num_hs(num), mNetworks(hs_list),
            mHandler(handler)
    {
    }

    HsListCommand(wifi_request_id id, wifi_interface_handle iface,
        int num)
        : WifiCommand(iface, id), num_hs(num), mNetworks(NULL)
    {
        mHandler.on_passpoint_network_found = NULL;
    }

    int createRequest(WifiRequest& request, int val) {
        int result;

        if (val) {
            result = request.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_SET_HS_LIST);
            result = request.put_u32(EPNO_ATTRIBUTE_HS_NUM, num_hs);
            if (result < 0) {
                return result;
            }
            nlattr *data = request.attr_start(NL80211_ATTR_VENDOR_DATA);

            struct nlattr * attr = request.attr_start(EPNO_ATTRIBUTE_HS_PARAM_LIST);
            for (int i = 0; i < num_hs; i++) {
                nlattr *attr2 = request.attr_start(i);
                if (attr2 == NULL) {
                    return WIFI_ERROR_OUT_OF_MEMORY;
                }
                result = request.put_u32(EPNO_ATTRIBUTE_HS_ID, mNetworks[i].id);
                if (result < 0) {
                    return result;
                }
                result = request.put(EPNO_ATTRIBUTE_HS_REALM, mNetworks[i].realm, 256);
                if (result < 0) {
                    return result;
                }
                result = request.put(EPNO_ATTRIBUTE_HS_CONSORTIUM_IDS, mNetworks[i].roamingConsortiumIds, 128);
                if (result < 0) {
                    return result;
                }
                result = request.put(EPNO_ATTRIBUTE_HS_PLMN, mNetworks[i].plmn, 3);
                if (result < 0) {
                    return result;
                }
                request.attr_end(attr2);
            }
            request.attr_end(attr);
            request.attr_end(data);
        }else {
            result = request.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_RESET_HS_LIST);
            if (result < 0) {
                return result;
            }
        }

        return WIFI_SUCCESS;
    }

    int start() {

        WifiRequest request(familyId(), ifaceId());
        int result = createRequest(request, num_hs);
        if (result != WIFI_SUCCESS) {
            ALOGE("failed to create request; result = %d", result);
            return result;
        }

        registerVendorHandler(GOOGLE_OUI, WIFI_HOTSPOT_MATCH);

        result = requestResponse(request);
        if (result != WIFI_SUCCESS) {
            ALOGE("failed to set ANQPO networks; result = %d", result);
            unregisterVendorHandler(GOOGLE_OUI, WIFI_HOTSPOT_MATCH);
            return result;
        }

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
                ALOGE("failed to reset ANQPO networks;result = %d", result);
            }
        }

        unregisterVendorHandler(GOOGLE_OUI, WIFI_HOTSPOT_MATCH);
        return WIFI_SUCCESS;
    }

    virtual int handleResponse(WifiEvent& reply) {
        /* Nothing to do on response! */
        return NL_SKIP;
    }

    virtual int handleEvent(WifiEvent& event) {
        nlattr *vendor_data = event.get_attribute(NL80211_ATTR_VENDOR_DATA);
        unsigned int len = event.get_vendor_data_len();
        if (vendor_data == NULL || len < sizeof(wifi_scan_result)) {
            ALOGE("ERROR: No scan results found");
            return NL_SKIP;
        }

        wifi_scan_result *result = (wifi_scan_result *)event.get_vendor_data();
        byte *anqp = (byte *)result + offsetof(wifi_scan_result, ie_data) + result->ie_length;
        int networkId = *(int *)anqp;
        anqp += sizeof(int);
        int anqp_len = *(u16 *)anqp;
        anqp += sizeof(u16);

        if(*mHandler.on_passpoint_network_found)
            (*mHandler.on_passpoint_network_found)(id(), networkId, result, anqp_len, anqp);

        return NL_SKIP;
    }
};

wifi_error wifi_set_passpoint_list(wifi_request_id id, wifi_interface_handle iface, int num,
        wifi_passpoint_network *networks, wifi_passpoint_event_handler handler)
{
    wifi_handle handle = getWifiHandle(iface);
    HsListCommand *cmd = new HsListCommand(id, iface, num, networks, handler);

    wifi_register_cmd(handle, id, cmd);
    wifi_error result = (wifi_error)cmd->start();
    if (result != WIFI_SUCCESS) {
        wifi_unregister_cmd(handle, id);
    }
    return result;
}

wifi_error wifi_reset_passpoint_list(wifi_request_id id, wifi_interface_handle iface)
{
    wifi_handle   handle = getWifiHandle(iface);
    wifi_error    result;
    HsListCommand *cmd = (HsListCommand *)(wifi_get_cmd(handle, id));

    if (cmd == NULL) {
        cmd = new HsListCommand(id, iface, 0);
        wifi_register_cmd(handle, id, cmd);
    }
    result = (wifi_error)cmd->cancel();
    wifi_unregister_cmd(handle, id);
    return result;
}
