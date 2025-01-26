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

#define LOG_TAG  "WifiHAL"

#include <log/log.h>

#include "wifi_hal.h"
#include "common.h"
#include "cpp_bindings.h"

#define REQUEST_ID_MAX 1000
#define get_requestid() ((arc4random()%REQUEST_ID_MAX) + 1)

enum roam_attributes {
    SLSI_ATTR_ROAM_CAPABILITY_BLACKLIST_SIZE,
    SLSI_ATTR_ROAM_CAPABILITY_WHITELIST_SIZE,
    SLSI_ATTR_ROAM_STATE,
    SLSI_ATTR_ROAM_MAX
};

class BssidBlacklistCommand : public WifiCommand
{
private:
    wifi_bssid_params *mParams;
public:
    BssidBlacklistCommand(wifi_interface_handle handle, int id,
            wifi_bssid_params *params)
        : WifiCommand(handle, id), mParams(params)
    { }
     int createRequest(WifiRequest& request) {
        int result = request.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_SET_BSSID_BLACKLIST);
        if (result < 0) {
            return result;
        }

        nlattr *data = request.attr_start(NL80211_ATTR_VENDOR_DATA);
        result = request.put_u32(GSCAN_ATTRIBUTE_NUM_BSSID, mParams->num_bssid);
        if (result < 0) {
            return result;
        }

        if (mParams->num_bssid > 0) {
            for (int i = 0; i < mParams->num_bssid; i++) {
                result = request.put_addr(GSCAN_ATTRIBUTE_BLACKLIST_BSSID, mParams->bssids[i]);
                if (result < 0) {
                    return result;
                }
            }
        }
        request.attr_end(data);
        return result;
    }

    int start() {
        WifiRequest request(familyId(), ifaceId());
        int result = createRequest(request);
        if (result < 0) {
            return result;
        }

        result = requestResponse(request);
        if (result < 0) {
            ALOGE("Failed to execute bssid blacklist request, result = %d", result);
            return result;
        }

        return result;
    }


    virtual int handleResponse(WifiEvent& reply) {
        /* Nothing to do on response! */
        return NL_SKIP;
    }
};

wifi_error wifi_set_bssid_blacklist(wifi_request_id id, wifi_interface_handle iface,
        wifi_bssid_params params)
{
    BssidBlacklistCommand *cmd = new BssidBlacklistCommand(iface, id, &params);
    wifi_error result = (wifi_error)cmd->start();
    //release the reference of command as well
    cmd->releaseRef();
    return result;
}


class RoamingCapabilitiesCommand : public WifiCommand
{
private:
    wifi_roaming_capabilities *mCaps;

public:
    RoamingCapabilitiesCommand(wifi_interface_handle handle, wifi_roaming_capabilities *caps)
        : WifiCommand(handle, 0) {
        mCaps = caps;
    }

    virtual int create() {
        int ret;

        ret = mMsg.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_GET_ROAMING_CAPABILITIES);
        if (ret < 0) {
             ALOGE("Can't create message to send to driver - %d", ret);
             return ret;
        }
        return WIFI_SUCCESS;

    }

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

        for (nl_iterator it(vendor_data); it.has_next(); it.next()) {
            switch(it.get_type()) {
                case SLSI_ATTR_ROAM_CAPABILITY_BLACKLIST_SIZE:
                    mCaps->max_blacklist_size = it.get_u32();
                    break;
                case SLSI_ATTR_ROAM_CAPABILITY_WHITELIST_SIZE:
                    mCaps->max_whitelist_size = it.get_u32();
                    break;
                default :
                    break;
            }
        }
        return NL_OK;
    }
};

wifi_error wifi_get_roaming_capabilities(wifi_interface_handle handle,
                                         wifi_roaming_capabilities *caps)
{
    RoamingCapabilitiesCommand cmd(handle, caps);
    return (wifi_error) cmd.requestResponse();
}

class RoamingStateCommand : public WifiCommand
{
private:
    fw_roaming_state_t mRoamingState;

public:
    RoamingStateCommand(wifi_interface_handle handle, fw_roaming_state_t roaming_state)
        : WifiCommand(handle, 0) {
        mRoamingState = roaming_state;
    }

    virtual int create() {
        int ret;
        ret = mMsg.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_SET_ROAMING_STATE);
        if (ret < 0) {
             ALOGE("Can't create message to send to driver - %d", ret);
             return ret;
        }

        nlattr *data = mMsg.attr_start(NL80211_ATTR_VENDOR_DATA);
        ret = mMsg.put_u8(SLSI_ATTR_ROAM_STATE, mRoamingState);
        if (ret < 0) {
            return ret;
        }
        mMsg.attr_end(data);
        return WIFI_SUCCESS;
    }
};

wifi_error wifi_enable_firmware_roaming(wifi_interface_handle handle, fw_roaming_state_t state) {
    RoamingStateCommand cmd(handle, state);
    wifi_error ret = (wifi_error) cmd.requestResponse();
    return ret;
}

wifi_error wifi_configure_roaming(wifi_interface_handle iface, wifi_roaming_config *roaming_config)
{
    wifi_error ret;
    int requestId;
    wifi_bssid_params bssid_params;

    if (!roaming_config) {
        ALOGE("%s: Invalid Buffer provided. Exit", __FUNCTION__);
        return WIFI_ERROR_INVALID_ARGS;
    }

    /* Generate request id randomly*/
    requestId = get_requestid();
    bssid_params.num_bssid = roaming_config->num_blacklist_bssid;


    memcpy(bssid_params.bssids, roaming_config->blacklist_bssid,
           (bssid_params.num_bssid * sizeof(mac_addr)));

    ret = wifi_set_bssid_blacklist(requestId, iface, bssid_params);
    if (ret != WIFI_SUCCESS) {
        ALOGE("%s: Failed to configure blacklist bssids", __FUNCTION__);
        return WIFI_ERROR_UNKNOWN;
    }

    return ret;
}
