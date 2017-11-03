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

#include <utils/Log.h>

#include "wifi_hal.h"
#include "common.h"
#include "cpp_bindings.h"

#define REQUEST_ID_MAX 1000
#define get_requestid() ((arc4random()%REQUEST_ID_MAX) + 1)

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

        for (int i = 0; i < mParams->num_bssid; i++) {
            result = request.put_addr(GSCAN_ATTRIBUTE_BLACKLIST_BSSID, mParams->bssids[i]);
            if (result < 0) {
                return result;
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

/*to be implemented*/
wifi_error wifi_get_roaming_capabilities(wifi_interface_handle iface,
                                         wifi_roaming_capabilities *caps);

/*to be implemented*/
wifi_error wifi_enable_firmware_roaming(wifi_interface_handle handle,
                                        fw_roaming_state_t state);

wifi_error wifi_configure_roaming(wifi_interface_handle iface, wifi_roaming_config *roaming_config)
{
    wifi_error ret;
    int requestId;
    wifi_bssid_params bssid_params;
    wifi_handle wifiHandle = getWifiHandle(iface);

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
