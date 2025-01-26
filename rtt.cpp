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

#include <string>
#include "nl80211_copy.h"

#include "sync.h"

#include <log/log.h>

#include "wifi_hal.h"
#include "common.h"
#include "cpp_bindings.h"
using namespace std;

typedef enum {
    SLSI_RTT_ATTRIBUTE_TARGET_CNT = WIFI_HAL_ATTR_START,
    SLSI_RTT_ATTRIBUTE_TARGET_INFO,
    SLSI_RTT_ATTRIBUTE_TARGET_MAC,
    SLSI_RTT_ATTRIBUTE_TARGET_TYPE,
    SLSI_RTT_ATTRIBUTE_TARGET_PEER,
    SLSI_RTT_ATTRIBUTE_TARGET_CHAN_FREQ,
    SLSI_RTT_ATTRIBUTE_TARGET_PERIOD,
    SLSI_RTT_ATTRIBUTE_TARGET_NUM_BURST,
    SLSI_RTT_ATTRIBUTE_TARGET_NUM_FTM_BURST,
    SLSI_RTT_ATTRIBUTE_TARGET_NUM_RETRY_FTM,
    SLSI_RTT_ATTRIBUTE_TARGET_NUM_RETRY_FTMR,
    SLSI_RTT_ATTRIBUTE_TARGET_LCI,
    SLSI_RTT_ATTRIBUTE_TARGET_LCR,
    SLSI_RTT_ATTRIBUTE_TARGET_BURST_DURATION,
    SLSI_RTT_ATTRIBUTE_TARGET_PREAMBLE,
    SLSI_RTT_ATTRIBUTE_TARGET_BW,
    SLSI_RTT_ATTRIBUTE_RESULTS_COMPLETE = 30,
    SLSI_RTT_ATTRIBUTE_RESULTS_PER_TARGET,
    SLSI_RTT_ATTRIBUTE_RESULT_CNT,
    SLSI_RTT_ATTRIBUTE_RESULT,
    SLSI_RTT_ATTRIBUTE_TARGET_ID,
    SLSI_RTT_ATTRIBUTE_MAX
} SLSI_RTT_ATTRIBUTE;

enum slsi_rtt_event_attributes {
	SLSI_RTT_EVENT_ATTR_ADDR     = 0,
	SLSI_RTT_EVENT_ATTR_BURST_NUM,
	SLSI_RTT_EVENT_ATTR_MEASUREMENT_NUM,
	SLSI_RTT_EVENT_ATTR_SUCCESS_NUM,
	SLSI_RTT_EVENT_ATTR_NUM_PER_BURST_PEER,
	SLSI_RTT_EVENT_ATTR_STATUS,
	SLSI_RTT_EVENT_ATTR_RETRY_AFTER_DURATION,
	SLSI_RTT_EVENT_ATTR_TYPE,
	SLSI_RTT_EVENT_ATTR_RSSI,
	SLSI_RTT_EVENT_ATTR_RSSI_SPREAD,
	SLSI_RTT_EVENT_ATTR_TX_PREAMBLE,
	SLSI_RTT_EVENT_ATTR_TX_NSS,
	SLSI_RTT_EVENT_ATTR_TX_BW,
	SLSI_RTT_EVENT_ATTR_TX_MCS,
	SLSI_RTT_EVENT_ATTR_TX_RATE,
	SLSI_RTT_EVENT_ATTR_RX_PREAMBLE,
	SLSI_RTT_EVENT_ATTR_RX_NSS,
	SLSI_RTT_EVENT_ATTR_RX_BW,
	SLSI_RTT_EVENT_ATTR_RX_MCS,
	SLSI_RTT_EVENT_ATTR_RX_RATE,
	SLSI_RTT_EVENT_ATTR_RTT,
	SLSI_RTT_EVENT_ATTR_RTT_SD,
	SLSI_RTT_EVENT_ATTR_RTT_SPREAD,
	SLSI_RTT_EVENT_ATTR_DISTANCE_MM,
	SLSI_RTT_EVENT_ATTR_DISTANCE_SD_MM,
	SLSI_RTT_EVENT_ATTR_DISTANCE_SPREAD_MM,
	SLSI_RTT_EVENT_ATTR_TIMESTAMP_US,
	SLSI_RTT_EVENT_ATTR_BURST_DURATION_MSN,
	SLSI_RTT_EVENT_ATTR_NEGOTIATED_BURST_NUM,
	SLSI_RTT_EVENT_ATTR_LCI,
	SLSI_RTT_EVENT_ATTR_LCR
};

struct dot11_rm_ie {
    u8 id;
    u8 len;
    u8 token;
    u8 mode;
    u8 type;
} __attribute__ ((packed));
typedef struct dot11_rm_ie dot11_rm_ie_t;
typedef struct strmap_entry {
    int			id;
    string		text;
} strmap_entry_t;

static const strmap_entry_t err_info[] = {
    {RTT_STATUS_SUCCESS, string("Success")},
    {RTT_STATUS_FAILURE, string("Failure")},
    {RTT_STATUS_FAIL_NO_RSP, string("No reponse")},
    {RTT_STATUS_FAIL_INVALID_TS, string("Invalid Timestamp")},
    {RTT_STATUS_FAIL_PROTOCOL, string("Protocol error")},
    {RTT_STATUS_FAIL_REJECTED, string("Rejected")},
    {RTT_STATUS_FAIL_NOT_SCHEDULED_YET, string("not scheduled")},
    {RTT_STATUS_FAIL_SCHEDULE,  string("schedule failed")},
    {RTT_STATUS_FAIL_TM_TIMEOUT, string("timeout")},
    {RTT_STATUS_FAIL_AP_ON_DIFF_CHANNEL, string("AP is on difference channel")},
    {RTT_STATUS_FAIL_NO_CAPABILITY, string("no capability")},
    {RTT_STATUS_FAIL_BUSY_TRY_LATER, string("busy and try later")},
    {RTT_STATUS_ABORTED, string("aborted")}
};
/*static const string get_err_info(int status)
{
    int i;
    const strmap_entry_t *p_entry;
    int num_entries = sizeof(err_info)/ sizeof(err_info[0]);
    * scan thru the table till end 
    p_entry = err_info;
    for (i = 0; i < (int) num_entries; i++)
    {
        if (p_entry->id == status)
            return p_entry->text;
        p_entry++;		* next entry 
    }
    return "unknown error";			* not found 
}*/
class RttCommand : public WifiCommand
{
    int request_id;
    unsigned numTargetDevice;
    int mCompleted;
    int currentIdx;
    int totalCnt;
    static const int MAX_RESULTS = 1024;
    wifi_rtt_result *rttResults[MAX_RESULTS];
    wifi_rtt_config *rttParams;
    wifi_rtt_event_handler rttHandler;
public:
    RttCommand(wifi_interface_handle iface, int id, unsigned num_rtt_config,
            wifi_rtt_config rtt_config[], wifi_rtt_event_handler handler)
        : WifiCommand(iface, id), request_id(id), numTargetDevice(num_rtt_config), rttParams(rtt_config),
        rttHandler(handler)
    {
        memset(rttResults, 0, sizeof(rttResults));
        currentIdx = 0;
        mCompleted = 0;
        totalCnt = 0;
    }

    RttCommand(wifi_interface_handle iface, int id)
        : WifiCommand(iface, id), request_id(id), rttParams(NULL)
    {
        rttHandler.on_rtt_results = NULL;
        memset(rttResults, 0, sizeof(rttResults));
        currentIdx = 0;
        mCompleted = 0;
        totalCnt = 0;
        numTargetDevice = 0;
    }
 int createSetupRequest(WifiRequest& request) {
        int result = request.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_RTT_RANGE_START);
        if (result < 0) {
            return result;
        }
        nlattr *data = request.attr_start(NL80211_ATTR_VENDOR_DATA);
	result = request.put_u16(SLSI_RTT_ATTRIBUTE_TARGET_ID, request_id);
        if (result < 0) {
            return result;
        }
        result = request.put_u8(SLSI_RTT_ATTRIBUTE_TARGET_CNT, numTargetDevice);
		ALOGI("numTargetDevice %d\n",numTargetDevice);
        if (result < 0) {
            return result;
        }
        nlattr *rtt_config = request.attr_start(SLSI_RTT_ATTRIBUTE_TARGET_INFO);
        for (unsigned i = 0; i < numTargetDevice; i++) {
            nlattr *attr2 = request.attr_start(i);

            result = request.put_addr(SLSI_RTT_ATTRIBUTE_TARGET_MAC, rttParams[i].addr);
			ALOGI("mac_addr %p\n",rttParams[i].addr);
            if (result < 0) {
                return result;
            }

            result = request.put_u8(SLSI_RTT_ATTRIBUTE_TARGET_TYPE, rttParams[i].type);
			ALOGI("\trtt_type %d\n",rttParams[i].type);
            if (result < 0) {
                return result;
            }

	     result = request.put_u8(SLSI_RTT_ATTRIBUTE_TARGET_PEER, rttParams[i].peer);
			ALOGI("\trtt_peer %d\n",rttParams[i].peer);
            if (result < 0) {
                return result;
            	}
		result = request.put_u16(SLSI_RTT_ATTRIBUTE_TARGET_CHAN_FREQ, rttParams[i].channel.center_freq);
			ALOGI("\trtt_ primary channel_freq %d\n",rttParams[i].channel.center_freq);
            if (result < 0) {
                return result;
            }
            result = request.put_u8(SLSI_RTT_ATTRIBUTE_TARGET_NUM_BURST, rttParams[i].num_burst);
			ALOGI("\tnum_burst %d\n",rttParams[i].num_burst);
            if (result < 0) {
                return result;
            }

            result = request.put_u8(SLSI_RTT_ATTRIBUTE_TARGET_NUM_FTM_BURST,
                    rttParams[i].num_frames_per_burst);
			ALOGI("\tnum_frames_per_burst %d\n",rttParams[i].num_frames_per_burst);
            if (result < 0) {
                return result;
            }

            result = request.put_u8(SLSI_RTT_ATTRIBUTE_TARGET_NUM_RETRY_FTM,
                    rttParams[i].num_retries_per_rtt_frame);
			ALOGI("\tnum_retries_per_rtt_frame %d\n",rttParams[i].num_retries_per_rtt_frame);
            if (result < 0) {
                return result;
            }

            result = request.put_u8(SLSI_RTT_ATTRIBUTE_TARGET_NUM_RETRY_FTMR,
                    rttParams[i].num_retries_per_ftmr);
			ALOGI("\tnum_retries_per_ftmr %d\n",rttParams[i].num_retries_per_ftmr);
            if (result < 0) {
                return result;
            }

            result = request.put_u8(SLSI_RTT_ATTRIBUTE_TARGET_PERIOD,
                    rttParams[i].burst_period);
			ALOGI("\tburst_period %d\n",rttParams[i].burst_period);
            if (result < 0) {
                return result;
            }

            result = request.put_u8(SLSI_RTT_ATTRIBUTE_TARGET_BURST_DURATION,
                    rttParams[i].burst_duration);
			ALOGI("\tburst_duration %d\n",rttParams[i].burst_duration);
            if (result < 0) {
                return result;
            }

            result = request.put_u16(SLSI_RTT_ATTRIBUTE_TARGET_LCI,
                    rttParams[i].LCI_request);
			ALOGI("\tLCI_request %d\n",rttParams[i].LCI_request);
            if (result < 0) {
                return result;
            }

            result = request.put_u16(SLSI_RTT_ATTRIBUTE_TARGET_LCR,
                    rttParams[i].LCR_request);
			ALOGI("\tLCR_ request%d\n",rttParams[i].LCR_request);
            if (result < 0) {
                return result;
            }

            result = request.put_u16(SLSI_RTT_ATTRIBUTE_TARGET_BW,
                    rttParams[i].bw);
			ALOGI("\tBW%d\n",rttParams[i].bw);
            if (result < 0) {
                return result;
            }

            result = request.put_u16(SLSI_RTT_ATTRIBUTE_TARGET_PREAMBLE,
                    rttParams[i].preamble);
			ALOGI("\tpreamble%d\n",rttParams[i].preamble);
            if (result < 0) {
                return result;
            }
            request.attr_end(attr2);
        }
	ALOGE("setup request created");
        request.attr_end(rtt_config);
        request.attr_end(data);
        return WIFI_SUCCESS;
    }

    int createTeardownRequest(WifiRequest& request, unsigned num_devices, mac_addr addr[]) {
        int result = request.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_RTT_RANGE_CANCEL);
        if (result < 0) {
            return result;
        }
        nlattr *data = request.attr_start(NL80211_ATTR_VENDOR_DATA);
        request.put_u16(SLSI_RTT_ATTRIBUTE_TARGET_CNT, num_devices);
        for(unsigned i = 0; i < num_devices; i++) {
            result = request.put_addr(SLSI_RTT_ATTRIBUTE_TARGET_MAC, addr[i]);
            if (result < 0) {
                return result;
            }
        }
        request.attr_end(data);
        return result;
    }
    int start() {
        WifiRequest request(familyId(), ifaceId());
        int result = createSetupRequest(request);
        if (result != WIFI_SUCCESS) {
            ALOGE("failed to create setup request; result = %d", result);
            return result;
        }

        result = requestResponse(request);
        if (result != WIFI_SUCCESS) {
            ALOGE("failed to configure RTT setup; result = %d", result);
            return result;
        }
        registerVendorHandler(GOOGLE_OUI, SLSI_RTT_RESULT_EVENT);
        registerVendorHandler(GOOGLE_OUI, SLSI_RTT_EVENT_COMPLETE);
        return result;
    }

    virtual int cancel() {
        ALOGD("Stopping RTT");

        WifiRequest request(familyId(), ifaceId());
        int result = createTeardownRequest(request, 0, NULL);
        if (result != WIFI_SUCCESS) {
            ALOGE("failed to create stop request; result = %d", result);
        } else {
            result = requestResponse(request);
            if (result != WIFI_SUCCESS) {
                ALOGE("failed to stop scan; result = %d", result);
            }
        }
        ALOGE("RTT stopped");
		/*This needs to be check */
	  unregisterVendorHandler(GOOGLE_OUI, SLSI_RTT_RESULT_EVENT);
        unregisterVendorHandler(GOOGLE_OUI, SLSI_RTT_EVENT_COMPLETE);
        return WIFI_SUCCESS;
    }

    int cancel_specific(unsigned num_devices, mac_addr addr[]) {
        ALOGE("Stopping RTT specific");

        WifiRequest request(familyId(), ifaceId());
        int result = createTeardownRequest(request, num_devices, addr);
        if (result != WIFI_SUCCESS) {
            ALOGE("failed to create stop request; result = %d", result);
        } else {
            result = requestResponse(request);
            if (result != WIFI_SUCCESS) {
                ALOGE("failed to stop RTT; result = %d", result);
            }
        }
        ALOGE("Specific RTT stopped");
	  /*This needs to be check */
	  unregisterVendorHandler(GOOGLE_OUI, SLSI_RTT_RESULT_EVENT);
        unregisterVendorHandler(GOOGLE_OUI, SLSI_RTT_EVENT_COMPLETE);
        return WIFI_SUCCESS;
    }

    virtual int handleResponse(WifiEvent& reply) {
        /* Nothing to do on response! */
        return NL_SKIP;
    }

    virtual int handleEvent(WifiEvent& event) {
        nlattr *vendor_data = event.get_attribute(NL80211_ATTR_VENDOR_DATA);
        int event_id = event.get_vendor_subcmd();
        ALOGD("Got an RTT event with id:%d\n",event_id);
        if(event_id == SLSI_RTT_EVENT_COMPLETE) {
             ALOGD("RTT event complete\n");
             mCompleted = 1;
             request_id = (u16)event.get_u16(NL80211_ATTR_VENDOR_DATA);
        } else if (event_id == SLSI_RTT_RESULT_EVENT) {
             int result_cnt = 0;
             ALOGD("RTT result event\n");
             for (nl_iterator it(vendor_data); it.has_next(); it.next()) {
                    if (it.get_type() == SLSI_RTT_ATTRIBUTE_RESULT_CNT) {
                              result_cnt = it.get_u16();
                              ALOGD("RTT results count : %d\n", result_cnt);
                     }  else if (it.get_type() == SLSI_RTT_ATTRIBUTE_TARGET_ID) {
                              request_id = it.get_u16();
                              ALOGD("RTT target id : %d\n", request_id);
                     } else if (it.get_type() == SLSI_RTT_ATTRIBUTE_RESULT) {
                              ALOGD("RTT result attribute : %d\n", SLSI_RTT_ATTRIBUTE_RESULT);
                              rttResults[currentIdx] =  (wifi_rtt_result *)malloc(sizeof(wifi_rtt_result));
                               wifi_rtt_result *rtt_result = rttResults[currentIdx];
                               if (rtt_result == NULL) {
                                         ALOGE("failed to allocate the wifi_rtt_result\n");
                                         unregisterVendorHandler(GOOGLE_OUI, SLSI_RTT_RESULT_EVENT);
                                         break;
                                }
                               memset(rtt_result, 0, sizeof(wifi_rtt_result));
                               rtt_result->LCI = NULL;
                               rtt_result->LCR = NULL;
                               for(nl_iterator nl_nested_itr((struct nlattr *)it.get()); nl_nested_itr.has_next(); nl_nested_itr.next()) {
                                  if (nl_nested_itr.get_type() == SLSI_RTT_EVENT_ATTR_ADDR) {
                                         memcpy(rtt_result->addr, nl_nested_itr.get_data(), nl_nested_itr.get_len());
                                  } else if (nl_nested_itr.get_type() == SLSI_RTT_EVENT_ATTR_BURST_NUM) {
                                         rtt_result->burst_num = (unsigned)nl_nested_itr.get_u16();
                                  } else if (nl_nested_itr.get_type() == SLSI_RTT_EVENT_ATTR_MEASUREMENT_NUM) {
                                         rtt_result->measurement_number = (unsigned)nl_nested_itr.get_u8();
                                  } else if (nl_nested_itr.get_type() == SLSI_RTT_EVENT_ATTR_SUCCESS_NUM) {
                                         rtt_result->success_number = (unsigned)nl_nested_itr.get_u8();
                                  } else if (nl_nested_itr.get_type() == SLSI_RTT_EVENT_ATTR_NUM_PER_BURST_PEER) {
                                         rtt_result->number_per_burst_peer = (unsigned char)nl_nested_itr.get_u8();
                                  } else if (nl_nested_itr.get_type() == SLSI_RTT_EVENT_ATTR_STATUS) {
                                         rtt_result->status = (wifi_rtt_status)nl_nested_itr.get_u16();
                                  } else if (nl_nested_itr.get_type() == SLSI_RTT_EVENT_ATTR_RETRY_AFTER_DURATION) {
                                         rtt_result->retry_after_duration = (unsigned char)nl_nested_itr.get_u8();
                                  } else if (nl_nested_itr.get_type() == SLSI_RTT_EVENT_ATTR_TYPE) {
                                         rtt_result->type = (wifi_rtt_type)nl_nested_itr.get_u8();
                                  } else if (nl_nested_itr.get_type() == SLSI_RTT_EVENT_ATTR_RSSI) {
                                         rtt_result->rssi = (wifi_rssi)nl_nested_itr.get_u8();
                                  } else if (nl_nested_itr.get_type() == SLSI_RTT_EVENT_ATTR_RSSI_SPREAD) {
                                         rtt_result->rssi_spread= (wifi_rssi)nl_nested_itr.get_u8();
                                  } else if (nl_nested_itr.get_type() == SLSI_RTT_EVENT_ATTR_TX_PREAMBLE) {
                                         rtt_result->tx_rate.preamble = nl_nested_itr.get_u32();
                                  } else if (nl_nested_itr.get_type() == SLSI_RTT_EVENT_ATTR_TX_NSS) {
                                         rtt_result->tx_rate.nss = nl_nested_itr.get_u32();
                                  } else if (nl_nested_itr.get_type() == SLSI_RTT_EVENT_ATTR_TX_BW) {
                                         rtt_result->tx_rate.bw = nl_nested_itr.get_u32();
                                  } else if (nl_nested_itr.get_type() == SLSI_RTT_EVENT_ATTR_TX_MCS) {
                                         rtt_result->tx_rate.rateMcsIdx = nl_nested_itr.get_u32();
                                  } else if (nl_nested_itr.get_type() == SLSI_RTT_EVENT_ATTR_TX_RATE) {
                                         rtt_result->tx_rate.bitrate = nl_nested_itr.get_u32();
                                  }else if (nl_nested_itr.get_type() == SLSI_RTT_EVENT_ATTR_RX_PREAMBLE) {
                                         rtt_result->rx_rate.preamble = nl_nested_itr.get_u32();
                                  } else if (nl_nested_itr.get_type() == SLSI_RTT_EVENT_ATTR_RX_NSS) {
                                         rtt_result->rx_rate.nss = nl_nested_itr.get_u32();
                                  } else if (nl_nested_itr.get_type() == SLSI_RTT_EVENT_ATTR_RX_BW) {
                                         rtt_result->rx_rate.bw = nl_nested_itr.get_u32();
                                  } else if (nl_nested_itr.get_type() == SLSI_RTT_EVENT_ATTR_RX_MCS) {
                                         rtt_result->rx_rate.rateMcsIdx = nl_nested_itr.get_u32();
                                  } else if (nl_nested_itr.get_type() == SLSI_RTT_EVENT_ATTR_RX_RATE) {
                                         rtt_result->rx_rate.bitrate = nl_nested_itr.get_u32();
                                  }  else if (nl_nested_itr.get_type() == SLSI_RTT_EVENT_ATTR_RTT) {
                                         rtt_result->rtt = (wifi_timespan)nl_nested_itr.get_u32();
                                  } else if (nl_nested_itr.get_type() == SLSI_RTT_EVENT_ATTR_RTT_SD) {
                                         rtt_result->rtt_sd = (wifi_timespan)nl_nested_itr.get_u16();
                                  } else if (nl_nested_itr.get_type() == SLSI_RTT_EVENT_ATTR_RTT_SPREAD) {
                                         rtt_result->rtt_spread = (wifi_timespan)nl_nested_itr.get_u16();
                                  } else if (nl_nested_itr.get_type() == SLSI_RTT_EVENT_ATTR_DISTANCE_MM) {
                                         rtt_result->distance_mm = nl_nested_itr.get_u32();
                                  } else if (nl_nested_itr.get_type() == SLSI_RTT_EVENT_ATTR_DISTANCE_SD_MM) {
                                         rtt_result->distance_sd_mm = nl_nested_itr.get_u32();
                                  } else if (nl_nested_itr.get_type() == SLSI_RTT_EVENT_ATTR_DISTANCE_SPREAD_MM) {
                                         rtt_result->distance_spread_mm = nl_nested_itr.get_u32();
                                  } else if (nl_nested_itr.get_type() == SLSI_RTT_EVENT_ATTR_TIMESTAMP_US) {
                                         rtt_result->ts = (wifi_timestamp)nl_nested_itr.get_u32();
                                  } else if (nl_nested_itr.get_type() == SLSI_RTT_EVENT_ATTR_BURST_DURATION_MSN) {
                                         rtt_result->burst_duration = nl_nested_itr.get_u8();
                                  } else if (nl_nested_itr.get_type() == SLSI_RTT_EVENT_ATTR_NEGOTIATED_BURST_NUM) {
                                         rtt_result->negotiated_burst_num = nl_nested_itr.get_u8();
                                  } else if (nl_nested_itr.get_type() == SLSI_RTT_EVENT_ATTR_LCI) {
                                         u8 *lci_ie = (u8 *)nl_nested_itr.get_data();
                                         rtt_result->LCI = (wifi_information_element *)malloc(sizeof(wifi_information_element) + nl_nested_itr.get_len() - 2);
                                         rtt_result->LCI->id = lci_ie[0];
                                         rtt_result->LCI->len =lci_ie[1];
                                         memcpy(rtt_result->LCI->data, &lci_ie[2], nl_nested_itr.get_len() - 2);
                                  } else if (nl_nested_itr.get_type() == SLSI_RTT_EVENT_ATTR_LCR) {
                                          u8 *lcr_ie = (u8 *)nl_nested_itr.get_data();
                                          rtt_result->LCR = (wifi_information_element *)malloc(sizeof(wifi_information_element) + nl_nested_itr.get_len() - 2);
                                          rtt_result->LCR->id = lcr_ie[0];
                                          rtt_result->LCR->len =lcr_ie[1];
                                          memcpy(rtt_result->LCR->data, &lcr_ie[2], nl_nested_itr.get_len() - 2);
                                  }
                           }
                           currentIdx++;
                       }
               }
       }
       if (mCompleted) {
             unregisterVendorHandler(GOOGLE_OUI, SLSI_RTT_EVENT_COMPLETE);
             unregisterVendorHandler(GOOGLE_OUI, SLSI_RTT_RESULT_EVENT);
             (*rttHandler.on_rtt_results)(request_id ,currentIdx, rttResults);
             for (int i = 0; i < currentIdx; i++) {
                    free(rttResults[i]);
                    rttResults[i] = NULL;
             }
             currentIdx = 0;
             WifiCommand *cmd = wifi_unregister_cmd(wifiHandle(), request_id);
             if (cmd)
                   cmd->releaseRef();
		mCompleted = 0;
             return NL_OK;
       }
       ALOGE("Handled response for rtt config");
       return NL_SKIP;
    }
};
class GetRttCapabilitiesCommand : public WifiCommand
	{
	wifi_rtt_capabilities *mCapabilities;
public:
    GetRttCapabilitiesCommand(wifi_interface_handle iface, wifi_rtt_capabilities *capabitlites)
        : WifiCommand(iface, 0), mCapabilities(capabitlites)
    {
        memset(mCapabilities, 0, sizeof(*mCapabilities));
    }

    virtual int create() {
        int ret = mMsg.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_RTT_GET_CAPABILITIES);
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
	  ALOGE("RTT capa response");
        return NL_OK;
    }
};
/*class GetRttResponderInfoCommand : public WifiCommand
{
    wifi_rtt_responder* mResponderInfo;
public:
    GetRttResponderInfoCommand(wifi_interface_handle iface, wifi_rtt_responder *responderInfo)
        : WifiCommand(iface, 0), mResponderInfo(responderInfo)
    {
        memset(mResponderInfo, 0 , sizeof(*mResponderInfo));

    }

    virtual int create() {
        ALOGD("Creating message to get responder info ; iface = %d", mIfaceInfo->id);

        int ret = mMsg.create(GOOGLE_OUI, SLSI_NL80211_VENDOR_SUBCMD_RTT_GETAVAILCHANNEL);
        if (ret < 0) {
            return ret;
        }

       // return ret;
    }

protected:
    virtual int handleResponse(WifiEvent& reply) {

        ALOGD("In GetRttResponderInfoCommand::handleResponse");

        if (reply.get_cmd() != NL80211_CMD_VENDOR) {
            ALOGD("Ignoring reply with cmd = %d", reply.get_cmd());
            return NL_SKIP;
        }

        int id = reply.get_vendor_id();
        int subcmd = reply.get_vendor_subcmd();

        void *data = reply.get_vendor_data();
        int len = reply.get_vendor_data_len();

        ALOGD("Id = %0x, subcmd = %d, len = %d, expected len = %d", id, subcmd, len,
                sizeof(*mResponderInfo));

        memcpy(mResponderInfo, data, min(len, (int) sizeof(*mResponderInfo)));

        return NL_OK;
    }
};*/

	/* API to request RTT measurement */
wifi_error wifi_rtt_range_request(wifi_request_id id, wifi_interface_handle iface,
        unsigned num_rtt_config, wifi_rtt_config rtt_config[], wifi_rtt_event_handler handler)
{
    ALOGE("Inside RTT RANGE request");
    wifi_handle handle = getWifiHandle(iface);
    RttCommand *cmd = new RttCommand(iface, id, num_rtt_config, rtt_config, handler);
    NULL_CHECK_RETURN(cmd, "memory allocation failure", WIFI_ERROR_OUT_OF_MEMORY);
    wifi_error result = wifi_register_cmd(handle, id, cmd);
    if (result != WIFI_SUCCESS) {
        cmd->releaseRef();
        return result;
    }
    result = (wifi_error)cmd->start();
    if (result != WIFI_SUCCESS) {
        (*handler.on_rtt_results)(id, 0, NULL);
        wifi_unregister_cmd(handle, id);
        cmd->releaseRef();
        return WIFI_SUCCESS;
    }
	ALOGE("wifi range request successfully executed");
    return result;
}

/* API to cancel RTT measurements */
wifi_error wifi_rtt_range_cancel(wifi_request_id id,  wifi_interface_handle iface,
        unsigned num_devices, mac_addr addr[])
{
    if (!iface)
             return WIFI_ERROR_UNINITIALIZED;
    RttCommand *cmd = new RttCommand(iface, id);
    NULL_CHECK_RETURN(cmd, "memory allocation failure", WIFI_ERROR_OUT_OF_MEMORY);
    cmd->cancel_specific(num_devices, addr);
    cmd->releaseRef();
    return WIFI_SUCCESS;
}

/* API to get RTT capability */
wifi_error wifi_get_rtt_capabilities(wifi_interface_handle iface,
        wifi_rtt_capabilities *capabilities)
{
	 ALOGE("Inside get rtt capabilities cap:%p iface:%p", capabilities, iface);
	 if (!iface)
             return WIFI_ERROR_UNINITIALIZED;
	GetRttCapabilitiesCommand command(iface, capabilities);
	return (wifi_error) command.requestResponse();

}
/* API to get the responder information */
wifi_error wifi_rtt_get_responder_info(wifi_interface_handle iface,
        wifi_rtt_responder* responderInfo)
{
    /*GetRttResponderInfoCommand command(iface, responderInfo);
    return (wifi_error) command.requestResponse();*/
    return WIFI_ERROR_NOT_SUPPORTED;

}
