#ifndef NAN_DATA_H
#define NAN_DATA_H

#include <netlink/netlink.h>

#define SLSI_NAN_MAX_NDP 5

class NanDataCommand {

    int m_ndp_count;
    u32 m_ndp_instance_id[SLSI_NAN_MAX_NDP];
    int m_max_ndp_sessions;
    int m_data_iface_count;
    char m_ifaceName[SLSI_NAN_MAX_NDP][IFNAMSIZ+1];
    static const int idx_iface_create = 0;
    static const int idx_iface_delete = 1;
    static const int idx_ndp_initiator = 2;
    static const int idx_ndp_responder = 3;
    static const int idx_ndp_end = 4;
    static const int idx_max = 5; /* should be the end of idx_* */
    u16 transaction_id[idx_max]; /* 5 = no of reqs: */


    nlattr *newNlVendorMsg(int subcmd, WifiRequest &request);

    void dataInterfaceCreated(char *ifaceName);
    void dataInterfaceDeleted(char *ifaceName);
    void dataRequestInitiateSuccess(NanDataPathInitiatorRequest *msg);
    void dataIndicationResponseSuccess(NanDataPathIndicationResponse *msg);
    void dataEndSuccess(NanDataPathEndRequest *msg);

    int dataInterfaceCreateDelete(char *ifaceName, int subcmd, WifiRequest &request);
    int dataRequestInitiate(NanDataPathInitiatorRequest *msg, WifiRequest &request);
    int dataIndicationResponse(NanDataPathIndicationResponse *msg, WifiRequest &request);
    int dataEnd(NanDataPathEndRequest *msg, WifiRequest &request);

    void processNdpChannelInfo(nlattr *nl_data, NanChannelInfo &channel_info);
    int processNdpReqEvent(WifiEvent &event, NanCallbackHandler &callbackEventHandler);
    int processNdpCfmEvent(WifiEvent &event, NanCallbackHandler &callbackEventHandler);
    int processNdpEndEvent(WifiEvent &event, NanCallbackHandler &callbackEventHandler);

public:
    NanDataCommand();
    int processResponse(WifiEvent &reply, NanResponseMsg *response);
    void requestSuccess(u16 id, void *data, int subcmd);
    int getDataPathNLMsg(u16 id, void *data, int subcmd, WifiRequest &request);
    void setMaxNdpSessions(int max_ndp);
    int handleEvent(WifiEvent &event, NanCallbackHandler &callbackEventHandler);
    int getResponseTransactionId(NanResponseMsg *res);
    static int putSecurityInfo(u32 cipher, NanSecurityKeyInfo *key_info, u32 scid_len,
                               u8 *scid, WifiRequest *request);
    static const u8 *getCmdName(int cmd);
};
#endif
