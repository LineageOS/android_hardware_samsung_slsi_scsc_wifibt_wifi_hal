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

    nlattr *newNlVendorMsg(int subcmd, WifiRequest &request);

    void dataInterfaceCreated(char *ifaceName);
    void dataInterfaceDeleted(char *ifaceName);
    void dataRequestInitiateSuccess(NanDataPathInitiatorRequest *msg);
    void dataIndicationResponseSuccess(NanDataPathIndicationResponse *msg);
    void dataEndSuccess(NanDataPathEndRequest *msg);

    int dataInterfaceCreateDelete(u16 id, char *ifaceName, int subcmd, WifiRequest &request);
    int dataRequestInitiate(u16 id, NanDataPathInitiatorRequest *msg, WifiRequest &request);
    int dataIndicationResponse(u16 id, NanDataPathIndicationResponse *msg, WifiRequest &request);
    int dataEnd(u16 id, NanDataPathEndRequest *msg, WifiRequest &request);

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
    static int putSecurityInfo(u32 cipher, NanSecurityKeyInfo *key_info, u32 scid_len,
                               u8 *scid, WifiRequest *request);
    static const u8 *getCmdName(int cmd);
};
#endif
