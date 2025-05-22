#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <string.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>

std::vector<u_char> engineId(std::string engineID)

{

    std::vector<u_char> returnValue;

    for (size_t i = 0; i < engineID.length(); i += 2) {

        std::string byteString = engineID.substr(i, 2);

        u_char byte = static_cast<u_char>(std::stoul(byteString, nullptr, 16));

        returnValue.push_back(byte);

    }

    return returnValue;

}

int main(int argc, char** argv)
{
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <IP[:PORT]>" << std::endl;
        return 1;
    }
    netsnmp_session session, * ss;
    netsnmp_pdu* pdu;

    init_snmp("snmpdemoapp");
    snmp_sess_init(&session);

    session.peername = _strdup(argv[1]); // use input IP:PORT from command line
    session.version = SNMP_VERSION_3;
    std::string xxxx = "8000000001020304";
    std::vector<u_char> engineIDVec = engineId(xxxx);
    for (u_char byte : engineIDVec)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte << " ";
    std::cout << std::endl;
    session.securityEngineID = engineIDVec.data();
    session.securityEngineIDLen = engineIDVec.size();
    session.contextEngineID = engineIDVec.data();
    session.contextEngineIDLen = engineIDVec.size();

    session.securityName = _strdup("myuser");
    session.securityNameLen = strlen(session.securityName);
    session.securityLevel = SNMP_SEC_LEVEL_AUTHPRIV;

    session.securityAuthProto = usmHMACMD5AuthProtocol;
    session.securityAuthProtoLen = sizeof(usmHMACMD5AuthProtocol) / sizeof(oid);
    session.securityAuthKeyLen = USM_AUTH_KU_LEN;
    generate_Ku(session.securityAuthProto, session.securityAuthProtoLen,
        (u_char*)"authpass", strlen("authpass"),
        session.securityAuthKey, &session.securityAuthKeyLen);

    session.securityPrivProto = usmDESPrivProtocol;
    session.securityPrivProtoLen = sizeof(usmDESPrivProtocol) / sizeof(oid);
    session.securityPrivKeyLen = USM_PRIV_KU_LEN;
    generate_Ku(session.securityAuthProto, session.securityAuthProtoLen,
        (u_char*)"privpass", strlen("privpass"),
        session.securityPrivKey, &session.securityPrivKeyLen);

    SOCK_STARTUP;

    std::cout << "Opening SNMPv3 trap session to " << session.peername << std::endl;
    ss = snmp_open(&session);
    if (!ss) {
        snmp_sess_perror("snmptrap", &session);
        SOCK_CLEANUP;
        return 1;
    }

    // ✅ Create SNMPv2-style trap PDU
    pdu = snmp_pdu_create(SNMP_MSG_TRAP2);

    // 1. sysUpTime.0
    oid uptimeOID[MAX_OID_LEN];
    size_t uptimeOID_len = MAX_OID_LEN;
    snmp_parse_oid(".1.3.6.1.2.1.1.3.0", uptimeOID, &uptimeOID_len);  // sysUpTime.0

    char uptimeStr[32];
    snprintf(uptimeStr, sizeof(uptimeStr), "%lu", get_uptime());
    snmp_add_var(pdu, uptimeOID, uptimeOID_len, 't', uptimeStr);

    // 2. snmpTrapOID.0
    oid trapOID[MAX_OID_LEN];
    size_t trapOID_len = MAX_OID_LEN;
    snmp_parse_oid(".1.3.6.1.6.3.1.1.4.1.0", trapOID, &trapOID_len);  // snmpTrapOID.0

    // Let's say we trap on sysDescr.0
    snmp_add_var(pdu, trapOID, trapOID_len, 'o', ".1.3.6.1.2.1.1.1.0");

    // 3. Your payload var: sysDescr.0 with test message
    oid sysDescrOID[MAX_OID_LEN];
    size_t sysDescrOID_len = MAX_OID_LEN;
    snmp_parse_oid(".1.3.6.1.2.1.1.1.0", sysDescrOID, &sysDescrOID_len);
    snmp_add_var(pdu, sysDescrOID, sysDescrOID_len, 's', "This is a test trap from C++");

    // ✅ Send the trap
    if (!snmp_send(ss, pdu)) {
        snmp_sess_perror("snmptrap send", ss);
        snmp_free_pdu(pdu);
    }
    else {
        std::cout << "SNMPv3 trap sent successfully." << std::endl;
    }

    snmp_close(ss);
    SOCK_CLEANUP;
    return 0;
}
