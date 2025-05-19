#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <string.h>
#include <iostream>

int main(int argc, char** argv)
{
    netsnmp_session session, * ss;
    netsnmp_pdu* pdu;

    init_snmp("snmpdemoapp");
    snmp_sess_init(&session);

    session.peername = _strdup("192.168.100.128:162"); // Your Ubuntu VM's IP
    session.version = SNMP_VERSION_3;

    u_char engineID[] = { 0x80, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04 };
    session.securityEngineID = engineID;
    session.securityEngineIDLen = sizeof(engineID);
    session.contextEngineID = engineID;
    session.contextEngineIDLen = sizeof(engineID);

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
