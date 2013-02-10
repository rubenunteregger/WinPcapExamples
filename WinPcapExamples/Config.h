#ifndef __CONFIG__
#define __CONFIG__

/*
 * Function forward declarations
 *
 */
void IP2String(unsigned char pIP[BIN_IP_LEN], unsigned char *pOutput, int pOutputLen);
void MAC2String(unsigned char pMAC[BIN_MAC_LEN], unsigned char *pOutput, int pOutputLen);
void LogMsg(char *pMsg, ...);
int GetIFCDetails(char *pIFCName, PSCANPARAMS pScanParams);
int SendARPPacket(pcap_t *pIFCHandle, PARPPacket pARPPacket);
int SendARPWhoHas(PSCANPARAMS pScanParams, unsigned long lIPAddress);
DWORD WINAPI CaptureARPReplies(LPVOID pScanParams);
char *iptos(unsigned long pIPAddr);

#endif