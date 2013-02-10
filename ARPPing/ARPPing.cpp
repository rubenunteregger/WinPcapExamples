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



/*
 * Global variables
 *
 */
CRITICAL_SECTION gWriteLog; 





/*
 * Program entry point
 *
 */
int main(int argc, char **argv)
{
  DWORD lRetVal = 0;
  ARPPacket lARPPacket;
  SCANPARAMS lScanParams;
  unsigned long lIPCounter = 0;
  unsigned long lStartIP = 0;
  unsigned long lStopIP = 0;
  unsigned long lDstIP = 0;
  HANDLE lThreadHandle = INVALID_HANDLE_VALUE;
  DWORD lThreadId = 0;
  int lCounter = 0;
  pcap_if_t *lAllDevs = NULL;
  pcap_if_t *lDevice = NULL;
  char lTemp[PCAP_ERRBUF_SIZE];

  HANDLE lICMPFile = INVALID_HANDLE_VALUE;
  char lSendData[32] = "Data Buffer";
  DWORD lReplySize = 0;
  LPVOID lReplyBuffer = NULL;
  unsigned long ipaddr = 0;

  char *lIFCName = argv[1];
  HANDLE lARPReplyThreadHandle = INVALID_HANDLE_VALUE;
  DWORD lARPReplyThreadID = 0;
  struct sockaddr_in lPeerIP;
  char lPeerIPStr[MAX_BUF_SIZE + 1];



  /*
   * Initialisation
   */
  ZeroMemory(&lScanParams, sizeof(lScanParams));
  InitializeCriticalSectionAndSpinCount(&gWriteLog, 0x00000400);

  if (argc >= 4)
  {
    ZeroMemory(&lARPPacket, sizeof(lARPPacket));
    GetIFCDetails(argv[1], &lScanParams);

	   lStartIP = ntohl(inet_addr(argv[2]));
	   lStopIP = ntohl(inet_addr(argv[3]));

    
    /*
     * Start ARP Reply listener thread
     */
    LogMsg("main() : Starting CaptureARPReplies\n");
    if ((lARPReplyThreadHandle = CreateThread(NULL, 0, CaptureARPReplies, &lScanParams, 0, &lARPReplyThreadID)) != NULL)
	   {
      if (lStartIP <= lStopIP)
      {        
        strncpy(lScanParams.IFCString, argv[1], sizeof(lScanParams.IFCString)-1);

        /*
         * Open interface.
         */
        if ((lScanParams.IfcWriteHandle = pcap_open(lIFCName, 65536, PCAP_OPENFLAG_NOCAPTURE_LOCAL|PCAP_OPENFLAG_MAX_RESPONSIVENESS, 5, NULL, lTemp)) != NULL)
        {
          for (lIPCounter = lStartIP; lIPCounter <= lStopIP; lIPCounter++)
          {
            if (memcmp(lScanParams.LocalIP, &lIPCounter, BIN_IP_LEN) &&
                memcmp(lScanParams.GWIP, &lIPCounter, BIN_IP_LEN))
            {
              /*
               * Send WhoHas ARP request and sleep ...
               */
              SendARPWhoHas(&lScanParams, lIPCounter);

              lPeerIP.sin_addr.s_addr = htonl(lIPCounter);
              strncpy(lPeerIPStr, inet_ntoa(lPeerIP.sin_addr), sizeof(lPeerIPStr)-1);

              LogMsg("Ping %s", lPeerIPStr);
              Sleep(SLEEP_BETWEEN_ARPS);
            } // if (memcmp...
          } // for (; lStartI...



          /*
           * Wait for all ARP replies and terminate thread.
           */
          Sleep(2000);
          TerminateThread(lARPReplyThreadHandle, 0);
          CloseHandle(lARPReplyThreadHandle);


          if (lScanParams.IfcWriteHandle)
            pcap_close((pcap_t *) lScanParams.IfcWriteHandle);

        } // if ((lIFCHandle...
        else
          LogMsg("main() : pcap_open() failed\n");

      } 
      else 
      {
        LogMsg("main() : Something is wrong with the start and/or end IP!\n");
        lRetVal = 1;
      } // if (lStart...
   	} // if ((lPOISO...
  } // if (argc >= 4)...

  DeleteCriticalSection(&gWriteLog);

  return(lRetVal);
}



/*
 *
 *
 */
DWORD WINAPI CaptureARPReplies(LPVOID pScanParams)
{
  pcap_t *lIFCHandle = NULL;
  char lTemp[1024];
  char lFilter[1024];
  bpf_u_int32 lNetMask;
  struct bpf_program lFCode;
  int lPcapRetVal = 0;
  PETHDR lEHdr = NULL;
  PARPHDR lARPHdr = NULL;
  u_char *lPktData = NULL;
  struct pcap_pkthdr *lPktHdr = NULL;
  PSCANPARAMS lScanParams = (PSCANPARAMS) pScanParams;
  char lEthDstStr[MAX_MAC_LEN+1];
  char lEthSrcStr[MAX_MAC_LEN+1];
  char lARPEthDstStr[MAX_MAC_LEN+1];
  char lARPEthSrcStr[MAX_MAC_LEN+1];
  char lARPIPDstStr[MAX_IP_LEN+1];
  char lARPIPSrcStr[MAX_IP_LEN+1];


  if ((lIFCHandle = pcap_open((char *) lScanParams->IFCString, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1, NULL, lTemp)) != NULL)
  {
    ZeroMemory(&lFCode, sizeof(lFCode));
    ZeroMemory(lFilter, sizeof(lFilter));

    _snprintf(lFilter, sizeof(lFilter) - 1, "arp");
    lNetMask = 0xffffff; // "255.255.255.0"

    // Compile the filter
    if(pcap_compile(lIFCHandle, &lFCode, (const char *) lFilter, 1, lNetMask) >= 0)
    {
      // Set the filter
      if(pcap_setfilter(lIFCHandle, &lFCode) >= 0)
      {
        while ((lPcapRetVal = pcap_next_ex((pcap_t*) lIFCHandle, (struct pcap_pkthdr **) &lPktHdr, (const u_char **) &lPktData)) >= 0)
        {
          if (lPcapRetVal == 1)      
          {
            lEHdr = (PETHDR) lPktData;
            lARPHdr = (PARPHDR) (lPktData + sizeof(ETHDR));
              
            ZeroMemory(lEthDstStr, sizeof(lEthDstStr));
            ZeroMemory(lEthSrcStr, sizeof(lEthSrcStr));
            ZeroMemory(lARPEthSrcStr, sizeof(lARPEthSrcStr));
            ZeroMemory(lARPEthDstStr, sizeof(lARPEthDstStr));
            ZeroMemory(lARPIPDstStr, sizeof(lARPIPDstStr));
            ZeroMemory(lARPIPSrcStr, sizeof(lARPIPSrcStr));

            MAC2String(lEHdr->ether_shost, (unsigned char *) lEthSrcStr, sizeof(lEthSrcStr)-1);
            MAC2String(lEHdr->ether_dhost, (unsigned char *) lEthDstStr, sizeof(lEthDstStr)-1);
            MAC2String(lARPHdr->sha, (unsigned char *) lARPEthSrcStr, sizeof(lARPEthSrcStr)-1);
            MAC2String(lARPHdr->tha, (unsigned char *) lARPEthDstStr, sizeof(lARPEthDstStr)-1);

            IP2String(lARPHdr->tpa, (unsigned char *) lARPIPDstStr, sizeof(lARPIPDstStr)-1);
            IP2String(lARPHdr->spa, (unsigned char *) lARPIPSrcStr, sizeof(lARPIPSrcStr)-1);

            if (ntohs(lARPHdr->oper) == ARP_REPLY)
            {
              ZeroMemory(lTemp, sizeof(lTemp));
              snprintf(lTemp, sizeof(lTemp)-1, "\n  Operation: %s (%d)\n  MAC : %s -> %s\n  ARP : %s -> %s\n  IP  : %s -> %s\n", (ntohs(lARPHdr->oper) == ARP_REQUEST)? "ARP Request" : "ARP Reply", lARPHdr->oper, lEthSrcStr, lEthDstStr, lARPEthSrcStr, lARPEthDstStr, lARPIPSrcStr, lARPIPDstStr);
              LogMsg(lTemp);
            }
          }
        }
      }
    }
  }

  return(0);
}


/*
 * Ethr:	LocalMAC -> 255:255:255:255:255:255
 * ARP :	LocMAC/LocIP -> 0:0:0:0:0:0/VicIP
 *
 */
int SendARPWhoHas(PSCANPARAMS pScanParams, unsigned long lIPAddress)
{
  int lRetVal = OK;
  unsigned long lDstIP = 0;
  ARPPacket lARPPacket;  

  lDstIP = htonl(lIPAddress);
  lARPPacket.lReqType = ARP_REQUEST;

  // Set src/dst MAC values
  CopyMemory(lARPPacket.Eth_SrcMAC, pScanParams->LocalMAC, BIN_MAC_LEN);
  memset(lARPPacket.Eth_DstMAC, 255, sizeof(lARPPacket.Eth_DstMAC));


  // Set ARP request values
  CopyMemory(lARPPacket.ARP_LocalMAC, pScanParams->LocalMAC, BIN_MAC_LEN);
  CopyMemory(lARPPacket.ARP_LocalIP, pScanParams->LocalIP, BIN_IP_LEN);
  CopyMemory(&lARPPacket.ARP_DstIP[0], &lDstIP, BIN_IP_LEN);

  // Send packet
  if (SendARPPacket((pcap_t *) pScanParams->IfcWriteHandle, &lARPPacket) != 0)
  {
    LogMsg("SendARPWhoHas() : Unable to send ARP packet.\n");
    lRetVal = NOK;
  } // if (SendARPPacket(lIF...

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
   * Layer 1/2 (Physical)
   */
  CopyMemory(lEHdr->ether_shost, pARPPacket->Eth_SrcMAC, BIN_MAC_LEN);
  CopyMemory(lEHdr->ether_dhost, pARPPacket->Eth_DstMAC, BIN_MAC_LEN);
  lEHdr->ether_type = htons(ETHERTYPE_ARP);


  /*
   * Layer 2
   */
  lARPHdr->htype = htons(0x0001); // Ethernet
  lARPHdr->ptype = htons(0x0800); // IP
  lARPHdr->hlen = 0x0006;
  lARPHdr->plen = 0x0004;
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