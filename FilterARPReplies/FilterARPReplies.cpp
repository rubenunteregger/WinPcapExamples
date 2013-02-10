#define HAVE_REMOTE
 
#include <stdio.h>
#include <pcap.h>
#include <Iphlpapi.h>

#include "../WinPcapExamples/Packets.h"
#include "../WinPcapExamples/Config.h"



#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")




/*
 * Program entry point
 *
 */
int main(int argc, char **argv)
{
  pcap_t *lIFCHandle = NULL;
  char lTemp[1024];
  char lFilter[1024];
  bpf_u_int32 lNetMask;
  struct bpf_program lFCode;
  char *lIFC = argv[1];
  int lPcapRetVal = 0;
  PETHDR lEHdr = NULL;
  PARPHDR lARPHdr = NULL;
  u_char *lPktData = NULL;
  struct pcap_pkthdr *lPktHdr = NULL;
  unsigned char lEthDstStr[MAX_MAC_LEN+1];
  unsigned char lEthSrcStr[MAX_MAC_LEN+1];
  unsigned char lARPEthDstStr[MAX_MAC_LEN+1];
  unsigned char lARPEthSrcStr[MAX_MAC_LEN+1];
  unsigned char lARPIPDstStr[MAX_IP_LEN+1];
  unsigned char lARPIPSrcStr[MAX_IP_LEN+1];


  if ((lIFCHandle = pcap_open(lIFC, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1, NULL, lTemp)) != NULL)
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

            MAC2String(lEHdr->ether_shost, lEthSrcStr, sizeof(lEthSrcStr)-1);
            MAC2String(lEHdr->ether_dhost, lEthDstStr, sizeof(lEthDstStr)-1);
            MAC2String(lARPHdr->sha, lARPEthSrcStr, sizeof(lARPEthSrcStr)-1);
            MAC2String(lARPHdr->tha, lARPEthDstStr, sizeof(lARPEthDstStr)-1);

            IP2String(lARPHdr->tpa, lARPIPDstStr, sizeof(lARPIPDstStr)-1);
            IP2String(lARPHdr->spa, lARPIPSrcStr, sizeof(lARPIPSrcStr)-1);

            printf("\nOperation: %s (%d)\n", (ntohs(lARPHdr->oper) == ARP_REQUEST)? "ARP Request" : "ARP Reply", lARPHdr->oper);
            printf("  MAC : %s -> %s\n", lEthSrcStr, lEthDstStr);
            printf("  ARP : %s -> %s\n", lARPEthSrcStr, lARPEthDstStr);
            printf("  IP  : %s -> %s\n", lARPIPSrcStr, lARPIPDstStr);
          }
        }
      }
    }
  }

  return(0);
}


void MAC2String(unsigned char pMAC[BIN_MAC_LEN], unsigned char *pOutput, int pOutputLen)
{
  if (pOutput && pOutputLen > 0 && pMAC != NULL && pOutputLen >= MAX_MAC_LEN)
    _snprintf((char *) pOutput, pOutputLen-1, "%02X-%02X-%02X-%02X-%02X-%02X", pMAC[0], pMAC[1], pMAC[2], pMAC[3], pMAC[4], pMAC[5]);
}

void IP2String(unsigned char pIP[BIN_IP_LEN], unsigned char *pOutput, int pOutputLen)
{
  if (pOutput && pOutputLen > 0)
    _snprintf((char *) pOutput, pOutputLen, "%d.%d.%d.%d", pIP[0], pIP[1], pIP[2], pIP[3]);
}
