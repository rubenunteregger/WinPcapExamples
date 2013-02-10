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
  char *lIFC = argv[1];
  int lPcapRetVal = 0;
  u_char *lPktData = NULL;
  struct pcap_pkthdr *lPktHdr = NULL;
  PETHDR lEHdr = NULL;
  PIPHDR lIPHdr = NULL;
  PTCPHDR lTCPHdr = NULL;
  struct sockaddr_in lSource;
  struct sockaddr_in lDest;
  int lIPHdrLen = 0;
  char lSrcIPStr[32];
  char lDstIPStr[32];
  char lSrcMAC[64];
  char lDstMAC[64];


  if (lIFC)
  {
    if ((lIFCHandle = pcap_open(lIFC , 65536, PCAP_OPENFLAG_PROMISCUOUS, 1, NULL, lTemp)) != NULL)
    {
      while ((lPcapRetVal = pcap_next_ex((pcap_t*) lIFCHandle, (struct pcap_pkthdr **) &lPktHdr, (const u_char **) &lPktData)) >= 0)
      {
        if (lPcapRetVal == 1)      
        {
          // Ethernet packet
          lEHdr = (PETHDR) lPktData;

          MAC2String(lEHdr->ether_shost, (unsigned char *) lSrcMAC, sizeof(lSrcMAC) - 1);
          MAC2String(lEHdr->ether_dhost, (unsigned char *) lDstMAC, sizeof(lDstMAC) - 1);
          printf("\n%s -> %s\n", lSrcMAC, lDstMAC);


          // IP packet
          if (htons(lEHdr->ether_type) == 0x0800)
          {
            lIPHdr = (PIPHDR) (lPktData + sizeof(ETHDR));
            lIPHdrLen = (lIPHdr->ver_ihl & 0xf) * 4;
            ZeroMemory(&lSource, sizeof(lSource));
            ZeroMemory(&lDest, sizeof(lDest));
            ZeroMemory(lSrcIPStr, sizeof(lSrcIPStr));
            ZeroMemory(lDstIPStr, sizeof(lDstIPStr));

            lSource.sin_addr.s_addr = lIPHdr->saddr;
            lDest.sin_addr.s_addr = lIPHdr->daddr;

            strncpy(lSrcIPStr, inet_ntoa(lSource.sin_addr), sizeof(lSrcIPStr)-1);
            strncpy(lDstIPStr, inet_ntoa(lDest.sin_addr), sizeof(lDstIPStr)-1);
            printf("  IP protocol no : %d\n", lIPHdr->proto);
            printf("  IP source      : %s\n", lSrcIPStr);
            printf("  IP dest.       : %s\n", lDstIPStr);

            // TCP packet
            if (lIPHdr->proto == 6)
            {
              lTCPHdr = (PTCPHDR) ((unsigned char*) lIPHdr + lIPHdrLen);
              printf("  TCP src port : %d\n", ntohs(lTCPHdr->sport));
              printf("  TCP dst port : %d\n", ntohs(lTCPHdr->dport));
            }
          }
        }
      }
    }
  }

  return(0);
}


void MAC2String(unsigned char pMAC[BIN_MAC_LEN], unsigned char *pOutput, int pOutputLen)
{
  if (pOutput && pOutputLen > 0)
  {
    snprintf((char *) pOutput, pOutputLen, "%02X:%02X:%02X:%02X:%02X:%02X", pMAC[0], pMAC[1], pMAC[2], pMAC[3], pMAC[4], pMAC[5]);
  }
}