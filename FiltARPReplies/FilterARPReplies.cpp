#define HAVE_REMOTE
 
#include <stdio.h>
#include <pcap.h>
#include <Iphlpapi.h>
 
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")

#define BIN_IP_LEN 4
#define BIN_MAC_LEN 6
#define MAX_IP_LEN 16
#define MAX_MAC_LEN 18


/*
 * Our data types
 *
 */
 
typedef struct tcphdr 
{
  unsigned short sport;  
  unsigned short dport;
  unsigned int   seq; 
  unsigned int   ack_seq; 
  unsigned short res1:4, 
                 doff:4,
                 fin:1,
                 syn:1,  
                 rst:1,  
                 psh:1,  
                 ack:1,  
                 urg:1, 
                 res2:2; 
  unsigned short window;
  unsigned short check;  
  unsigned short urg_ptr;
} TCPHDR, *PTCPHDR;


typedef struct ipaddress
{
  unsigned char byte1;
  unsigned char byte2;
  unsigned char byte3;
  unsigned char byte4;
} IPADDRESS;
 
typedef struct iphdr
{
  unsigned char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
  unsigned char  tos;            // Type of service 
  unsigned short tlen;           // Total length 
  unsigned short identification; // Identification
  unsigned short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
  unsigned char  ttl;            // Time to live
  unsigned char  proto;          // Protocol
  unsigned short crc;            // Header checksum
  unsigned long      saddr;      // Source address
  unsigned long      daddr;      // Destination address
  unsigned int   opt;        // Option + padding
} IPHDR, *PIPHDR;


typedef struct ethern_hdr
{
  unsigned char ether_dhost[BIN_MAC_LEN];  // dest Ethernet address
  unsigned char ether_shost[BIN_MAC_LEN];  // source Ethernet address
  unsigned short ether_type;     // protocol (16-bit)
} ETHDR, *PETHDR;


#define ARP_REQUEST 1   
#define ARP_REPLY 2     
typedef struct arp_hdr 
{ 
  u_int16_t htype;    // Hardware Type         
  u_int16_t ptype;    // Protocol Type            
  u_char hlen;        // Hardware Address Length  
  u_char plen;        // Protocol Address Length  
  u_int16_t oper;     // Operation Code           
  u_char sha[6];      // Sender hardware address  
  u_char spa[4];      // Sender IP address        
  u_char tha[6];      // Target hardware address  
  u_char tpa[4];      // Target IP address        
} ARPHDR, *PARPHDR; 




/*
 * Function forward declaration
 */
char *iptos(unsigned long pIPAddr);
void listNetworkAdapters();
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
void IP2String(unsigned char pIP[BIN_IP_LEN], unsigned char *pOutput, int pOutputLen);
void MAC2String(unsigned char pMAC[BIN_MAC_LEN], unsigned char *pOutput, int pOutputLen);



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
//unsigned char lEthDst[BIN_MAC_LEN];
//unsigned char lEthSrc[BIN_MAC_LEN];
unsigned char lEthDstStr[MAX_MAC_LEN+1];
unsigned char lEthSrcStr[MAX_MAC_LEN+1];

unsigned char lARPEthDstStr[MAX_MAC_LEN+1];
unsigned char lARPEthSrcStr[MAX_MAC_LEN+1];

unsigned char lARPIPDstStr[MAX_IP_LEN+1];
unsigned char lARPIPSrcStr[MAX_IP_LEN+1];



//unsigned char lARPEthDst[BIN_MAC_LEN];
//unsigned char lARPEthSrc[BIN_MAC_LEN];
//unsigned char lARPIPDst[BIN_MAC_LEN];
//unsigned char lARPIPSrc[BIN_MAC_LEN];

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
