#define HAVE_REMOTE
 
#include <stdio.h>
#include <pcap.h>
#include <Iphlpapi.h>

#include "../WinPcapExamples/Packets.h"
#include "../WinPcapExamples/Config.h" 


#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")


void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);


/*
 * Program entry point
 *
 */
int main(int argc, char **argv)
{
  pcap_t *lIFCHandle = NULL;
  char lTemp[1024];
  char *lIFC = argv[1];

  if (lIFC)
    if ((lIFCHandle = pcap_open(lIFC , 65536, PCAP_OPENFLAG_PROMISCUOUS, 1, NULL, lTemp)) != NULL)
      pcap_loop(lIFCHandle, 0, packet_handler, NULL);


  return(0);
}


void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
  printf(".");
}