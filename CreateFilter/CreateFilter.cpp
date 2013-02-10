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

  if ((lIFCHandle = pcap_open(lIFC, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1, NULL, lTemp)) != NULL)
  {
    ZeroMemory(&lFCode, sizeof(lFCode));
    ZeroMemory(lFilter, sizeof(lFilter));

    strcpy(lFilter, "arp");
    lNetMask = 0xffffff; // "255.255.255.0"

    // Compile the filter
    if(pcap_compile(lIFCHandle, &lFCode, (const char *) lFilter, 1, lNetMask) == 0)
    {
      // Set the filter
      if(pcap_setfilter(lIFCHandle, &lFCode) == 0)
      {
        //...
      }
    }
  }

  return(0);
}