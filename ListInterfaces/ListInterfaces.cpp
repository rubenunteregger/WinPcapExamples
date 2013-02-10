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
  int lRetVal = 0;
  pcap_if_t *lAllDevs = NULL;
  pcap_if_t *lDevice = NULL;
  pcap_addr_t *lAddress = NULL;
  char lIP6Str[128];
  char lTemp[PCAP_ERRBUF_SIZE];
  int lCounter;

  if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &lAllDevs, lTemp) != -1)
  {
    for (lDevice = lAllDevs, lCounter = 0; lDevice; lDevice = lDevice->next, lCounter++)
    {
      printf("\n%s\n", lDevice->name);

      if (lDevice->description)
        printf("  %-30s %s\n", "Description", lDevice->description);

      /* 
       * Enumerate all IP addresses related to this adapter.
       */
      for (lAddress = lDevice->addresses; lAddress != NULL ; lAddress = lAddress->next) 
      {  
        switch(lAddress->addr->sa_family)
        {
          case AF_INET:
            printf("  %-30s AF_INET\n", "Address Family Name");
            if (lAddress->addr)
              printf("  %-30s %s\n", "IPv4 address", 
                     iptos(((struct sockaddr_in *)lAddress->addr)->sin_addr.s_addr));
            if (lAddress->netmask)
              printf("  %-30s %s\n", "Netmask address", 
                     iptos(((struct sockaddr_in *)lAddress->netmask)->sin_addr.s_addr));
            if (lAddress->broadaddr)
              printf("  %-30s %s\n", "Broadcast Address", 
                     iptos(((struct sockaddr_in *)lAddress->broadaddr)->sin_addr.s_addr));
            if (lAddress->dstaddr)
              printf("  %-30s %s\n", "Destination Address",
                      iptos(((struct sockaddr_in *)lAddress->dstaddr)->sin_addr.s_addr));
            break;

          case AF_INET6:
            printf("  %-30s AF_INET6\n", "Address Family Name");
            if (lAddress->addr && 
                getnameinfo(lAddress->addr, sizeof(struct sockaddr_in6), lIP6Str, sizeof(lIP6Str), NULL, 0, NI_NUMERICHOST) == 0)
              printf("  %-30s %s\n", "IPv6 Address", lIP6Str);
           break;

          default:
            printf("  %-30s Unknown\n", "Address Family Name");
            break;
        }
      }
    }

    pcap_freealldevs(lAllDevs);
  }

  return(lRetVal);
}

/*
 * Convert a numeric IP address to a string ()
 *
 */
#define IPTOSBUFFERS 12
char *iptos(unsigned long pIPAddr)
{
  static char lRetVal[IPTOSBUFFERS][3*4+3+1];
  static short lIndex;
  u_char *lIPPtr;

  lIPPtr = (u_char *) &pIPAddr;
  lIndex = (lIndex + 1 == IPTOSBUFFERS ? 0 : lIndex + 1);
  _snprintf(lRetVal[lIndex], sizeof(lRetVal[lIndex]), "%d.%d.%d.%d", lIPPtr[0], lIPPtr[1], lIPPtr[2], lIPPtr[3]);

  return(lRetVal[lIndex]);
}
