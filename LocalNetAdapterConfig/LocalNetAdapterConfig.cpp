#include <stdio.h>
#include <winsock2.h>
#include <iphlpapi.h>

#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib, "Ws2_32.lib")

#define BIN_MAC_LEN 6



/*
 * Program entry point
 *
 */
int main(int argc, char **argv)
{
  ULONG lGWMACAddrLen = 6;
  unsigned char lGWMAC[BIN_MAC_LEN];
  unsigned char lLocalMAC[BIN_MAC_LEN];
  unsigned long lGWIPAddr = 0;
  int lFuncRetVal = 0;
  ULONG lOutBufLen = sizeof (IP_ADAPTER_INFO);
  PIP_ADAPTER_INFO lAdapterInfoPtr = NULL;
  PIP_ADAPTER_INFO lAdapter = NULL;


  if (GetAdaptersInfo(lAdapterInfoPtr, &lOutBufLen) == ERROR_BUFFER_OVERFLOW) 
  {
    if ((lAdapterInfoPtr = (IP_ADAPTER_INFO *) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, lOutBufLen)) != NULL) 
    {
      if ((lFuncRetVal = GetAdaptersInfo(lAdapterInfoPtr, &lOutBufLen)) == NO_ERROR) 
      {
        for (lAdapter = lAdapterInfoPtr; lAdapter; lAdapter = lAdapter->Next)
        {
   	      if ((lAdapter->Type == MIB_IF_TYPE_ETHERNET || lAdapter->Type == IF_TYPE_IEEE80211) &&
              strncmp(lAdapter->IpAddressList.IpAddress.String, "0.0.0.0", 16) && strncmp(lAdapter->GatewayList.IpAddress.String, "0.0.0.0", 16))
	         {
            // lLocalMAC
            CopyMemory(lLocalMAC, lAdapter->Address, sizeof(lLocalMAC));

            // Get gateway MAC address
            ZeroMemory(&lGWMAC, sizeof(lGWMAC));
            lGWIPAddr = inet_addr(lAdapter->GatewayList.IpAddress.String);
            SendARP(lGWIPAddr, 0, lGWMAC, &lGWMACAddrLen);

            printf("Adapter name  : %s\n", lAdapter->AdapterName);
            printf("Description   : %s\n", lAdapter->Description);
            printf("Local IP      : %s\n", lAdapter->IpAddressList.IpAddress.String);
            printf("Local MAC     : %02X-%02X-%02X-%02X-%02X-%02X\n", lLocalMAC[0], lLocalMAC[1], lLocalMAC[2], lLocalMAC[3], lLocalMAC[4], lLocalMAC[5]);
            printf("Gateway IP    : %s\n", lAdapter->GatewayList.IpAddress.String);
            printf("Gateway MAC   : %02X-%02X-%02X-%02X-%02X-%02X\n", lGWMAC[0], lGWMAC[1], lGWMAC[2], lGWMAC[3], lGWMAC[4], lGWMAC[5]);
          } // 
        } // for (lAdapter = lAdapterInfoPtr...
      } // if ((lFuncRetVal = GetAdaptersInfo(...
    } // if ((lAdapterInfoPtr...
  } // if (GetAdaptersInfo(...

  return(0);
}