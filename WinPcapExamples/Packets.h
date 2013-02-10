#ifndef __PACKETS__
#define __PACKETS__

#include <stdio.h>

//  warning C4996: This function or variable may be unsafe ... use _CRT_SECURE_NO_WARNINGS. See online help for details.
#pragma warning(disable: 4996)

#define snprintf _snprintf
#define MAX_BUF_SIZE 1024

#define OK 0
#define NOK 1

#define BIN_IP_LEN 4
#define BIN_MAC_LEN 6
#define MAX_IP_LEN 16
#define MAX_MAC_LEN 18



#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_IP 0x0800

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



typedef struct pARPPacket
{
  char IFCName[MAX_BUF_SIZE + 1];
  int lReqType;
  unsigned char Eth_SrcMAC[BIN_MAC_LEN];
  unsigned char Eth_DstMAC[BIN_MAC_LEN];

  unsigned char ARP_LocalMAC[BIN_MAC_LEN];
  unsigned char ARP_LocalIP[BIN_IP_LEN];
  unsigned char ARP_Dst_MAC[BIN_MAC_LEN];
  unsigned char ARP_DstIP[BIN_IP_LEN];
} ARPPacket, *PARPPacket;


typedef struct SCANPARAMS
{
  unsigned char IFCName[MAX_BUF_SIZE + 1];
  unsigned char IFCAlias[MAX_BUF_SIZE + 1];
  unsigned char IFCDescr[MAX_BUF_SIZE + 1];
  char IFCString[MAX_BUF_SIZE + 1];
  int Index;
  unsigned char GWIP[BIN_IP_LEN];
  unsigned char GWMAC[BIN_MAC_LEN];
  unsigned char StartIP[BIN_IP_LEN];
  unsigned long StartIPNum;
  unsigned char StopIP[BIN_IP_LEN];
  unsigned long StopIPNum;
  unsigned char LocalIP[BIN_IP_LEN];
  unsigned char LocalMAC[BIN_MAC_LEN];
  void *IfcWriteHandle;
} SCANPARAMS, *PSCANPARAMS;


#endif