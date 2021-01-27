#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#define _IPV4 0x0800
#define _IPV6 0x86DD
#define _TCP 0x6
#define _UDP 0x11

#define _PSH 0x08
#define _URG 0x20
#define _FIN 0x01
#define _SYN 0x02
#define _RST 0x04
#define _PUSH 0x08
#define _ACK 0x10
#define _CWE 0x80
#define _ECE 0x40


unsigned char *bffRawTrafic;
unsigned char *bffAlertTrafic;
uint64_t pointerbffRawTrafic=0;
uint64_t pointerbffAlertTrafic=0;
//colums featurs
const char titlecolums[] = {"proto,ts,flow,srcIP,srcPrt,dstIP,dstPrt,feduration,total_fpackets,total_bpackets,total_fpktl,total_bpktl,min_fpktl,min_bpktl,max_fpktl,max_bpktl,mean_fpktl,mean_bpktl,std_fpktl,std_bpktl,total_fiat,total_biat,min_fiat,min_biat,max_fiat,max_biat,mean_fiat,mean_biat,std_fiat,std_biat,fpsh_cnt,bpsh_cnt,furg_cnt,burg_cnt,total_fhlen,total_bhlen,fPktsPerSecond,bPktsPerSecond,flowPktsPerSecond,flowBytesPerSecond,min_flowpktl,max_flowpktl,mean_flowpktl,std_flowpktl,min_flowiat,max_flowiat,mean_flowiat,std_flowiat,flow_fin,flow_syn,flow_rst,flow_psh,flow_ack,flow_urg,flow_cwr,flow_ece,downUpRatio,avgPacketSize,fAvgSegmentSize,fAvgBytesPerBulk,fAvgPacketsPerBulk,fAvgBulkRate,bAvgSegmentSize,bAvgBytesPerBulk,bAvgPacketsPerBulk,bAvgBulkRate,label\n"};
struct PacapFileHeader
{
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    uint32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct PcapPackHeader
{
    uint32_t ts_sec;   /* timestamp seconds */
    uint32_t ts_usec;  /* timestamp microseconds */
    uint32_t incl_len; /* number of octets of packet saved in file */
    uint32_t orig_len; /* actual length of packet */
};
struct EtherHeader
{
    uint8_t ether_dhost[6]; // destination host
    uint8_t ether_shost[6]; // source host
    uint16_t ether_type;    //
};

struct Ipv4Header
{
    uint8_t versionIHL;
    uint8_t differentiatedServices;
    uint16_t totallength;
    uint16_t identification;
    uint16_t flagsFragmentoffset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t headerchecksum;
    uint32_t ip_shost; //
    uint32_t ip_dhost; //
};
struct Ipv6Header
{
    uint16_t versionTraficlass;
    uint16_t flowLabel;
    uint16_t payloadLength;
    uint8_t nextHeader;
    uint8_t hopLimit;
    uint8_t ip_shost[16];
    uint8_t ip_dhost[16];
};
struct TCPheader
{
    uint16_t srcPort;
    uint16_t dstPort;

};

struct Packetipv4
{
    struct PcapPackHeader packetHeader;
    struct EtherHeader ethernetHeader;
    struct Ipv4Header ipv4Header;
    struct TCPheader tcpHeader;
};
struct ipv4cast{
    uint8_t ipcast[4];
};
struct Packetipv6
{
    PcapPackHeader packetHeader;
    EtherHeader ethernetHeader;
    Ipv6Header ipv6Header;
    TCPheader tcpHeader;
};
