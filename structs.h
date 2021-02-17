#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#ifndef STRUCTS
#define STRUCTS
#define _IPV4 0x0800
#define __IPV4 0x0008
#define _IPV6 0x86DD
#define __IPV6 0xDD86
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
#define uint128_t __uint128_t
//#define uint128_t unsigned __int128

#ifdef __SIZEOF_INT128__
int detected_ok() { return 1; }
#endif

enum
{
    IPV4_OTDER_PROTO = 0,
    IPV4_TCP,
    IPV4_UDP,
    IPV6_OTDER_PROTO,
    IPV6_TCP,
    IPV6_UDP,
    OTDER_TRAFIC
};

unsigned char *bffRawTrafic;
unsigned char *bffAlertTrafic;
uint64_t pointerbffRawTrafic = 0;
uint64_t pointerbffAlertTrafic = 0;
//colums featurs
const char titlecolums[] = {"proto,ts,flow,srcIP,srcPrt,dstIP,dstPrt,feduration,total_fpackets,total_bpackets,total_fpktl,total_bpktl,min_fpktl,min_bpktl,max_fpktl,max_bpktl,mean_fpktl,mean_bpktl,std_fpktl,std_bpktl,total_fiat,total_biat,min_fiat,min_biat,max_fiat,max_biat,mean_fiat,mean_biat,std_fiat,std_biat,fpsh_cnt,bpsh_cnt,furg_cnt,burg_cnt,total_fhlen,total_bhlen,fPktsPerSecond,bPktsPerSecond,flowPktsPerSecond,flowBytesPerSecond,min_flowpktl,max_flowpktl,mean_flowpktl,std_flowpktl,min_flowiat,max_flowiat,mean_flowiat,std_flowiat,flow_fin,flow_syn,flow_rst,flow_psh,flow_ack,flow_urg,flow_cwr,flow_ece,downUpRatio,avgPacketSize,fAvgSegmentSize,fAvgBytesPerBulk,fAvgPacketsPerBulk,fAvgBulkRate,bAvgSegmentSize,bAvgBytesPerBulk,bAvgPacketsPerBulk,bAvgBulkRate,label\n"};
typedef struct PacapFileHeader
{
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    uint32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} PacapFileHeader_t;

typedef struct PcapPackHeader
{
    uint32_t ts_sec;   /* timestamp seconds */
    uint32_t ts_usec;  /* timestamp microseconds */
    uint32_t incl_len; /* number of octets of packet saved in file */
    uint32_t orig_len; /* actual length of packet */
} PcapPackHeader_t;

typedef struct EtherHeader
{
    uint8_t ether_dhost[6]; // destination host
    uint8_t ether_shost[6]; // source host
    uint16_t ether_type;    //
} EtherHeader_t;
typedef struct Ipv4Header
{

    union
    {
        uint8_t version : 4;
        uint8_t IHL : 4;
    } V_I;
    uint8_t differentiatedServices;
    uint16_t totallength;
    uint16_t identification;
    union
    {
        uint16_t flags : 3;
        uint16_t FragmentOffset : 13;
    } F_F;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t headerchecksum;
    uint32_t ip_shost; //
    uint32_t ip_dhost; //
} Ipv4Header_t;
typedef struct Ipv6Header
{
    union
    {
        /* data */
        uint32_t version : 4;
        uint32_t trafiClass : 8;
        uint32_t flowLabel : 20;
    } V_T;
    uint16_t payloadLength;
    uint8_t nextHeader;
    uint8_t hopLimit;
    __uint128_t ip_shost;
    __uint128_t ip_dhost;
    // uint8_t ip_shost[16];
    // uint8_t ip_dhost[16];
} Ipv6Header_t;

typedef struct TCPheader
{
    uint16_t srcPort;
    uint16_t dstPort;
    uint32_t sequence_Number;
    uint32_t acknowledgment_Number;
    union
    {
        /* data */
        uint16_t data_Offset : 4;
        uint16_t reserved : 3;
        uint16_t ecn : 3;
        uint16_t controlBits : 6;
    } DO_r_ECN_C;

    uint16_t window;
    uint16_t checksum;
    uint16_t urgentPointer;
} TCPheader_t;
typedef struct UDPheader
{
    uint16_t srcPort;
    uint16_t dstPort;
    uint16_t length;
    uint16_t checksum;
} UDPheader_t;

typedef struct Packet_pcap
{
    PcapPackHeader packetHeader;
    EtherHeader ethernetHeader;
    union
    {
        /* data */
        Ipv6Header ipv6Header;
        Ipv4Header ipv4Header;
    } ip_layer;
    union
    {
        /* data */
        TCPheader tcpHeader;
        UDPheader uDPheader;
    } proto;
    uint8_t tipe;
    uint8_t *payload;
} Packet_pcap_t;

struct ipv4cast
{
    uint8_t ipcast[4];
};
typedef struct Packetipv6
{
    PcapPackHeader packetHeader;
    EtherHeader ethernetHeader;
    Ipv6Header ipv6Header;
    TCPheader tcpHeader;
} Packetipv6_t;
#endif