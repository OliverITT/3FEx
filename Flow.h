#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#ifndef _FLOW
#define _FLOW
class Flow
{
public:
    uint8_t protocol; //layer prococol
    double timestamp; //timestamp
    //ipv4
    uint32_t ip_shost; //
    uint32_t ip_dhost; //
    uint16_t srcPort;  // source port
    uint16_t dstPort;  // destination port
    //ipv6
    __uint128_t ipv6_shost; // ip v6 source
    __uint128_t ipv6_dhost; // ip v6 destination
    double fduration;       // Duration of the flow in Microsecond
    //flow
    uint64_t total_fpackets;  // = 0; // Total packets in the forward direction
    uint64_t total_bpackets;  // = 0; // Total packets in the backward direction
    uint64_t total_fpktl;     // = 0;    // Total size of packet in forward direction
    uint64_t total_bpktl;     // = 0;    // Total size of packet in backward direction
    uint32_t min_fpktl;       // = 65535; // Minimum size of packet in forward direction
    uint32_t min_bpktl;       // = 65535; // Minimum size of packet in backward direction
    uint32_t max_fpktl;       // = 0;  // Maximum size of packet in forward direction
    uint32_t max_bpktl;       // = 0;  // Maximum size of packet in backward direction
    float mean_fpktl;         // = 0;    // Mean size of packet in forward direction
    float mean_bpktl;         // = 0;    // Mean size of packet in backward direction
    double std_fpktl;         // = 0.0;  // Standard deviation size of packet in forward direction
    double std_bpktl;         // = 0.0;  // Standard deviation size of packet in backward direction
    double total_fipt;        // = 0;   // Total time between two packets sent in the forward direction
    double total_bipt;        // = 0;   // Total time between two packets sent in the backward direction
    float min_fipt;           // = 65536;  // Minimum time between two packets sent in the forward direction
    float min_bipt;           // = 65536;  // Minimum time between two packets sent in the backward direction
    float max_fipt;           // = 0;      // Maximum time between two packets sent in the forward direction
    float max_bipt;           // = 0;      // Maximum time between two packets sent in the backward direction
    float mean_fipt;          // = 0;     // Mean time between two packets sent in the forward direction
    float mean_bipt;          // = 0;     // Mean time between two packets sent in the backward direction
    float std_fipt;           // = 0;      // Standard deviation time between two packets sent in the forward direction
    float std_bipt;           // = 0;      // Standard deviation time between two packets sent in the backward direction
    uint32_t fpsh_cnt;        // = 0;   // Number of times the PSH flag was set in packets travelling in the forward direction (0 for UDP)
    uint32_t bpsh_cnt;        // = 0;   // Number of times the PSH flag was set in packets travelling in the backward direction (0 for UDP)
    uint32_t furg_cnt;        // = 0;   // Number of times the URG flag was set in packets travelling in the forward direction (0 for UDP)
    uint32_t burg_cnt;        // = 0;   // Number of times the URG flag was set in packets travelling in the backward direction (0 for UDP)
    uint32_t total_fhlen;     // = 0; // Total bytes used for headers in the forward direction
    uint32_t total_bhlen;     // = 0; // Total bytes used for headers in the forward direction
    float fPktsPerSecond;     // = 0;     // Number of forward packets per second
    float bPktsPerSecond;     // = 0;     // Number of backward packets per second
    float flowPktsPerSecond;  // = 0;  // Number of flow packets per second
    float flowBytesPerSecond; // = 0; // Number of flow bytes per second
    double mean_flowpktl;     // = 0;  // Mean length of a flow
    float std_flowpktl;       // = 0;   // Standard deviation length of a flow
    double mean_flowipt;      // = 0; // Mean inter-arrival time of packet
    double std_flowipt;       // = 0;   // Standard deviation inter-arrival time of packet
    uint32_t flow_fin;        // = 0;    // Number of packets with FIN
    uint32_t flow_syn;        // = 0;    // Number of packets with SYN
    uint32_t flow_rst;        // = 0;    // Number of packets with RST
    uint32_t flow_psh;        // = 0;    // Number of packets with PUSH
    uint32_t flow_ack;        // = 0;    // Number of packets with ACK
    uint32_t flow_urg;        // = 0;    // Number of packets with URG
    uint32_t flow_cwr;        // = 0;    // Number of packets with CWE
    uint32_t flow_ece;        // = 0;    // Number of packets with ECE
    float downUpRation;
    int priority;
    int classification;

public:
    Flow(/* args */);
    ~Flow();
};

Flow::Flow(/* args */)
{
    this->protocol = -1;  //layer prococol
    this->timestamp = -1; //timestamp
    //ipv4
    this->ip_shost = 0; //
    this->ip_dhost = 0; //
    this->srcPort = 0;  // source port
    this->dstPort = 0;  // destination port
    //ipv6
    this->ipv6_shost = 0; // ip v6 source
    this->ipv6_dhost = 0; // ip v6 destination
    this->fduration = -1; // Duration of the flow in Microsecond
    //flow
    this->total_fpackets = 0;     // Total packets in the forward direction
    this->total_bpackets = 0;     // Total packets in the backward direction
    this->total_fpktl = 0;        // Total size of packet in forward direction
    this->total_bpktl = 0;        // Total size of packet in backward direction
    this->min_fpktl = 65535;      // Minimum size of packet in forward direction
    this->min_bpktl = 65535;      // Minimum size of packet in backward direction
    this->max_fpktl = 0;          // Maximum size of packet in forward direction
    this->max_bpktl = 0;          // Maximum size of packet in backward direction
    this->mean_fpktl = 0;         // Mean size of packet in forward direction
    this->mean_bpktl = 0;         // Mean size of packet in backward direction
    this->std_fpktl = 0.0;        // Standard deviation size of packet in forward direction
    this->std_bpktl = 0.0;        // Standard deviation size of packet in backward direction
    this->total_fipt = 0;         // Total time between two packets sent in the forward direction
    this->total_bipt = 0;         // Total time between two packets sent in the backward direction
    this->min_fipt = 65536;       // Minimum time between two packets sent in the forward direction
    this->min_bipt = 65536;       // Minimum time between two packets sent in the backward direction
    this->max_fipt = 0;           // Maximum time between two packets sent in the forward direction
    this->max_bipt = 0;           // Maximum time between two packets sent in the backward direction
    this->mean_fipt = 0;          // Mean time between two packets sent in the forward direction
    this->mean_bipt = 0;          // Mean time between two packets sent in the backward direction
    this->std_fipt = 0;           // Standard deviation time between two packets sent in the forward direction
    this->std_bipt = 0;           // Standard deviation time between two packets sent in the backward direction
    this->fpsh_cnt = 0;           // Number of times the PSH flag was set in packets travelling in the forward direction (0 for UDP)
    this->bpsh_cnt = 0;           // Number of times the PSH flag was set in packets travelling in the backward direction (0 for UDP)
    this->furg_cnt = 0;           // Number of times the URG flag was set in packets travelling in the forward direction (0 for UDP)
    this->burg_cnt = 0;           // Number of times the URG flag was set in packets travelling in the backward direction (0 for UDP)
    this->total_fhlen = 0;        // Total bytes used for headers in the forward direction
    this->total_bhlen = 0;        // Total bytes used for headers in the forward direction
    this->fPktsPerSecond = 0;     // Number of forward packets per second
    this->bPktsPerSecond = 0;     // Number of backward packets per second
    this->flowPktsPerSecond = 0;  // Number of flow packets per second
    this->flowBytesPerSecond = 0; // Number of flow bytes per second
    this->mean_flowpktl = 0;      // Mean length of a flow
    this->std_flowpktl = 0;       // Standard deviation length of a flow
    this->mean_flowipt = 0;       // Mean inter-arrival time of packet
    this->std_flowipt = 0;        // Standard deviation inter-arrival time of packet
    this->flow_fin = 0;           // Number of packets with FIN
    this->flow_syn = 0;           // Number of packets with SYN
    this->flow_rst = 0;           // Number of packets with RST
    this->flow_psh = 0;           // Number of packets with PUSH
    this->flow_ack = 0;           // Number of packets with ACK
    this->flow_urg = 0;           // Number of packets with URG
    this->flow_cwr = 0;           // Number of packets with CWE
    this->flow_ece = 0;           // Number of packets with ECE
    this->downUpRation = -1;
    this->priority = -1;
    this->classification = -1;
}

Flow::~Flow()
{
}

#endif