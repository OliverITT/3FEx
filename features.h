//#include <stdint.h>
//#include <stdlib.h>
//#include <stdio.h>
#include <iostream>
#include "structs.h"
#include <vector>
// #include <iomanip>
#include <sstream>

//
std::vector<float> vector_std_fpktl;
std::vector<float>::iterator it_std_fpktl;
//
std::vector<float> vector_std_bpktl;
std::vector<float>::iterator it_std_bpktl;
//
std::vector<float> vector_std_fiat;
std::vector<float>::iterator it_std_fiat;
//
std::vector<float> vector_std_biat;
std::vector<float>::iterator it_std_biat;
//
std::vector<float> vector_std_flowpktl;
std::vector<float>::iterator it_std_flowpktl;
//
std::vector<float> vector_std_flowiat;
//ipts
std::string iptsCad = "";
std::string ipv6_SCad="";
std::string ipv6_DCad="";
std::stringstream stream;
double iptTemp = 0;
//var flow
bool iatForwardState =false;
bool iatBackwardState =false;
//var flow
double timestampInit = 0;
double timestampPrev = 0;
double timestampPrevForward = 0;
double timestampPrevBackware = 0;
uint32_t ip_shost = 0; //
uint32_t ip_dhost = 0;
uint32_t ip_shost_temp = 0; //
uint32_t ip_dhost_temp = 0; //
__uint128_t ipv6_shost =0;
__uint128_t ipv6_dhost =0;
__uint128_t ipv6_shost_temp =0;
__uint128_t ipv6_dhost_temp =0;
TCPheader ports;
TCPheader ports_temp;
//"feduration",	        // Duration of the flow in Microsecond
uint64_t total_fpackets = 0; // Total packets in the forward direction
uint64_t total_bpackets = 0; // Total packets in the backward direction
uint64_t total_fpktl = 0;    // Total size of packet in forward direction
uint64_t total_bpktl = 0;    // Total size of packet in backward direction
uint32_t min_fpktl = 65535;  // Minimum size of packet in forward direction
uint32_t min_bpktl = 65535;  // Minimum size of packet in backward direction
uint32_t max_fpktl = 0;      // Maximum size of packet in forward direction
uint32_t max_bpktl = 0;      // Maximum size of packet in backward direction
float mean_fpktl = 0;        // Mean size of packet in forward direction
float mean_bpktl = 0;        // Mean size of packet in backward direction
double std_fpktl = 0.0;      // Standard deviation size of packet in forward direction
double std_bpktl = 0.0;      // Standard deviation size of packet in backward direction
double total_fiat = 0;       // Total time between two packets sent in the forward direction
double total_biat = 0;       // Total time between two packets sent in the backward direction

float min_fiat = 65536; // Minimum time between two packets sent in the forward direction
float min_biat = 65536; // Minimum time between two packets sent in the backward direction
//
float max_fiat = 0; // Maximum time between two packets sent in the forward direction
float max_biat = 0; // Maximum time between two packets sent in the backward direction

float mean_fiat = 0; // Mean time between two packets sent in the forward direction
float mean_biat = 0; // Mean time between two packets sent in the backward direction
//
float std_fiat = 0; // Standard deviation time between two packets sent in the forward direction
float std_biat = 0; // Standard deviation time between two packets sent in the backward direction
//
uint32_t fpsh_cnt = 0; // Number of times the PSH flag was set in packets travelling in the forward direction (0 for UDP)
uint32_t bpsh_cnt = 0; // Number of times the PSH flag was set in packets travelling in the backward direction (0 for UDP)
uint32_t furg_cnt = 0; // Number of times the URG flag was set in packets travelling in the forward direction (0 for UDP)
uint32_t burg_cnt = 0; // Number of times the URG flag was set in packets travelling in the backward direction (0 for UDP)

/*            
            ->"total_fhlen",	        // Total bytes used for headers in the forward direction
            ->"total_bhlen",	        // Total bytes used for headers in the forward direction
            */
/* ya calculados en archivo functions
float fPktsPerSecond = 0;     // Number of forward packets per second
float bPktsPerSecond = 0;     // Number of backward packets per second
float flowPktsPerSecond = 0;  // Number of flow packets per second
float flowBytesPerSecond = 0; // Number of flow bytes per second
            -> numero de paquetes en direccion / duracion de flujo? "fPktsPerSecond",	    // Number of forward packets per second
            ->*"bPktsPerSecond",	    // Number of backward packets per second
            ->*"flowPktsPerSecond",	// Number of flow packets per second
            ->*"flowBytesPerSecond",	// Number of flow bytes per second
*/

uint32_t min_flowpktl = 0; // Minimum length of a flow
uint32_t max_flowpktl = 0; // Maximum length of a flow
double mean_flowpktl = 0;  // Mean length of a flow
float std_flowpktl = 0;    // Standard deviation length of a flow

float min_flowiat = 0;   // Minimum inter-arrival time of packet
float max_flowiat = 0;   // Maximum inter-arrival time of packet
double mean_flowiat = 0; // Mean inter-arrival time of packet
double std_flowiat = 0;  // Standard deviation inter-arrival time of packet

uint32_t flow_fin = 0; // Number of packets with FIN
uint32_t flow_syn = 0; // Number of packets with SYN
uint32_t flow_rst = 0; // Number of packets with RST
uint32_t flow_psh = 0; // Number of packets with PUSH
uint32_t flow_ack = 0; // Number of packets with ACK
uint32_t flow_urg = 0; // Number of packets with URG
uint32_t flow_cwr = 0; // Number of packets with CWE
uint32_t flow_ece = 0; // Number of packets with ECE
/*
           -> "downUpRatio",	        // Download and upload ratio
            "avgPacketSize",	    // Average size of packet
            ->"fAvgSegmentSize",	    // Average size observed in the forward direction
            ->"fAvgBytesPerBulk",	    // Average number of bytes bulk rate in the forward direction
            ->"fAvgPacketsPerBulk",	// Average number of packets bulk rate in the forward direction
            ->"bAvgBulkRate", 	    # Average number of bulk rate in the backward direction
            ->"fAvgBulkRate", 	    // Average number of bulk rate in the forward direction
            ->"bAvgSegmentSize",	    // Average size observed in the backward direction
            ->"bAvgBytesPerBulk",	    // Average number of bytes bulk rate in the backward direction
            ->"bAvgPacketsPerBulk",	// Average number of packets bulk rate in the backward direction
             
            "label",                # Classification Label
            */
//vars control
uint32_t incl_leng = 0; /* number of octets of packet saved in file */
uint32_t orig_len =0; /* actual length of packet */
uint64_t jump = 0;
uint64_t traficPointer = 0;
uint8_t traficTipe = 0;

double timestampTemp = 0;

void resetVar()
{
    //ipts
    iptsCad = "";
    ipv6_SCad = "";
    ipv6_DCad = "";
    iptTemp = 0;
    //
    vector_std_fpktl.clear();
    vector_std_bpktl.clear();
    vector_std_fiat.clear();
    vector_std_biat.clear();
    vector_std_flowpktl.clear();
    vector_std_flowiat.clear();
    
    iatForwardState =false;
    iatBackwardState =false;
    //flow
    timestampInit = 0;
    timestampPrev = 0;
    total_fpackets = 0; // Total packets in the forward direction
    total_bpackets = 0; // Total packets in the backward direction
    total_fpktl = 0;    // Total size of packet in forward direction
    total_bpktl = 0;    // Total size of packet in backward direction
    min_fpktl = 65535;  // Minimum size of packet in forward direction
    min_bpktl = 65535;  // Minimum size of packet in backward direction
    max_fpktl = 0;      // Maximum size of packet in forward direction
    max_bpktl = 0;      // Maximum size of packet in backward direction
    mean_fpktl = 0;     // Mean size of packet in forward direction
    mean_bpktl = 0;     // Mean size of packet in backward direction
    std_fpktl = 0;      // Standard deviation size of packet in forward direction
    std_bpktl = 0;      // Standard deviation size of packet in backward direction

    total_fiat = 0; // Total time between two packets sent in the forward direction
    total_biat = 0; // Total time between two packets sent in the backward direction

    min_fiat = 65536; // Minimum time between two packets sent in the forward direction
    min_biat = 65536; // Minimum time between two packets sent in the backward direction
    max_fiat = 0;     // Maximum time between two packets sent in the forward direction
    max_biat = 0;     // Maximum time between two packets sent in the backward direction
    mean_fiat = 0;    // Mean time between two packets sent in the forward direction
    mean_biat = 0;    // Mean time between two packets sent in the backward direction
    std_fiat = 0;     // Standard deviation time between two packets sent in the forward direction
    std_biat = 0;     // Standard deviation time between two packets sent in the backward direction

    fpsh_cnt = 0; // Number of times the PSH flag was set in packets travelling in the forward direction (0 for UDP)
    bpsh_cnt = 0; // Number of times the PSH flag was set in packets travelling in the backward direction (0 for UDP)
    furg_cnt = 0; // Number of times the URG flag was set in packets travelling in the forward direction (0 for UDP)
    burg_cnt = 0; // Number of times the URG flag was set in packets travelling in the backward direction (0 for UDP)

    /*

            ->"total_fhlen",	        // Total bytes used for headers in the forward direction
            ->"total_bhlen",	        // Total bytes used for headers in the forward direction
            */
    /* calculados en archivo functions
        fPktsPerSecond = 0;     // Number of forward packets per second
        bPktsPerSecond = 0;     // Number of backward packets per second
        flowPktsPerSecond = 0;  // Number of flow packets per second
        flowBytesPerSecond = 0; // Number of flow bytes per second*
*/

    /*
            -> numero de paquetes en direccion / duracion de flujo? "fPktsPerSecond",	    // Number of forward packets per second
            ->*"bPktsPerSecond",	    // Number of backward packets per second
            ->*"flowPktsPerSecond",	// Number of flow packets per second
            ->*"flowBytesPerSecond",	// Number of flow bytes per second
    */

    min_flowpktl = 0;  // Minimum length of a flow
    max_flowpktl = 0;  // Maximum length of a flow
    mean_flowpktl = 0; // Mean length of a flow
    std_flowpktl = 0;  // Standard deviation length of a flow

    min_flowiat = 0;  // Minimum inter-arrival time of packet
    max_flowiat = 0;  // Maximum inter-arrival time of packet
    mean_flowiat = 0; // Mean inter-arrival time of packet
    std_flowiat = 0;  // Standard deviation inter-arrival time of packet

    flow_fin = 0; // Number of packets with FIN
    flow_syn = 0; // Number of packets with SYN
    flow_rst = 0; // Number of packets with RST
    flow_psh = 0; // Number of packets with PUSH
    flow_ack = 0; // Number of packets with ACK
    flow_urg = 0; // Number of packets with URG
    flow_cwr = 0; // Number of packets with CWE
    flow_ece = 0; // Number of packets with ECE

    /*
    ->"downUpRatio",                                                                              // Download and upload ratio
        ->"avgPacketSize",                                                                        // Average size of packet
        ->"fAvgSegmentSize",                                                                      // Average size observed in the forward direction
        ->"fAvgBytesPerBulk",                                                                     // Average number of bytes bulk rate in the forward direction
        ->"fAvgPacketsPerBulk",                                                                   // Average number of packets bulk rate in the forward direction
        ->"bAvgBulkRate", #Average number of bulk rate in the backward direction->"fAvgBulkRate", // Average number of bulk rate in the forward direction
        ->"bAvgSegmentSize",                                                                      // Average size observed in the backward direction
        ->"bAvgBytesPerBulk",                                                                     // Average number of bytes bulk rate in the backward direction
        ->"bAvgPacketsPerBulk",                                                                   // Average number of packets bulk rate in the backward direction

        "label", #Classification Label 
        */
    //vars control
    incl_leng = 0;
    orig_len =0;
    //jump = 0;
    traficTipe = 0;

    timestampTemp = 0;
    timestampInit = 0;
    timestampPrev = 0;
    //var test
    //clear ips and port
    ip_shost = ip_dhost = 0;
    ports.srcPort = ports.dstPort = 0;
    ipv6_shost = ipv6_dhost = 0;
    ports_temp.dstPort = ports_temp.srcPort =0;
}