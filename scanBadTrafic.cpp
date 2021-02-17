#ifndef SCAN_BAD_TRAFIC
#define SCAN_BAD_TRAFIC
#include "IOPcapFile.h"
#include <map>
#include <inttypes.h>

std::map<std::string, uint8_t> data;
std::map<std::string, uint8_t>::iterator it;
std::string *ip_proto;
void readBadTrafic(FILE &badTrafic)
{
    Packet_pcap *packet_pcap; // = new Packet_pcap;
    int cont = 0;

    while (getNextPacket(badTrafic, packet_pcap))
    {
        cont++;
        ip_proto = new std::string;
        switch (packet_pcap->tipe)
        {
        case IPV4_TCP:
            //*ip_proto = "" + std::to_string(packet_pcap->ip_layer.ipv4Header.ip_dhost) +":"+ std::to_string(packet_pcap->proto.tcpHeader.dstPort) + std::to_string(packet_pcap->ip_layer.ipv4Header.ip_shost) +":"+ std::to_string(packet_pcap->proto.tcpHeader.srcPort);
            // data[*ip_proto] = 0;
            break;
        case IPV4_UDP:
            /* code */
            break;
        case IPV6_TCP:
            /* code */
            break;
        case IPV6_UDP:
            /* code */
            break;

        default:
            break;
        }
        delete ip_proto;
    }
    printf("\ncontador:%d\n", cont);
    delete packet_pcap;
}
#endif
int main(int argc, char **argv)
{
    FILE *badTrafic = fopen(argv[1], "rb");
    FILE *OTrafic = fopen(argv[2], "wb");
    if (!badTrafic)
    {
        return 1;
    }

    PacapFileHeader *fileHeader;
    readHeaderPcapFile(*badTrafic, fileHeader);
    writeHeaderPcapFile(*OTrafic, fileHeader);
    Packet_pcap *packete;
    int cont = 0;
    while (getNextPacket(*badTrafic, packete))
    {
        cont++;
        if (packete->tipe == OTDER_TRAFIC)
        {
            printf("tipstap:%d\n", packete->packetHeader.ts_usec);
        }
        std::string *s = new std::string;
        int y = 1100;
        *s = std::to_string((uint64_t)(packete->ip_layer.ipv6Header.ip_shost));
        printf("ip:%s\n",s->c_str());
        //printf("%016" PRIx64 ":%016" PRIx64 "\n", (uint64_t)(packete->ip_layer.ipv6Header.ip_shost), (uint64_t)(packete->ip_layer.ipv6Header.ip_shost >> 64));
        writePacket(*OTrafic, packete);
    }
    /* 
    readBadTrafic(*badTrafic);
    for (it = data.begin(); it != data.end(); ++it)
    {
        printf("%s,%d\n", it->first.c_str(), it->second);
    } */

    return 0;
}
