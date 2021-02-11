#include "packet.h"
#include <stdio.h>
#include "ipv4.h"
#include "protocol.h"
#include <iostream>
#include <map>

extern std::map<std::string, char> data;
void readBadTrafic(FILE &badTrafic)
{
    fseek(&badTrafic, 24L, SEEK_SET);
    Packet_pcap *packet_pcap = new Packet_pcap;

    while (fread(&packet_pcap->packetHeader, sizeof(PcapPackHeader), 1, &badTrafic))
    {
        /* code */

        if (!fread(&packet_pcap->ethernetHeader, sizeof(EtherHeader), 1, &badTrafic))
        {
            printf("unknown file");
            return;
        }
        switch (packet_pcap->ethernetHeader.ether_type)
        {
        case __IPV4:

            if (!fread(&packet_pcap->ip_layer.ipv4Header, sizeof(Ipv4Header), 1, &badTrafic))
            {
                return;
            }
            packet_pcap->ip_tipe = _IPV4;
            switch (packet_pcap->ip_layer.ipv4Header.protocol)
            {
            case _TCP:
                if (!fread(&packet_pcap->proto.tcpHeader, sizeof(TCPheader), 1, &badTrafic))
                {
                    return;
                }
                packet_pcap->protocol = _TCP;
                fseek(&badTrafic, (packet_pcap->packetHeader.incl_len - 14 - 40), SEEK_CUR);
                break;
            case _UDP:
                if (!fread(&packet_pcap->proto.uDPheader, sizeof(UDPheader), 1, &badTrafic))
                {
                    return;
                }
                packet_pcap->protocol = _UDP;
                fseek(&badTrafic, (packet_pcap->packetHeader.incl_len - 14 - 20 - 8), SEEK_CUR);
                break;

            default:
                fseek(&badTrafic, (packet_pcap->packetHeader.incl_len - 14 - 20), SEEK_CUR);
                break;
            }
            break;
        case __IPV6:
            if (!fread(&packet_pcap->ip_layer.ipv6Header, sizeof(Ipv6Header), 1, &badTrafic))
            {
                return;
            }
            packet_pcap->ip_tipe = _IPV6;
            switch (packet_pcap->ip_layer.ipv6Header.nextHeader)
            {
            case _TCP:
                if (!fread(&packet_pcap->proto.tcpHeader, sizeof(TCPheader), 1, &badTrafic))
                {
                    return;
                }
                packet_pcap->protocol = _TCP;
                fseek(&badTrafic, (packet_pcap->packetHeader.incl_len - 14 - 40 - 20), SEEK_CUR);
                break;
            case _UDP:
                if (!fread(&packet_pcap->proto.uDPheader, sizeof(UDPheader), 1, &badTrafic))
                {
                    return;
                }
                packet_pcap->protocol = _UDP;
                fseek(&badTrafic, (packet_pcap->packetHeader.incl_len - 14 - 40 - 8), SEEK_CUR);
                break;

            default:
                fseek(&badTrafic, (packet_pcap->packetHeader.incl_len - 14 - 40), SEEK_CUR);
                break;
            }
            break;
        default:
            fseek(&badTrafic, (packet_pcap->packetHeader.incl_len - 14), SEEK_CUR);
            break;
        }

        printf("time stamp sec:%d\n", packet_pcap->packetHeader.ts_sec);
        printf("time stamp mic:%d\n", packet_pcap->packetHeader.ts_usec);
        printf("incl_len:%d\n", packet_pcap->packetHeader.incl_len);
        printf("orig_len:%d\n", packet_pcap->packetHeader.orig_len);
        printf("mac %X:%X:%X:%X:%X:%X\n", packet_pcap->ethernetHeader.ether_dhost[0], packet_pcap->ethernetHeader.ether_dhost[1], packet_pcap->ethernetHeader.ether_dhost[2], packet_pcap->ethernetHeader.ether_dhost[3], packet_pcap->ethernetHeader.ether_dhost[4], packet_pcap->ethernetHeader.ether_dhost[5]);
        printf("tipo trafic %X\n",packet_pcap->ip_tipe);
        //return;
    }
    delete packet_pcap;
}
int main(int argc, char **argv)
{
    FILE *badTrafic = fopen(argv[1], "rb");
    if (!badTrafic)
    {
        return 1;
    }
    readBadTrafic(*badTrafic);
    /*
    printf("flags :%lu\n", sizeof(Packet_pcap));
    printf("ethernet :%lu\n", sizeof(EtherHeader));
    printf("ipv4 :%lu\n", sizeof(Ipv4Header));
    printf("ipv6 :%lu\n", sizeof(Ipv6Header));
    printf("tcp :%lu\n", sizeof(TCPheader));
    printf("udp :%lu\n", sizeof(UDPheader));
    */
    return 0;
}