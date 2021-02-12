#ifndef READ_PCAP_FILE
#define READ_PCAP_FILE
#include "structs.h"
#include <stdio.h>
#include <iostream>

void *getNextPacket(FILE &badTrafic, Packet_pcap *&packet_pcap)
{
    if (ftell(&badTrafic) == 0)
    {
        fseek(&badTrafic, 24L, SEEK_SET);
    }
    packet_pcap = new Packet_pcap;

    if (fread(&packet_pcap->packetHeader, sizeof(PcapPackHeader), 1, &badTrafic))
    {
        /* code */

        if (!fread(&packet_pcap->ethernetHeader, sizeof(EtherHeader), 1, &badTrafic))
        {
            printf("unknown file");
            return NULL;
        }
        switch (packet_pcap->ethernetHeader.ether_type)
        {
        case __IPV4:

            if (!fread(&packet_pcap->ip_layer.ipv4Header, sizeof(Ipv4Header), 1, &badTrafic))
            {
                return NULL;
            }
            switch (packet_pcap->ip_layer.ipv4Header.protocol)
            {
            case _TCP:
                if (!fread(&packet_pcap->proto.tcpHeader, sizeof(TCPheader), 1, &badTrafic))
                {
                    return NULL;
                }
                packet_pcap->tipe =IPV4_TCP;
                //fseek(&badTrafic, (packet_pcap->packetHeader.incl_len - 14 - 40), SEEK_CUR);
                //packet_pcap->payload = new uint8_t[8];
                fseek(&badTrafic, (packet_pcap->packetHeader.incl_len - 14 - 40), SEEK_CUR);
                break;
            case _UDP:
                if (!fread(&packet_pcap->proto.uDPheader, sizeof(UDPheader), 1, &badTrafic))
                {
                    return NULL;
                }
                packet_pcap->tipe = IPV4_UDP;
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
                return NULL;
            }
            switch (packet_pcap->ip_layer.ipv6Header.nextHeader)
            {
            case _TCP:
                if (!fread(&packet_pcap->proto.tcpHeader, sizeof(TCPheader), 1, &badTrafic))
                {
                    return NULL;
                }
                packet_pcap->tipe = IPV6_TCP;
                fseek(&badTrafic, (packet_pcap->packetHeader.incl_len - 14 - 40 - 20), SEEK_CUR);
                break;
            case _UDP:
                if (!fread(&packet_pcap->proto.uDPheader, sizeof(UDPheader), 1, &badTrafic))
                {
                    return NULL;
                }
                packet_pcap->tipe = IPV6_UDP;
                fseek(&badTrafic, (packet_pcap->packetHeader.incl_len - 14 - 40 - 8), SEEK_CUR);
                break;

            default:
                fseek(&badTrafic, (packet_pcap->packetHeader.incl_len - 14 - 40), SEEK_CUR);
                break;
            }
            break;
        default:
            fseek(&badTrafic, (packet_pcap->packetHeader.incl_len - 14), SEEK_CUR);
           packet_pcap->tipe = OTDER_TRAFIC;
            break;
        }
        return (void *)1;
    }

    return NULL;
}
#endif
