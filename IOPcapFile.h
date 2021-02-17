#ifndef READ_PCAP_FILE
#define READ_PCAP_FILE
#include "structs.h"
#include <stdio.h>
#include <iostream>

void *getNextPacket(FILE &FileTrafic, Packet_pcap *&packet_pcap)
{
    if (ftell(&FileTrafic) == 0)
    {
        fseek(&FileTrafic, 24L, SEEK_SET);
    }
    packet_pcap = new Packet_pcap;

    if (fread(&packet_pcap->packetHeader, sizeof(PcapPackHeader), 1, &FileTrafic))
    {
        /* code */

        if (!fread(&packet_pcap->ethernetHeader, sizeof(EtherHeader), 1, &FileTrafic))
        {
            printf("unknown file");
            return NULL;
        }
        switch (packet_pcap->ethernetHeader.ether_type)
        {
        case __IPV4:

            if (!fread(&packet_pcap->ip_layer.ipv4Header, sizeof(Ipv4Header), 1, &FileTrafic))
            {
                return NULL;
            }
            switch (packet_pcap->ip_layer.ipv4Header.protocol)
            {
            case _TCP:
                if (!fread(&packet_pcap->proto.tcpHeader, sizeof(TCPheader), 1, &FileTrafic))
                {
                    return NULL;
                }
                packet_pcap->tipe = IPV4_TCP;
                //fseek(&FileTrafic, (packet_pcap->packetHeader.incl_len - 14 - 40), SEEK_CUR);
                packet_pcap->payload = new uint8_t[(packet_pcap->packetHeader.incl_len - 14 - 40)];
                if (!fread(packet_pcap->payload, sizeof(uint8_t), (packet_pcap->packetHeader.incl_len - 14 - 40), &FileTrafic))
                {
                    return NULL;
                }
                break;
            case _UDP:
                if (!fread(&packet_pcap->proto.uDPheader, sizeof(UDPheader), 1, &FileTrafic))
                {
                    return NULL;
                }
                packet_pcap->tipe = IPV4_UDP;
                //fseek(&FileTrafic, (packet_pcap->packetHeader.incl_len - 14 - 20 - 8), SEEK_CUR);
                packet_pcap->payload = new uint8_t[(packet_pcap->packetHeader.incl_len - 14 - 20 - 8)];
                if (!fread(packet_pcap->payload, sizeof(uint8_t), (packet_pcap->packetHeader.incl_len - 14 - 20 - 8), &FileTrafic))
                {
                    return NULL;
                }
                break;

            default:
                //fseek(&FileTrafic, (packet_pcap->packetHeader.incl_len - 14 - 20), SEEK_CUR);
                packet_pcap->tipe = IPV4_OTDER_PROTO;
                packet_pcap->payload = new uint8_t[(packet_pcap->packetHeader.incl_len - 14 - 20)];
                if (!fread(packet_pcap->payload, sizeof(uint8_t), (packet_pcap->packetHeader.incl_len - 14 - 20), &FileTrafic))
                {
                    return NULL;
                }
                break;
            }
            break;
        case __IPV6:
            if (!fread(&packet_pcap->ip_layer.ipv6Header, sizeof(Ipv6Header) -8, 1, &FileTrafic))
            {
                return NULL;
            }

            switch (packet_pcap->ip_layer.ipv6Header.nextHeader)
            {
            case _TCP:
                if (!fread(&packet_pcap->proto.tcpHeader, sizeof(TCPheader), 1, &FileTrafic))
                {
                    return NULL;
                }
                packet_pcap->tipe = IPV6_TCP;
                //fseek(&FileTrafic, (packet_pcap->packetHeader.incl_len - 14 - 40 - 20), SEEK_CUR);
                packet_pcap->payload = new uint8_t[(packet_pcap->packetHeader.incl_len - 14 - 40 - 20)];
                if (!fread(packet_pcap->payload, sizeof(uint8_t), (packet_pcap->packetHeader.incl_len - 14 - 40 - 20), &FileTrafic))
                {
                    return NULL;
                }
                break;
            case _UDP:
                if (!fread(&packet_pcap->proto.uDPheader, sizeof(UDPheader), 1, &FileTrafic))
                {
                    return NULL;
                }
                packet_pcap->tipe = IPV6_UDP;
                //fseek(&FileTrafic, (packet_pcap->packetHeader.incl_len - 14 - 40 - 8), SEEK_CUR);
                packet_pcap->payload = new uint8_t[(packet_pcap->packetHeader.incl_len - 14 - 40 - 8)];
                if (!fread(packet_pcap->payload, sizeof(uint8_t), (packet_pcap->packetHeader.incl_len - 14 - 40 - 8), &FileTrafic))
                {
                    return NULL;
                }
                break;

            default:
                //fseek(&FileTrafic, (packet_pcap->packetHeader.incl_len - 14 - 40), SEEK_CUR);
                packet_pcap->tipe = IPV6_OTDER_PROTO;
                packet_pcap->payload = new uint8_t[(packet_pcap->packetHeader.incl_len - 14 - 40)];
                if (!fread(packet_pcap->payload, sizeof(uint8_t), (packet_pcap->packetHeader.incl_len - 14 - 40), &FileTrafic))
                {
                    return NULL;
                }
                break;
            }
            break;
        default:
            //fseek(&FileTrafic, (packet_pcap->packetHeader.incl_len - 14), SEEK_CUR);
            packet_pcap->tipe = OTDER_TRAFIC;
            packet_pcap->payload = new uint8_t[(packet_pcap->packetHeader.incl_len - 14)];
            if (!fread(packet_pcap->payload, sizeof(uint8_t), (packet_pcap->packetHeader.incl_len - 14), &FileTrafic))
            {
                return NULL;
            }
            break;
        }
        return (void *)1;
    }

    return NULL;
}
void writePacket(FILE &FileTrafic, Packet_pcap *&packet_pcap, ...)
{

    switch (packet_pcap->tipe)
    {
    case IPV4_OTDER_PROTO:
        fwrite(&packet_pcap->packetHeader, sizeof(PcapPackHeader), 1, &FileTrafic);
        fwrite(&packet_pcap->ethernetHeader, sizeof(EtherHeader), 1, &FileTrafic);
        fwrite(&packet_pcap->ip_layer.ipv4Header, sizeof(Ipv4Header), 1, &FileTrafic);
        fwrite(packet_pcap->payload, sizeof(uint8_t), (packet_pcap->packetHeader.incl_len - 14 - 20), &FileTrafic);
        break;
    case IPV4_TCP:
        fwrite(&packet_pcap->packetHeader, sizeof(PcapPackHeader), 1, &FileTrafic);
        fwrite(&packet_pcap->ethernetHeader, sizeof(EtherHeader), 1, &FileTrafic);
        fwrite(&packet_pcap->ip_layer.ipv4Header, sizeof(Ipv4Header), 1, &FileTrafic);
        fwrite(&packet_pcap->proto.tcpHeader, sizeof(TCPheader), 1, &FileTrafic);
        fwrite(packet_pcap->payload, sizeof(uint8_t), (packet_pcap->packetHeader.incl_len - 14 - 40), &FileTrafic);
        break;
    case IPV4_UDP:
        fwrite(&packet_pcap->packetHeader, sizeof(PcapPackHeader), 1, &FileTrafic);
        fwrite(&packet_pcap->ethernetHeader, sizeof(EtherHeader), 1, &FileTrafic);
        fwrite(&packet_pcap->ip_layer.ipv4Header, sizeof(Ipv4Header), 1, &FileTrafic);
        fwrite(&packet_pcap->proto.uDPheader, sizeof(UDPheader), 1, &FileTrafic);
        fwrite(packet_pcap->payload, sizeof(uint8_t), (packet_pcap->packetHeader.incl_len - 14 - 20 - 8), &FileTrafic);
        break;
    case IPV6_OTDER_PROTO:
        fwrite(&packet_pcap->packetHeader, sizeof(PcapPackHeader), 1, &FileTrafic);
        fwrite(&packet_pcap->ethernetHeader, sizeof(EtherHeader), 1, &FileTrafic);
        fwrite(&packet_pcap->ip_layer.ipv4Header, sizeof(Ipv6Header) -8, 1, &FileTrafic);
        fwrite(packet_pcap->payload, sizeof(uint8_t), (packet_pcap->packetHeader.incl_len - 14 - 40), &FileTrafic);
        break;
    case IPV6_TCP:
        fwrite(&packet_pcap->packetHeader, sizeof(PcapPackHeader), 1, &FileTrafic);
        fwrite(&packet_pcap->ethernetHeader, sizeof(EtherHeader), 1, &FileTrafic);
        fwrite(&packet_pcap->ip_layer.ipv6Header, sizeof(Ipv6Header) -8, 1, &FileTrafic);
        fwrite(&packet_pcap->proto.tcpHeader, sizeof(TCPheader), 1, &FileTrafic);
        fwrite(packet_pcap->payload, sizeof(uint8_t), (packet_pcap->packetHeader.incl_len - 14 - 40 - 20), &FileTrafic);
        break;
    case IPV6_UDP:
        fwrite(&packet_pcap->packetHeader, sizeof(PcapPackHeader), 1, &FileTrafic);
        fwrite(&packet_pcap->ethernetHeader, sizeof(EtherHeader), 1, &FileTrafic);
        fwrite(&packet_pcap->ip_layer.ipv6Header, sizeof(Ipv6Header) -8, 1, &FileTrafic);
        fwrite(&packet_pcap->proto.uDPheader, sizeof(UDPheader), 1, &FileTrafic);
        fwrite(packet_pcap->payload, sizeof(uint8_t), (packet_pcap->packetHeader.incl_len - 14 - 40 - 8), &FileTrafic);
        break;
    default:
        fwrite(&packet_pcap->packetHeader, sizeof(PcapPackHeader), 1, &FileTrafic);
        fwrite(&packet_pcap->ethernetHeader, sizeof(EtherHeader), 1, &FileTrafic);
        fwrite(packet_pcap->payload, sizeof(uint8_t), (packet_pcap->packetHeader.incl_len - 14), &FileTrafic);
        break;
    }
    delete packet_pcap;
}
void readHeaderPcapFile(FILE &FileTrafic, PacapFileHeader *&pacapFileHeader)
{
    pacapFileHeader = new PacapFileHeader;
    fread(pacapFileHeader, sizeof(PacapFileHeader), 1, &FileTrafic);
}
void writeHeaderPcapFile(FILE &FileTrafic, PacapFileHeader *&pacapFileHeader)
{
    fwrite(pacapFileHeader, sizeof(PacapFileHeader), 1, &FileTrafic);
}
#endif
