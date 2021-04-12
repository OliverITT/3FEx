#ifndef SCAN_SNORT_LOG
#define SCAN_SNORT_LOG
#include "TDA_U2.h"
#include "structs_u2.h"
#include "IOU2File.h"
#include "IOPcapFile.h"
#include <map>
std::map<std::string, TDA_U2 *> data_u2;

void readSnortLogs(FILE &u2_File)
{
    Unified2_Packet *u2_packet;
    while (getEvent(u2_File, u2_packet))
    {
        switch (swap_endian<uint32_t>(u2_packet->header->record_type))
        {
        case __Unified2_IDS_Event:
            switch (swap_endian<uint8_t>(u2_packet->IDS_EVENT.IDS_Event->protocol))
            {
            case __UDP_:
            case __TCP_:
                TDA_U2 *dato;
                dato = new TDA_U2(swap_endian<uint8_t>(u2_packet->IDS_EVENT.IDS_Event->protocol), swap_endian<uint32_t>(u2_packet->IDS_EVENT.IDS_Event->priority_id), swap_endian<uint32_t>(u2_packet->IDS_EVENT.IDS_Event->classification_id));
                /* code */
                data_u2[*u2_packet->IDS_EVENT.IDS_Event->eventIpToString()] = dato;
                data_u2[*u2_packet->IDS_EVENT.IDS_Event->eventIpToStringBackward()] = dato;
                break;
            default:
                break;
            }
            /* code */
            break;
        case __Unified2_IDS_Event_V2:
            /* code */
            switch (swap_endian<uint8_t>(u2_packet->IDS_EVENT.IDS_Event_V2->protocol))
            {
            case __UDP_:
            case __TCP_:
                TDA_U2 *dato;
                dato = new TDA_U2(swap_endian<uint8_t>(u2_packet->IDS_EVENT.IDS_Event_V2->protocol), swap_endian<uint32_t>(u2_packet->IDS_EVENT.IDS_Event_V2->priority_id), swap_endian<uint32_t>(u2_packet->IDS_EVENT.IDS_Event_V2->classification_id));
                /* code */
                data_u2[*u2_packet->IDS_EVENT.IDS_Event_V2->eventIpToString()] = dato;
                data_u2[*u2_packet->IDS_EVENT.IDS_Event_V2->eventIpToStringBackward()] = dato;
                break;
            default:
                break;
            }
            break;
        case __Unified2_IDS_Event_IP6:
            /* code */
            switch (swap_endian<uint8_t>(u2_packet->IDS_EVENT.IDS_Event_IP6->protocol))
            {
            case __UDP_:
            case __TCP_:
                TDA_U2 *dato;
                dato = new TDA_U2(swap_endian<uint8_t>(u2_packet->IDS_EVENT.IDS_Event_IP6->protocol), swap_endian<uint32_t>(u2_packet->IDS_EVENT.IDS_Event_IP6->priority_id), swap_endian<uint32_t>(u2_packet->IDS_EVENT.IDS_Event_IP6->classification_id));
                /* code */
                data_u2[*u2_packet->IDS_EVENT.IDS_Event_IP6->eventIpToString()] = dato;
                data_u2[*u2_packet->IDS_EVENT.IDS_Event_IP6->eventIpToStringBackward()] = dato;
                break;
            default:
                break;
            }
            break;
        case __Unified2_IDS_Event_IP6_V2:
            /* code */
            switch (swap_endian<uint8_t>(u2_packet->IDS_EVENT.IDS_Event_IP6_V2->protocol))
            {
            case __UDP_:
            case __TCP_:
                TDA_U2 *dato;
                dato = new TDA_U2(swap_endian<uint8_t>(u2_packet->IDS_EVENT.IDS_Event_IP6_V2->protocol), swap_endian<uint32_t>(u2_packet->IDS_EVENT.IDS_Event_IP6_V2->priority_id), swap_endian<uint32_t>(u2_packet->IDS_EVENT.IDS_Event_IP6_V2->classification_id));
                /* code */
                data_u2[*u2_packet->IDS_EVENT.IDS_Event_IP6_V2->eventIpToString()] = dato;
                data_u2[*u2_packet->IDS_EVENT.IDS_Event_IP6_V2->eventIpToStringBackward()] = dato;
                break;
            default:
                break;
            }
            break;
        default:
            break;
        }
    }
    delete u2_packet;
}
int getPriority(std::string socket_ip, uint8_t protocol)
{
    std::map<std::string, TDA_U2 *>::iterator it;
    it = data_u2.find(socket_ip);
    if (it != data_u2.end() && it->second->protocol == protocol)
    {
        return it->second->priority;
    }
    return 0;
}
int getClassification(std::string socket_ip, uint8_t protocol)
{
    std::map<std::string, TDA_U2 *>::iterator it;
    it = data_u2.find(socket_ip);
    if (it != data_u2.end() && it->second->protocol == protocol)
    {
        return it->second->classification_id;
    }
    return 0;
}
void splitTraficBeSnortLogs(FILE &rawTrafic, FILE &u2_SnortLogs, FILE &freeAnomaliTrafic, uint32_t priority)
{
    PcapFileHeader *fileHeader;
    readHeaderPcapFile(rawTrafic, fileHeader);
    writeHeaderPcapFile(freeAnomaliTrafic, fileHeader);
    readSnortLogs(u2_SnortLogs);
    Packet_pcap *packete; // = new Packet_pcap();c
    while (getNextPacket(rawTrafic, packete))
    {
        uint8_t proto = 0;
        switch (packete->tipe)
        {
        case 1:
        case 4:
            proto = 0x6;
            break;
        case 2:
        case 5:
            proto = 0x11;
            break;

        default:
            break;
        }
        if (!((getPriority(*packete->to_string(), proto) <= (uint32_t)priority) && getPriority(*packete->to_string(), proto) != 0))
        {
            writePacket(freeAnomaliTrafic, packete);
        }
    }
    delete fileHeader;
    delete packete;
}
#endif