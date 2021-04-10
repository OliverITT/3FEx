#ifndef IO_U2
#define IO_U2
#include "structs_u2.h"
// FILE *u2_file;
bool getEvent(FILE &U2_file, Unified2_Packet *&u2_packet)
{
    u2_packet = new Unified2_Packet();
    if (!fread(u2_packet->header, sizeof(Serial_Unified2_Header), 1, &U2_file))
    {
        //printf("u2 header unknown file\n");
        return false;
    }
    switch (swap_endian<uint32_t>(u2_packet->header->record_type))
    {
    case __Unified2_Packet:
        u2_packet->data_Packet = new U2_Packet;
        if (!fread(u2_packet->data_Packet, 28, 1, &U2_file))
        {

            //printf("u2 packet unknown file\n");
            return false;
        }
        uint32_t buff_size;
        buff_size = swap_endian<uint32_t>(u2_packet->data_Packet->packet_length_);
        u2_packet->data_Packet->packet_data = new uint8_t[buff_size];
        if (!fread(u2_packet->data_Packet->packet_data, sizeof(uint8_t), buff_size, &U2_file))
        {
            //printf("u2 packet payload unknown file\n");
            return false;
        }
        break;
    case __Unified2_IDS_Event:
        u2_packet->IDS_EVENT.IDS_Event = new Event;
        if (!fread(u2_packet->IDS_EVENT.IDS_Event, sizeof(Event), 1, &U2_file))
        {
            //printf("u2 evetn unknown file\n");
            return false;
        }
        break;
    case __Unified2_IDS_Event_IP6:
        u2_packet->IDS_EVENT.IDS_Event_IP6 = new Event_IP6;
        if (!fread(u2_packet->IDS_EVENT.IDS_Event_IP6, sizeof(Event_IP6), 1, &U2_file))
        {
            //printf("u2 event ip6 unknown file\n");
            return false;
        }
        break;
    case __Unified2_IDS_Event_V2:
        u2_packet->IDS_EVENT.IDS_Event_V2 = new Event_V2;
        if (!fread(u2_packet->IDS_EVENT.IDS_Event_V2, sizeof(Event_V2), 1, &U2_file))
        {
            //printf("u2 event v2 unknown file\n");
            return false;
        }
        break;
    case __Unified2_IDS_Event_IP6_V2:
        u2_packet->IDS_EVENT.IDS_Event_IP6_V2 = new Event_IP6_V2;
        if (!fread(u2_packet->IDS_EVENT.IDS_Event_IP6_V2, sizeof(Event_IP6_V2), 1, &U2_file))
        {
            //printf("u2 event ip6 v2 unknown file\n");
            return false;
        }
        break;
    case __Unified2_Extra_Data:
        u2_packet->extra_Data = new Extra_Data;
        if (!fread(u2_packet->extra_Data, sizeof(Extra_Data), 1, &U2_file))
        {
            //printf("u2 extra data unknown file\n");
            return false;
        }
        break;

    default:
        break;
    }
    return true;
}
#endif
