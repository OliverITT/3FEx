#ifndef STRUCTS_UNIFIED_2
#define STRUCTS_UNIFIED_2
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string>
#define __TCP_ 0x6
#define __UDP_ 0x11
//Record Type
enum
{
    __Unified2_Packet = 2,
    __Unified2_IDS_Event = 7,
    __Unified2_IDS_Event_IP6 = 72,
    __Unified2_IDS_Event_V2 = 104,
    __Unified2_IDS_Event_IP6_V2,
    __Unified2_Extra_Data = 110

};

#include <climits>
template <typename T>
T swap_endian(T u)
{
    static_assert(CHAR_BIT == 8, "CHAR_BIT != 8");

    union
    {
        T u;
        unsigned char u8[sizeof(T)];
    } source, dest;

    source.u = u;

    for (size_t k = 0; k < sizeof(T); k++)
        dest.u8[k] = source.u8[sizeof(T) - k - 1];

    return dest.u;
}
/*Unified2 File Format*/
typedef struct Serial_Unified2_Header
{
    uint32_t record_type;   // 4 bytes
    uint32_t record_length; // 4 bytes
} Serial_Unified2_Header_t;

typedef struct U2_Packet
{
    uint32_t sensor_id;          // 4 bytes
    uint32_t event_id;           // 4 bytes
    uint32_t event_seconds;      // 4 bytes
    uint32_t event_microseconds; // 4 bytes
    uint32_t linktype;           // 4 bytes
    uint32_t packet_length;      // 4 bytes
    uint32_t packet_length_;     // 4 bytes
    uint8_t *packet_data;        // <variable length>
} U2_packet_t;

typedef struct Event
{
    uint32_t sensor_id;          // 4 bytes
    uint32_t event_id;           // 4 bytes
    uint32_t event_second;       // 4 bytes
    uint32_t event_microsecond;  // 4 bytes
    uint32_t signature_id;       // 4 bytes
    uint32_t generator_id;       // 4 bytes
    uint32_t signature_revision; // 4 bytes
    uint32_t classification_id;  // 4 bytes
    uint32_t priority_id;        // 4 bytes
    uint32_t ip_source;          // 4 bytes
    uint32_t ip_destination;     // 4 bytes
    union
    {

        uint16_t source_port; // 2 bytes
        uint16_t icmp_type;   // 2 bytes
    } s_i;
    union
    {

        uint16_t dest_port; // 2 bytes
        uint16_t icmp_code; // 2 bytes
    } s_ic;

    uint8_t protocol;    // 1 byte
    uint8_t impact_flag; // 1 byte
    uint8_t impact;      // 1 byte
    uint8_t blocked;     // 1 byte

    std::string *eventIpToString()
    {
        std::string *socket_proto = new std::string("");
        char buffer[17];
        sprintf(buffer, "%x", swap_endian<uint32_t>(ip_destination));
        *socket_proto += buffer;
        sprintf(buffer, "%x", swap_endian<uint16_t>(s_ic.dest_port));
        *socket_proto += buffer;
        sprintf(buffer, "%x", swap_endian<uint32_t>(ip_source));
        *socket_proto += buffer;
        sprintf(buffer, "%x", swap_endian<uint16_t>(s_i.source_port));
        *socket_proto += buffer;
        return socket_proto;
    }
    std::string *eventIpToStringBackward()
    {
        std::string *socket_proto = new std::string("");
        char buffer[17];
        sprintf(buffer, "%x", swap_endian<uint32_t>(ip_source));
        *socket_proto += buffer;
        sprintf(buffer, "%x", swap_endian<uint16_t>(s_i.source_port));
        *socket_proto += buffer;
        sprintf(buffer, "%x", swap_endian<uint32_t>(ip_destination));
        *socket_proto += buffer;
        sprintf(buffer, "%x", swap_endian<uint16_t>(s_ic.dest_port));
        *socket_proto += buffer;
        return socket_proto;
    }
} Event_t;

typedef struct Event_IP6
{
    uint32_t sensor_id;          // 4 bytes
    uint32_t event_id;           // 4 bytes
    uint32_t event_second;       // 4 bytes
    uint32_t event_microsecond;  // 4 bytes
    uint32_t signature_id;       // 4 bytes
    uint32_t generator_id;       // 4 bytes
    uint32_t signature_revision; // 4 bytes
    uint32_t classification_id;  // 4 bytes
    uint32_t priority_id;        // 4 bytes
    uint8_t ip_source[16];       // 16 bytes
    uint8_t ip_destination[16];  // 16 bytes
    union
    {

        uint16_t source_port; // 2 bytes
        uint16_t icmp_type;   // 2 bytes
    } s_i;
    union
    {

        uint16_t dest_port; // 2 bytes
        uint16_t icmp_code; // 2 bytes
    } s_ic;
    uint8_t protocol;    // 1 byte
    uint8_t impact_flag; // 1 byte
    uint8_t impact;      // 1 byte
    uint8_t blocked;     // 1 byte
    std::string *eventIpToString()
    {
        std::string *socket_proto = new std::string("");
        char buffer[32];
                sprintf(buffer, "%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x",
                (uint8_t)(ip_destination[0]),
                (uint8_t)(ip_destination[1]),
                (uint8_t)(ip_destination[2]),
                (uint8_t)(ip_destination[3]),
                (uint8_t)(ip_destination[4]),
                (uint8_t)(ip_destination[5]),
                (uint8_t)(ip_destination[6]),
                (uint8_t)(ip_destination[7]),
                (uint8_t)(ip_destination[8]),
                (uint8_t)(ip_destination[9]),
                (uint8_t)(ip_destination[10]),
                (uint8_t)(ip_destination[11]),
                (uint8_t)(ip_destination[12]),
                (uint8_t)(ip_destination[13]),
                (uint8_t)(ip_destination[14]),
                (uint8_t)(ip_destination[15]));
        *socket_proto += buffer;
        sprintf(buffer, "%x", swap_endian<uint16_t>(s_ic.dest_port));
        *socket_proto += buffer;
        sprintf(buffer, "%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x",
                (uint8_t)(ip_source[0]),
                (uint8_t)(ip_source[1]),
                (uint8_t)(ip_source[2]),
                (uint8_t)(ip_source[3]),
                (uint8_t)(ip_source[4]),
                (uint8_t)(ip_source[5]),
                (uint8_t)(ip_source[6]),
                (uint8_t)(ip_source[7]),
                (uint8_t)(ip_source[8]),
                (uint8_t)(ip_source[9]),
                (uint8_t)(ip_source[10]),
                (uint8_t)(ip_source[11]),
                (uint8_t)(ip_source[12]),
                (uint8_t)(ip_source[13]),
                (uint8_t)(ip_source[14]),
                (uint8_t)(ip_source[15]));
        *socket_proto += buffer;
        sprintf(buffer, "%x", swap_endian<uint16_t>(s_i.source_port));
        *socket_proto += buffer;
        return socket_proto;
    }
    
    std::string *eventIpToStringBackward()
    {
        std::string *socket_proto = new std::string("");
        char buffer[32];
        sprintf(buffer, "%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x",
                (uint8_t)(ip_source[0]),
                (uint8_t)(ip_source[1]),
                (uint8_t)(ip_source[2]),
                (uint8_t)(ip_source[3]),
                (uint8_t)(ip_source[4]),
                (uint8_t)(ip_source[5]),
                (uint8_t)(ip_source[6]),
                (uint8_t)(ip_source[7]),
                (uint8_t)(ip_source[8]),
                (uint8_t)(ip_source[9]),
                (uint8_t)(ip_source[10]),
                (uint8_t)(ip_source[11]),
                (uint8_t)(ip_source[12]),
                (uint8_t)(ip_source[13]),
                (uint8_t)(ip_source[14]),
                (uint8_t)(ip_source[15]));
        *socket_proto += buffer;
        sprintf(buffer, "%x", swap_endian<uint16_t>(s_i.source_port));
        *socket_proto += buffer;
        sprintf(buffer, "%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x",
                (uint8_t)(ip_destination[0]),
                (uint8_t)(ip_destination[1]),
                (uint8_t)(ip_destination[2]),
                (uint8_t)(ip_destination[3]),
                (uint8_t)(ip_destination[4]),
                (uint8_t)(ip_destination[5]),
                (uint8_t)(ip_destination[6]),
                (uint8_t)(ip_destination[7]),
                (uint8_t)(ip_destination[8]),
                (uint8_t)(ip_destination[9]),
                (uint8_t)(ip_destination[10]),
                (uint8_t)(ip_destination[11]),
                (uint8_t)(ip_destination[12]),
                (uint8_t)(ip_destination[13]),
                (uint8_t)(ip_destination[14]),
                (uint8_t)(ip_destination[15]));
        *socket_proto += buffer;
        sprintf(buffer, "%x", swap_endian<uint16_t>(s_ic.dest_port));
        *socket_proto += buffer;
        return socket_proto;
    }
} Event_IP6_t;

typedef struct Event_V2
{
    uint32_t sensor_id;          // 4 bytes
    uint32_t event_id;           // 4 bytes
    uint32_t event_second;       // 4 bytes
    uint32_t event_microsecond;  // 4 bytes
    uint32_t signature_id;       // 4 bytes
    uint32_t generator_id;       // 4 bytes
    uint32_t signature_revision; // 4 bytes
    uint32_t classification_id;  // 4 bytes
    uint32_t priority_id;        // 4 bytes
    uint32_t ip_source;          // 4 bytes
    uint32_t ip_destination;     // 4 bytes
    union
    {

        uint16_t source_port; // 2 bytes
        uint16_t icmp_type;   // 2 bytes
    } s_i;
    union
    {

        uint16_t dest_port; // 2 bytes
        uint16_t icmp_code; // 2 bytes
    } s_ic;
    uint8_t protocol;    // 1 byte
    uint8_t impact_flag; // 1 byte
    uint8_t impact;      // 1 byte
    uint8_t blocked;     // 1 byte
    uint32_t mpls_label; // 4 bytes
    uint16_t vlan_id;    // 2 bytes
    uint16_t padding;    // 2 bytes
    std::string *eventIpToString()
    {
        std::string *socket_proto = new std::string("");
        char buffer[17];
        sprintf(buffer, "%x", swap_endian<uint32_t>(ip_destination));
        *socket_proto += buffer;
        sprintf(buffer, "%x", swap_endian<uint16_t>(s_ic.dest_port));
        *socket_proto += buffer;
        sprintf(buffer, "%x", swap_endian<uint32_t>(ip_source));
        *socket_proto += buffer;
        sprintf(buffer, "%x", swap_endian<uint16_t>(s_i.source_port));
        *socket_proto += buffer;
        return socket_proto;
    }
    std::string *eventIpToStringBackward()
    {
        std::string *socket_proto = new std::string("");
        char buffer[17];
        sprintf(buffer, "%x", swap_endian<uint32_t>(ip_source));
        *socket_proto += buffer;
        sprintf(buffer, "%x", swap_endian<uint16_t>(s_i.source_port));
        *socket_proto += buffer;
        sprintf(buffer, "%x", swap_endian<uint32_t>(ip_destination));
        *socket_proto += buffer;
        sprintf(buffer, "%x", swap_endian<uint16_t>(s_ic.dest_port));
        *socket_proto += buffer;
        return socket_proto;
    }
} Event_V2_t;

typedef struct Event_IP6_V2
{
    uint32_t sensor_id;          // 4 bytes
    uint32_t event_id;           // 4 bytes
    uint32_t event_second;       // 4 bytes
    uint32_t event_microsecond;  // 4 bytes
    uint32_t signature_id;       // 4 bytes
    uint32_t generator_id;       // 4 bytes
    uint32_t signature_revision; // 4 bytes
    uint32_t classification_id;  // 4 bytes
    uint32_t priority_id;        // 4 bytes
    uint8_t ip_source[16];       // 16 bytes
    uint8_t ip_destination[16];  // 16 bytes

    union
    {

        uint16_t source_port; // 2 bytes
        uint16_t icmp_type;   // 2 bytes
    } s_i;
    union
    {

        uint16_t dest_port; // 2 bytes
        uint16_t icmp_code; // 2 bytes
    } s_ic;
    uint8_t protocol;    // 1 byte
    uint8_t impact_flag; // 1 byte
    uint8_t impact;      // 1 byte
    uint8_t blocked;     // 1 byte
    uint32_t mpls_label; // 4 bytes
    uint16_t vlan_id;    // 2 bytes
    uint16_t padding;    // 2 bytes

    std::string *eventIpToString()
    {
        std::string *socket_proto = new std::string("");
        char buffer[32];
                sprintf(buffer, "%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x",
                (uint8_t)(ip_destination[0]),
                (uint8_t)(ip_destination[1]),
                (uint8_t)(ip_destination[2]),
                (uint8_t)(ip_destination[3]),
                (uint8_t)(ip_destination[4]),
                (uint8_t)(ip_destination[5]),
                (uint8_t)(ip_destination[6]),
                (uint8_t)(ip_destination[7]),
                (uint8_t)(ip_destination[8]),
                (uint8_t)(ip_destination[9]),
                (uint8_t)(ip_destination[10]),
                (uint8_t)(ip_destination[11]),
                (uint8_t)(ip_destination[12]),
                (uint8_t)(ip_destination[13]),
                (uint8_t)(ip_destination[14]),
                (uint8_t)(ip_destination[15]));
        *socket_proto += buffer;
        sprintf(buffer, "%x", swap_endian<uint16_t>(s_ic.dest_port));
        *socket_proto += buffer;
        sprintf(buffer, "%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x",
                (uint8_t)(ip_source[0]),
                (uint8_t)(ip_source[1]),
                (uint8_t)(ip_source[2]),
                (uint8_t)(ip_source[3]),
                (uint8_t)(ip_source[4]),
                (uint8_t)(ip_source[5]),
                (uint8_t)(ip_source[6]),
                (uint8_t)(ip_source[7]),
                (uint8_t)(ip_source[8]),
                (uint8_t)(ip_source[9]),
                (uint8_t)(ip_source[10]),
                (uint8_t)(ip_source[11]),
                (uint8_t)(ip_source[12]),
                (uint8_t)(ip_source[13]),
                (uint8_t)(ip_source[14]),
                (uint8_t)(ip_source[15]));
        *socket_proto += buffer;
        sprintf(buffer, "%x", swap_endian<uint16_t>(s_i.source_port));
        *socket_proto += buffer;
        return socket_proto;
    }

    std::string *eventIpToStringBackward()
    {
        std::string *socket_proto = new std::string("");
        char buffer[32];
        sprintf(buffer, "%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x",
                (uint8_t)(ip_source[0]),
                (uint8_t)(ip_source[1]),
                (uint8_t)(ip_source[2]),
                (uint8_t)(ip_source[3]),
                (uint8_t)(ip_source[4]),
                (uint8_t)(ip_source[5]),
                (uint8_t)(ip_source[6]),
                (uint8_t)(ip_source[7]),
                (uint8_t)(ip_source[8]),
                (uint8_t)(ip_source[9]),
                (uint8_t)(ip_source[10]),
                (uint8_t)(ip_source[11]),
                (uint8_t)(ip_source[12]),
                (uint8_t)(ip_source[13]),
                (uint8_t)(ip_source[14]),
                (uint8_t)(ip_source[15]));
        *socket_proto += buffer;
        sprintf(buffer, "%x", swap_endian<uint16_t>(s_i.source_port));
        *socket_proto += buffer;
        sprintf(buffer, "%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x",
                (uint8_t)(ip_destination[0]),
                (uint8_t)(ip_destination[1]),
                (uint8_t)(ip_destination[2]),
                (uint8_t)(ip_destination[3]),
                (uint8_t)(ip_destination[4]),
                (uint8_t)(ip_destination[5]),
                (uint8_t)(ip_destination[6]),
                (uint8_t)(ip_destination[7]),
                (uint8_t)(ip_destination[8]),
                (uint8_t)(ip_destination[9]),
                (uint8_t)(ip_destination[10]),
                (uint8_t)(ip_destination[11]),
                (uint8_t)(ip_destination[12]),
                (uint8_t)(ip_destination[13]),
                (uint8_t)(ip_destination[14]),
                (uint8_t)(ip_destination[15]));
        *socket_proto += buffer;
        sprintf(buffer, "%x", swap_endian<uint16_t>(s_ic.dest_port));
        *socket_proto += buffer;
        return socket_proto;
    }
} Event_IP6_V2_t;

typedef struct Extra_Data
{
    uint32_t sensor_id;    // 4 bytes
    uint32_t event_id;     // 4 bytes
    uint32_t event_second; // 4 bytes
    uint32_t type;         // 4 bytes
    uint32_t data_type;    // 4 bytes
    uint32_t data_length;  // 4 bytes
    uint32_t data_length_; // 4 bytes
    uint8_t *data;         // <variable length>
} Extra_Data_t;

typedef struct Unified2_Packet
{
    Serial_Unified2_Header *header;
    union
    {
        Event *IDS_Event;
        Event_IP6 *IDS_Event_IP6;
        Event_V2 *IDS_Event_V2;
        Event_IP6_V2 *IDS_Event_IP6_V2;
    } IDS_EVENT;

    U2_Packet *data_Packet;
    Extra_Data *extra_Data;
    Unified2_Packet()
    {
        this->header = new Serial_Unified2_Header;
    }

} Unified2_Packet_t;

#endif