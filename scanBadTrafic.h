#ifndef SCAN_BAD_TRAFIC
#define SCAN_BAD_TRAFIC
#include "IOPcapFile.h"
#include <map>

#include <inttypes.h> //PRIx64

// #include <algorithm>//reverse
// #include <sstream> //stringstream
// #include <iostream>//cout
#include <string> //
// #include <cstdlib>//malloc

// data["5d119cfa:50->afb178b:81ae"] = 'Tipetrafic';
std::map<std::string, uint8_t> data;
// std::map<std::string, uint8_t>::iterator it_;
bool isBadTrafic(std::string ip_proto, uint8_t tipe)
{
    std::map<std::string, uint8_t>::iterator it;
    it = data.find(ip_proto);
    if (it != data.end() && it->second == tipe && it->first.size() > 5)
    {
        return true;
    }
    return false;
}
void readBadTrafic(FILE &badTrafic)
{
    Packet_pcap *packet_pcap; // = new Packet_pcap;
    while (getNextPacket(badTrafic, packet_pcap))
    {
        data[*packet_pcap->to_string()] = packet_pcap->tipe;
        data[*packet_pcap->to_stringBackward()] = packet_pcap->tipe;
    }
    delete packet_pcap;
}
void splitBadTrafic(FILE &rawTrafic, FILE &badTrafic, FILE &freeAnomaliTrafic)
{
    PcapFileHeader *fileHeader;
    readHeaderPcapFile(rawTrafic, fileHeader);
    writeHeaderPcapFile(freeAnomaliTrafic, fileHeader);
    readBadTrafic(badTrafic);
    Packet_pcap *packete; // = new Packet_pcap();
    while (getNextPacket(rawTrafic, packete))
    {

        if (!isBadTrafic(*packete->to_string(), packete->tipe))
        {
            writePacket(freeAnomaliTrafic, packete);
        }
    }
    delete fileHeader;
    delete packete;
}
#endif