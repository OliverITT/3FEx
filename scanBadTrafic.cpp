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
std::map<std::string, uint8_t>::iterator it_;
bool isBadTrafic(std::string ip_proto, uint8_t tipe)
{
    std::map<std::string, uint8_t>::iterator it;
    it = data.find(ip_proto);
    // printf("bad: %s\n",ip_proto.c_str());
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
    }
    delete packet_pcap;
}
void splitBadTrafic(FILE &rawTrafic, FILE &badTrafic, FILE &freeAnomaliTrafic)
{
    PacapFileHeader *fileHeader;
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
int main(int argc, char **argv)
{
    FILE *rawTrafic = fopen(argv[1], "rb");
    FILE *badTrafic = fopen(argv[2], "rb");
    FILE *feetrafic = fopen(argv[3], "wb");
    if (!badTrafic)
    {
        return 1;
    }

    splitBadTrafic(*rawTrafic, *badTrafic, *feetrafic);
    for (it_ = data.begin(); it_ != data.end(); ++it_)
    {
        printf("%s,%d\n", it_->first.c_str(), it_->second);
    }
}
