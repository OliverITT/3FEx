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
std::map<std::string, uint8_t>::iterator it;

static void readBadTrafic(FILE &badTrafic)
{
    Packet_pcap *packet_pcap; // = new Packet_pcap;
    while (getNextPacket(badTrafic, packet_pcap))
    {
        data[*packet_pcap->to_string()] = packet_pcap->tipe;
    }
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
    Packet_pcap *packete = new Packet_pcap();
    /*
    int cont = 0;
         while (getNextPacket(*badTrafic, packete))
    {
        cont++;
        if (packete->tipe == OTDER_TRAFIC)
        {
            printf("tipstap:%d\n", packete->packetHeader.ts_usec);
        }
        if (packete->tipe == IPV4_TCP)
        {
            printf("ip:%s\n", packet_to_string(packete)->c_str());
        }
        writePacket(*OTrafic, packete);
    } */

    readBadTrafic(*badTrafic);
    for (it = data.begin(); it != data.end(); ++it)
    {
        printf("%s,%d\n", it->first.c_str(), it->second);
    }
    return 0;
}
