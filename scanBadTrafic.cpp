#ifndef SCAN_BAD_TRAFIC
#define SCAN_BAD_TRAFIC
#include "IOPcapFile.h"
#include <map>

extern std::map<std::string, char> data;
void readBadTrafic(FILE &badTrafic)
{
    Packet_pcap *packet_pcap; // = new Packet_pcap;
    int cont = 0;
    while (getNextPacket(badTrafic, packet_pcap))
    {
        cont++;
        printf("packet: %d timeStamp %d.%d :", cont, packet_pcap->packetHeader.ts_sec, packet_pcap->packetHeader.ts_usec);
        printf("%d\n", packet_pcap->tipe);      
        //packet_pcap->ip_tipe == _IPV4 ? printf("ipv4\n") : printf("%X\n", packet_pcap->ip_tipe);
    }
    printf("\ncontador:%d", cont);
    delete packet_pcap;
}
#endif
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
