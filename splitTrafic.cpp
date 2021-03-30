#include "scanBadTrafic.h"
const char banner[] = {"-r  Input pcap raw file\n-b  Input pcap alert file\n-o  Output pcap freeatack packets"};
#define ERROR 1
int main(int argc, char **argv)
{
    FILE *rawTrafic;// = fopen(argv[1], "rb");
    FILE *badTrafic;// = fopen(argv[2], "rb");
    FILE *freeAnomaliTrafic;// = fopen(argv[3], "wb");
    if (argc < 7)
    {
        printf("%s", banner);
        return 1;
    }
    if (argc > 6)
    {
        for (int i = 1; i < argc; i++)
        {
            std::string arg = argv[i];
            if (arg == "-r")
            {
                rawTrafic = fopen((char *)argv[i + 1], "rb");
                if (!rawTrafic)
                {
                    printf("no open file: %s", argv[i + 1]);
                    return ERROR;
                }
                if (!isPcapFile(*rawTrafic))
                {
                    return ERROR;
                }
            }
            if (arg == "-b")
            {
                badTrafic = fopen((char *)argv[i + 1], "rb");
                if (!badTrafic)
                {
                    printf("no open file: %s", argv[i + 1]);
                    return ERROR;
                }
                if (!isPcapFile(*badTrafic))
                {
                    return ERROR;
                }
            }
            if (arg == "-o")
            {
                freeAnomaliTrafic = fopen(argv[i + 1], "wb");
                if (!freeAnomaliTrafic)
                {
                    printf("no open file: %s", argv[i + 1]);
                    return ERROR;
                }
            }
        }
    }
    if (!rawTrafic || !badTrafic || !freeAnomaliTrafic)
    {
        printf("unknown file\n");
        return 1;
    }
    if(!isPcapFile(*rawTrafic)||!isPcapFile(*badTrafic)){
        return 1;
    }
    splitBadTrafic(*rawTrafic, *badTrafic, *freeAnomaliTrafic);
    if (rawTrafic)
    {
        fclose(rawTrafic);
    }
    if (badTrafic)
    {
        fclose(badTrafic);
    }
    if (freeAnomaliTrafic)
    {
        fclose(freeAnomaliTrafic);
    }
    return 0;
}

/*

    
*/