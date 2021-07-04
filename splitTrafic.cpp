#include "scanBadTrafic.h"
#include "scanSnortLogs.h"
const char banner[] = {"-r  Input pcap raw file\n-b  Input pcap alert file, no use with -u param\n-o  Output pcap freeatack packets\n-u  Input Unified2 snort logs file, no use with -b param\n-p  Priority snort log\n"};
#define ERROR 1
int main(int argc, char **argv)
{
    FILE *rawTrafic;         // = fopen(argv[1], "rb");
    FILE *badTrafic = NULL;         // = fopen(argv[2], "rb");
    FILE *freeAnomaliTrafic; // = fopen(argv[3], "wb");
    FILE *u2Event = NULL;
    uint32_t priority = -1;
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
                    printf("no open file: %s\n", argv[i + 1]);
                    return ERROR;
                }
                if (!isPcapFile(*rawTrafic))
                {
                    return ERROR;
                }
            }
            if (arg == "-b")
            {
                if (u2Event)
                {
                    printf("-b only use -u or -b \n");
                    return ERROR;
                }
                badTrafic = fopen((char *)argv[i + 1], "rb");
                if (!badTrafic)
                {
                    printf("no open file: %s\n", argv[i + 1]);
                    return ERROR;
                }
                if (!isPcapFile(*badTrafic))
                {
                    return ERROR;
                }
            }
            if (arg == "-u")
            {
                if (badTrafic)
                {
                    printf("-u only use -u or -b \n");
                    return ERROR;
                }
                u2Event = fopen((char *)argv[i + 1], "rb");
                if (!u2Event)
                {
                    printf("no open file: %s\n", argv[i + 1]);
                    return ERROR;
                }
            }
            if (arg == "-p")
            {
                if (argc < 9)
                {
                    printf("params no valid\n");
                    return ERROR;
                }
                priority = std::stoi(argv[i + 1]);
            }
            if (arg == "-o")
            {
                freeAnomaliTrafic = fopen(argv[i + 1], "wb");
                if (!freeAnomaliTrafic)
                {
                    printf("no open file: %s\n", argv[i + 1]);
                    return ERROR;
                }
            }
        }
    }
    if (!rawTrafic || !freeAnomaliTrafic)
    {
        printf("Required raw trafic file and output name file\n");
        return ERROR;
    }
    if (badTrafic)
    {
        splitBadTrafic(*rawTrafic, *badTrafic, *freeAnomaliTrafic);
        fclose(badTrafic);
    }
    if (u2Event)
    {
        if (priority == -1)
        {
            printf("priority is required\n");
            return ERROR;
        }
        splitTraficBeSnortLogs(*rawTrafic, *u2Event, *freeAnomaliTrafic, priority);
        fclose(u2Event);
    }
    if (rawTrafic)
    {
        fclose(rawTrafic);
    }

    if (freeAnomaliTrafic)
    {
        fclose(freeAnomaliTrafic);
    }
    return 0;
}
