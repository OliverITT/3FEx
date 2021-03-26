
#include "functions.h"

char *fileTrafic;
char *fileFeatures;
char *fileIpts;
char *alertTrafic;
const char banner[] = "banner.txt";
#define ERROR 1
void printBanner()
{
    FILE *bannerFile;
    bannerFile = fopen(banner, "r");
    char c;
    while ((c = getc(bannerFile)) != EOF)
    {
        printf("%c", c);
    }
    if (bannerFile)
    {
        fclose(bannerFile);
    }
}
int main(int argc, char **argv)
{
    if (argc < 5)
    {
        printBanner();
        return ERROR;
    }
    if (argc > 4)
    {
        for (int i = 1; i < argc; i++)
        {
            std::string arg = argv[i];
            if (arg == "-r")
            {
                raw = fopen((char *)argv[i + 1], "rb");
                if (!raw)
                {
                    printf("no open file: %s", argv[i + 1]);
                    return ERROR;
                }
                if (!isPcapFile(*raw))
                {
                    return ERROR;
                }
            }
            if (arg == "-f")
            {
                csv = fopen(argv[i + 1], "w");
                if (!csv)
                {
                    printf("no open file: %s", argv[i + 1]);
                    return ERROR;
                }
            }
            if (arg == "-b")
            {
                alertT = fopen((char *)argv[i + 1], "rb");
                if (!alertT)
                {
                    printf("no open file: %s", argv[i + 1]);
                    return ERROR;
                }
                if (!isPcapFile(*alertT))
                {
                    return ERROR;
                }
                readBadTrafic(*alertT);
                printf("alerts:\t%lu\n", data.size());
            }
            if (arg == "-i")
            {
                ipts = fopen(argv[i + 1], "w");
                if (!ipts)
                {
                    printf("no open file: %s", argv[i + 1]);
                    return ERROR;
                }
            }
        }
    }
    /*scan*/
    fseek(raw, 0L, SEEK_END);
    pointerbffRawTrafic = ftell(raw) - 24;
    fseek(raw, 24L, SEEK_SET);
    bffRawTrafic = new unsigned char[pointerbffRawTrafic];
    pointerbffRawTrafic = fread(bffRawTrafic, sizeof(unsigned char), pointerbffRawTrafic, raw);
    printf("bytes raw trafic: %" PRId64 "\n", pointerbffRawTrafic);
    /*close pcap raw trafic */
    if (raw)
    {
        fclose(raw);
    }

    pthread_t hilo0, hilo1, hilo2, hilo3;
    int u = 1, p = 2, o = 3, r = 4;
    ;
    pthread_mutex_init(&mutex, NULL);

    pthread_mutex_lock(&mutex);
    if (alertT)
    {
        fprintf(csv, "%s", titlecolums_2);
    }
    else
    {
        fprintf(csv, "%s", titlecolums);
    }
    if (alertT)
    {
        fclose(alertT);
    }

    pthread_mutex_unlock(&mutex);

    pthread_create(&hilo0, NULL, scanFlowIpv4TCP, (void *)&u);
    pthread_create(&hilo1, NULL, scanFlowIpv4UDP, (void *)&p);
    pthread_create(&hilo2, NULL, scanFlowIpv6TCP, (void *)&o);
    pthread_create(&hilo3, NULL, scanFlowIpv6UDP, (void *)&r);
    pthread_join(hilo0, NULL);
    pthread_join(hilo1, NULL);
    pthread_join(hilo2, NULL);
    pthread_join(hilo3, NULL);

    /*close file*/
    if (csv)
    {
        fclose(csv);
    }
    if (ipts)
    {
        fclose(ipts);
    }
    return 0;
}
