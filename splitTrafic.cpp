#include "scanBadTrafic.h"
int main(int argc, char **argv)
{
    FILE *rawTrafic = fopen(argv[1], "rb");
    FILE *badTrafic = fopen(argv[2], "rb");
    FILE *freeAnomaliTrafic = fopen(argv[3], "wb");
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