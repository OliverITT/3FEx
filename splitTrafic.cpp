#include "scanBadTrafic.h"
int main(int argc, char **argv)
{
    FILE *rawTrafic = fopen(argv[1], "rb");
    FILE *badTrafic = fopen(argv[2], "rb");
    FILE *feetrafic = fopen(argv[3], "wb");
    if (!rawTrafic || !badTrafic || !feetrafic)
    {
        printf("unknown file");
        return 1;
    }

    splitBadTrafic(*rawTrafic, *badTrafic, *feetrafic);
}