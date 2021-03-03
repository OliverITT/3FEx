//#include <iostream>
//#include <fstream>
//#include <stdint.h>
//#include <stdio.h>
//#include <stdlib.h>
//#include "structs.h"
#include "functions.h"
//#include <type_traits>
//using namespace std;

char *fileTrafic;
char *fileFeatures;
char *fileIpts;
char *alertTrafic;
int main(int argc, char **argv)
{

    if (argc == 4)
    {
        fileTrafic = *(argv + 1);
        fileFeatures = *(argv + 2);
        fileIpts = *(argv + 3);
    }
    if (argc == 5)
    {
        fileTrafic = *(argv + 1);
        alertTrafic = *(argv + 2);
        fileFeatures = *(argv + 3);
        fileIpts = *(argv + 4);
        alertT = fopen(alertTrafic, "rb");
        /*
        fseek(alertT, 0L, SEEK_END);
        pointerbffAlertTrafic = ftell(alertT) - 24;
        fseek(alertT, 24L, SEEK_SET);
        bffAlertTrafic = new unsigned char[pointerbffAlertTrafic];
        pointerbffAlertTrafic = fread(bffAlertTrafic, sizeof(unsigned char), pointerbffAlertTrafic, alertT);
        printf("bytes alert trafic: %" PRId64 "\n", pointerbffAlertTrafic);
        */
        readBadTrafic(*alertT);
    }

    raw = fopen(fileTrafic, "rb");
    csv = fopen(fileFeatures, "w");
    ipts = fopen(fileIpts, "w");
    if (!ipts)
    {
        printf("problemas con archivo csv");
    }

    PcapFileHeader fileheader;
    if (!fread(&fileheader, sizeof(PcapFileHeader), 1, raw))
    {
        printf("unknown file");
        return 0;
    }
    if (!(fileheader.version_major == 2 && fileheader.version_minor == 4))
    {
        printf("unknown file format");
        return 0;
    }
    fseek(raw, 0L, SEEK_END);
    pointerbffRawTrafic = ftell(raw) - 24;
    fseek(raw, 24L, SEEK_SET);
    bffRawTrafic = new unsigned char[pointerbffRawTrafic];
    pointerbffRawTrafic = fread(bffRawTrafic, sizeof(unsigned char), pointerbffRawTrafic, raw);
    printf("bytes raw trafic: %" PRId64 "\n", pointerbffRawTrafic);

    if (raw)
    {
        fclose(raw);
    }
    if (alertT)
    {
        fclose(alertT);
    }
    pthread_t hilo0, hilo1, hilo2, hilo3;
    int u = 1, p = 2, o = 3, r = 4;
    ;
    pthread_mutex_init(&mutex, NULL);

    pthread_mutex_lock(&mutex);
    fprintf(csv, "%s", titlecolums);
    pthread_mutex_unlock(&mutex);

    pthread_create(&hilo0, NULL, scanFlowIpv4TCP, (void *)&u);
    pthread_create(&hilo1, NULL, scanFlowIpv4UDP, (void *)&p);
    pthread_create(&hilo2, NULL, scanFlowIpv6TCP, (void *)&o);
    pthread_create(&hilo3, NULL, scanFlowIpv6UDP, (void *)&r);
    pthread_join(hilo0, NULL);
    pthread_join(hilo1, NULL);
    pthread_join(hilo2, NULL);
    pthread_join(hilo3, NULL);

    fclose(csv);
    fclose(ipts);
    return 0;
}
