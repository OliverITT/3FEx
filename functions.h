//#include "structs.h"
#include <pthread.h>
#include <string.h>
#include "features.h"
#include <inttypes.h>
#include <math.h>
#include "scanBadTrafic.h"

FILE *raw, *csv, *ipts, *alertT;

pthread_mutex_t mutex;

std::string *socket_to_String(std::string *ip_dhost, std::string *ip_shost, TCPheader *ports)
{
    std::string *socket = new std::string;
    char buffer[17];
    *socket += *ip_dhost;
    sprintf(buffer, "%x", (uint16_t)ports->dstPort);
    *socket += buffer;
    *socket += *ip_shost;
    sprintf(buffer, "%x", (uint16_t)ports->srcPort);
    *socket += buffer;
    return socket;
}
std::string *socket_to_String(uint32_t *ip_dhost, uint32_t *ip_shost, TCPheader *ports)
{
    std::string *socket = new std::string;
    char buffer[17];
    sprintf(buffer, "%x", (uint32_t)*ip_dhost);
    // sprintf(buffer, "%x%x%x%x", (uint8_t)(*ip_dhost >> 24), (uint8_t)(*ip_dhost >> 16), (uint8_t)(*ip_dhost >> 8), (uint8_t)(*ip_dhost));
    *socket += buffer;
    sprintf(buffer, "%x", (uint16_t)ports->dstPort);
    *socket += buffer;
    sprintf(buffer, "%x", (uint32_t)*ip_shost);
    // sprintf(buffer, "%x%x%x%x", (uint8_t)(*ip_shost)>> 24, (uint8_t)(*ip_shost >> 16), (uint8_t)(*ip_shost >> 8), (uint8_t)(*ip_shost));
    *socket += buffer;
    sprintf(buffer, "%x", (uint16_t)ports->srcPort);
    *socket += buffer;
    return socket;
}
void mark(uint64_t point)
{
    for (int i = 0; i < 4; i++)
    {
        *(bffRawTrafic + point + i) = 0;
    }
}

void yield(void)
{
    if (rand() % 2)
        sched_yield();
}

void calculate_std_pktl()
{

    double std_temp = 0;
    for (it_std_fpktl = vector_std_fpktl.begin(); it_std_fpktl != vector_std_fpktl.end(); ++it_std_fpktl)
    {
        *it_std_fpktl -= mean_fpktl;
        *it_std_fpktl = pow(*it_std_fpktl, 2);
    }
    //
    for (it_std_fpktl = vector_std_fpktl.begin(); it_std_fpktl != vector_std_fpktl.end(); ++it_std_fpktl)
    {
        std_temp += (*it_std_fpktl);
    }
    std_fpktl = sqrt((std_temp / (total_fpackets - 1)));
    if (total_bpackets > 1)
    {
        std_temp = 0;
        for (it_std_bpktl = vector_std_bpktl.begin(); it_std_bpktl != vector_std_bpktl.end(); ++it_std_bpktl)
        {
            *it_std_bpktl -= mean_bpktl;
            *it_std_bpktl = pow(*it_std_bpktl, 2);
        }
        //
        for (it_std_bpktl = vector_std_bpktl.begin(); it_std_bpktl != vector_std_bpktl.end(); ++it_std_bpktl)
        {
            std_temp += (*it_std_bpktl);
        }
        std_bpktl = sqrt((std_temp / (total_bpackets - 1)));
    }
}
void calculate_std_iat()
{
    double temp_std_iat = 0;
    for (it_std_fiat = vector_std_fiat.begin(); it_std_fiat != vector_std_fiat.end(); ++it_std_fiat)
    {
        *it_std_fiat -= mean_fiat;
        *it_std_fiat = pow(*it_std_fiat, 2);
    }
    for (it_std_fiat = vector_std_fiat.begin(); it_std_fiat != vector_std_fiat.end(); ++it_std_fiat)
    {
        temp_std_iat += *it_std_fiat;
    }
    std_fiat = sqrt(temp_std_iat / (vector_std_fiat.size() - 1));
    temp_std_iat = 0;
    if (total_bpackets > 1)
    {
        for (it_std_biat = vector_std_biat.begin(); it_std_biat != vector_std_biat.end(); ++it_std_biat)
        {
            *it_std_biat -= mean_biat;
            *it_std_biat = pow(*it_std_biat, 2);
        }
        for (it_std_biat = vector_std_biat.begin(); it_std_biat != vector_std_biat.end(); ++it_std_biat)
        {
            temp_std_iat += *it_std_biat;
        }
        std_biat = sqrt(temp_std_iat / (vector_std_biat.size() - 1));
    }
}
void calculateFlagsFlow()
{

    if ((*(bffRawTrafic + jump + 63) & _PSH))
    {
        flow_psh++;
    }
    if ((*(bffRawTrafic + jump + 63) & _URG))
    {
        flow_urg++;
    }
    if ((*(bffRawTrafic + jump + 63) & _FIN))
    {
        flow_fin++;
    }
    if ((*(bffRawTrafic + jump + 63) & _SYN))
    {
        flow_syn++;
    }
    if ((*(bffRawTrafic + jump + 63) & _RST))
    {
        flow_rst++;
    }
    if ((*(bffRawTrafic + jump + 63) & _ACK))
    {
        flow_ack++;
    }
    if ((*(bffRawTrafic + jump + 63) & _CWE))
    {
        flow_cwr++;
    }
    if ((*(bffRawTrafic + jump + 63) & _ECE))
    {
        flow_ece++;
    }
}
//forward direction flags
void calculateFlagsForward()
{

    if ((*(bffRawTrafic + jump + 63) & _PSH))
    {
        fpsh_cnt++;
    }
    if ((*(bffRawTrafic + jump + 63) & _URG))
    {
        furg_cnt++;
    }
}
//backward direction flags
void calculateFlagsBackward()
{
    if ((*(bffRawTrafic + jump + 63) & _PSH))
    {
        bpsh_cnt++;
    }
    if ((*(bffRawTrafic + jump + 63) & _URG))
    {
        burg_cnt++;
    }
}

void calculateFlagsFlowv6()
{

    if ((*(bffRawTrafic + jump + 83) & _PSH))
    {
        flow_psh++;
    }
    if ((*(bffRawTrafic + jump + 83) & _URG))
    {
        flow_urg++;
    }
    if ((*(bffRawTrafic + jump + 83) & _FIN))
    {
        flow_fin++;
    }
    if ((*(bffRawTrafic + jump + 83) & _SYN))
    {
        flow_syn++;
    }
    if ((*(bffRawTrafic + jump + 83) & _RST))
    {
        flow_rst++;
    }
    if ((*(bffRawTrafic + jump + 83) & _ACK))
    {
        flow_ack++;
    }
    if ((*(bffRawTrafic + jump + 83) & _CWE))
    {
        flow_cwr++;
    }
    if ((*(bffRawTrafic + jump + 83) & _ECE))
    {
        flow_ece++;
    }
}
//forward direction flags
void calculateFlagsForwardv6()
{

    if ((*(bffRawTrafic + jump + 83) & _PSH))
    {
        fpsh_cnt++;
    }
    if ((*(bffRawTrafic + jump + 83) & _URG))
    {
        furg_cnt++;
    }
}
//backward direction flags
void calculateFlagsBackwardv6()
{
    if ((*(bffRawTrafic + jump + 83) & _PSH))
    {
        bpsh_cnt++;
    }
    if ((*(bffRawTrafic + jump + 83) & _URG))
    {
        burg_cnt++;
    }
}

void calculate_std_flowpktl()
{
    //vector_std_flowpktl
    double temp_std_ = 0;
    for (it_std_flowpktl = vector_std_flowpktl.begin(); it_std_flowpktl != vector_std_flowpktl.end(); ++it_std_flowpktl)
    {
        *it_std_flowpktl -= mean_flowpktl;
        *it_std_flowpktl = pow(*it_std_flowpktl, 2);
    }
    for (it_std_flowpktl = vector_std_flowpktl.begin(); it_std_flowpktl != vector_std_flowpktl.end(); ++it_std_flowpktl)
    {
        temp_std_ += *it_std_flowpktl;
    }
    std_flowpktl = sqrt(temp_std_ / (vector_std_flowpktl.size() - 1));
}
void calculate_std_flowiat()
{
    std::vector<float>::iterator it_temp1;
    double temp_std_ = 0;
    for (it_temp1 = vector_std_flowiat.begin(); it_temp1 != vector_std_flowiat.end(); ++it_temp1)
    {
        *it_temp1 -= mean_flowiat;
        *it_temp1 = pow(*it_temp1, 2);
    }
    for (it_temp1 = vector_std_flowiat.begin(); it_temp1 != vector_std_flowiat.end(); ++it_temp1)
    {
        temp_std_ += *it_temp1;
    }
    std_flowiat = sqrt(temp_std_ / (vector_std_flowiat.size() - 1));
}
void *scanFlowIpv4TCP(void *valor)
{
    //yield();
    pthread_mutex_lock(&mutex); //Inicio SC
    printf("thread->%d\n", *(int *)valor);
    resetVar();
    jump = 0;

    while (true)
    {
        //printf("primer ciclo\n");
        while (true)
        {
            //printf("segundo ciclo\n");

            //verifica si ya se recorrio todo el archivo, si es asi limpia los contadores y jump = ultima posicion de primer paquete del flojo
            if (jump >= pointerbffRawTrafic)
            {
                //printf("\nTermino scaneo\n");
                if (traficTipe == _TCP)
                {
                    //printf("fin sesion\n");
                    //guardar featurs en archivo csv
                    min_bpktl = min_bpktl == 65535 ? 0 : min_bpktl;
                    mean_fpktl = total_fpktl / ((float)total_fpackets);
                    mean_bpktl = (total_bpktl / ((float)total_bpackets));
                    //
                    min_fiat = total_fpackets > 1 ? min_fiat : 0;
                    min_biat = total_bpackets > 1 ? min_biat : 0;
                    //
                    total_fiat = total_fpackets > 1 ? total_fiat : 0;
                    total_biat = total_bpackets > 1 ? total_biat : 0;

                    //
                    mean_fiat = total_fpackets > 1 ? ((float)total_fiat) / (total_fpackets - 1) : 0;
                    mean_biat = total_bpackets > 1 ? total_biat / (total_bpackets - 1) : 0;
                    //
                    max_fiat = total_fpackets > 1 ? max_fiat : 0;
                    max_biat = total_bpackets > 1 ? max_biat : 0;
                    //
                    min_flowiat = (total_fpackets + total_bpackets) > 1 ? min_flowiat : 0;
                    max_flowiat = (total_fpackets + total_bpackets) > 1 ? max_flowiat : 0;
                    //
                    mean_flowpktl = (mean_flowpktl / (total_fpackets + total_bpackets));
                    //
                    mean_flowiat = (total_fpackets + total_bpackets - 1) > 0 ? mean_flowiat / (total_fpackets + total_bpackets - 1) : 0;
                    //
                    calculate_std_pktl();
                    calculate_std_iat();
                    calculate_std_flowpktl();
                    calculate_std_flowiat();

                    std_flowpktl = (total_fpackets + total_bpackets) > 1 ? std_flowpktl : 0;
                    std_fpktl = total_fpackets > 1 ? std_fpktl : 0;
                    std_bpktl = total_bpackets > 1 ? std_bpktl : 0;
                    std_fiat = total_fpackets > 1 ? std_fiat : 0;
                    std_biat = total_bpackets > 1 ? std_biat : 0;
                    std_flowiat = (total_fpackets + total_bpackets) > 2 ? std_flowiat : 0;
                    mean_flowiat = (total_fpackets + total_bpackets) > 1 ? mean_flowiat : 0;
                    fprintf(csv, "TCP,%f,%d.%d.%d.%d->%d.%d.%d.%d,%d.%d.%d.%d,%u,%d.%d.%d.%d,%u,%f,%" PRId64 ",%" PRId64 ",%" PRId64 ",%" PRId64 ",%d,%d,%d,%d,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%d,%d,%d,%d,%d,%d,%f,%f,%f,%f,%f,%f,%f,%f,%d,%d,%d,%d,%d,%d,%d,%f,%d\n",
                            timestampInit,
                            ip_shost >> 24, ((ip_shost >> 16) & 0x0ff), ((ip_shost >> 8) & 0x0ff), ((ip_shost)&0x0ff),
                            ip_dhost >> 24, ((ip_dhost >> 16) & 0x0ff), ((ip_dhost >> 8) & 0x0ff), ((ip_dhost)&0x0ff),
                            ip_shost >> 24, (ip_shost >> 16) & 0x0ff, (ip_shost >> 8) & 0x0ff, (ip_shost)&0x0ff, ports.srcPort,
                            ip_dhost >> 24, (ip_dhost >> 16) & 0x0ff, (ip_dhost >> 8) & 0x0ff, (ip_dhost)&0x0ff, ports.dstPort,
                            timestampPrev - timestampInit,
                            total_fpackets,
                            total_bpackets,
                            total_fpktl,
                            total_bpktl,
                            min_fpktl,
                            min_bpktl,
                            max_fpktl,
                            max_bpktl,
                            mean_fpktl,
                            mean_bpktl,
                            std_fpktl,
                            std_bpktl,
                            total_fiat,
                            total_biat,
                            min_fiat,
                            min_biat,
                            max_fiat,
                            max_biat,
                            mean_fiat,
                            mean_biat,
                            std_fiat,
                            std_biat,
                            fpsh_cnt,
                            bpsh_cnt,
                            furg_cnt,
                            burg_cnt,
                            total_fhlen,
                            total_bhlen,
                            (total_fpackets / (timestampPrev - timestampInit)),
                            (total_bpackets / (timestampPrev - timestampInit)),
                            ((total_fpackets + total_bpackets) / (timestampPrev - timestampInit)),
                            ((total_fpktl + total_bpktl) / (timestampPrev - timestampInit)),
                            // min_flowpktl,
                            // max_flowpktl,
                            mean_flowpktl,
                            std_flowpktl,
                            // min_flowiat,
                            // max_flowiat,
                            mean_flowiat,
                            std_flowiat,
                            flow_fin,
                            flow_syn,
                            flow_rst,
                            // flow_psh,
                            flow_ack,
                            flow_urg,
                            flow_cwr,
                            flow_ece,
                            (total_bpktl / (float)total_fpktl),
                            isBadTrafic(*socket_to_String(&ip_dhost, &ip_shost, &ports), IPV4_TCP));
                    fprintf(ipts, "\n");
                    //printf("No. packet TCP: %llu\n", TCP_cont);
                    //printf("Timestamp%f\n",timestampInit);
                    //printf("Timestamp%f\n",timestampPrev);
                    // printf("time sesion: %f\n",(timestampPrev-timestampInit));
                }

                if (traficTipe == 0)
                {
                    //fin de scaneo de trafico
                    //printf("\nEnd program\n");
                    //printf("jump:%llu",jump);
                    printf("End program:%" PRId64 "\n", jump);
                    resetVar();
                    pthread_mutex_unlock(&mutex); //Fin SC
                    return NULL;
                }
                //limpiar varibles
                resetVar();
                if (traficPointer % 1024 == 0)
                {
                    printf("Bytes->%" PRId64 "\n", traficPointer);
                }
                jump = traficPointer;
                traficTipe = 0;
            }
            while (jump < pointerbffRawTrafic)
            {
                //printf("miestras es menor");

                //
                incl_leng = (*(bffRawTrafic + (jump + 11)) << 24 | *(bffRawTrafic + (jump + 10)) << 16 | *(bffRawTrafic + (jump + 9)) << 8 | *(bffRawTrafic + (jump + 8)));
                orig_len = (*(bffRawTrafic + (jump + 15)) << 24 | *(bffRawTrafic + (jump + 14)) << 16 | *(bffRawTrafic + (jump + 13)) << 8 | *(bffRawTrafic + (jump + 12)));
                timestampTemp = *(bffRawTrafic + jump + 3) << 24 | *(bffRawTrafic + jump + 2) << 16 | *(bffRawTrafic + jump + 1) << 8 | *(bffRawTrafic + jump);

                //busca paquetes distintos de cero
                while (timestampTemp == 0 || !((*(bffRawTrafic + (jump + 28)) << 8 | *(bffRawTrafic + (jump + 29))) == _IPV4) || !(*(bffRawTrafic + (jump + 39)) == _TCP))
                {
                    if (jump == pointerbffRawTrafic)
                    {
                        break;
                    }
                    jump += incl_leng + 16;

                    incl_leng = (*(bffRawTrafic + (jump + 11)) << 24 | *(bffRawTrafic + (jump + 10)) << 16 | *(bffRawTrafic + (jump + 9)) << 8 | *(bffRawTrafic + (jump + 8)));
                    orig_len = (*(bffRawTrafic + (jump + 15)) << 24 | *(bffRawTrafic + (jump + 14)) << 16 | *(bffRawTrafic + (jump + 13)) << 8 | *(bffRawTrafic + (jump + 12)));
                    timestampTemp = *(bffRawTrafic + jump + 3) << 24 | *(bffRawTrafic + jump + 2) << 16 | *(bffRawTrafic + jump + 1) << 8 | *(bffRawTrafic + jump);
                }
                //check if ipv4
                if ((*(bffRawTrafic + (jump + 28)) << 8 | *(bffRawTrafic + (jump + 29))) == _IPV4)
                {

                    if (!(*(bffRawTrafic + (jump + 39)) == _TCP))
                    {
                        jump += incl_leng + 16;
                        break;
                    }
                    if (!traficTipe)
                    {

                        traficTipe = *(bffRawTrafic + (jump + 39));
                        timestampTemp += (*(bffRawTrafic + jump + 7) << 24 | *(bffRawTrafic + jump + 6) << 16 | *(bffRawTrafic + jump + 5) << 8 | *(bffRawTrafic + jump + 4)) / 1e6;
                        timestampPrev = timestampPrevForward = timestampInit = timestampTemp;
                        //extraccion de ip y puertos
                        ip_shost = *(bffRawTrafic + jump + 42) << 24 | *(bffRawTrafic + jump + 43) << 16 | *(bffRawTrafic + jump + 44) << 8 | *(bffRawTrafic + jump + 45);
                        ip_dhost = *(bffRawTrafic + jump + 46) << 24 | *(bffRawTrafic + jump + 47) << 16 | *(bffRawTrafic + jump + 48) << 8 | *(bffRawTrafic + jump + 49);
                        ports.srcPort = *(bffRawTrafic + jump + 50) << 8 | *(bffRawTrafic + jump + 51);
                        ports.dstPort = *(bffRawTrafic + jump + 52) << 8 | *(bffRawTrafic + jump + 53);
                        //extraccion de featurs forward direccion primer paquete encontrado de la sesion a scanear
                        total_fpackets++;
                        total_fpktl = orig_len;
                        //
                        min_fpktl = orig_len;
                        //
                        max_fpktl = orig_len;
                        //
                        vector_std_fpktl.push_back(orig_len);
                        //
                        calculateFlagsForward();
                        //
                        min_flowpktl = max_flowpktl = orig_len;
                        //
                        mean_flowpktl = orig_len;
                        //
                        vector_std_flowpktl.push_back(orig_len);
                        //
                        total_fhlen += (*(bffRawTrafic + jump + 62) >> 4) * 4;
                        calculateFlagsFlow();
                        //marca el paquete time stamp segundo en 0 para indicar que ya fue procesado ese paquete
                        mark(jump);
                        jump += incl_leng + 16;
                        traficPointer = jump;
                        break;
                    }
                    ip_shost_temp = *(bffRawTrafic + jump + 42) << 24 | *(bffRawTrafic + jump + 43) << 16 | *(bffRawTrafic + jump + 44) << 8 | *(bffRawTrafic + jump + 45);
                    ip_dhost_temp = *(bffRawTrafic + jump + 46) << 24 | *(bffRawTrafic + jump + 47) << 16 | *(bffRawTrafic + jump + 48) << 8 | *(bffRawTrafic + jump + 49);
                    ports_temp.srcPort = *(bffRawTrafic + jump + 50) << 8 | *(bffRawTrafic + jump + 51);
                    ports_temp.dstPort = *(bffRawTrafic + jump + 52) << 8 | *(bffRawTrafic + jump + 53);
                    //timeout sesion
                    if (timestampTemp - timestampPrev > 100)
                    {
                        jump = pointerbffRawTrafic;
                        //printf("timeout\n");
                        break;
                    }
                    //check if the forward direction
                    if (ip_shost == ip_shost_temp && ip_dhost == ip_dhost_temp && ports.srcPort == ports_temp.srcPort && ports.dstPort == ports_temp.dstPort)
                    {

                        timestampTemp += (*(bffRawTrafic + jump + 7) << 24 | *(bffRawTrafic + jump + 6) << 16 | *(bffRawTrafic + jump + 5) << 8 | *(bffRawTrafic + jump + 4)) / 1e6;
                        //
                        iptTemp = (float)(timestampTemp - timestampPrev);
                        //
                        fprintf(ipts, "%.20f,", iptTemp);
                        timestampPrev = timestampTemp;

                        //extraccion de caracteristicas forward direccion
                        total_fpackets++;
                        total_fpktl += orig_len;
                        //
                        min_fpktl = orig_len < min_fpktl ? orig_len : min_fpktl;
                        max_fpktl = orig_len > max_fpktl ? orig_len : max_fpktl;
                        //
                        vector_std_fpktl.push_back(orig_len);
                        //
                        iptTemp = timestampTemp - timestampPrevForward;
                        /* if (!iatForwardState)
                        {
                            min_fiat = iptTemp;
                            min_flowiat = iptTemp;
                            printf("if_min_fiat\t%f\n",min_fiat);
                        } */
                        total_fiat += iptTemp;
                        //
                        min_fiat = iptTemp < min_fiat ? iptTemp : min_fiat;
                        //
                        max_fiat = iptTemp > max_fiat ? iptTemp : max_fiat;
                        //
                        vector_std_fiat.push_back(iptTemp);
                        //
                        calculateFlagsForward();
                        //
                        min_flowpktl = orig_len < min_flowpktl ? orig_len : min_flowpktl;
                        //
                        max_flowpktl = orig_len > max_flowpktl ? orig_len : max_flowpktl;
                        //
                        mean_flowpktl += orig_len;
                        //
                        vector_std_flowpktl.push_back(orig_len);
                        //
                        min_flowiat = iptTemp < min_flowiat ? iptTemp : min_flowiat;
                        //
                        max_flowiat = iptTemp > max_flowiat ? iptTemp : max_flowiat;
                        //
                        mean_flowiat += iptTemp;
                        //
                        vector_std_flowiat.push_back(iptTemp);
                        //
                        timestampPrevForward = timestampTemp;
                        //
                        total_fhlen += (*(bffRawTrafic + jump + 62) >> 4) * 4;
                        //
                        calculateFlagsFlow();
                        //marcar el paquete
                        mark(jump);
                    }

                    //check if the backward direction
                    if (ip_shost == ip_dhost_temp && ip_dhost == ip_shost_temp && ports.srcPort == ports_temp.dstPort && ports.dstPort == ports_temp.srcPort)
                    {

                        timestampTemp += (*(bffRawTrafic + jump + 7) << 24 | *(bffRawTrafic + jump + 6) << 16 | *(bffRawTrafic + jump + 5) << 8 | *(bffRawTrafic + jump + 4)) / 1e6;

                        iptTemp = timestampTemp - timestampPrev;
                        fprintf(ipts, "%.20f,", iptTemp);
                        timestampPrev = timestampTemp;

                        //extraccion de caracteristicas en backward direccion
                        total_bpackets++;
                        total_bpktl += orig_len;
                        //

                        //
                        vector_std_bpktl.push_back(orig_len);
                        //
                        vector_std_flowiat.push_back(iptTemp);
                        //
                        min_flowiat = iptTemp < min_flowiat ? iptTemp : min_flowiat;
                        //
                        max_flowiat = iptTemp > max_flowiat ? iptTemp : max_flowiat;
                        //
                        mean_flowiat += iptTemp;
                        if (!iatBackwardState)
                        {
                            iatBackwardState = true;
                            timestampPrevBackware = timestampTemp;
                            min_bpktl = orig_len;
                            min_biat = timestampTemp;
                        }
                        else
                        {
                            iptTemp = timestampTemp - timestampPrevBackware;
                            //
                            total_biat += iptTemp;
                            //
                            min_biat = iptTemp < min_biat ? iptTemp : min_biat;
                            //
                            max_biat = iptTemp > max_biat ? iptTemp : max_biat;
                            //
                            vector_std_biat.push_back(iptTemp);
                        }

                        min_bpktl = orig_len < min_bpktl ? orig_len : min_bpktl;
                        max_bpktl = orig_len > max_bpktl ? orig_len : max_bpktl;
                        timestampPrevBackware = timestampTemp;
                        //
                        calculateFlagsBackward();
                        //
                        min_flowpktl = orig_len < min_flowpktl ? orig_len : min_flowpktl;
                        //
                        max_flowpktl = orig_len > max_flowpktl ? orig_len : max_flowpktl;
                        //
                        mean_flowpktl += orig_len;
                        //
                        vector_std_flowpktl.push_back(orig_len);
                        //
                        total_bhlen += (*(bffRawTrafic + jump + 62) >> 4) * 4;
                        //
                        calculateFlagsFlow();
                        //marcar el paquete
                        mark(jump);
                    }
                }
                else
                {
                    jump += incl_leng + 16;
                    break;
                }
                jump += incl_leng + 16;
            }
        }
    }

    //  yield();
    pthread_mutex_unlock(&mutex); //Fin SC
    //yield();
    printf("End function TCP");
    return NULL;
}
//flow UDP
void *scanFlowIpv4UDP(void *valor)
{
    //yield();
    pthread_mutex_lock(&mutex); //Inicio SC
    resetVar();
    jump = 0; //yield();
    printf("thread->%d\n", *(int *)valor);

    while (true)
    {
        //printf("primer ciclo\n");
        while (true)
        {
            //printf("segundo ciclo\n");

            //verifica si ya se recorrio todo el archivo, si es asi limpia los contadores y jump = ultima posicion de primer paquete del flojo
            if (jump >= pointerbffRawTrafic)
            {
                //printf("\nTermino scaneo\n");
                if (traficTipe == _UDP)
                {
                    //printf("fin sesion\n");
                    //guardar featurs en archivo csv
                    min_bpktl = min_bpktl == 65535 ? 0 : min_bpktl;
                    mean_fpktl = total_fpktl / ((float)total_fpackets);
                    mean_bpktl = (total_bpktl / ((float)total_bpackets));
                    //
                    min_fiat = total_fpackets > 1 ? min_fiat : 0;
                    min_biat = total_bpackets > 1 ? min_biat : 0;
                    //
                    total_fiat = total_fpackets > 1 ? total_fiat : 0;
                    total_biat = total_bpackets > 1 ? total_biat : 0;

                    //
                    mean_fiat = total_fpackets > 1 ? ((float)total_fiat) / (total_fpackets - 1) : 0;
                    mean_biat = total_bpackets > 1 ? total_biat / (total_bpackets - 1) : 0;
                    //
                    max_fiat = total_fpackets > 1 ? max_fiat : 0;
                    max_biat = total_bpackets > 1 ? max_biat : 0;
                    //
                    min_flowiat = (total_fpackets + total_bpackets) > 1 ? min_flowiat : 0;
                    max_flowiat = (total_fpackets + total_bpackets) > 1 ? max_flowiat : 0;
                    //
                    mean_flowpktl = (mean_flowpktl / (total_fpackets + total_bpackets));
                    //
                    mean_flowiat = (total_fpackets + total_bpackets - 1) > 0 ? mean_flowiat / (total_fpackets + total_bpackets - 1) : 0;
                    ;
                    //
                    calculate_std_pktl();
                    calculate_std_iat();
                    calculate_std_flowpktl();
                    calculate_std_flowiat();

                    std_flowpktl = (total_fpackets + total_bpackets) > 1 ? std_flowpktl : 0;
                    std_fpktl = total_fpackets > 1 ? std_fpktl : 0;
                    std_bpktl = total_bpackets > 1 ? std_bpktl : 0;
                    std_fiat = total_fpackets > 1 ? std_fiat : 0;
                    std_biat = total_bpackets > 1 ? std_biat : 0;
                    std_flowiat = (total_fpackets + total_bpackets) > 2 ? std_flowiat : 0;
                    mean_flowiat = (total_fpackets + total_bpackets) > 1 ? mean_flowiat : 0;
                    fprintf(csv, "UDP,%f,%d.%d.%d.%d->%d.%d.%d.%d,%d.%d.%d.%d,%u,%d.%d.%d.%d,%u,%f,%" PRId64 ",%" PRId64 ",%" PRId64 ",%" PRId64 ",%d,%d,%d,%d,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%d,%d,%d,%d,%d,%d,%f,%f,%f,%f,%f,%f,%f,%f,%d,%d,%d,%d,%d,%d,%d,%f,%d\n",
                            timestampInit,
                            ip_shost >> 24, ((ip_shost >> 16) & 0x0ff), ((ip_shost >> 8) & 0x0ff), ((ip_shost)&0x0ff),
                            ip_dhost >> 24, ((ip_dhost >> 16) & 0x0ff), ((ip_dhost >> 8) & 0x0ff), ((ip_dhost)&0x0ff),
                            ip_shost >> 24, (ip_shost >> 16) & 0x0ff, (ip_shost >> 8) & 0x0ff, (ip_shost)&0x0ff, ports.srcPort,
                            ip_dhost >> 24, (ip_dhost >> 16) & 0x0ff, (ip_dhost >> 8) & 0x0ff, (ip_dhost)&0x0ff, ports.dstPort,
                            timestampPrev - timestampInit,
                            total_fpackets,
                            total_bpackets,
                            total_fpktl,
                            total_bpktl,
                            min_fpktl,
                            min_bpktl,
                            max_fpktl,
                            max_bpktl,
                            mean_fpktl,
                            mean_bpktl,
                            std_fpktl,
                            std_bpktl,
                            total_fiat,
                            total_biat,
                            min_fiat,
                            min_biat,
                            max_fiat,
                            max_biat,
                            mean_fiat,
                            mean_biat,
                            std_fiat,
                            std_biat,
                            fpsh_cnt,
                            bpsh_cnt,
                            furg_cnt,
                            burg_cnt,
                            total_fhlen,
                            total_bhlen,
                            (total_fpackets / (timestampPrev - timestampInit)),
                            (total_bpackets / (timestampPrev - timestampInit)),
                            ((total_fpackets + total_bpackets) / (timestampPrev - timestampInit)),
                            ((total_fpktl + total_bpktl) / (timestampPrev - timestampInit)),
                            // min_flowpktl,
                            // max_flowpktl,
                            mean_flowpktl,
                            std_flowpktl,
                            // min_flowiat,
                            // max_flowiat,
                            mean_flowiat,
                            std_flowiat,
                            flow_fin,
                            flow_syn,
                            flow_rst,
                            //flow_psh,
                            flow_ack,
                            flow_urg,
                            flow_cwr,
                            flow_ece,
                            (total_bpktl / (float)total_fpktl),
                            isBadTrafic(*socket_to_String(&ip_dhost, &ip_shost, &ports), IPV4_UDP));
                    fprintf(ipts, "\n");
                    //printf("srcport:%u",ports.srcPort);
                    //printf("No. packet TCP: %llu\n", TCP_cont);
                    //printf("Timestamp%f\n",timestampInit);
                    //printf("Timestamp%f\n",timestampPrev);
                    // printf("time sesion: %f\n",(timestampPrev-timestampInit));
                }

                if (traficTipe == 0)
                {
                    //fin de scaneo de trafico
                    //printf("\nEnd program\n");
                    //printf("jump:%llu",jump);
                    printf("End program:%" PRId64 "\n", jump);
                    resetVar();
                    pthread_mutex_unlock(&mutex); //Fin SC
                    return NULL;
                }
                //limpiar varibles
                resetVar();
                if (traficPointer % 1024 == 0)
                {
                    printf("Bytes->%" PRId64 "\n", traficPointer);
                }
                jump = traficPointer;
                traficTipe = 0;
            }
            while (jump < pointerbffRawTrafic)
            {
                //printf("miestras es menor");

                //
                incl_leng = (*(bffRawTrafic + (jump + 11)) << 24 | *(bffRawTrafic + (jump + 10)) << 16 | *(bffRawTrafic + (jump + 9)) << 8 | *(bffRawTrafic + (jump + 8)));
                orig_len = (*(bffRawTrafic + (jump + 15)) << 24 | *(bffRawTrafic + (jump + 14)) << 16 | *(bffRawTrafic + (jump + 13)) << 8 | *(bffRawTrafic + (jump + 12)));
                timestampTemp = *(bffRawTrafic + jump + 3) << 24 | *(bffRawTrafic + jump + 2) << 16 | *(bffRawTrafic + jump + 1) << 8 | *(bffRawTrafic + jump);

                //busca paquetes distintos de cero
                while (timestampTemp == 0 || !((*(bffRawTrafic + (jump + 28)) << 8 | *(bffRawTrafic + (jump + 29))) == _IPV4) || !(*(bffRawTrafic + (jump + 39)) == _UDP))
                {
                    if (jump == pointerbffRawTrafic)
                    {
                        break;
                    }
                    jump += incl_leng + 16;

                    incl_leng = (*(bffRawTrafic + (jump + 11)) << 24 | *(bffRawTrafic + (jump + 10)) << 16 | *(bffRawTrafic + (jump + 9)) << 8 | *(bffRawTrafic + (jump + 8)));
                    orig_len = (*(bffRawTrafic + (jump + 15)) << 24 | *(bffRawTrafic + (jump + 14)) << 16 | *(bffRawTrafic + (jump + 13)) << 8 | *(bffRawTrafic + (jump + 12)));
                    timestampTemp = *(bffRawTrafic + jump + 3) << 24 | *(bffRawTrafic + jump + 2) << 16 | *(bffRawTrafic + jump + 1) << 8 | *(bffRawTrafic + jump);
                }
                //check if ipv4
                if ((*(bffRawTrafic + (jump + 28)) << 8 | *(bffRawTrafic + (jump + 29))) == _IPV4)
                {

                    if (!(*(bffRawTrafic + (jump + 39)) == _UDP))
                    {
                        jump += incl_leng + 16;
                        break;
                    }
                    if (!traficTipe)
                    {
                        //calculateFlagsFlow();
                        traficTipe = *(bffRawTrafic + (jump + 39));
                        timestampTemp += (*(bffRawTrafic + jump + 7) << 24 | *(bffRawTrafic + jump + 6) << 16 | *(bffRawTrafic + jump + 5) << 8 | *(bffRawTrafic + jump + 4)) / 1e6;
                        timestampPrev = timestampPrevForward = timestampInit = timestampTemp;
                        //extraccion de ip y puertos
                        ip_shost = *(bffRawTrafic + jump + 42) << 24 | *(bffRawTrafic + jump + 43) << 16 | *(bffRawTrafic + jump + 44) << 8 | *(bffRawTrafic + jump + 45);
                        ip_dhost = *(bffRawTrafic + jump + 46) << 24 | *(bffRawTrafic + jump + 47) << 16 | *(bffRawTrafic + jump + 48) << 8 | *(bffRawTrafic + jump + 49);
                        ports.srcPort = *(bffRawTrafic + jump + 50) << 8 | *(bffRawTrafic + jump + 51);
                        ports.dstPort = *(bffRawTrafic + jump + 52) << 8 | *(bffRawTrafic + jump + 53);
                        //extraccion de featurs forward direccion primer paquete encontrado de la sesion a scanear
                        total_fpackets++;
                        total_fpktl = orig_len;
                        //
                        min_fpktl = orig_len;
                        //
                        max_fpktl = orig_len;
                        //
                        vector_std_fpktl.push_back(orig_len);
                        //
                        //
                        min_flowpktl = max_flowpktl = orig_len;
                        //
                        mean_flowpktl = orig_len;
                        //
                        vector_std_flowpktl.push_back(orig_len);
                        //
                        total_fhlen += *(bffRawTrafic + jump + 54) << 8 | *(bffRawTrafic + jump + 55);
                        //marca el paquete time stamp segundo en 0 para indicar que ya fue procesado ese paquete
                        mark(jump);
                        jump += incl_leng + 16;
                        traficPointer = jump;
                        break;
                    }
                    ip_shost_temp = *(bffRawTrafic + jump + 42) << 24 | *(bffRawTrafic + jump + 43) << 16 | *(bffRawTrafic + jump + 44) << 8 | *(bffRawTrafic + jump + 45);
                    ip_dhost_temp = *(bffRawTrafic + jump + 46) << 24 | *(bffRawTrafic + jump + 47) << 16 | *(bffRawTrafic + jump + 48) << 8 | *(bffRawTrafic + jump + 49);
                    ports_temp.srcPort = *(bffRawTrafic + jump + 50) << 8 | *(bffRawTrafic + jump + 51);
                    ports_temp.dstPort = *(bffRawTrafic + jump + 52) << 8 | *(bffRawTrafic + jump + 53);
                    //timeout sesion
                    if (timestampTemp - timestampPrev > 100)
                    {
                        jump = pointerbffRawTrafic;
                        //printf("timeout\n");
                        break;
                    }
                    //check if the forward direction
                    if (ip_shost == ip_shost_temp && ip_dhost == ip_dhost_temp && ports.srcPort == ports_temp.srcPort && ports.dstPort == ports_temp.dstPort)
                    {

                        timestampTemp += (*(bffRawTrafic + jump + 7) << 24 | *(bffRawTrafic + jump + 6) << 16 | *(bffRawTrafic + jump + 5) << 8 | *(bffRawTrafic + jump + 4)) / 1e6;
                        //
                        iptTemp = timestampTemp - timestampPrev;
                        //
                        fprintf(ipts, "%.20f,", iptTemp);
                        timestampPrev = timestampTemp;

                        //extraccion de caracteristicas forward direccion
                        total_fpackets++;
                        total_fpktl += orig_len;
                        //
                        min_fpktl = orig_len < min_fpktl ? orig_len : min_fpktl;
                        max_fpktl = orig_len > max_fpktl ? orig_len : max_fpktl;
                        //
                        vector_std_fpktl.push_back(orig_len);
                        //
                        iptTemp = timestampTemp - timestampPrevForward;
                        /*     if (!iatForwardState)
                        {
                            min_fiat = iptTemp;
                            min_flowiat = iptTemp;
                        } */
                        total_fiat += iptTemp;
                        //
                        min_fiat = iptTemp < min_fiat ? iptTemp : min_fiat;
                        //
                        max_fiat = iptTemp > max_fiat ? iptTemp : max_fiat;
                        //
                        vector_std_fiat.push_back(iptTemp);
                        //
                        //
                        min_flowpktl = orig_len < min_flowpktl ? orig_len : min_flowpktl;
                        //
                        max_flowpktl = orig_len > max_flowpktl ? orig_len : max_flowpktl;
                        //
                        mean_flowpktl += orig_len;
                        //
                        vector_std_flowpktl.push_back(orig_len);
                        //
                        min_flowiat = iptTemp < min_flowiat ? iptTemp : min_flowiat;
                        //
                        max_flowiat = iptTemp > max_flowiat ? iptTemp : max_flowiat;
                        //
                        mean_flowiat += iptTemp;
                        //
                        vector_std_flowiat.push_back(iptTemp);
                        //
                        timestampPrevForward = timestampTemp;
                        //
                        total_fhlen += *(bffRawTrafic + jump + 54) << 8 | *(bffRawTrafic + jump + 55);
                        //marcar el paquete
                        mark(jump);
                    }

                    //check if the backward direction
                    if (ip_shost == ip_dhost_temp && ip_dhost == ip_shost_temp && ports.srcPort == ports_temp.dstPort && ports.dstPort == ports_temp.srcPort)
                    {

                        timestampTemp += (*(bffRawTrafic + jump + 7) << 24 | *(bffRawTrafic + jump + 6) << 16 | *(bffRawTrafic + jump + 5) << 8 | *(bffRawTrafic + jump + 4)) / 1e6;

                        iptTemp = timestampTemp - timestampPrev;
                        fprintf(ipts, "%.20f,", iptTemp);
                        timestampPrev = timestampTemp;

                        //extraccion de caracteristicas en backward direccion
                        total_bpackets++;
                        total_bpktl += orig_len;
                        //

                        //
                        vector_std_bpktl.push_back(orig_len);
                        //
                        vector_std_flowiat.push_back(iptTemp);
                        //
                        min_flowiat = iptTemp < min_flowiat ? iptTemp : min_flowiat;
                        //
                        max_flowiat = iptTemp > max_flowiat ? iptTemp : max_flowiat;
                        //
                        mean_flowiat += iptTemp;
                        if (!iatBackwardState)
                        {
                            iatBackwardState = true;
                            timestampPrevBackware = timestampTemp;
                            min_bpktl = orig_len;
                            min_biat = timestampTemp;
                        }
                        else
                        {
                            iptTemp = timestampTemp - timestampPrevBackware;
                            //
                            total_biat += iptTemp;
                            //
                            min_biat = iptTemp < min_biat ? iptTemp : min_biat;
                            //
                            max_biat = iptTemp > max_biat ? iptTemp : max_biat;
                            //
                            vector_std_biat.push_back(iptTemp);
                        }

                        min_bpktl = orig_len < min_bpktl ? orig_len : min_bpktl;
                        max_bpktl = orig_len > max_bpktl ? orig_len : max_bpktl;
                        timestampPrevBackware = timestampTemp;
                        //
                        //
                        min_flowpktl = orig_len < min_flowpktl ? orig_len : min_flowpktl;
                        //
                        max_flowpktl = orig_len > max_flowpktl ? orig_len : max_flowpktl;
                        //
                        mean_flowpktl += orig_len;
                        //
                        vector_std_flowpktl.push_back(orig_len);
                        //
                        total_bhlen += *(bffRawTrafic + jump + 54) << 8 | *(bffRawTrafic + jump + 55);
                        //
                        //marcar el paquete
                        mark(jump);
                    }
                }
                else
                {
                    jump += incl_leng + 16;
                    break;
                }
                jump += incl_leng + 16;
            }
        }
    }

    //  yield();
    pthread_mutex_unlock(&mutex); //Fin SC
    //yield();
    printf("End funtion UDP");
    return NULL;
}

void *scanFlowIpv6TCP(void *valor)
{

    //yield();
    pthread_mutex_lock(&mutex); //Inicio SC
    printf("thread->%d\n", *(int *)valor);
    resetVar();
    jump = 0;

    while (true)
    {
        //printf("primer ciclo\n");
        while (true)
        {
            //printf("segundo ciclo\n");

            //verifica si ya se recorrio todo el archivo, si es asi limpia los contadores y jump = ultima posicion de primer paquete del flojo
            if (jump >= pointerbffRawTrafic)
            {
                // printf("\nTermino scaneo\n");
                if (traficTipe == _TCP)
                {
                    //printf("fin sesion\n");
                    //guardar featurs en archivo csv
                    min_bpktl = min_bpktl == 65535 ? 0 : min_bpktl;
                    mean_fpktl = total_fpktl / ((float)total_fpackets);
                    mean_bpktl = (total_bpktl / ((float)total_bpackets));
                    //
                    min_fiat = total_fpackets > 1 ? min_fiat : 0;
                    min_biat = total_bpackets > 1 ? min_biat : 0;
                    //
                    total_fiat = total_fpackets > 1 ? total_fiat : 0;
                    total_biat = total_bpackets > 1 ? total_biat : 0;

                    //
                    mean_fiat = total_fpackets > 1 ? ((float)total_fiat) / (total_fpackets - 1) : 0;
                    mean_biat = total_bpackets > 1 ? total_biat / (total_bpackets - 1) : 0;
                    //
                    max_fiat = total_fpackets > 1 ? max_fiat : 0;
                    max_biat = total_bpackets > 1 ? max_biat : 0;
                    //
                    min_flowiat = (total_fpackets + total_bpackets) > 1 ? min_flowiat : 0;
                    max_flowiat = (total_fpackets + total_bpackets) > 1 ? max_flowiat : 0;
                    //
                    mean_flowpktl = (mean_flowpktl / (total_fpackets + total_bpackets));
                    //
                    mean_flowiat = (total_fpackets + total_bpackets - 1) > 0 ? mean_flowiat / (total_fpackets + total_bpackets - 1) : 0;
                    ;
                    //
                    calculate_std_pktl();
                    calculate_std_iat();
                    calculate_std_flowpktl();
                    calculate_std_flowiat();

                    std_flowpktl = (total_fpackets + total_bpackets) > 1 ? std_flowpktl : 0;
                    std_fpktl = total_fpackets > 1 ? std_fpktl : 0;
                    std_bpktl = total_bpackets > 1 ? std_bpktl : 0;
                    std_fiat = total_fpackets > 1 ? std_fiat : 0;
                    std_biat = total_bpackets > 1 ? std_biat : 0;
                    std_flowiat = (total_fpackets + total_bpackets) > 2 ? std_flowiat : 0;
                    mean_flowiat = (total_fpackets + total_bpackets) > 1 ? mean_flowiat : 0;
                    fprintf(csv, "TCP,%f,%s->%s,%s,%u,%s,%u,%f,%" PRId64 ",%" PRId64 ",%" PRId64 ",%" PRId64 ",%d,%d,%d,%d,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%d,%d,%d,%d,%d,%d,%f,%f,%f,%f,%f,%f,%f,%f,%d,%d,%d,%d,%d,%d,%d,%f,%d\n",
                            timestampInit,
                            ipv6_SCad.c_str(),
                            ipv6_DCad.c_str(),
                            ipv6_SCad.c_str(), ports.srcPort,
                            ipv6_DCad.c_str(), ports.dstPort,
                            timestampPrev - timestampInit,
                            total_fpackets,
                            total_bpackets,
                            total_fpktl,
                            total_bpktl,
                            min_fpktl,
                            min_bpktl,
                            max_fpktl,
                            max_bpktl,
                            mean_fpktl,
                            mean_bpktl,
                            std_fpktl,
                            std_bpktl,
                            total_fiat,
                            total_biat,
                            min_fiat,
                            min_biat,
                            max_fiat,
                            max_biat,
                            mean_fiat,
                            mean_biat,
                            std_fiat,
                            std_biat,
                            fpsh_cnt,
                            bpsh_cnt,
                            furg_cnt,
                            burg_cnt,
                            total_fhlen,
                            total_bhlen,
                            (total_fpackets / (float)(timestampPrev - timestampInit)),
                            (total_bpackets / (float)(timestampPrev - timestampInit)),
                            ((total_fpackets + total_bpackets) / (timestampPrev - timestampInit)),
                            ((total_fpktl + total_bpktl) / (timestampPrev - timestampInit)),
                            // min_flowpktl,
                            // max_flowpktl,
                            mean_flowpktl,
                            std_flowpktl,
                            // min_flowiat,
                            // max_flowiat,
                            mean_flowiat,
                            std_flowiat,
                            flow_fin,
                            flow_syn,
                            flow_rst,
                            // flow_psh,
                            flow_ack,
                            flow_urg,
                            flow_cwr,
                            flow_ece,
                            (total_bpktl / (float)total_fpktl),
                            isBadTrafic(*socket_to_String(&ipv6_SCad, &ipv6_SCad, &ports), IPV6_TCP));
                    fprintf(ipts, "\n");
                    //printf("srcport:%u",ports.srcPort);
                    //printf("No. packet TCP: %llu\n", TCP_cont);
                    //printf("Timestamp->init: %.20f\n",timestampInit);
                    //printf("Timestamp->prev: %f\n",timestampPrev);
                    //printf("resultado:%.20f\n", (timestampPrev-timestampInit));
                    //printf("total de paquete f:%d\n",total_fpackets);
                    // printf("time sesion: %f\n",(timestampPrev-timestampInit));
                }

                if (traficTipe == 0)
                {
                    //fin de scaneo de trafico
                    //printf("\nEnd program\n");
                    //printf("jump:%llu",jump);
                    printf("End program:%" PRId64 "\n", jump);
                    resetVar();
                    pthread_mutex_unlock(&mutex); //Fin SC
                    return NULL;
                }
                //limpiar varibles
                resetVar();
                if (traficPointer % 1024 == 0)
                {
                    printf("Bytes->%" PRId64 "\n", traficPointer);
                }
                jump = traficPointer;
                traficTipe = 0;
            }
            while (jump < pointerbffRawTrafic)
            {
                //printf("miestras es menor");

                //
                incl_leng = (*(bffRawTrafic + (jump + 11)) << 24 | *(bffRawTrafic + (jump + 10)) << 16 | *(bffRawTrafic + (jump + 9)) << 8 | *(bffRawTrafic + (jump + 8)));
                orig_len = (*(bffRawTrafic + (jump + 15)) << 24 | *(bffRawTrafic + (jump + 14)) << 16 | *(bffRawTrafic + (jump + 13)) << 8 | *(bffRawTrafic + (jump + 12)));
                timestampTemp = *(bffRawTrafic + jump + 3) << 24 | *(bffRawTrafic + jump + 2) << 16 | *(bffRawTrafic + jump + 1) << 8 | *(bffRawTrafic + jump);

                //busca paquetes distintos de cero
                while (timestampTemp == 0 || !((*(bffRawTrafic + (jump + 28)) << 8 | *(bffRawTrafic + (jump + 29))) == _IPV6) || !(*(bffRawTrafic + (jump + 36)) == _TCP))
                {
                    if (jump == pointerbffRawTrafic)
                    {
                        break;
                    }
                    jump += incl_leng + 16;

                    incl_leng = (*(bffRawTrafic + (jump + 11)) << 24 | *(bffRawTrafic + (jump + 10)) << 16 | *(bffRawTrafic + (jump + 9)) << 8 | *(bffRawTrafic + (jump + 8)));
                    orig_len = (*(bffRawTrafic + (jump + 15)) << 24 | *(bffRawTrafic + (jump + 14)) << 16 | *(bffRawTrafic + (jump + 13)) << 8 | *(bffRawTrafic + (jump + 12)));
                    timestampTemp = *(bffRawTrafic + jump + 3) << 24 | *(bffRawTrafic + jump + 2) << 16 | *(bffRawTrafic + jump + 1) << 8 | *(bffRawTrafic + jump);
                }

                //check if ipv4
                if ((*(bffRawTrafic + (jump + 28)) << 8 | *(bffRawTrafic + (jump + 29))) == _IPV6)
                {

                    if (!(*(bffRawTrafic + (jump + 36)) == _TCP))
                    {
                        jump += incl_leng + 16;
                        break;
                    }
                    if (!traficTipe)
                    {
                        traficTipe = *(bffRawTrafic + (jump + 36));
                        timestampTemp += (*(bffRawTrafic + jump + 7) << 24 | *(bffRawTrafic + jump + 6) << 16 | *(bffRawTrafic + jump + 5) << 8 | *(bffRawTrafic + jump + 4)) / 1e6;
                        timestampPrev = timestampPrevForward = timestampInit = timestampTemp;
                        //extraccion de ip y puertos
                        for (size_t i = 0; i < 16; i++)
                        {
                            ipv6_shost = ipv6_shost << 8 | *(bffRawTrafic + jump + 38 + i);
                            stream << std::hex << (int)(*(bffRawTrafic + jump + 38 + i));
                            ipv6_SCad += stream.str();
                            stream.str("");
                            ipv6_dhost = ipv6_dhost << 8 | *(bffRawTrafic + jump + 54 + i);
                            stream << std::hex << (int)(*(bffRawTrafic + jump + 54 + i));
                            ipv6_DCad += stream.str();
                            stream.str("");
                        }

                        ports.srcPort = *(bffRawTrafic + jump + 70) << 8 | *(bffRawTrafic + jump + 71);
                        ports.dstPort = *(bffRawTrafic + jump + 72) << 8 | *(bffRawTrafic + jump + 73);
                        //extraccion de featurs forward direccion primer paquete encontrado de la sesion a scanear
                        total_fpackets++;
                        total_fpktl = orig_len;
                        //
                        min_fpktl = orig_len;
                        //
                        max_fpktl = orig_len;
                        //
                        vector_std_fpktl.push_back(orig_len);
                        //
                        calculateFlagsForwardv6();
                        //
                        min_flowpktl = max_flowpktl = orig_len;
                        //
                        mean_flowpktl = orig_len;
                        //
                        vector_std_flowpktl.push_back(orig_len);
                        //
                        total_fhlen += (*(bffRawTrafic + jump + 74) >> 4) * 4;
                        //
                        calculateFlagsFlowv6();
                        //marca el paquete time stamp segundo en 0 para indicar que ya fue procesado ese paquete
                        mark(jump);
                        jump += orig_len + 16;
                        traficPointer = jump;
                        break;
                    }
                    for (size_t i = 0; i < 16; i++)
                    {
                        ipv6_shost_temp = ipv6_shost_temp << 8 | *(bffRawTrafic + jump + 38 + i);
                        ipv6_dhost_temp = ipv6_dhost_temp << 8 | *(bffRawTrafic + jump + 54 + i);
                    }
                    ports_temp.srcPort = *(bffRawTrafic + jump + 70) << 8 | *(bffRawTrafic + jump + 71);
                    ports_temp.dstPort = *(bffRawTrafic + jump + 72) << 8 | *(bffRawTrafic + jump + 73);
                    //timeout sesion
                    if (timestampTemp - timestampPrev > 100)
                    {
                        jump = pointerbffRawTrafic;
                        //printf("timeout\n");
                        break;
                    }
                    //check if the forward direction
                    if (ipv6_shost == ipv6_shost_temp && ipv6_dhost == ipv6_dhost_temp && ports.srcPort == ports_temp.srcPort && ports.dstPort == ports_temp.dstPort)
                    {

                        timestampTemp += (*(bffRawTrafic + jump + 7) << 24 | *(bffRawTrafic + jump + 6) << 16 | *(bffRawTrafic + jump + 5) << 8 | *(bffRawTrafic + jump + 4)) / 1e6;
                        //
                        iptTemp = timestampTemp - timestampPrev;
                        //
                        fprintf(ipts, "%.20f,", iptTemp);
                        timestampPrev = timestampTemp;
                        //extraccion de caracteristicas forward direccion
                        total_fpackets++;
                        total_fpktl += orig_len;
                        //
                        min_fpktl = orig_len < min_fpktl ? orig_len : min_fpktl;
                        max_fpktl = orig_len > max_fpktl ? orig_len : max_fpktl;
                        //
                        vector_std_fpktl.push_back(orig_len);
                        //
                        iptTemp = timestampTemp - timestampPrevForward;
                        /*                         if (!iatForwardState)
                        {
                            min_fiat = iptTemp;
                            min_flowiat = iptTemp;
                        } */
                        total_fiat += iptTemp;
                        //
                        min_fiat = iptTemp < min_fiat ? iptTemp : min_fiat;
                        //
                        max_fiat = iptTemp > max_fiat ? iptTemp : max_fiat;
                        //
                        vector_std_fiat.push_back(iptTemp);
                        //
                        calculateFlagsForwardv6();
                        //
                        min_flowpktl = orig_len < min_flowpktl ? orig_len : min_flowpktl;
                        //
                        max_flowpktl = orig_len > max_flowpktl ? orig_len : max_flowpktl;
                        //
                        mean_flowpktl += orig_len;
                        //
                        vector_std_flowpktl.push_back(orig_len);
                        //
                        min_flowiat = iptTemp < min_flowiat ? iptTemp : min_flowiat;
                        //
                        max_flowiat = iptTemp > max_flowiat ? iptTemp : max_flowiat;
                        //
                        mean_flowiat += iptTemp;
                        //
                        vector_std_flowiat.push_back(iptTemp);
                        //
                        timestampPrevForward = timestampTemp;
                        //
                        total_fhlen += (*(bffRawTrafic + jump + 74) >> 4) * 4;
                        //
                        calculateFlagsFlowv6();
                        //marcar el paquete
                        mark(jump);
                    }

                    //check if the backward direction
                    if (ipv6_dhost == ipv6_shost_temp && ipv6_shost == ipv6_dhost_temp && ports.dstPort == ports_temp.srcPort && ports.srcPort == ports_temp.dstPort)
                    {

                        timestampTemp += (*(bffRawTrafic + jump + 7) << 24 | *(bffRawTrafic + jump + 6) << 16 | *(bffRawTrafic + jump + 5) << 8 | *(bffRawTrafic + jump + 4)) / 1e6;

                        iptTemp = timestampTemp - timestampPrev;
                        fprintf(ipts, "%.20f,", iptTemp);
                        timestampPrev = timestampTemp;

                        //extraccion de caracteristicas en backward direccion
                        total_bpackets++;
                        total_bpktl += orig_len;
                        //

                        //
                        vector_std_bpktl.push_back(orig_len);
                        //
                        vector_std_flowiat.push_back(iptTemp);
                        //
                        min_flowiat = iptTemp < min_flowiat ? iptTemp : min_flowiat;
                        //
                        max_flowiat = iptTemp > max_flowiat ? iptTemp : max_flowiat;
                        //
                        mean_flowiat += iptTemp;
                        if (!iatBackwardState)
                        {
                            iatBackwardState = true;
                            timestampPrevBackware = timestampTemp;
                            min_bpktl = orig_len;
                            min_biat = timestampTemp;
                        }
                        else
                        {
                            iptTemp = timestampTemp - timestampPrevBackware;
                            //
                            total_biat += iptTemp;
                            //
                            min_biat = iptTemp < min_biat ? iptTemp : min_biat;
                            //
                            max_biat = iptTemp > max_biat ? iptTemp : max_biat;
                            //
                            vector_std_biat.push_back(iptTemp);
                        }

                        min_bpktl = orig_len < min_bpktl ? orig_len : min_bpktl;
                        max_bpktl = orig_len > max_bpktl ? orig_len : max_bpktl;
                        timestampPrevBackware = timestampTemp;
                        //
                        calculateFlagsBackwardv6();
                        //
                        min_flowpktl = orig_len < min_flowpktl ? orig_len : min_flowpktl;
                        //
                        max_flowpktl = orig_len > max_flowpktl ? orig_len : max_flowpktl;
                        //
                        mean_flowpktl += orig_len;
                        //
                        vector_std_flowpktl.push_back(orig_len);
                        //
                        total_bhlen += (*(bffRawTrafic + jump + 74) >> 4) * 4;
                        //
                        calculateFlagsFlowv6();
                        //marcar el paquete
                        mark(jump);
                    }
                }
                else
                {
                    jump += incl_leng + 16;
                    break;
                }
                jump += incl_leng + 16;
            }
        }
    }

    //  yield();
    //pthread_mutex_unlock(&mutex); //Fin SC
    //yield();
    printf("End funtion");
    return NULL;
}

void *scanFlowIpv6UDP(void *valor)
{

    //yield();
    pthread_mutex_lock(&mutex); //Inicio SC
    printf("thread->%d\n", *(int *)valor);
    resetVar();
    jump = 0;

    while (true)
    {
        //printf("primer ciclo\n");
        while (true)
        {
            //printf("segundo ciclo\n");

            //verifica si ya se recorrio todo el archivo, si es asi limpia los contadores y jump = ultima posicion de primer paquete del flojo
            if (jump >= pointerbffRawTrafic)
            {
                // printf("\nTermino scaneo\n");
                if (traficTipe == _UDP)
                {
                    //printf("fin sesion\n");
                    //guardar featurs en archivo csv
                    min_bpktl = min_bpktl == 65535 ? 0 : min_bpktl;
                    mean_fpktl = total_fpktl / ((float)total_fpackets);
                    mean_bpktl = (total_bpktl / ((float)total_bpackets));
                    //
                    min_fiat = total_fpackets > 1 ? min_fiat : 0;
                    min_biat = total_bpackets > 1 ? min_biat : 0;
                    //
                    total_fiat = total_fpackets > 1 ? total_fiat : 0;
                    total_biat = total_bpackets > 1 ? total_biat : 0;

                    //
                    mean_fiat = total_fpackets > 1 ? ((float)total_fiat) / (total_fpackets - 1) : 0;
                    mean_biat = total_bpackets > 1 ? total_biat / (total_bpackets - 1) : 0;
                    //
                    max_fiat = total_fpackets > 1 ? max_fiat : 0;
                    max_biat = total_bpackets > 1 ? max_biat : 0;
                    //
                    min_flowiat = (total_fpackets + total_bpackets) > 1 ? min_flowiat : 0;
                    max_flowiat = (total_fpackets + total_bpackets) > 1 ? max_flowiat : 0;
                    //
                    mean_flowpktl = (mean_flowpktl / (total_fpackets + total_bpackets));
                    //
                    mean_flowiat = (total_fpackets + total_bpackets - 1) > 0 ? mean_flowiat / (total_fpackets + total_bpackets - 1) : 0;
                    ;
                    //
                    calculate_std_pktl();
                    calculate_std_iat();
                    calculate_std_flowpktl();
                    calculate_std_flowiat();

                    std_flowpktl = (total_fpackets + total_bpackets) > 1 ? std_flowpktl : 0;
                    std_fpktl = total_fpackets > 1 ? std_fpktl : 0;
                    std_bpktl = total_bpackets > 1 ? std_bpktl : 0;
                    std_fiat = total_fpackets > 1 ? std_fiat : 0;
                    std_biat = total_bpackets > 1 ? std_biat : 0;
                    std_flowiat = (total_fpackets + total_bpackets) > 2 ? std_flowiat : 0;
                    mean_flowiat = (total_fpackets + total_bpackets) > 1 ? mean_flowiat : 0;
                    fprintf(csv, "UDP,%s->%s,%s,%u,%s,%u,%f,%" PRId64 ",%" PRId64 ",%" PRId64 ",%" PRId64 ",%d,%d,%d,%d,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%d,%d,%d,%d,%d,%d,%f,%f,%f,%f,%f,%f,%f,%f,%d,%d,%d,%d,%d,%d,%d,%f,%d\n",
                            ipv6_SCad.c_str(),
                            ipv6_DCad.c_str(),
                            ipv6_SCad.c_str(), ports.srcPort,
                            ipv6_DCad.c_str(), ports.dstPort,
                            timestampPrev - timestampInit,
                            total_fpackets,
                            total_bpackets,
                            total_fpktl,
                            total_bpktl,
                            min_fpktl,
                            min_bpktl,
                            max_fpktl,
                            max_bpktl,
                            mean_fpktl,
                            mean_bpktl,
                            std_fpktl,
                            std_bpktl,
                            total_fiat,
                            total_biat,
                            min_fiat,
                            min_biat,
                            max_fiat,
                            max_biat,
                            mean_fiat,
                            mean_biat,
                            std_fiat,
                            std_biat,
                            fpsh_cnt,
                            bpsh_cnt,
                            furg_cnt,
                            burg_cnt,
                            total_fhlen,
                            total_bhlen,
                            (total_fpackets / (float)(timestampPrev - timestampInit)),
                            (total_bpackets / (float)(timestampPrev - timestampInit)),
                            ((total_fpackets + total_bpackets) / (timestampPrev - timestampInit)),
                            ((total_fpktl + total_bpktl) / (timestampPrev - timestampInit)),
                            // min_flowpktl,
                            // max_flowpktl,
                            mean_flowpktl,
                            std_flowpktl,
                            // min_flowiat,
                            // max_flowiat,
                            mean_flowiat,
                            std_flowiat,
                            flow_fin,
                            flow_syn,
                            flow_rst,
                            // flow_psh,
                            flow_ack,
                            flow_urg,
                            flow_cwr,
                            flow_ece,
                            (total_bpktl / (float)total_fpktl),
                            isBadTrafic(*socket_to_String(&ipv6_SCad, &ipv6_SCad, &ports), IPV6_UDP));
                    fprintf(ipts, "\n");
                    //printf("srcport:%u",ports.srcPort);
                    //printf("No. packet TCP: %llu\n", TCP_cont);
                    //printf("Timestamp->init: %.20f\n",timestampInit);
                    //printf("Timestamp->prev: %f\n",timestampPrev);
                    //printf("resultado:%.20f\n", (timestampPrev-timestampInit));
                    //printf("total de paquete f:%d\n",total_fpackets);
                    // printf("time sesion: %f\n",(timestampPrev-timestampInit));
                }

                if (traficTipe == 0)
                {
                    //fin de scaneo de trafico
                    //printf("\nEnd program\n");
                    //printf("jump:%llu",jump);
                    printf("End program:%" PRId64 "\n", jump);
                    resetVar();
                    pthread_mutex_unlock(&mutex); //Fin SC
                    return NULL;
                }
                //limpiar varibles
                resetVar();
                if (traficPointer % 1024 == 0)
                {
                    printf("Bytes->%" PRId64 "\n", traficPointer);
                }
                jump = traficPointer;
                traficTipe = 0;
            }
            while (jump < pointerbffRawTrafic)
            {
                //printf("miestras es menor");

                //
                incl_leng = (*(bffRawTrafic + (jump + 11)) << 24 | *(bffRawTrafic + (jump + 10)) << 16 | *(bffRawTrafic + (jump + 9)) << 8 | *(bffRawTrafic + (jump + 8)));
                orig_len = (*(bffRawTrafic + (jump + 15)) << 24 | *(bffRawTrafic + (jump + 14)) << 16 | *(bffRawTrafic + (jump + 13)) << 8 | *(bffRawTrafic + (jump + 12)));
                timestampTemp = *(bffRawTrafic + jump + 3) << 24 | *(bffRawTrafic + jump + 2) << 16 | *(bffRawTrafic + jump + 1) << 8 | *(bffRawTrafic + jump);

                //busca paquetes distintos de cero
                while (timestampTemp == 0 || !((*(bffRawTrafic + (jump + 28)) << 8 | *(bffRawTrafic + (jump + 29))) == _IPV6) || !(*(bffRawTrafic + (jump + 36)) == _UDP))
                {
                    if (jump == pointerbffRawTrafic)
                    {
                        break;
                    }
                    jump += incl_leng + 16;

                    incl_leng = (*(bffRawTrafic + (jump + 11)) << 24 | *(bffRawTrafic + (jump + 10)) << 16 | *(bffRawTrafic + (jump + 9)) << 8 | *(bffRawTrafic + (jump + 8)));
                    orig_len = (*(bffRawTrafic + (jump + 15)) << 24 | *(bffRawTrafic + (jump + 14)) << 16 | *(bffRawTrafic + (jump + 13)) << 8 | *(bffRawTrafic + (jump + 12)));
                    timestampTemp = *(bffRawTrafic + jump + 3) << 24 | *(bffRawTrafic + jump + 2) << 16 | *(bffRawTrafic + jump + 1) << 8 | *(bffRawTrafic + jump);
                }

                //check if ipv6
                if ((*(bffRawTrafic + (jump + 28)) << 8 | *(bffRawTrafic + (jump + 29))) == _IPV6)
                {

                    if (!(*(bffRawTrafic + (jump + 36)) == _UDP))
                    {
                        jump += incl_leng + 16;
                        break;
                    }
                    if (!traficTipe)
                    {
                        traficTipe = *(bffRawTrafic + (jump + 36));
                        timestampTemp += (*(bffRawTrafic + jump + 7) << 24 | *(bffRawTrafic + jump + 6) << 16 | *(bffRawTrafic + jump + 5) << 8 | *(bffRawTrafic + jump + 4)) / 1e6;
                        timestampPrev = timestampPrevForward = timestampInit = timestampTemp;
                        //extraccion de ip y puertos
                        for (size_t i = 0; i < 16; i++)
                        {
                            ipv6_shost = ipv6_shost << 8 | *(bffRawTrafic + jump + 38 + i);
                            stream << std::hex << (int)(*(bffRawTrafic + jump + 38 + i));
                            ipv6_SCad += stream.str();
                            stream.str("");
                            ipv6_dhost = ipv6_dhost << 8 | *(bffRawTrafic + jump + 54 + i);
                            stream << std::hex << (int)(*(bffRawTrafic + jump + 54 + i));
                            ipv6_DCad += stream.str();
                            stream.str("");
                        }

                        ports.srcPort = *(bffRawTrafic + jump + 70) << 8 | *(bffRawTrafic + jump + 71);
                        ports.dstPort = *(bffRawTrafic + jump + 72) << 8 | *(bffRawTrafic + jump + 73);
                        //extraccion de featurs forward direccion primer paquete encontrado de la sesion a scanear
                        total_fpackets++;
                        total_fpktl = orig_len;
                        //
                        min_fpktl = orig_len;
                        //
                        max_fpktl = orig_len;
                        //
                        vector_std_fpktl.push_back(orig_len);
                        //
                        min_flowpktl = max_flowpktl = orig_len;
                        //
                        mean_flowpktl = orig_len;
                        //
                        vector_std_flowpktl.push_back(orig_len);
                        //
                        total_fhlen += *(bffRawTrafic + jump + 74) << 8 | *(bffRawTrafic + jump + 75);
                        //marca el paquete time stamp segundo en 0 para indicar que ya fue procesado ese paquete
                        mark(jump);
                        jump += incl_leng + 16;
                        traficPointer = jump;
                        break;
                    }
                    for (size_t i = 0; i < 16; i++)
                    {
                        ipv6_shost_temp = ipv6_shost_temp << 8 | *(bffRawTrafic + jump + 38 + i);
                        ipv6_dhost_temp = ipv6_dhost_temp << 8 | *(bffRawTrafic + jump + 54 + i);
                    }
                    ports_temp.srcPort = *(bffRawTrafic + jump + 70) << 8 | *(bffRawTrafic + jump + 71);
                    ports_temp.dstPort = *(bffRawTrafic + jump + 72) << 8 | *(bffRawTrafic + jump + 73);
                    //timeout sesion
                    if (timestampTemp - timestampPrev > 100)
                    {
                        jump = pointerbffRawTrafic;
                        //printf("timeout\n");
                        break;
                    }
                    //check if the forward direction
                    if (ipv6_shost == ipv6_shost_temp && ipv6_dhost == ipv6_dhost_temp && ports.srcPort == ports_temp.srcPort && ports.dstPort == ports_temp.dstPort)
                    {

                        timestampTemp += (*(bffRawTrafic + jump + 7) << 24 | *(bffRawTrafic + jump + 6) << 16 | *(bffRawTrafic + jump + 5) << 8 | *(bffRawTrafic + jump + 4)) / 1e6;
                        //
                        iptTemp = timestampTemp - timestampPrev;
                        //
                        fprintf(ipts, "%.20f,", iptTemp);
                        timestampPrev = timestampTemp;
                        //extraccion de caracteristicas forward direccion
                        total_fpackets++;
                        total_fpktl += orig_len;
                        //
                        min_fpktl = orig_len < min_fpktl ? orig_len : min_fpktl;
                        max_fpktl = orig_len > max_fpktl ? orig_len : max_fpktl;
                        //
                        vector_std_fpktl.push_back(orig_len);
                        //
                        iptTemp = timestampTemp - timestampPrevForward;
                        /*
                         if (!iatForwardState)
                        {
                            min_fiat = iptTemp;
                            min_flowiat = iptTemp;
                        } */
                        total_fiat += iptTemp;
                        //
                        min_fiat = iptTemp < min_fiat ? iptTemp : min_fiat;
                        //
                        max_fiat = iptTemp > max_fiat ? iptTemp : max_fiat;
                        //
                        vector_std_fiat.push_back(iptTemp);
                        //
                        min_flowpktl = orig_len < min_flowpktl ? orig_len : min_flowpktl;
                        //
                        max_flowpktl = orig_len > max_flowpktl ? orig_len : max_flowpktl;
                        //
                        mean_flowpktl += orig_len;
                        //
                        vector_std_flowpktl.push_back(orig_len);
                        //
                        min_flowiat = iptTemp < min_flowiat ? iptTemp : min_flowiat;
                        //
                        max_flowiat = iptTemp > max_flowiat ? iptTemp : max_flowiat;
                        //
                        mean_flowiat += iptTemp;
                        //
                        vector_std_flowiat.push_back(iptTemp);
                        //
                        timestampPrevForward = timestampTemp;
                        //
                        total_fhlen += *(bffRawTrafic + jump + 74) << 8 | *(bffRawTrafic + jump + 75);
                        //marcar el paquete
                        mark(jump);
                    }

                    //check if the backward direction
                    if (ipv6_dhost == ipv6_shost_temp && ipv6_shost == ipv6_dhost_temp && ports.dstPort == ports_temp.srcPort && ports.srcPort == ports_temp.dstPort)
                    {

                        timestampTemp += (*(bffRawTrafic + jump + 7) << 24 | *(bffRawTrafic + jump + 6) << 16 | *(bffRawTrafic + jump + 5) << 8 | *(bffRawTrafic + jump + 4)) / 1e6;

                        iptTemp = timestampTemp - timestampPrev;
                        fprintf(ipts, "%.20f,", iptTemp);
                        timestampPrev = timestampTemp;

                        //extraccion de caracteristicas en backward direccion
                        total_bpackets++;
                        total_bpktl += orig_len;
                        //

                        //
                        vector_std_bpktl.push_back(orig_len);
                        //
                        vector_std_flowiat.push_back(iptTemp);
                        //
                        min_flowiat = iptTemp < min_flowiat ? iptTemp : min_flowiat;
                        //
                        max_flowiat = iptTemp > max_flowiat ? iptTemp : max_flowiat;
                        //
                        mean_flowiat += iptTemp;
                        if (!iatBackwardState)
                        {
                            iatBackwardState = true;
                            timestampPrevBackware = timestampTemp;
                            min_bpktl = orig_len;
                            min_biat = timestampTemp;
                        }
                        else
                        {
                            iptTemp = timestampTemp - timestampPrevBackware;
                            //
                            total_biat += iptTemp;
                            //
                            min_biat = iptTemp < min_biat ? iptTemp : min_biat;
                            //
                            max_biat = iptTemp > max_biat ? iptTemp : max_biat;
                            //
                            vector_std_biat.push_back(iptTemp);
                        }

                        min_bpktl = orig_len < min_bpktl ? orig_len : min_bpktl;
                        max_bpktl = orig_len > max_bpktl ? orig_len : max_bpktl;
                        timestampPrevBackware = timestampTemp;
                        //
                        min_flowpktl = orig_len < min_flowpktl ? orig_len : min_flowpktl;
                        //
                        max_flowpktl = orig_len > max_flowpktl ? orig_len : max_flowpktl;
                        //
                        mean_flowpktl += orig_len;
                        //
                        vector_std_flowpktl.push_back(orig_len);
                        //
                        total_bhlen += *(bffRawTrafic + jump + 74) << 8 | *(bffRawTrafic + jump + 75);
                        //marcar el paquete
                        mark(jump);
                    }
                }
                else
                {
                    jump += incl_leng + 16;
                    break;
                }
                jump += incl_leng + 16;
            }
        }
    }

    //  yield();
    //pthread_mutex_unlock(&mutex); //Fin SC
    //yield();
    printf("End funtion");
    return NULL;
}