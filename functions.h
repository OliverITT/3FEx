//#include "structs.h"
#include <pthread.h>
#include <string.h>
#include "features.h"
#include <inttypes.h>
#include <math.h>
#include "scanBadTrafic.h"
#include "scanSnortLogs.h"
#include "FlowToImage.h"

FILE *raw, *csv, *ipts, *alertT, *u2_File;
uint8_t inputPriority = -1;
pthread_mutex_t mutex;
/*flag split ip's bytes per colum*/
bool sips = false;

std::string *socket_to_String(std::string *ip_dhost, std::string *ip_shost, TCPheader *ports)
{
    std::string *socket = new std::string;
    char buffer[32];
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
    char buffer[32];
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
        *it_std_fpktl -= flow->mean_fpktl;
        *it_std_fpktl = pow(*it_std_fpktl, 2);
    }
    //
    for (it_std_fpktl = vector_std_fpktl.begin(); it_std_fpktl != vector_std_fpktl.end(); ++it_std_fpktl)
    {
        std_temp += (*it_std_fpktl);
    }
    flow->std_fpktl = sqrt((std_temp / (flow->total_fpackets - 1)));
    if (flow->total_bpackets > 1)
    {
        std_temp = 0;
        for (it_std_bpktl = vector_std_bpktl.begin(); it_std_bpktl != vector_std_bpktl.end(); ++it_std_bpktl)
        {
            *it_std_bpktl -= flow->mean_bpktl;
            *it_std_bpktl = pow(*it_std_bpktl, 2);
        }
        //
        for (it_std_bpktl = vector_std_bpktl.begin(); it_std_bpktl != vector_std_bpktl.end(); ++it_std_bpktl)
        {
            std_temp += (*it_std_bpktl);
        }
        flow->std_bpktl = sqrt((std_temp / (flow->total_bpackets - 1)));
    }
}
void calculate_std_ipt()
{
    double temp_std_ipt = 0;
    for (it_std_fipt = vector_std_fipt.begin(); it_std_fipt != vector_std_fipt.end(); ++it_std_fipt)
    {
        *it_std_fipt -= flow->mean_fipt;
        *it_std_fipt = pow(*it_std_fipt, 2);
    }
    for (it_std_fipt = vector_std_fipt.begin(); it_std_fipt != vector_std_fipt.end(); ++it_std_fipt)
    {
        temp_std_ipt += *it_std_fipt;
    }
    flow->std_fipt = sqrt(temp_std_ipt / (vector_std_fipt.size() - 1));
    temp_std_ipt = 0;
    if (flow->total_bpackets > 1)
    {
        for (it_std_bipt = vector_std_bipt.begin(); it_std_bipt != vector_std_bipt.end(); ++it_std_bipt)
        {
            *it_std_bipt -= flow->mean_bipt;
            *it_std_bipt = pow(*it_std_bipt, 2);
        }
        for (it_std_bipt = vector_std_bipt.begin(); it_std_bipt != vector_std_bipt.end(); ++it_std_bipt)
        {
            temp_std_ipt += *it_std_bipt;
        }
        flow->std_bipt = sqrt(temp_std_ipt / (vector_std_bipt.size() - 1));
    }
}
void calculateFlagsFlow()
{

    if ((*(bffRawTrafic + jump + 63) & _PSH))
    {
        flow->flow_psh++;
    }
    if ((*(bffRawTrafic + jump + 63) & _URG))
    {
        flow->flow_urg++;
    }
    if ((*(bffRawTrafic + jump + 63) & _FIN))
    {
        flow->flow_fin++;
    }
    if ((*(bffRawTrafic + jump + 63) & _SYN))
    {
        flow->flow_syn++;
    }
    if ((*(bffRawTrafic + jump + 63) & _RST))
    {
        flow->flow_rst++;
    }
    if ((*(bffRawTrafic + jump + 63) & _ACK))
    {
        flow->flow_ack++;
    }
    if ((*(bffRawTrafic + jump + 63) & _CWE))
    {
        flow->flow_cwr++;
    }
    if ((*(bffRawTrafic + jump + 63) & _ECE))
    {
        flow->flow_ece++;
    }
}
//forward direction flags
void calculateFlagsForward()
{

    if ((*(bffRawTrafic + jump + 63) & _PSH))
    {
        flow->fpsh_cnt++;
    }
    if ((*(bffRawTrafic + jump + 63) & _URG))
    {
        flow->furg_cnt++;
    }
}
//backward direction flags
void calculateFlagsBackward()
{
    if ((*(bffRawTrafic + jump + 63) & _PSH))
    {
        flow->bpsh_cnt++;
    }
    if ((*(bffRawTrafic + jump + 63) & _URG))
    {
        flow->burg_cnt++;
    }
}

void calculateFlagsFlowv6()
{

    if ((*(bffRawTrafic + jump + 83) & _PSH))
    {
        flow->flow_psh++;
    }
    if ((*(bffRawTrafic + jump + 83) & _URG))
    {
        flow->flow_urg++;
    }
    if ((*(bffRawTrafic + jump + 83) & _FIN))
    {
        flow->flow_fin++;
    }
    if ((*(bffRawTrafic + jump + 83) & _SYN))
    {
        flow->flow_syn++;
    }
    if ((*(bffRawTrafic + jump + 83) & _RST))
    {
        flow->flow_rst++;
    }
    if ((*(bffRawTrafic + jump + 83) & _ACK))
    {
        flow->flow_ack++;
    }
    if ((*(bffRawTrafic + jump + 83) & _CWE))
    {
        flow->flow_cwr++;
    }
    if ((*(bffRawTrafic + jump + 83) & _ECE))
    {
        flow->flow_ece++;
    }
}
//forward direction flags
void calculateFlagsForwardv6()
{

    if ((*(bffRawTrafic + jump + 83) & _PSH))
    {
        flow->fpsh_cnt++;
    }
    if ((*(bffRawTrafic + jump + 83) & _URG))
    {
        flow->furg_cnt++;
    }
}
//backward direction flags
void calculateFlagsBackwardv6()
{
    if ((*(bffRawTrafic + jump + 83) & _PSH))
    {
        flow->bpsh_cnt++;
    }
    if ((*(bffRawTrafic + jump + 83) & _URG))
    {
        flow->burg_cnt++;
    }
}
void calculate_std_flowpktl()
{
    //vector_std_flowpktl
    double temp_std_ = 0;
    for (it_std_flowpktl = vector_std_flowpktl.begin(); it_std_flowpktl != vector_std_flowpktl.end(); ++it_std_flowpktl)
    {
        *it_std_flowpktl -= flow->mean_flowpktl;
        *it_std_flowpktl = pow(*it_std_flowpktl, 2);
    }
    for (it_std_flowpktl = vector_std_flowpktl.begin(); it_std_flowpktl != vector_std_flowpktl.end(); ++it_std_flowpktl)
    {
        temp_std_ += *it_std_flowpktl;
    }
    flow->std_flowpktl = sqrt(temp_std_ / (vector_std_flowpktl.size() - 1));
}

void calculate_std_flowipt()
{
    std::vector<float>::iterator it_temp1;
    double temp_std_ = 0;
    for (it_temp1 = vector_std_flowipt.begin(); it_temp1 != vector_std_flowipt.end(); ++it_temp1)
    {
        *it_temp1 -= flow->mean_flowipt;
        *it_temp1 = pow(*it_temp1, 2);
    }
    for (it_temp1 = vector_std_flowipt.begin(); it_temp1 != vector_std_flowipt.end(); ++it_temp1)
    {
        temp_std_ += *it_temp1;
    }
    flow->std_flowipt = sqrt(temp_std_ / (vector_std_flowipt.size() - 1));
}
void *scanFlowIpv4TCP(void *valor)
{
    //yield();
    pthread_mutex_lock(&mutex); //Inicio SC
    printf("thread->%d\n", *(int *)valor);
    flow = new Flow();
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
                    flow->min_bpktl = flow->min_bpktl == 65535 ? 0 : flow->min_bpktl;
                    flow->mean_fpktl = flow->total_fpackets > 0 ? flow->total_fpktl / ((float)flow->total_fpackets) : 0;
                    flow->mean_bpktl = flow->total_bpackets > 0 ? (flow->total_bpktl / ((float)flow->total_bpackets)) : 0;
                    //
                    flow->min_fipt = flow->total_fpackets > 1 ? flow->min_fipt : 0;
                    flow->min_bipt = flow->total_bpackets > 1 ? flow->min_bipt : 0;
                    //
                    flow->total_fipt = flow->total_fpackets > 1 ? flow->total_fipt : 0;
                    flow->total_bipt = flow->total_bpackets > 1 ? flow->total_bipt : 0;

                    //
                    flow->mean_fipt = flow->total_fpackets > 1 ? ((float)flow->total_fipt) / (flow->total_fpackets - 1) : 0;
                    flow->mean_bipt = flow->total_bpackets > 1 ? flow->total_bipt / (flow->total_bpackets - 1) : 0;
                    //
                    flow->max_fipt = flow->total_fpackets > 1 ? flow->max_fipt : 0;
                    flow->max_bipt = flow->total_bpackets > 1 ? flow->max_bipt : 0;
                    //
                    min_flowipt = (flow->total_fpackets + flow->total_bpackets) > 1 ? min_flowipt : 0;
                    max_flowipt = (flow->total_fpackets + flow->total_bpackets) > 1 ? max_flowipt : 0;
                    //
                    flow->mean_flowpktl = (flow->mean_flowpktl / (flow->total_fpackets + flow->total_bpackets));
                    //
                    flow->mean_flowipt = (flow->total_fpackets + flow->total_bpackets - 1) > 0 ? flow->mean_flowipt / (flow->total_fpackets + flow->total_bpackets - 1) : 0;
                    //
                    calculate_std_pktl();
                    calculate_std_ipt();
                    calculate_std_flowpktl();
                    calculate_std_flowipt();

                    flow->std_flowpktl = (flow->total_fpackets + flow->total_bpackets) > 1 ? flow->std_flowpktl : 0;
                    flow->std_fpktl = flow->total_fpackets > 1 ? flow->std_fpktl : 0;
                    flow->std_bpktl = flow->total_bpackets > 1 ? flow->std_bpktl : 0;
                    flow->std_fipt = flow->total_fpackets > 2 ? flow->std_fipt : 0;
                    flow->std_bipt = flow->total_bpackets > 2 ? flow->std_bipt : 0;
                    flow->std_flowipt = (flow->total_fpackets + flow->total_bpackets) > 2 ? flow->std_flowipt : 0;
                    flow->mean_flowipt = (flow->total_fpackets + flow->total_bpackets) > 1 ? flow->mean_flowipt : 0;
                    //
                    flow->fduration = timestampPrev - flow->timestamp;

                    flow->fPktsPerSecond = (timestampPrev - flow->timestamp) > 0 && flow->total_fpackets > 0 ? (flow->total_fpackets / (float)(timestampPrev - flow->timestamp)) : 0;                                               // Number of forward packets per second
                    flow->bPktsPerSecond = flow->total_bpackets > 0 && (timestampPrev - flow->timestamp) > 0 ? (flow->total_bpackets / (timestampPrev - flow->timestamp)) : 0;                                                      // Number of backward packets per second
//                    flow->flowPktsPerSecond = (flow->total_fpackets + flow->total_bpackets) > 0 && (timestampPrev - flow->timestamp) > 0 ? ((flow->total_fpackets + flow->total_bpackets) / (timestampPrev - flow->timestamp)) : 0; // Number of flow packets per second
                    flow->flowBytesPerSecond = (flow->total_fpktl + flow->total_bpktl) > 0 && (timestampPrev - flow->timestamp) > 0 ? ((flow->total_fpktl + flow->total_bpktl) / (timestampPrev - flow->timestamp)) : 0;            // Number of flow bytes per second*
                    flow->downUpRation = (flow->total_bpktl / (float)flow->total_fpktl);
                    fprintf(csv, "TCP,%f,", flow->timestamp);
                    if (sips)
                    {
                        fprintf(csv, "%d,%d,%d,%d,%u,%d,%d,%d,%d,%u,",
                                flow->ip_shost >> 24, (flow->ip_shost >> 16) & 0x0ff, (flow->ip_shost >> 8) & 0x0ff, (flow->ip_shost) & 0x0ff, ports.srcPort,
                                flow->ip_dhost >> 24, (flow->ip_dhost >> 16) & 0x0ff, (flow->ip_dhost >> 8) & 0x0ff, (flow->ip_dhost) & 0x0ff, ports.dstPort);
                    }
                    else
                    {
                        fprintf(csv, "%d.%d.%d.%d,%u,%d.%d.%d.%d,%u,",
                                flow->ip_shost >> 24, (flow->ip_shost >> 16) & 0x0ff, (flow->ip_shost >> 8) & 0x0ff, (flow->ip_shost) & 0x0ff, ports.srcPort,
                                flow->ip_dhost >> 24, (flow->ip_dhost >> 16) & 0x0ff, (flow->ip_dhost >> 8) & 0x0ff, (flow->ip_dhost) & 0x0ff, ports.dstPort);
                    }
                    fprintf(csv, "%f,%" PRId64 ",%" PRId64 ",%" PRId64 ",%" PRId64 ",%d,%d,%d,%d,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%d,%d,%d,%d,%d,%d,%f,%f,%f,%f,%f,%f,%f,%d,%d,%d,%d,%d,%d,%d,%f",
                            flow->fduration,
                            flow->total_fpackets,
                            flow->total_bpackets,
                            flow->total_fpktl,
                            flow->total_bpktl,
                            flow->min_fpktl,
                            flow->min_bpktl,
                            flow->max_fpktl,
                            flow->max_bpktl,
                            flow->mean_fpktl,
                            flow->mean_bpktl,
                            flow->std_fpktl,
                            flow->std_bpktl,
                            flow->total_fipt,
                            flow->total_bipt,
                            flow->min_fipt,
                            flow->min_bipt,
                            flow->max_fipt,
                            flow->max_bipt,
                            flow->mean_fipt,
                            flow->mean_bipt,
                            flow->std_fipt,
                            flow->std_bipt,
                            flow->fpsh_cnt,
                            flow->bpsh_cnt,
                            flow->furg_cnt,
                            flow->burg_cnt,
                            flow->total_fhlen,
                            flow->total_bhlen,
                            flow->fPktsPerSecond,
                            flow->bPktsPerSecond,
//                            flow->flowPktsPerSecond,
                            flow->flowBytesPerSecond,
                            // min_flowpktl,
                            // max_flowpktl,
                            flow->mean_flowpktl,
                            flow->std_flowpktl,
                            // min_flowipt,
                            // max_flowipt,
                            flow->mean_flowipt,
                            flow->std_flowipt,
                            flow->flow_fin,
                            flow->flow_syn,
                            flow->flow_rst,
                            // flow->flow_psh,
                            flow->flow_ack,
                            flow->flow_urg,
                            flow->flow_cwr,
                            flow->flow_ece,
                            flow->downUpRation);

                    if (alertT)
                    {
                        flow->priority = (int)isBadTrafic(*socket_to_String(&flow->ip_dhost, &flow->ip_shost, &ports), IPV4_TCP);
                        fprintf(csv, ",%d", flow->priority);
                    }
                    if (u2_File)
                    {
                        int priority = getPriority(*socket_to_String(&flow->ip_dhost, &flow->ip_shost, &ports), 0x6);
                        flow->priority = priority <= inputPriority ? priority : 0;
                        if (flow->priority)
                        {
                            flow->classification = getClassification(*socket_to_String(&flow->ip_dhost, &flow->ip_shost, &ports), 0x6);
                        }
                        fprintf(csv, ",%d,%d", flow->priority, flow->classification);
                    }
                    fprintf(csv, "\n");
                    if (ipts)
                    {
                        fprintf(ipts, "\n");
                    }
                    flow->protocol = _TCP;
                    flow->dstPort = ports.dstPort;
                    flow->srcPort = ports.srcPort;
                    if (flowsPerImage)
                    {
                        addFlowToImage();
                    }
                    //printf("No. packet TCP: %llu\n", TCP_cont);
                    //printf("Timestamp%f\n",flow->timestamp);
                    //printf("Timestamp%f\n",timestampPrev);
                    // printf("time sesion: %f\n",(timestampPrev-flow->timestamp));
                }

                if (traficTipe == 0)
                {
                    //fin de scaneo de trafico
                    //printf("\nEnd program\n");
                    //printf("jump:%llu",jump);
                    //printf("End program:%" PRId64 "\n", jump);
                    flow = new Flow();
                    resetVar();
                    pthread_mutex_unlock(&mutex); //Fin SC
                    return NULL;
                }
                //limpiar varibles
                flow = new Flow();
                resetVar();
                if (traficPointer % 1024 == 0)
                {
                    printf("\rBytes->%" PRId64 "", traficPointer);
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
                        timestampPrev = timestampPrevForward = flow->timestamp = timestampTemp;
                        //extraccion de ip y puertos
                        flow->ip_shost = *(bffRawTrafic + jump + 42) << 24 | *(bffRawTrafic + jump + 43) << 16 | *(bffRawTrafic + jump + 44) << 8 | *(bffRawTrafic + jump + 45);
                        flow->ip_dhost = *(bffRawTrafic + jump + 46) << 24 | *(bffRawTrafic + jump + 47) << 16 | *(bffRawTrafic + jump + 48) << 8 | *(bffRawTrafic + jump + 49);
                        ports.srcPort = *(bffRawTrafic + jump + 50) << 8 | *(bffRawTrafic + jump + 51);
                        ports.dstPort = *(bffRawTrafic + jump + 52) << 8 | *(bffRawTrafic + jump + 53);
                        //extraccion de featurs forward direccion primer paquete encontrado de la sesion a scanear
                        flow->total_fpackets++;
                        flow->total_fpktl = orig_len;
                        //
                        flow->min_fpktl = orig_len;
                        //
                        flow->max_fpktl = orig_len;
                        //
                        vector_std_fpktl.push_back(orig_len);
                        //
                        calculateFlagsForward();
                        //
                        min_flowpktl = max_flowpktl = orig_len;
                        //
                        flow->mean_flowpktl = orig_len;
                        //
                        vector_std_flowpktl.push_back(orig_len);
                        //
                        flow->total_fhlen += (*(bffRawTrafic + jump + 62) >> 4) * 4;
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
                    if (flow->ip_shost == ip_shost_temp && flow->ip_dhost == ip_dhost_temp && ports.srcPort == ports_temp.srcPort && ports.dstPort == ports_temp.dstPort)
                    {

                        timestampTemp += (*(bffRawTrafic + jump + 7) << 24 | *(bffRawTrafic + jump + 6) << 16 | *(bffRawTrafic + jump + 5) << 8 | *(bffRawTrafic + jump + 4)) / 1e6;
                        //
                        iptTemp = (float)(timestampTemp - timestampPrev);
                        //
                        if (ipts)
                        {
                            fprintf(ipts, "%.20f,", iptTemp);
                        }
                        timestampPrev = timestampTemp;

                        //extraccion de caracteristicas forward direccion
                        flow->total_fpackets++;
                        flow->total_fpktl += orig_len;
                        //
                        flow->min_fpktl = orig_len < flow->min_fpktl ? orig_len : flow->min_fpktl;
                        flow->max_fpktl = orig_len > flow->max_fpktl ? orig_len : flow->max_fpktl;
                        //
                        vector_std_fpktl.push_back(orig_len);
                        //
                        iptTemp = timestampTemp - timestampPrevForward;
                        /* if (!iptForwardState)
                        {
                            flow->min_fipt = iptTemp;
                            min_flowipt = iptTemp;
                            printf("if_flow->min_fipt\t%f\n",flow->min_fipt);
                        } */
                        flow->total_fipt += iptTemp;
                        //
                        flow->min_fipt = iptTemp < flow->min_fipt ? iptTemp : flow->min_fipt;
                        //
                        flow->max_fipt = iptTemp > flow->max_fipt ? iptTemp : flow->max_fipt;
                        //
                        vector_std_fipt.push_back(iptTemp);
                        //
                        calculateFlagsForward();
                        //
                        min_flowpktl = orig_len < min_flowpktl ? orig_len : min_flowpktl;
                        //
                        max_flowpktl = orig_len > max_flowpktl ? orig_len : max_flowpktl;
                        //
                        flow->mean_flowpktl += orig_len;
                        //
                        vector_std_flowpktl.push_back(orig_len);
                        //
                        min_flowipt = iptTemp < min_flowipt ? iptTemp : min_flowipt;
                        //
                        max_flowipt = iptTemp > max_flowipt ? iptTemp : max_flowipt;
                        //
                        flow->mean_flowipt += iptTemp;
                        //
                        vector_std_flowipt.push_back(iptTemp);
                        //
                        timestampPrevForward = timestampTemp;
                        //
                        flow->total_fhlen += (*(bffRawTrafic + jump + 62) >> 4) * 4;
                        //
                        calculateFlagsFlow();
                        //marcar el paquete
                        mark(jump);
                    }

                    //check if the backward direction
                    if (flow->ip_shost == ip_dhost_temp && flow->ip_dhost == ip_shost_temp && ports.srcPort == ports_temp.dstPort && ports.dstPort == ports_temp.srcPort)
                    {

                        timestampTemp += (*(bffRawTrafic + jump + 7) << 24 | *(bffRawTrafic + jump + 6) << 16 | *(bffRawTrafic + jump + 5) << 8 | *(bffRawTrafic + jump + 4)) / 1e6;

                        iptTemp = timestampTemp - timestampPrev;
                        if (ipts)
                        {
                            fprintf(ipts, "%.20f,", iptTemp);
                        }
                        timestampPrev = timestampTemp;

                        //extraccion de caracteristicas en backward direccion
                        flow->total_bpackets++;
                        flow->total_bpktl += orig_len;
                        //

                        //
                        vector_std_bpktl.push_back(orig_len);
                        //
                        vector_std_flowipt.push_back(iptTemp);
                        //
                        min_flowipt = iptTemp < min_flowipt ? iptTemp : min_flowipt;
                        //
                        max_flowipt = iptTemp > max_flowipt ? iptTemp : max_flowipt;
                        //
                        flow->mean_flowipt += iptTemp;
                        if (!iptBackwardState)
                        {
                            iptBackwardState = true;
                            timestampPrevBackware = timestampTemp;
                            flow->min_bpktl = orig_len;
                            flow->min_bipt = timestampTemp;
                        }
                        else
                        {
                            iptTemp = timestampTemp - timestampPrevBackware;
                            //
                            flow->total_bipt += iptTemp;
                            //
                            flow->min_bipt = iptTemp < flow->min_bipt ? iptTemp : flow->min_bipt;
                            //
                            flow->max_bipt = iptTemp > flow->max_bipt ? iptTemp : flow->max_bipt;
                            //
                            vector_std_bipt.push_back(iptTemp);
                        }

                        flow->min_bpktl = orig_len < flow->min_bpktl ? orig_len : flow->min_bpktl;
                        flow->max_bpktl = orig_len > flow->max_bpktl ? orig_len : flow->max_bpktl;
                        timestampPrevBackware = timestampTemp;
                        //
                        calculateFlagsBackward();
                        //
                        min_flowpktl = orig_len < min_flowpktl ? orig_len : min_flowpktl;
                        //
                        max_flowpktl = orig_len > max_flowpktl ? orig_len : max_flowpktl;
                        //
                        flow->mean_flowpktl += orig_len;
                        //
                        vector_std_flowpktl.push_back(orig_len);
                        //
                        flow->total_bhlen += (*(bffRawTrafic + jump + 62) >> 4) * 4;
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
    flow = new Flow();
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
                    flow->min_bpktl = flow->min_bpktl == 65535 ? 0 : flow->min_bpktl;
                    flow->mean_fpktl = flow->total_fpackets > 0 ? flow->total_fpktl / ((float)flow->total_fpackets) : 0;
                    flow->mean_bpktl = flow->total_bpackets > 0 ? (flow->total_bpktl / ((float)flow->total_bpackets)) : 0;
                    //
                    flow->min_fipt = flow->total_fpackets > 1 ? flow->min_fipt : 0;
                    flow->min_bipt = flow->total_bpackets > 1 ? flow->min_bipt : 0;
                    //
                    flow->total_fipt = flow->total_fpackets > 1 ? flow->total_fipt : 0;
                    flow->total_bipt = flow->total_bpackets > 1 ? flow->total_bipt : 0;

                    //
                    flow->mean_fipt = flow->total_fpackets > 1 ? ((float)flow->total_fipt) / (flow->total_fpackets - 1) : 0;
                    flow->mean_bipt = flow->total_bpackets > 1 ? flow->total_bipt / (flow->total_bpackets - 1) : 0;
                    //
                    flow->max_fipt = flow->total_fpackets > 1 ? flow->max_fipt : 0;
                    flow->max_bipt = flow->total_bpackets > 1 ? flow->max_bipt : 0;
                    //
                    min_flowipt = (flow->total_fpackets + flow->total_bpackets) > 1 ? min_flowipt : 0;
                    max_flowipt = (flow->total_fpackets + flow->total_bpackets) > 1 ? max_flowipt : 0;
                    //
                    flow->mean_flowpktl = (flow->mean_flowpktl / (flow->total_fpackets + flow->total_bpackets));
                    //
                    flow->mean_flowipt = (flow->total_fpackets + flow->total_bpackets - 1) > 0 ? flow->mean_flowipt / (flow->total_fpackets + flow->total_bpackets - 1) : 0;
                    ;
                    //
                    calculate_std_pktl();
                    calculate_std_ipt();
                    calculate_std_flowpktl();
                    calculate_std_flowipt();

                    flow->std_flowpktl = (flow->total_fpackets + flow->total_bpackets) > 1 ? flow->std_flowpktl : 0;
                    flow->std_fpktl = flow->total_fpackets > 1 ? flow->std_fpktl : 0;
                    flow->std_bpktl = flow->total_bpackets > 1 ? flow->std_bpktl : 0;
                    flow->std_fipt = flow->total_fpackets > 2 ? flow->std_fipt : 0;
                    flow->std_bipt = flow->total_bpackets > 2 ? flow->std_bipt : 0;
                    flow->std_flowipt = (flow->total_fpackets + flow->total_bpackets) > 2 ? flow->std_flowipt : 0;
                    flow->mean_flowipt = (flow->total_fpackets + flow->total_bpackets) > 1 ? flow->mean_flowipt : 0;
                    //
                    flow->fduration = timestampPrev - flow->timestamp;

                    flow->fPktsPerSecond = (timestampPrev - flow->timestamp) > 0 && flow->total_fpackets > 0 ? (flow->total_fpackets / (float)(timestampPrev - flow->timestamp)) : 0;                                               // Number of forward packets per second
                    flow->bPktsPerSecond = flow->total_bpackets > 0 && (timestampPrev - flow->timestamp) > 0 ? (flow->total_bpackets / (timestampPrev - flow->timestamp)) : 0;                                                      // Number of backward packets per second
//                    flow->flowPktsPerSecond = (flow->total_fpackets + flow->total_bpackets) > 0 && (timestampPrev - flow->timestamp) > 0 ? ((flow->total_fpackets + flow->total_bpackets) / (timestampPrev - flow->timestamp)) : 0; // Number of flow packets per second
                    flow->flowBytesPerSecond = (flow->total_fpktl + flow->total_bpktl) > 0 && (timestampPrev - flow->timestamp) > 0 ? ((flow->total_fpktl + flow->total_bpktl) / (timestampPrev - flow->timestamp)) : 0;
                    flow->downUpRation = (flow->total_bpktl / (float)flow->total_fpktl);
                    fprintf(csv, "UDP,%f,", flow->timestamp);
                    if (sips)
                    {
                        fprintf(csv, "%d,%d,%d,%d,%u,%d,%d,%d,%d,%u,",
                                flow->ip_shost >> 24, (flow->ip_shost >> 16) & 0x0ff, (flow->ip_shost >> 8) & 0x0ff, (flow->ip_shost) & 0x0ff, ports.srcPort,
                                flow->ip_dhost >> 24, (flow->ip_dhost >> 16) & 0x0ff, (flow->ip_dhost >> 8) & 0x0ff, (flow->ip_dhost) & 0x0ff, ports.dstPort);
                    }
                    else
                    {
                        fprintf(csv, "%d.%d.%d.%d,%u,%d.%d.%d.%d,%u,",
                                flow->ip_shost >> 24, (flow->ip_shost >> 16) & 0x0ff, (flow->ip_shost >> 8) & 0x0ff, (flow->ip_shost) & 0x0ff, ports.srcPort,
                                flow->ip_dhost >> 24, (flow->ip_dhost >> 16) & 0x0ff, (flow->ip_dhost >> 8) & 0x0ff, (flow->ip_dhost) & 0x0ff, ports.dstPort);
                    }
                    fprintf(csv, "%f,%" PRId64 ",%" PRId64 ",%" PRId64 ",%" PRId64 ",%d,%d,%d,%d,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%d,%d,%d,%d,%d,%d,%f,%f,%f,%f,%f,%f,%f,%d,%d,%d,%d,%d,%d,%d,%f",
                            flow->fduration,
                            flow->total_fpackets,
                            flow->total_bpackets,
                            flow->total_fpktl,
                            flow->total_bpktl,
                            flow->min_fpktl,
                            flow->min_bpktl,
                            flow->max_fpktl,
                            flow->max_bpktl,
                            flow->mean_fpktl,
                            flow->mean_bpktl,
                            flow->std_fpktl,
                            flow->std_bpktl,
                            flow->total_fipt,
                            flow->total_bipt,
                            flow->min_fipt,
                            flow->min_bipt,
                            flow->max_fipt,
                            flow->max_bipt,
                            flow->mean_fipt,
                            flow->mean_bipt,
                            flow->std_fipt,
                            flow->std_bipt,
                            flow->fpsh_cnt,
                            flow->bpsh_cnt,
                            flow->furg_cnt,
                            flow->burg_cnt,
                            flow->total_fhlen,
                            flow->total_bhlen,
                            flow->fPktsPerSecond,
                            flow->bPktsPerSecond,
//                            flow->flowPktsPerSecond,
                            flow->flowBytesPerSecond,
                            // min_flowpktl,
                            // max_flowpktl,
                            flow->mean_flowpktl,
                            flow->std_flowpktl,
                            // min_flowipt,
                            // max_flowipt,
                            flow->mean_flowipt,
                            flow->std_flowipt,
                            flow->flow_fin,
                            flow->flow_syn,
                            flow->flow_rst,
                            //flow->flow_psh,
                            flow->flow_ack,
                            flow->flow_urg,
                            flow->flow_cwr,
                            flow->flow_ece,
                            flow->downUpRation);
                    if (alertT)
                    {
                        flow->priority = isBadTrafic(*socket_to_String(&flow->ip_dhost, &flow->ip_shost, &ports), IPV4_UDP);
                        fprintf(csv, ",%d", flow->priority);
                    }
                    if (u2_File)
                    {
                        int priority = getPriority(*socket_to_String(&flow->ip_dhost, &flow->ip_shost, &ports), 0x11);
                        flow->priority = priority <= inputPriority ? priority : 0;
                        if (flow->priority)
                        {
                            flow->classification = getClassification(*socket_to_String(&flow->ip_dhost, &flow->ip_shost, &ports), 0x11);
                        }
                        fprintf(csv, ",%d,%d", flow->priority, flow->classification);
                    }
                    fprintf(csv, "\n");
                    if (ipts)
                    {
                        fprintf(ipts, "\n");
                    }
                    flow->protocol = _UDP;
                    flow->dstPort = ports.dstPort;
                    flow->srcPort = ports.srcPort;
                    if (flowsPerImage)
                    {
                        addFlowToImage();
                    }
                    //printf("srcport:%u",ports.srcPort);
                    //printf("No. packet TCP: %llu\n", TCP_cont);
                    //printf("Timestamp%f\n",flow->timestamp);
                    //printf("Timestamp%f\n",timestampPrev);
                    // printf("time sesion: %f\n",(timestampPrev-flow->timestamp));
                }

                if (traficTipe == 0)
                {
                    //fin de scaneo de trafico
                    //printf("\nEnd program\n");
                    //printf("jump:%llu",jump);
                    //printf("End program:%" PRId64 "\n", jump);
                    resetVar();
                    flow = new Flow();
                    pthread_mutex_unlock(&mutex); //Fin SC
                    return NULL;
                }
                //limpiar varibles
                resetVar();
                flow = new Flow();
                if (traficPointer % 1024 == 0)
                {
                    printf("\rBytes->%" PRId64 "", traficPointer);
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
                        timestampPrev = timestampPrevForward = flow->timestamp = timestampTemp;
                        //extraccion de ip y puertos
                        flow->ip_shost = *(bffRawTrafic + jump + 42) << 24 | *(bffRawTrafic + jump + 43) << 16 | *(bffRawTrafic + jump + 44) << 8 | *(bffRawTrafic + jump + 45);
                        flow->ip_dhost = *(bffRawTrafic + jump + 46) << 24 | *(bffRawTrafic + jump + 47) << 16 | *(bffRawTrafic + jump + 48) << 8 | *(bffRawTrafic + jump + 49);
                        ports.srcPort = *(bffRawTrafic + jump + 50) << 8 | *(bffRawTrafic + jump + 51);
                        ports.dstPort = *(bffRawTrafic + jump + 52) << 8 | *(bffRawTrafic + jump + 53);
                        //extraccion de featurs forward direccion primer paquete encontrado de la sesion a scanear
                        flow->total_fpackets++;
                        flow->total_fpktl = orig_len;
                        //
                        flow->min_fpktl = orig_len;
                        //
                        flow->max_fpktl = orig_len;
                        //
                        vector_std_fpktl.push_back(orig_len);
                        //
                        //
                        min_flowpktl = max_flowpktl = orig_len;
                        //
                        flow->mean_flowpktl = orig_len;
                        //
                        vector_std_flowpktl.push_back(orig_len);
                        //
                        flow->total_fhlen += *(bffRawTrafic + jump + 54) << 8 | *(bffRawTrafic + jump + 55);
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
                    if (flow->ip_shost == ip_shost_temp && flow->ip_dhost == ip_dhost_temp && ports.srcPort == ports_temp.srcPort && ports.dstPort == ports_temp.dstPort)
                    {

                        timestampTemp += (*(bffRawTrafic + jump + 7) << 24 | *(bffRawTrafic + jump + 6) << 16 | *(bffRawTrafic + jump + 5) << 8 | *(bffRawTrafic + jump + 4)) / 1e6;
                        //
                        iptTemp = timestampTemp - timestampPrev;
                        //
                        if (ipts)
                        {
                            fprintf(ipts, "%.20f,", iptTemp);
                        }
                        timestampPrev = timestampTemp;

                        //extraccion de caracteristicas forward direccion
                        flow->total_fpackets++;
                        flow->total_fpktl += orig_len;
                        //
                        flow->min_fpktl = orig_len < flow->min_fpktl ? orig_len : flow->min_fpktl;
                        flow->max_fpktl = orig_len > flow->max_fpktl ? orig_len : flow->max_fpktl;
                        //
                        vector_std_fpktl.push_back(orig_len);
                        //
                        iptTemp = timestampTemp - timestampPrevForward;
                        /*     if (!iptForwardState)
                        {
                            flow->min_fipt = iptTemp;
                            min_flowipt = iptTemp;
                        } */
                        flow->total_fipt += iptTemp;
                        //
                        flow->min_fipt = iptTemp < flow->min_fipt ? iptTemp : flow->min_fipt;
                        //
                        flow->max_fipt = iptTemp > flow->max_fipt ? iptTemp : flow->max_fipt;
                        //
                        vector_std_fipt.push_back(iptTemp);
                        //
                        //
                        min_flowpktl = orig_len < min_flowpktl ? orig_len : min_flowpktl;
                        //
                        max_flowpktl = orig_len > max_flowpktl ? orig_len : max_flowpktl;
                        //
                        flow->mean_flowpktl += orig_len;
                        //
                        vector_std_flowpktl.push_back(orig_len);
                        //
                        min_flowipt = iptTemp < min_flowipt ? iptTemp : min_flowipt;
                        //
                        max_flowipt = iptTemp > max_flowipt ? iptTemp : max_flowipt;
                        //
                        flow->mean_flowipt += iptTemp;
                        //
                        vector_std_flowipt.push_back(iptTemp);
                        //
                        timestampPrevForward = timestampTemp;
                        //
                        flow->total_fhlen += *(bffRawTrafic + jump + 54) << 8 | *(bffRawTrafic + jump + 55);
                        //marcar el paquete
                        mark(jump);
                    }

                    //check if the backward direction
                    if (flow->ip_shost == ip_dhost_temp && flow->ip_dhost == ip_shost_temp && ports.srcPort == ports_temp.dstPort && ports.dstPort == ports_temp.srcPort)
                    {

                        timestampTemp += (*(bffRawTrafic + jump + 7) << 24 | *(bffRawTrafic + jump + 6) << 16 | *(bffRawTrafic + jump + 5) << 8 | *(bffRawTrafic + jump + 4)) / 1e6;

                        iptTemp = timestampTemp - timestampPrev;
                        if (ipts)
                        {
                            fprintf(ipts, "%.20f,", iptTemp);
                        }
                        timestampPrev = timestampTemp;

                        //extraccion de caracteristicas en backward direccion
                        flow->total_bpackets++;
                        flow->total_bpktl += orig_len;
                        //

                        //
                        vector_std_bpktl.push_back(orig_len);
                        //
                        vector_std_flowipt.push_back(iptTemp);
                        //
                        min_flowipt = iptTemp < min_flowipt ? iptTemp : min_flowipt;
                        //
                        max_flowipt = iptTemp > max_flowipt ? iptTemp : max_flowipt;
                        //
                        flow->mean_flowipt += iptTemp;
                        if (!iptBackwardState)
                        {
                            iptBackwardState = true;
                            timestampPrevBackware = timestampTemp;
                            flow->min_bpktl = orig_len;
                            flow->min_bipt = timestampTemp;
                        }
                        else
                        {
                            iptTemp = timestampTemp - timestampPrevBackware;
                            //
                            flow->total_bipt += iptTemp;
                            //
                            flow->min_bipt = iptTemp < flow->min_bipt ? iptTemp : flow->min_bipt;
                            //
                            flow->max_bipt = iptTemp > flow->max_bipt ? iptTemp : flow->max_bipt;
                            //
                            vector_std_bipt.push_back(iptTemp);
                        }

                        flow->min_bpktl = orig_len < flow->min_bpktl ? orig_len : flow->min_bpktl;
                        flow->max_bpktl = orig_len > flow->max_bpktl ? orig_len : flow->max_bpktl;
                        timestampPrevBackware = timestampTemp;
                        //
                        //
                        min_flowpktl = orig_len < min_flowpktl ? orig_len : min_flowpktl;
                        //
                        max_flowpktl = orig_len > max_flowpktl ? orig_len : max_flowpktl;
                        //
                        flow->mean_flowpktl += orig_len;
                        //
                        vector_std_flowpktl.push_back(orig_len);
                        //
                        flow->total_bhlen += *(bffRawTrafic + jump + 54) << 8 | *(bffRawTrafic + jump + 55);
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
    flow = new Flow();
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
                    flow->min_bpktl = flow->min_bpktl == 65535 ? 0 : flow->min_bpktl;
                    flow->mean_fpktl = flow->total_fpackets > 0 ? flow->total_fpktl / ((float)flow->total_fpackets) : 0;
                    flow->mean_bpktl = flow->total_bpackets > 0 ? (flow->total_bpktl / ((float)flow->total_bpackets)) : 0;
                    //
                    flow->min_fipt = flow->total_fpackets > 1 ? flow->min_fipt : 0;
                    flow->min_bipt = flow->total_bpackets > 1 ? flow->min_bipt : 0;
                    //
                    flow->total_fipt = flow->total_fpackets > 1 ? flow->total_fipt : 0;
                    flow->total_bipt = flow->total_bpackets > 1 ? flow->total_bipt : 0;

                    //
                    flow->mean_fipt = flow->total_fpackets > 1 ? ((float)flow->total_fipt) / (flow->total_fpackets - 1) : 0;
                    flow->mean_bipt = flow->total_bpackets > 1 ? flow->total_bipt / (flow->total_bpackets - 1) : 0;
                    //
                    flow->max_fipt = flow->total_fpackets > 1 ? flow->max_fipt : 0;
                    flow->max_bipt = flow->total_bpackets > 1 ? flow->max_bipt : 0;
                    //
                    min_flowipt = (flow->total_fpackets + flow->total_bpackets) > 1 ? min_flowipt : 0;
                    max_flowipt = (flow->total_fpackets + flow->total_bpackets) > 1 ? max_flowipt : 0;
                    //
                    flow->mean_flowpktl = (flow->mean_flowpktl / (flow->total_fpackets + flow->total_bpackets));
                    //
                    flow->mean_flowipt = (flow->total_fpackets + flow->total_bpackets - 1) > 0 ? flow->mean_flowipt / (flow->total_fpackets + flow->total_bpackets - 1) : 0;
                    ;
                    //
                    calculate_std_pktl();
                    calculate_std_ipt();
                    calculate_std_flowpktl();
                    calculate_std_flowipt();

                    flow->std_flowpktl = (flow->total_fpackets + flow->total_bpackets) > 1 ? flow->std_flowpktl : 0;
                    flow->std_fpktl = flow->total_fpackets > 1 ? flow->std_fpktl : 0;
                    flow->std_bpktl = flow->total_bpackets > 1 ? flow->std_bpktl : 0;
                    flow->std_fipt = flow->total_fpackets > 2 ? flow->std_fipt : 0;
                    flow->std_bipt = flow->total_bpackets > 2 ? flow->std_bipt : 0;
                    flow->std_flowipt = (flow->total_fpackets + flow->total_bpackets) > 2 ? flow->std_flowipt : 0;
                    flow->mean_flowipt = (flow->total_fpackets + flow->total_bpackets) > 1 ? flow->mean_flowipt : 0;
                    //
                    flow->fduration = timestampPrev - flow->timestamp;

                    flow->fPktsPerSecond = (timestampPrev - flow->timestamp) > 0 && flow->total_fpackets > 0 ? (flow->total_fpackets / (float)(timestampPrev - flow->timestamp)) : 0;                                               // Number of forward packets per second
                    flow->bPktsPerSecond = flow->total_bpackets > 0 && (timestampPrev - flow->timestamp) > 0 ? (flow->total_bpackets / (timestampPrev - flow->timestamp)) : 0;                                                      // Number of backward packets per second
//                    flow->flowPktsPerSecond = (flow->total_fpackets + flow->total_bpackets) > 0 && (timestampPrev - flow->timestamp) > 0 ? ((flow->total_fpackets + flow->total_bpackets) / (timestampPrev - flow->timestamp)) : 0; // Number of flow packets per second
                    flow->flowBytesPerSecond = (flow->total_fpktl + flow->total_bpktl) > 0 && (timestampPrev - flow->timestamp) > 0 ? ((flow->total_fpktl + flow->total_bpktl) / (timestampPrev - flow->timestamp)) : 0;
                    flow->downUpRation = (flow->total_bpktl / (float)flow->total_fpktl);
                    fprintf(csv, "TCP,%f,%s,%u,%s,%u,%f,%" PRId64 ",%" PRId64 ",%" PRId64 ",%" PRId64 ",%d,%d,%d,%d,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%d,%d,%d,%d,%d,%d,%f,%f,%f,%f,%f,%f,%f,%d,%d,%d,%d,%d,%d,%d,%f",
                            flow->timestamp,
                            ipv6_SCad.c_str(), ports.srcPort,
                            ipv6_DCad.c_str(), ports.dstPort,
                            flow->fduration,
                            flow->total_fpackets,
                            flow->total_bpackets,
                            flow->total_fpktl,
                            flow->total_bpktl,
                            flow->min_fpktl,
                            flow->min_bpktl,
                            flow->max_fpktl,
                            flow->max_bpktl,
                            flow->mean_fpktl,
                            flow->mean_bpktl,
                            flow->std_fpktl,
                            flow->std_bpktl,
                            flow->total_fipt,
                            flow->total_bipt,
                            flow->min_fipt,
                            flow->min_bipt,
                            flow->max_fipt,
                            flow->max_bipt,
                            flow->mean_fipt,
                            flow->mean_bipt,
                            flow->std_fipt,
                            flow->std_bipt,
                            flow->fpsh_cnt,
                            flow->bpsh_cnt,
                            flow->furg_cnt,
                            flow->burg_cnt,
                            flow->total_fhlen,
                            flow->total_bhlen,
                            flow->fPktsPerSecond,
                            flow->bPktsPerSecond,
//                            flow->flowPktsPerSecond,
                            flow->flowBytesPerSecond,
                            // min_flowpktl,
                            // max_flowpktl,
                            flow->mean_flowpktl,
                            flow->std_flowpktl,
                            // min_flowipt,
                            // max_flowipt,
                            flow->mean_flowipt,
                            flow->std_flowipt,
                            flow->flow_fin,
                            flow->flow_syn,
                            flow->flow_rst,
                            // flow->flow_psh,
                            flow->flow_ack,
                            flow->flow_urg,
                            flow->flow_cwr,
                            flow->flow_ece,
                            flow->downUpRation);
                    if (alertT)
                    {
                        flow->priority = (int)isBadTrafic(*socket_to_String(&ipv6_DCad, &ipv6_SCad, &ports), IPV4_TCP);
                        fprintf(csv, ",%d", flow->priority);
                    }
                    if (u2_File)
                    {
                        int priority = getPriority(*socket_to_String(&ipv6_DCad, &ipv6_SCad, &ports), 0x6);
                        flow->priority = priority <= inputPriority ? priority : 0;
                        if (flow->priority)
                        {
                            flow->classification = getClassification(*socket_to_String(&ipv6_DCad, &ipv6_SCad, &ports), 0x6);
                        }
                        fprintf(csv, ",%d,%d", flow->priority, flow->classification);
                    }
                    fprintf(csv, "\n");
                    if (ipts)
                    {
                        fprintf(ipts, "\n");
                    }
                    flow->protocol = _TCP;
                    flow->dstPort = ports.dstPort;
                    flow->srcPort = ports.srcPort;
                    if (flowsPerImage)
                    {
                        addFlowToImage();
                    }
                    //printf("srcport:%u",ports.srcPort);
                    //printf("No. packet TCP: %llu\n", TCP_cont);
                    //printf("Timestamp->init: %.20f\n",flow->timestamp);
                    //printf("Timestamp->prev: %f\n",timestampPrev);
                    //printf("resultado:%.20f\n", (timestampPrev-flow->timestamp));
                    //printf("total de paquete f:%d\n",flow->total_fpackets);
                    // printf("time sesion: %f\n",(timestampPrev-flow->timestamp));
                }

                if (traficTipe == 0)
                {
                    //fin de scaneo de trafico
                    //printf("\nEnd program\n");
                    //printf("jump:%llu",jump);
                    //printf("End program:%" PRId64 "\n", jump);
                    resetVar();
                    flow = new Flow();
                    pthread_mutex_unlock(&mutex); //Fin SC
                    return NULL;
                }
                //limpiar varibles
                resetVar();
                flow = new Flow();
                if (traficPointer % 1024 == 0)
                {
                    printf("\rBytes->%" PRId64 "", traficPointer);
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
                        timestampPrev = timestampPrevForward = flow->timestamp = timestampTemp;
                        //extraccion de ip y puertos
                        for (size_t i = 0; i < 16; i++)
                        {
                            flow->ipv6_shost = flow->ipv6_shost << 8 | *(bffRawTrafic + jump + 38 + i);
                            stream << std::hex << (int)(*(bffRawTrafic + jump + 38 + i));
                            ipv6_SCad += stream.str();
                            stream.str("");
                            flow->ipv6_dhost = flow->ipv6_dhost << 8 | *(bffRawTrafic + jump + 54 + i);
                            stream << std::hex << (int)(*(bffRawTrafic + jump + 54 + i));
                            ipv6_DCad += stream.str();
                            stream.str("");
                        }

                        ports.srcPort = *(bffRawTrafic + jump + 70) << 8 | *(bffRawTrafic + jump + 71);
                        ports.dstPort = *(bffRawTrafic + jump + 72) << 8 | *(bffRawTrafic + jump + 73);
                        //extraccion de featurs forward direccion primer paquete encontrado de la sesion a scanear
                        flow->total_fpackets++;
                        flow->total_fpktl = orig_len;
                        //
                        flow->min_fpktl = orig_len;
                        //
                        flow->max_fpktl = orig_len;
                        //
                        vector_std_fpktl.push_back(orig_len);
                        //
                        calculateFlagsForwardv6();
                        //
                        min_flowpktl = max_flowpktl = orig_len;
                        //
                        flow->mean_flowpktl = orig_len;
                        //
                        vector_std_flowpktl.push_back(orig_len);
                        //
                        flow->total_fhlen += (*(bffRawTrafic + jump + 74) >> 4) * 4;
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
                    if (flow->ipv6_shost == ipv6_shost_temp && flow->ipv6_dhost == ipv6_dhost_temp && ports.srcPort == ports_temp.srcPort && ports.dstPort == ports_temp.dstPort)
                    {

                        timestampTemp += (*(bffRawTrafic + jump + 7) << 24 | *(bffRawTrafic + jump + 6) << 16 | *(bffRawTrafic + jump + 5) << 8 | *(bffRawTrafic + jump + 4)) / 1e6;
                        //
                        iptTemp = timestampTemp - timestampPrev;
                        //
                        if (ipts)
                        {
                            fprintf(ipts, "%.20f,", iptTemp);
                        }
                        timestampPrev = timestampTemp;
                        //extraccion de caracteristicas forward direccion
                        flow->total_fpackets++;
                        flow->total_fpktl += orig_len;
                        //
                        flow->min_fpktl = orig_len < flow->min_fpktl ? orig_len : flow->min_fpktl;
                        flow->max_fpktl = orig_len > flow->max_fpktl ? orig_len : flow->max_fpktl;
                        //
                        vector_std_fpktl.push_back(orig_len);
                        //
                        iptTemp = timestampTemp - timestampPrevForward;
                        /*                         if (!iptForwardState)
                        {
                            flow->min_fipt = iptTemp;
                            min_flowipt = iptTemp;
                        } */
                        flow->total_fipt += iptTemp;
                        //
                        flow->min_fipt = iptTemp < flow->min_fipt ? iptTemp : flow->min_fipt;
                        //
                        flow->max_fipt = iptTemp > flow->max_fipt ? iptTemp : flow->max_fipt;
                        //
                        vector_std_fipt.push_back(iptTemp);
                        //
                        calculateFlagsForwardv6();
                        //
                        min_flowpktl = orig_len < min_flowpktl ? orig_len : min_flowpktl;
                        //
                        max_flowpktl = orig_len > max_flowpktl ? orig_len : max_flowpktl;
                        //
                        flow->mean_flowpktl += orig_len;
                        //
                        vector_std_flowpktl.push_back(orig_len);
                        //
                        min_flowipt = iptTemp < min_flowipt ? iptTemp : min_flowipt;
                        //
                        max_flowipt = iptTemp > max_flowipt ? iptTemp : max_flowipt;
                        //
                        flow->mean_flowipt += iptTemp;
                        //
                        vector_std_flowipt.push_back(iptTemp);
                        //
                        timestampPrevForward = timestampTemp;
                        //
                        flow->total_fhlen += (*(bffRawTrafic + jump + 74) >> 4) * 4;
                        //
                        calculateFlagsFlowv6();
                        //marcar el paquete
                        mark(jump);
                    }

                    //check if the backward direction
                    if (flow->ipv6_dhost == ipv6_shost_temp && flow->ipv6_shost == ipv6_dhost_temp && ports.dstPort == ports_temp.srcPort && ports.srcPort == ports_temp.dstPort)
                    {

                        timestampTemp += (*(bffRawTrafic + jump + 7) << 24 | *(bffRawTrafic + jump + 6) << 16 | *(bffRawTrafic + jump + 5) << 8 | *(bffRawTrafic + jump + 4)) / 1e6;

                        iptTemp = timestampTemp - timestampPrev;
                        if (ipts)
                        {
                            fprintf(ipts, "%.20f,", iptTemp);
                        }
                        timestampPrev = timestampTemp;

                        //extraccion de caracteristicas en backward direccion
                        flow->total_bpackets++;
                        flow->total_bpktl += orig_len;
                        //

                        //
                        vector_std_bpktl.push_back(orig_len);
                        //
                        vector_std_flowipt.push_back(iptTemp);
                        //
                        min_flowipt = iptTemp < min_flowipt ? iptTemp : min_flowipt;
                        //
                        max_flowipt = iptTemp > max_flowipt ? iptTemp : max_flowipt;
                        //
                        flow->mean_flowipt += iptTemp;
                        if (!iptBackwardState)
                        {
                            iptBackwardState = true;
                            timestampPrevBackware = timestampTemp;
                            flow->min_bpktl = orig_len;
                            flow->min_bipt = timestampTemp;
                        }
                        else
                        {
                            iptTemp = timestampTemp - timestampPrevBackware;
                            //
                            flow->total_bipt += iptTemp;
                            //
                            flow->min_bipt = iptTemp < flow->min_bipt ? iptTemp : flow->min_bipt;
                            //
                            flow->max_bipt = iptTemp > flow->max_bipt ? iptTemp : flow->max_bipt;
                            //
                            vector_std_bipt.push_back(iptTemp);
                        }

                        flow->min_bpktl = orig_len < flow->min_bpktl ? orig_len : flow->min_bpktl;
                        flow->max_bpktl = orig_len > flow->max_bpktl ? orig_len : flow->max_bpktl;
                        timestampPrevBackware = timestampTemp;
                        //
                        calculateFlagsBackwardv6();
                        //
                        min_flowpktl = orig_len < min_flowpktl ? orig_len : min_flowpktl;
                        //
                        max_flowpktl = orig_len > max_flowpktl ? orig_len : max_flowpktl;
                        //
                        flow->mean_flowpktl += orig_len;
                        //
                        vector_std_flowpktl.push_back(orig_len);
                        //
                        flow->total_bhlen += (*(bffRawTrafic + jump + 74) >> 4) * 4;
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
    flow = new Flow();
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
                    flow->min_bpktl = flow->min_bpktl == 65535 ? 0 : flow->min_bpktl;
                    flow->mean_fpktl = flow->total_fpackets > 0 ? flow->total_fpktl / ((float)flow->total_fpackets) : 0;
                    flow->mean_bpktl = flow->total_bpackets > 0 ? (flow->total_bpktl / ((float)flow->total_bpackets)) : 0;
                    //
                    flow->min_fipt = flow->total_fpackets > 1 ? flow->min_fipt : 0;
                    flow->min_bipt = flow->total_bpackets > 1 ? flow->min_bipt : 0;
                    //
                    flow->total_fipt = flow->total_fpackets > 1 ? flow->total_fipt : 0;
                    flow->total_bipt = flow->total_bpackets > 1 ? flow->total_bipt : 0;

                    //
                    flow->mean_fipt = flow->total_fpackets > 1 ? ((float)flow->total_fipt) / (flow->total_fpackets - 1) : 0;
                    flow->mean_bipt = flow->total_bpackets > 1 ? flow->total_bipt / (flow->total_bpackets - 1) : 0;
                    //
                    flow->max_fipt = flow->total_fpackets > 1 ? flow->max_fipt : 0;
                    flow->max_bipt = flow->total_bpackets > 1 ? flow->max_bipt : 0;
                    //
                    min_flowipt = (flow->total_fpackets + flow->total_bpackets) > 1 ? min_flowipt : 0;
                    max_flowipt = (flow->total_fpackets + flow->total_bpackets) > 1 ? max_flowipt : 0;
                    //
                    flow->mean_flowpktl = (flow->mean_flowpktl / (flow->total_fpackets + flow->total_bpackets));
                    //
                    flow->mean_flowipt = (flow->total_fpackets + flow->total_bpackets - 1) > 0 ? flow->mean_flowipt / (flow->total_fpackets + flow->total_bpackets - 1) : 0;
                    ;
                    //
                    calculate_std_pktl();
                    calculate_std_ipt();
                    calculate_std_flowpktl();
                    calculate_std_flowipt();

                    flow->std_flowpktl = (flow->total_fpackets + flow->total_bpackets) > 1 ? flow->std_flowpktl : 0;
                    flow->std_fpktl = flow->total_fpackets > 1 ? flow->std_fpktl : 0;
                    flow->std_bpktl = flow->total_bpackets > 1 ? flow->std_bpktl : 0;
                    flow->std_fipt = flow->total_fpackets > 2 ? flow->std_fipt : 0;
                    flow->std_bipt = flow->total_bpackets > 2 ? flow->std_bipt : 0;
                    flow->std_flowipt = (flow->total_fpackets + flow->total_bpackets) > 2 ? flow->std_flowipt : 0;
                    flow->mean_flowipt = (flow->total_fpackets + flow->total_bpackets) > 1 ? flow->mean_flowipt : 0;
                    //
                    flow->fduration = timestampPrev - flow->timestamp;

                    flow->fPktsPerSecond = (timestampPrev - flow->timestamp) > 0 && flow->total_fpackets > 0 ? (flow->total_fpackets / (float)(timestampPrev - flow->timestamp)) : 0;                                               // Number of forward packets per second
                    flow->bPktsPerSecond = flow->total_bpackets > 0 && (timestampPrev - flow->timestamp) > 0 ? (flow->total_bpackets / (timestampPrev - flow->timestamp)) : 0;                                                      // Number of backward packets per second
//                    flow->flowPktsPerSecond = (flow->total_fpackets + flow->total_bpackets) > 0 && (timestampPrev - flow->timestamp) > 0 ? ((flow->total_fpackets + flow->total_bpackets) / (timestampPrev - flow->timestamp)) : 0; // Number of flow packets per second
                    flow->flowBytesPerSecond = (flow->total_fpktl + flow->total_bpktl) > 0 && (timestampPrev - flow->timestamp) > 0 ? ((flow->total_fpktl + flow->total_bpktl) / (timestampPrev - flow->timestamp)) : 0;
                    flow->downUpRation = (flow->total_bpktl / (float)flow->total_fpktl);
                    fprintf(csv, "UDP,%s,%u,%s,%u,%f,%" PRId64 ",%" PRId64 ",%" PRId64 ",%" PRId64 ",%d,%d,%d,%d,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%d,%d,%d,%d,%d,%d,%f,%f,%f,%f,%f,%f,%f,%d,%d,%d,%d,%d,%d,%d,%f",
                            ipv6_SCad.c_str(), ports.srcPort,
                            ipv6_DCad.c_str(), ports.dstPort,
                            flow->fduration,
                            flow->total_fpackets,
                            flow->total_bpackets,
                            flow->total_fpktl,
                            flow->total_bpktl,
                            flow->min_fpktl,
                            flow->min_bpktl,
                            flow->max_fpktl,
                            flow->max_bpktl,
                            flow->mean_fpktl,
                            flow->mean_bpktl,
                            flow->std_fpktl,
                            flow->std_bpktl,
                            flow->total_fipt,
                            flow->total_bipt,
                            flow->min_fipt,
                            flow->min_bipt,
                            flow->max_fipt,
                            flow->max_bipt,
                            flow->mean_fipt,
                            flow->mean_bipt,
                            flow->std_fipt,
                            flow->std_bipt,
                            flow->fpsh_cnt,
                            flow->bpsh_cnt,
                            flow->furg_cnt,
                            flow->burg_cnt,
                            flow->total_fhlen,
                            flow->total_bhlen,
                            flow->fPktsPerSecond,
                            flow->bPktsPerSecond,
//                            flow->flowPktsPerSecond,
                            flow->flowBytesPerSecond,
                            // min_flowpktl,
                            // max_flowpktl,
                            flow->mean_flowpktl,
                            flow->std_flowpktl,
                            // min_flowipt,
                            // max_flowipt,
                            flow->mean_flowipt,
                            flow->std_flowipt,
                            flow->flow_fin,
                            flow->flow_syn,
                            flow->flow_rst,
                            // flow->flow_psh,
                            flow->flow_ack,
                            flow->flow_urg,
                            flow->flow_cwr,
                            flow->flow_ece,
                            flow->downUpRation);
                    if (alertT)
                    {
                        flow->priority = (int)isBadTrafic(*socket_to_String(&ipv6_DCad, &ipv6_SCad, &ports), IPV4_UDP);
                        fprintf(csv, ",%d", flow->priority);
                    }
                    if (u2_File)
                    {
                        int priority = getPriority(*socket_to_String(&ipv6_DCad, &ipv6_SCad, &ports), 0x11);
                        flow->priority = priority <= inputPriority ? priority : 0;
                        if (flow->priority)
                        {
                            flow->classification = getClassification(*socket_to_String(&ipv6_DCad, &ipv6_SCad, &ports), 0x11);
                        }
                        fprintf(csv, ",%d,%d", flow->priority, flow->classification);
                    }
                    fprintf(csv, "\n");
                    if (ipts)
                    {
                        fprintf(ipts, "\n");
                    }
                    flow->protocol = _UDP;
                    flow->dstPort = ports.dstPort;
                    flow->srcPort = ports.srcPort;
                    if (flowsPerImage)
                    {
                        addFlowToImage();
                    }
                    //printf("srcport:%u",ports.srcPort);
                    //printf("No. packet TCP: %llu\n", TCP_cont);
                    //printf("Timestamp->init: %.20f\n",flow->timestamp);
                    //printf("Timestamp->prev: %f\n",timestampPrev);
                    //printf("resultado:%.20f\n", (timestampPrev-flow->timestamp));
                    //printf("total de paquete f:%d\n",flow->total_fpackets);
                    // printf("time sesion: %f\n",(timestampPrev-flow->timestamp));
                }

                if (traficTipe == 0)
                {
                    //fin de scaneo de trafico
                    //printf("\nEnd program\n");
                    //printf("jump:%llu",jump);
                    //printf("End program:%" PRId64 "\n", jump);
                    resetVar();
                    flow = new Flow();
                    pthread_mutex_unlock(&mutex); //Fin SC
                    return NULL;
                }
                //limpiar varibles
                resetVar();
                flow = new Flow();
                if (traficPointer % 1024 == 0)
                {
                    printf("\rBytes->%" PRId64 "", traficPointer);
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
                        timestampPrev = timestampPrevForward = flow->timestamp = timestampTemp;
                        //extraccion de ip y puertos
                        for (size_t i = 0; i < 16; i++)
                        {
                            flow->ipv6_shost = flow->ipv6_shost << 8 | *(bffRawTrafic + jump + 38 + i);
                            stream << std::hex << (int)(*(bffRawTrafic + jump + 38 + i));
                            ipv6_SCad += stream.str();
                            stream.str("");
                            flow->ipv6_dhost = flow->ipv6_dhost << 8 | *(bffRawTrafic + jump + 54 + i);
                            stream << std::hex << (int)(*(bffRawTrafic + jump + 54 + i));
                            ipv6_DCad += stream.str();
                            stream.str("");
                        }

                        ports.srcPort = *(bffRawTrafic + jump + 70) << 8 | *(bffRawTrafic + jump + 71);
                        ports.dstPort = *(bffRawTrafic + jump + 72) << 8 | *(bffRawTrafic + jump + 73);
                        //extraccion de featurs forward direccion primer paquete encontrado de la sesion a scanear
                        flow->total_fpackets++;
                        flow->total_fpktl = orig_len;
                        //
                        flow->min_fpktl = orig_len;
                        //
                        flow->max_fpktl = orig_len;
                        //
                        vector_std_fpktl.push_back(orig_len);
                        //
                        min_flowpktl = max_flowpktl = orig_len;
                        //
                        flow->mean_flowpktl = orig_len;
                        //
                        vector_std_flowpktl.push_back(orig_len);
                        //
                        flow->total_fhlen += *(bffRawTrafic + jump + 74) << 8 | *(bffRawTrafic + jump + 75);
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
                    if (flow->ipv6_shost == ipv6_shost_temp && flow->ipv6_dhost == ipv6_dhost_temp && ports.srcPort == ports_temp.srcPort && ports.dstPort == ports_temp.dstPort)
                    {

                        timestampTemp += (*(bffRawTrafic + jump + 7) << 24 | *(bffRawTrafic + jump + 6) << 16 | *(bffRawTrafic + jump + 5) << 8 | *(bffRawTrafic + jump + 4)) / 1e6;
                        //
                        iptTemp = timestampTemp - timestampPrev;
                        //
                        if (ipts)
                        {
                            fprintf(ipts, "%.20f,", iptTemp);
                        }
                        timestampPrev = timestampTemp;
                        //extraccion de caracteristicas forward direccion
                        flow->total_fpackets++;
                        flow->total_fpktl += orig_len;
                        //
                        flow->min_fpktl = orig_len < flow->min_fpktl ? orig_len : flow->min_fpktl;
                        flow->max_fpktl = orig_len > flow->max_fpktl ? orig_len : flow->max_fpktl;
                        //
                        vector_std_fpktl.push_back(orig_len);
                        //
                        iptTemp = timestampTemp - timestampPrevForward;
                        /*
                         if (!iptForwardState)
                        {
                            flow->min_fipt = iptTemp;
                            min_flowipt = iptTemp;
                        } */
                        flow->total_fipt += iptTemp;
                        //
                        flow->min_fipt = iptTemp < flow->min_fipt ? iptTemp : flow->min_fipt;
                        //
                        flow->max_fipt = iptTemp > flow->max_fipt ? iptTemp : flow->max_fipt;
                        //
                        vector_std_fipt.push_back(iptTemp);
                        //
                        min_flowpktl = orig_len < min_flowpktl ? orig_len : min_flowpktl;
                        //
                        max_flowpktl = orig_len > max_flowpktl ? orig_len : max_flowpktl;
                        //
                        flow->mean_flowpktl += orig_len;
                        //
                        vector_std_flowpktl.push_back(orig_len);
                        //
                        min_flowipt = iptTemp < min_flowipt ? iptTemp : min_flowipt;
                        //
                        max_flowipt = iptTemp > max_flowipt ? iptTemp : max_flowipt;
                        //
                        flow->mean_flowipt += iptTemp;
                        //
                        vector_std_flowipt.push_back(iptTemp);
                        //
                        timestampPrevForward = timestampTemp;
                        //
                        flow->total_fhlen += *(bffRawTrafic + jump + 74) << 8 | *(bffRawTrafic + jump + 75);
                        //marcar el paquete
                        mark(jump);
                    }

                    //check if the backward direction
                    if (flow->ipv6_dhost == ipv6_shost_temp && flow->ipv6_shost == ipv6_dhost_temp && ports.dstPort == ports_temp.srcPort && ports.srcPort == ports_temp.dstPort)
                    {

                        timestampTemp += (*(bffRawTrafic + jump + 7) << 24 | *(bffRawTrafic + jump + 6) << 16 | *(bffRawTrafic + jump + 5) << 8 | *(bffRawTrafic + jump + 4)) / 1e6;

                        iptTemp = timestampTemp - timestampPrev;
                        if (ipts)
                        {
                            fprintf(ipts, "%.20f,", iptTemp);
                        }
                        timestampPrev = timestampTemp;

                        //extraccion de caracteristicas en backward direccion
                        flow->total_bpackets++;
                        flow->total_bpktl += orig_len;
                        //

                        //
                        vector_std_bpktl.push_back(orig_len);
                        //
                        vector_std_flowipt.push_back(iptTemp);
                        //
                        min_flowipt = iptTemp < min_flowipt ? iptTemp : min_flowipt;
                        //
                        max_flowipt = iptTemp > max_flowipt ? iptTemp : max_flowipt;
                        //
                        flow->mean_flowipt += iptTemp;
                        if (!iptBackwardState)
                        {
                            iptBackwardState = true;
                            timestampPrevBackware = timestampTemp;
                            flow->min_bpktl = orig_len;
                            flow->min_bipt = timestampTemp;
                        }
                        else
                        {
                            iptTemp = timestampTemp - timestampPrevBackware;
                            //
                            flow->total_bipt += iptTemp;
                            //
                            flow->min_bipt = iptTemp < flow->min_bipt ? iptTemp : flow->min_bipt;
                            //
                            flow->max_bipt = iptTemp > flow->max_bipt ? iptTemp : flow->max_bipt;
                            //
                            vector_std_bipt.push_back(iptTemp);
                        }

                        flow->min_bpktl = orig_len < flow->min_bpktl ? orig_len : flow->min_bpktl;
                        flow->max_bpktl = orig_len > flow->max_bpktl ? orig_len : flow->max_bpktl;
                        timestampPrevBackware = timestampTemp;
                        //
                        min_flowpktl = orig_len < min_flowpktl ? orig_len : min_flowpktl;
                        //
                        max_flowpktl = orig_len > max_flowpktl ? orig_len : max_flowpktl;
                        //
                        flow->mean_flowpktl += orig_len;
                        //
                        vector_std_flowpktl.push_back(orig_len);
                        //
                        flow->total_bhlen += *(bffRawTrafic + jump + 74) << 8 | *(bffRawTrafic + jump + 75);
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
