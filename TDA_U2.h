#ifndef __CLASS_TDA_U2
#define __CLASS_TDA_U2
#include <stdlib.h>
class TDA_U2
{
public:
    /* data */
    uint8_t protocol;
    uint32_t priority;
    uint32_t classification_id;

public:
    TDA_U2(/* args */);
    TDA_U2(uint8_t protocol, uint32_t priority, uint32_t classification);
    TDA_U2(const TDA_U2 &tda_u2);
    ~TDA_U2();
};

TDA_U2::TDA_U2(/* args */)
{
}
TDA_U2::TDA_U2(uint8_t protocol, uint32_t priority,uint32_t classification)
{
    this->protocol = protocol;
    this->priority = priority;
    this->classification_id = classification;
    
}
TDA_U2::TDA_U2(const TDA_U2 &tda_u2)
{
    this->protocol = tda_u2.protocol;
    this->priority = tda_u2.priority;
    this->classification_id = tda_u2.classification_id;
}
TDA_U2::~TDA_U2()
{
}

#endif