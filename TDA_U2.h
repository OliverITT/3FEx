#ifndef __CLASS_TDA_U2
#define __CLASS_TDA_U2
#include <stdlib.h>
class TDA_U2
{
public:
    /* data */
    uint8_t protocol;
    uint8_t priority;

public:
    TDA_U2(/* args */);
    TDA_U2(uint8_t protocol, uint8_t priority);
    TDA_U2(const TDA_U2 &tda_u2);
    ~TDA_U2();
};

TDA_U2::TDA_U2(/* args */)
{
}
TDA_U2::TDA_U2(uint8_t protocol, uint8_t priority)
{
    this->protocol = protocol;
    this->priority = priority;
}
TDA_U2::TDA_U2(const TDA_U2 &tda_u2)
{
    this->protocol = tda_u2.protocol;
    this->priority = tda_u2.priority;
}
TDA_U2::~TDA_U2()
{
}

#endif