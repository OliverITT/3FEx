#ifndef FLOW_TO_IMG
#define FLOW_TO_IMG
#include "Flow.h"
#include <stdio.h>
#include <opencv2/opencv.hpp>
using namespace cv;
Mat img;
Flow *flow;
char *nameImage;
uint32_t flowsPerImage = 0;
uint32_t countFlows = 0;
uint32_t outimg =0;
void saveImage()
{
    if (countFlows)
    {
        imwrite(std::to_string(outimg) + ".jpg", img);
        countFlows =0;
        outimg++;
    }
}
void addFlowToImage()
{
    uint8_t data[320];

    for (int i = 0; i < sizeof(Flow); i++)
    {
        data[i] = ((char *)*&flow)[i];
    }
    if (!countFlows)
    {
        img = Mat(1, 320, CV_8U, data);
    }
    else
    {
        img.push_back(Mat(1, 320, CV_8U, data));
    }
    countFlows++;
    if(countFlows == flowsPerImage){
        saveImage();
    }
}

#endif