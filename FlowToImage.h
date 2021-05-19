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
bool noips = true;
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
    uint16_t size_image_bytes=320;
    if(!noips){
        size_image_bytes -= 40;
    }
    uint8_t data[size_image_bytes];
    
    for (int i=0,e = 0; i+e < sizeof(Flow); i++)
    {
        if(!noips && i == 5){
            e = 45;
        }else{
            data[i] = ((char *)*&flow)[i+e];
        }
    }
    if (!countFlows)
    {
        img = Mat(1, size_image_bytes, CV_8U, data);
    }
    else
    {
        img.push_back(Mat(1, size_image_bytes, CV_8U, data));
    }
    countFlows++;
    if(countFlows == flowsPerImage){
        saveImage();
    }
}

#endif