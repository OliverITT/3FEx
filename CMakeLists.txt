cmake_minimum_required(VERSION 2.8)
project( 3fex )
find_package( OpenCV REQUIRED )
find_package(Threads REQUIRED)
SET(CMAKE_CXX_FLAGS "-pthread")
include_directories( ${OpenCV_INCLUDE_DIRS} )
add_executable( 3fex 3fex.cpp )
target_link_libraries( 3fex ${OpenCV_LIBS})
