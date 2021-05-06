clear
cmake .
make
cp banner.txt /usr/bin/banner.txt
cp ./3fex /usr/bin/3fex
#g++ tcpv4.cpp -o /usr/bin/tcpv4 -lpthread
#g++ udpv4.cpp -o /usr/bin/udpv4 -lpthread
#g++ tcpv6.cpp -o /usr/bin/tcpv6 -lpthread
#g++ udpv6.cpp -o /usr/bin/udpv6 -lpthread
g++ splitTrafic.cpp -o /usr/bin/splitTrafic

