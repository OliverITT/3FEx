all:
	make compile
	make run
	
compile:
	clear
	g++ 3fex.cpp -o 3fex.x -lpthread
	g++ tcpv4.cpp -o tcpv4.x -lpthread
	g++ udpv4.cpp -o udpv4.x -lpthread
	g++ tcpv6.cpp -o tcpv6.x -lpthread
	g++ udpv6.cpp -o udpv6.x -lpthread
	g++ splitTrafic.cpp -o splitTrafic.x

run:
	#./3fex.x prueba.pcap malo.pcap hola.csv holaipts.txt
	#./tcpv4.x prueba.pcap hola.csv holaipts.txt
	#./tcpv6.x tftp_rrq.pcap hola.csv holaipts.txt
	#./udpv4.x nb6-http.pcap hola.csv holaipts.txt
	#./udpv6.x sesioncompleta1.pcap malo.pcap hola.csv holaipts.txt
	#./3fex.x ../../securitylab/Proyecto_generador_de_trazas\ /idprueba.pcap  otro.csv ipst_otro.txt
	#./splitTrafic.x rawTrafic.pcap badTrafic.pcap nameFreeAnomali.pcap
