all:
	make compile
	make run
	
compile:
	clear
	g++ generador.cpp -o generador.x -lpthread
	g++ tcpv4.cpp -o tcpv4.x -lpthread
	g++ udpv4.cpp -o udpv4.x -lpthread
	g++ tcpv6.cpp -o tcpv6.x -lpthread
	g++ udpv6.cpp -o udpv6.x -lpthread
	g++ splitTrafic.cpp -o splitTrafic.x

run:
	#./generador.x prueba.pcap malo.pcap hola.csv holaipts.txt
	#./generador.x prueba.pcap hola.csv holaipts.txt
	#./generador.x tftp_rrq.pcap hola.csv holaipts.txt
	#./generador.x nb6-http.pcap hola.csv holaipts.txt
	#./generador.x sesioncompleta1.pcap malo.pcap hola.csv holaipts.txt
	#/generador.x tcpdump1.out hola.csv holaipts.txt
	#./generador.x idprueba.pcap hola.csv holaipts.txt
	#./generador.x idprueba.pcap holaipv6.csv holaiptsipv6.txt
	#./generador.x sesion_01_completa.pcap holaipv6.csv holaiptsipv6.txt
	#./generador.x ../../securitylab/Proyecto_generador_de_trazas\ /idprueba.pcap  otro.csv ipst_otro.txt
	#./splitTrafic.x rawTrafic.pcap badTrafic.pcap nameFreeAnomali.pcap
