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
	#./generador prueba.pcap malo.pcap hola.csv holaipts.txt
	#./generador prueba.pcap hola.csv holaipts.txt
	#./generador tftp_rrq.pcap hola.csv holaipts.txt
	#./generador nb6-http.pcap hola.csv holaipts.txt
	#./generador sesioncompleta1.pcap malo.pcap hola.csv holaipts.txt
	#/generador tcpdump1.out hola.csv holaipts.txt
	#./generador idprueba.pcap hola.csv holaipts.txt
	#./generador idprueba.pcap holaipv6.csv holaiptsipv6.txt
	#./generador sesion_01_completa.pcap holaipv6.csv holaiptsipv6.txt
	#./generador ../../securitylab/Proyecto_generador_de_trazas\ /idprueba.pcap  otro.csv ipst_otro.txt
