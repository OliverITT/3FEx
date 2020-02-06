all:
	clear
	g++ generador.cpp -o generador -lpthread
	g++ tcpv4.cpp -o tcpv4 -lpthread
	g++ udpv4.cpp -o udpv4 -lpthread
	g++ tcpv6.cpp -o tcpv6 -lpthread
	g++ udpv6.cpp -o udpv6 -lpthread
	#./generador prueba.pcap malo.pcap hola.csv holaipts.txt
	#./generador prueba.pcap hola.csv holaipts.txt
	#./generador sesioncompleta1.pcap malo.pcap hola.csv holaipts.txt
	#/generador tcpdump1.out hola.csv holaipts.txt
	#./generador idprueba.pcap hola.csv holaipts.txt
	#./generador idprueba.pcap holaipv6.csv holaiptsipv6.txt
	#./generador sesion_01_completa.pcap holaipv6.csv holaiptsipv6.txt
	#./generador ../../securitylab/Proyecto_generador_de_trazas\ /idprueba.pcap  otro.csv ipst_otro.txt
