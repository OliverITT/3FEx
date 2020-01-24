all:
	clear
	g++ generador.cpp -o generador -lpthread
	#./generador prueba.pcap malo.pcap hola.csv holaipts.txt
	#./generador prueba.pcap hola.csv holaipts.txt
	#./generador sesioncompleta1.pcap malo.pcap hola.csv holaipts.txt
	#/generador tcpdump1.out hola.csv holaipts.txt
	#./generador idprueba.pcap hola.csv holaipts.txt
	#./generador idprueba.pcap holaipv6.csv holaiptsipv6.txt
	./generador sesion_01_completa.pcap holaipv6.csv holaiptsipv6.txt
