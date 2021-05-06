# 3FEx
Fast Flow Feature Extractor
<br>
<h2>About</h2>
this tool extrac features the pcap file

<h2>Install OpenCV</h2>
<p>This step make one time only per host </p>
<p> chmod +x  installOpenCV.sh</p>
<p>sudo ./installOpenCV.sh</p>
<p>wait for compile and install libraries</p>
<h2>Install 3FEx</h2>
<p> chmod +x  install3Fex.sh</p>
<p>sudo ./install3Fex.sh</p>
<h2>Params</h2>
<p>
<br>
-r  Input pcap raw file 
<br>
-b  Input pcap alert file 
<br>
-f  Output csv features file
<br>
-i  Output txt inter packet times file
<br>
-u  Input Unified2 snort logs file
<br>
-o  Flow per image
</p>

<h2>Examples</h2>
<p>
    3fex -r ftp-session-134pkts.pcap -b alert.pcap -f featurs.csv -i times.txt <br>
    3fex -r ftp-session-134pkts.pcap -f featurs.csv -i times.txt <br>
    3fex -r ftp-session-134pkts.pcap -f featurs.csv<br>
    3fex -r ftp-session-134pkts.pcap -f featurs.csv -u snort.log.1617246713
</p>
