gcc -o snap snap.c -lpcap      
gcc -o convert convert.c -lz     
chmod +x snap       
chmod +x convert       
sudo ./snap      
sudo ./convert      
