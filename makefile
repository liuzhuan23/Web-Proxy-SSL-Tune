Web-Proxy.app : csapp.o proxy.o
	gcc -g -o Web-Proxy proxy.o csapp.o -pthread -lssl -lcrypto
	
proxy.o : proxy.c
	gcc -g -c proxy.c -pthread -lssl -lcrypto -w
	
csapp.o : csapp.c
	gcc -g -c csapp.c -pthread
	
all : Web-Proxy.app

clean : 
	-rm Web-Proxy proxy.o csapp.o
