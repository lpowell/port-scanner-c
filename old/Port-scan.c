// Outcomes
// Default network scan
// Full scan for common open ports
// -a, -a 10.0.0.1
// -f full scan, WORKING
// -s, select scan, WORKING
// -p, port
// -d, default scan, WORKING, INCREDIBLY slow, add timeout
// full scan is an intensive scan on one address
// default scan is what searches for all addresses
// select scan allows you to choose both an address and port



#include <stdio.h> // std
#include <sys/socket.h> // sockets
#include <unistd.h> // getopts
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <ctype.h> 
#include <time.h> // time
#include <sys/stat.h> // mkdir
#include <sys/types.h> // mkdir
#include <netinet/tcp.h>


short socketCreate(void){
	short hSocket;// 2-byte data type
	// Usage socket(domain, type, protocol) AF_INET = IPv4 Internet Protocols, 
	// SOCK_STREAM is 2 way connection-based byte stream
	// protocol is 0 if a single protocol exists for a type
	hSocket = socket(AF_INET, SOCK_STREAM, 0); 
	// == 0 if exist
	if(hSocket == -1){
		printf("\nSocket creation failed\n");
		printf("See Help \'port-scan -h\'\n");
		abort();
	}
	return hSocket;
}


int socketConnect(int hSocket, char *address, int serverPort){
	int iRetval = -1;
	struct sockaddr_in remote = {0};

	remote.sin_addr.s_addr = inet_addr(address);
	remote.sin_family = AF_INET;
	remote.sin_port = htons(serverPort);

	iRetval = connect(hSocket, (struct sockaddr *)&remote, sizeof(struct sockaddr_in));
	return iRetval;
}


void defaultScan(){
	printf("Scanning the network for devices...\n");
	printf("This will take some time\n");
	int blockOne = 10;
	int blockTwo,blockThree,blockFour;
	char address[16];
	int socket;
	struct timeval timeout;
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;
	int synRetries = 1;
	do{
		printf("FLAG START\n");
		socket = socketCreate();
		setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
		// setsockopt(socket, IPPROTO_TCP, TCP_SYNCNT, &synRetries, sizeof( synRetries));
		printf("FLAG SOCKET CREATED\n");
		sprintf(address, "%d.%d.%d.%d",blockOne,blockTwo,blockThree,blockFour);
		printf("\nADDRESS %s\n",address);
		if(socketConnect(socket, address, 80) < 0){	
			shutdown(socket,1);
			printf("FLAG ADDRESS FAILED\n");
		}else{
			printf("\n%s exists\n",address);
			shutdown(socket,1);
		}
		printf("FLAG SOCKET OVER\n");
		blockFour++;
		if(blockFour==256){
			blockThree++;
			blockFour=0;
		}
		if(blockThree == 256){
			blockTwo++;
			blockThree =0;
		}
		printf("FLAG ADDRESS ENUMERATION\n");
	}while(blockTwo <=255);
	printf("FLAG E");
}

void fullScan(char *address){
	time_t t = time(NULL);
	char fileName[0x100];
	mkdir("Scans", 0777);
	snprintf(fileName, sizeof(fileName), "Scans/Scan Report %s.txt", asctime(gmtime(&t)));
	FILE *f = fopen(fileName, "a");
	if(f == NULL){
		printf("Report file could not be opened, or could not be created.\n");
	}
	int socket[14];
	int port[14] = {20,21,22,23,25,53,139,80,443,445,1433,1434,3306,3389};
	fprintf(f,"\n");
	fprintf(f, "<------------------------------------------------------------>\n");
	fprintf(f,"Scan details for a scan performed at %s\n",asctime(gmtime(&t)));
	fprintf(f,"Scanning %s for vulnerable ports\n", address);
	printf("Scanning %s for vulnerable ports.\n", address);
	printf("This may take several minutes.\n");
	for(int x=0;x < 14;x++){
		socket[x] = socketCreate();
		printf("\nTesting port: %d\n",port[x]);
		if((socketConnect(socket[x], address, port[x])) < 0){
			// printf("\nAddress not found\n");
			// printf("Please view the help menu for more information\n");
			// return;
			printf("\tPort %d is closed\n", port[x]);
		}else{
			printf("\tPort %d is open\n", port[x]);
			switch(port[x]){
				case 20:
				fprintf(f,"Port 20 && 21 are used for FTP.\n");
					break;
				case 21:
					fprintf(f,"Port 20 && 21 are used for FTP.\n");
					break;
				case 22:
					fprintf(f,"Port 22 is used for SSH.\n");
					break;
				case 23:
					fprintf(f,"Port 23 is used for Telnet.\n");
					break;
				case 25:
					fprintf(f,"Port 25 is used for SMTP.\n");
					break;
				case 53:
					fprintf(f,"Port 53 is used for DNS.\n");
					break;
				case 139:
					fprintf(f,"Port 139 is used for NetBIOS.\n");
					break;
				case 445:
					fprintf(f,"Port 445 is used for SMB.\n");
					break;
				case 1433:
					fprintf(f,"Ports 1433,1434, and 3306 are used for SQL.\n");
					break;
				case 1434:
					fprintf(f,"Ports 1433,1434, and 3306 are used for SQL.\n");
					break;
				case 3306:
					fprintf(f,"Ports 1433,1434, and 3306 are used for SQL.\n");
					break;
				case 3389:
					fprintf(f,"Port 3389 is used for Remote Desktop.\n");
					break;
				case 80:
					fprintf(f,"\nPort 80 was found open on %s\n", address);
					fprintf(f,"Port 80 is used by HTTP\n");
					fprintf(f,"HTTP services are commonly attacked\n");
					break;
				case 443:
					fprintf(f,"\nPort 443 was found open on %s\n", address);
					fprintf(f,"Port 443 is used by HTTPS\n");
					fprintf(f,"HTTPS services are commonly attacked\n");
					break;
				default:
					break;
			}

		}
		close(socket[x]);
		shutdown(socket[x],1);
	}
	printf("\nScan completed.\nA full report can be found in %s\n", fileName);
}

void selectScan(char *address, int port){
	int socket;
	socket = socketCreate();
	if((socketConnect(socket, address, port)) < 0){
		printf("\nPort %d does not exist on address %s", port, address);
		return;
	}else{
		printf("\nPort %d exists on address %s", port, address);

	}
	close(socket);
	shutdown(socket,1);
}

void help(){
	printf("Help will go here\n");
	return;
}

int main(int argc, char **argv){
	int choice;

	// getopts
	int switchVal;
	int c;
	char *address;
	int port;
	opterr = 0;
	while((c=getopt(argc,argv,"hdfsa:p:"))!=-1){
		switch(c){
			case 'h':
				help();
				break;
			case 'a':
				address = optarg;
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 'd':
				defaultScan();
				break;
			case 's':
				selectScan(address, port);
				break;
			case 'f':
				fullScan(address);
				break;
			case '?':
				help();
				break;
			default:
				abort();
		}
	}


	return 0;
}
