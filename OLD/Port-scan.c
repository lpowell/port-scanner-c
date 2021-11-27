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


// Connect the socket 
int socketConnect(int hSocket, char *address, int serverPort){

	int iRetval = -1;

	struct sockaddr_in remote = {0};

	// address to connect to 
	remote.sin_addr.s_addr = inet_addr(address);

	// ipv4 family of addresses
	remote.sin_family = AF_INET;

	// port to connect to
	remote.sin_port = htons(serverPort);

	iRetval = connect(hSocket, (struct sockaddr *)&remote, sizeof(struct sockaddr_in));

	return iRetval;
}


// Default scan 
void defaultScan(){

	printf("Scanning the network for devices...\n");

	printf("This will take some time\n");

	// Create vars for IP address generation
	int blockOne = 10;

	int blockTwo,blockThree,blockFour;

	// create a char array to store the completed address
	char address[16];

	// socket 
	int socket;

	// trying some timeout stuff
	struct timeval timeout;

	timeout.tv_sec = 1;

	timeout.tv_usec = 0;

	int synRetries = 1;

	do{
		// call the function that creates the socket
		socket = socketCreate();

		// Trying timeout stuff
		setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

		// *setsockopt(socket, IPPROTO_TCP, TCP_SYNCNT, &synRetries, sizeof( synRetries));
		// combine the block ints into a char array
		sprintf(address, "%d.%d.%d.%d",blockOne,blockTwo,blockThree,blockFour);

		// print addres confirmation
		printf("\nADDRESS %s\n",address);

		// attempt a connection and print exists if the connection is successful
		if(socketConnect(socket, address, 80) < 0){	

			// shutdown socket after connection fail
			shutdown(socket,1);

		}else{

			printf("\n%s exists\n",address);

			// shutdown socket after connection success
			shutdown(socket,1);
		}

		// block iterations
		blockFour++;

		if(blockFour==256){

			blockThree++;

			blockFour=0;
		}

		if(blockThree == 256){

			blockTwo++;

			blockThree =0;
		}

	}while(blockTwo <=255);
}


// In-depth scan with a report on the open ports
// Takes in the address from getopts
void fullScan(char *address){

	// time variable 
	time_t t = time(NULL);

	// file name array
	char fileName[0x100];

	// make a directory if one does not exist
	// it is faster to attempt to create the dir rather than test if it exists first
	mkdir("Scans", 0777);

	// combine the filename and time var into the filenmame variable
	snprintf(fileName, sizeof(fileName), "Scans/Scan Report %s.txt", asctime(gmtime(&t)));

	// create the file the scan report will go in
	FILE *f = fopen(fileName, "a");

	// if the file cannot be opened or created report the error
	if(f == NULL){

		printf("Report file could not be opened, or could not be created.\n");
	}

	// create a socket array
	int socket[14];

	// int array to store port values
	int port[14] = {20,21,22,23,25,53,139,80,443,445,1433,1434,3306,3389};

	// make the scan report
	fprintf(f,"\n");

	fprintf(f, "<------------------------------------------------------------>\n");

	fprintf(f,"Scan details for a scan performed at %s\n",asctime(gmtime(&t)));

	fprintf(f,"Scanning %s for vulnerable ports\n", address);

	printf("Scanning %s for vulnerable ports.\n", address);

	printf("This may take several minutes.\n");

	// loop through the socket array and port array
	for(int x=0;x < 14;x++){

		// create the socket for any given entry in the socket array
		socket[x] = socketCreate();

		// print and test any given port in the port array
		// prints to console and file
		// only prints to file if the port is open to reduce visual clutter
		printf("\nTesting port: %d\n",port[x]);

		if((socketConnect(socket[x], address, port[x])) < 0){

			// *printf("\nAddress not found\n");

			// *printf("Please view the help menu for more information\n");

			// *return;

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

		// close and shutdown any given socket in socket array
		close(socket[x]);

		shutdown(socket[x],1);
	}

	// print the location of the scan report
	printf("\nScan completed.\nA full report can be found in %s\n", fileName);

	// close the scan report file
	fclose(f);
}


// scans a specific ip address to see if it is open on a given port
// takes both address and port from getopts
void selectScan(char *address, int port){

	// create the socket variable
	int socket;

	// create the socket
	socket = socketCreate();

	// test the given address and port
	if((socketConnect(socket, address, port)) < 0){

		// report the status of the address
		printf("\nPort %d does not exist on address %s", port, address);

		return;

	}else{

		printf("\nPort %d exists on address %s", port, address);

	}

	// shutdown and close the socket
	close(socket);

	shutdown(socket,1);
}


// display help and usage
void help(){

	printf("Help will go here\n");

	return;
}


// main function grabs arguments from the commandline with getopts
int main(int argc, char **argv){

	// int choice;

	// getopts
	// int switchVal;

	// getopts variables and variables to pass through to the scan functions
	int c;

	char *address;

	int port;

	opterr = 0;

	// test the commandline arguments / options and pass to the correct function 
	// accepts -h,-f,-s,-a [string], -p [string]
	// reads until no more options are found
	while((c=getopt(argc,argv,"hdfsa:p:"))!=-1){

		switch(c){

			case 'h':

				help();

				break;

			case 'a':

				// store the char value of -a to the pointer address for pass through
				address = optarg;

				break;

			case 'p':

				// convert the char value of -p to int to pass through to scan functions
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
