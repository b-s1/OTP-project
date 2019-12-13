/*
Biran Shah
This program accepts a connection from the client (up to 5), gets a single sequence of data from the client and 
...parses it into the key and ciphered text, deciphers the text, then sends back the deciphered text back to the client, otp_dec
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>

//for modulo and encrypting
//reference: https://www.lemoda.net/c/modulo-operator/
#define MOD(a,b) ((((a)%(b))+(b))%(b))
int b =27;
int MAX = 300000;

void error(const char *msg) { perror(msg); exit(1); } // Error function used for reporting issues

int main(int argc, char *argv[])
{
	int listenSocketFD, establishedConnectionFD, portNumber, charsRead;
	socklen_t sizeOfClientInfo;
	struct sockaddr_in serverAddress, clientAddress;

	if (argc < 2) { fprintf(stderr,"USAGE: %s port\n", argv[0]); exit(1); } // Check usage & args

	// Set up the address struct for this process (the server)
	memset((char *)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
	portNumber = atoi(argv[1]); // Get the port number, convert to an integer from a string
	serverAddress.sin_family = AF_INET; // Create a network-capable socket
	serverAddress.sin_port = htons(portNumber); // Store the port number
	serverAddress.sin_addr.s_addr = INADDR_ANY; // Any address is allowed for connection to this process

	// Set up the socket
	listenSocketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
	if (listenSocketFD < 0) error("ERROR opening socket");

	// Enable the socket to begin listening
	if (bind(listenSocketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) // Connect socket to port
		error("ERROR on binding");
	listen(listenSocketFD, 5); // Flip the socket on - it can now receive up to 5 connections

	int childCount=0;
	while (1) 
	{
		// Accept a connection, blocking if one is not available until one connects
		sizeOfClientInfo = sizeof(clientAddress); // Get the size of the address for the client that will connect
		establishedConnectionFD = accept(listenSocketFD, (struct sockaddr *)&clientAddress, &sizeOfClientInfo); // Accept
		if (establishedConnectionFD < 0) error("ERROR on accept");
//		printf("SERVER: Connected Client at port %d\n", ntohs(clientAddress.sin_port));



		pid_t spawnPid = -5;
		//start child process
		spawnPid = fork();
		switch (spawnPid)
		{
			//if error spawning child proc
    		case -1: 
    		{
      			perror("hull breach!\n"); 
    		}


			case 0:
			{
				//get in string from client and store into fullText.
				//piazza post 133: had problems with plaintext4, but I needed to accept chunks of the data at a time
				//so I used a loop as suggested.
				char buffer[10000];
				char fullText[300000];
				memset(fullText, '\0', 300000);
				const char ch = '*';		//signals end of file (piazza post 133 adaptation)
				if ((strchr(fullText, ch) == NULL))
				{
					do
					{
						memset(buffer, '\0', sizeof(buffer));	//need to clear buffer each loop until all data received
						charsRead = recv(establishedConnectionFD, buffer, sizeof(buffer) - 1, 0); // Read the client's message from the socket
						strcat(fullText, buffer);	//append full string buffer
						if (charsRead < 0) error("ERROR reading from socket");
					}while(strchr(fullText, ch) == NULL);	//keep going until signal found, *
				}	

				char sendback[300000];	//for sending back
				int incomingLength = strlen(fullText);
				fullText[incomingLength-1] = '\0';	//get rid of signal for UNciphering stuff

				const char s[2] = ".";	//for strtok b/w key and plaintext strings
  				char *token;
   
  				
   				token = strtok(fullText, s);	//get 1st token aka key
//         		printf( " %s\n", token );
    			int keysize = strlen(token);
//    			printf("keysize is: %d\n", keysize);
    			char keystring[MAX];	//to store key
    			memset(keystring, '\0',sizeof(keystring));
    			strcpy(keystring,token);
//    			printf("key string is:%s\n", keystring);

    			token = strtok(NULL, s);
    			int plaintextsize = strlen(token);
//    			printf("plaintextsize is: %d\n", plaintextsize);
    			char plaintextstring[MAX];
    			memset(plaintextstring, '\0',sizeof(plaintextstring));
    			strcpy(plaintextstring,token);
//    			printf("plaintext string is:%s\n", plaintextstring);

				char bank[]="ABCDEFGHIJKLMNOPQRSTUVWXYZ ";		//made this to use as a char--int conversion
				int banksize = strlen(bank);
//				printf("plaintextsize is: %d\n", plaintextsize);

    
  /****DEcipher explanation: 
	 * 1. set vars
	 * 2. in first for loop, convert both key and ciphered text strings into int strings
	 * ...this is done by using the "bank" string defined above as reference for matching the character
	 * ...and using both inner for loops to set a number into respective key and ciphered int arrays
	 *  NOTE: variable names are same from otp_dec_d file, hence the oddity when following along
	 */
    int x, y, z;
    int alphaLen = strlen(plaintextstring);
//   printf("secretAlpha length: %d\n", alphaLen);
    int alphaDec[MAX];
    int keyDec[MAX];
    
    int finalKeyINT[alphaLen];
    
    for (x=0; x<alphaLen;x++)
    {
        for(y=0; y<banksize;y++)
        {
            if (plaintextstring[x]==bank[y])
            {
                alphaDec[x] = y;
                break;
            }
        }

        
        for(z=0; z<banksize;z++)
        {
            if (keystring[x]==bank[z])
            {
                keyDec[x] = z;
                break;
            }
        }
		/****DEcipher explanation: part 2:
		   * 3. do reverse onetimepad encryption by subtracting ciphered text INTs by the key INTs and
		   * ...saving them into a new INT arr. then modulo each element in the array.
		   */

        finalKeyINT[x] = (alphaDec[x] - keyDec[x]);
        finalKeyINT[x] = MOD((finalKeyINT[x]), b);


	} 
//	printf("finalKeyINT length is: %d\n", sizeof(finalKeyINT));
//    printf("got to here\n");

	/* ***DEcipher explanation: part3:
	* 4. now, convert the INTs from the reverse one time pad method arr back into chars in a new 
	*...char arr using the bank array as reference.
	*/
    char final[MAX];
    
    	for (x=0; x<alphaLen;x++)
	{
	        final[x] = bank[finalKeyINT[x]]; 
	}
//	printf("final size is: %d\n", sizeof(final));
//	printf("\nfinal deciphyerd is:%s\n\n", final);	
	strcpy(sendback, final);
	strcat(sendback, "*");	//add back the signal, *, and then send back to client

//		printf("\n\n\n\n\n\nSERVER: I received this from the client: %s\n\n\n", fullText);


				int status = 0;
				int loop = strlen(sendback);
				while (loop > status)	//(as mentioned piazza post 133)here: keeps sending chunks of data till done bc sometimes not possible to send it all in one go
				{
					charsRead = send(establishedConnectionFD, sendback, strlen(sendback), 0);
					status = (status + charsRead);
				}


				close(establishedConnectionFD); // Close the existing socket which is connected to the client
			}

			default:
			{
				childCount++;	//spam line, not sure what to do here.
			//close(establishedConnectionFD);
			}
		}	

	}

	close(listenSocketFD); // Close the listening socket
	return 0; 
}
