/*
Biran Shah
This program accepts a connection from the client (up to 5), gets a single sequence of data from the client and 
...parses it into the key and plain text, ciphers the text, then sends back the ciphered text back to the client, otp_enc
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
//max buffer size 
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
				const char ch = '*';	//signals end of file (piazza post 133 adaptation)
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
				fullText[incomingLength-1] = '\0';	//get rid of signal for ciphering stuff
		
				const char s[2] = ".";	//for strtok b/w key and plaintext strings
  				char *token;
   
  				
   				token = strtok(fullText, s); //get 1st token aka key
//         		printf( " %s\n", token );
    			int keysize = strlen(token);
//    			printf("keysize is: %d\n", keysize);
    			char keystring[MAX];		//to store key
    			memset(keystring, '\0',sizeof(keystring));
    			strcpy(keystring,token);
//    			printf("key string is:%s\n", keystring);

    			token = strtok(NULL, s);
    			int plaintextsize = strlen(token);
//    			printf("plaintextsize is: %d\n", plaintextsize);
    			char plaintextstring[MAX];	//to store plaintext
    			memset(plaintextstring, '\0',sizeof(plaintextstring));
    			strcpy(plaintextstring,token);
//    			printf("plaintext string is:%s\n", plaintextstring);

				char bank[]="ABCDEFGHIJKLMNOPQRSTUVWXYZ ";		//made this to use as a char--int conversion
//				printf("plaintextsize is: %d\n", plaintextsize);
   
    /****cipher explanation: 
	 * 1. set vars
	 * 2. in first for loop, convert both key and plaintext char strings into int strings
	 * ...this is done by using the "bank" string defined above as reference for matching the character
	 * ...and using both inner for loops to set a number into respective key and plaintext int arrays
	 */
    int i,j,k;
    int text[MAX];
    int key[MAX];
    int banksize = strlen(bank);
    int secretINTS[MAX];
    

	for (i = 0; i<plaintextsize; i++)
	{
	    for (j=0; j<banksize;j++)
	    {
	        if (plaintextstring[i]==bank[j])
	        {
	            text[i] = j;
	            break;
	        }
	        
	    }
	    for (k=0; k<banksize;k++)
	    {
	        if (keystring[i]==bank[k])
	        {
	            key[i] = k;
	            break;
	        }
	        
	    }
		  /****cipher explanation: part 2:
		   * 3. do the onetimepad encryption by summing the key and plaintext INTs and
		   * ...saving them into a new INT arr. then modulo each element in the array.
		   */
        secretINTS[i]=(text[i]+key[i]);
        secretINTS[i]= MOD((secretINTS[i]),b);
        
	    
	  
	}
	/* ***cipher explanation: part3:
	* 4. now, convert the INTs from the one time pad method arr back into chars in a new 
	*...char arr using the bank array as reference.
	*/
    int x,y,z;
	char secretAlpha[MAX];
	for (x=0; x<plaintextsize;x++)
	{
	        secretAlpha[x] = bank[secretINTS[x]]; 
	}
//	printf("secretAlpha Length is: %d\n", sizeof(secretAlpha));
//    printf("Secret ALPHA key:%s\n", secretAlpha);
    

    int alphaLen = strlen(secretAlpha);
	//add back the signal, *, and then send back to client
	strcpy(sendback, secretAlpha);
	strcat(sendback, "*");


				int status = 0;
				int loop = strlen(sendback);
//		printf("SERVER: LOOP IS: %d\n",loop);
				while (loop > status)	//here: keeps sending chunks of data till done bc sometimes not possible to send it all in one go

				{
					charsRead = send(establishedConnectionFD, sendback, strlen(sendback), 0);
					status = (status + charsRead);
				}


				close(establishedConnectionFD); // Close the existing socket which is connected to the client
			}

			default:
			{
				childCount++;		//spam line, not sure what to do here.
			//close(establishedConnectionFD);
			}
		}	

	}

	close(listenSocketFD); // Close the listening socket
	return 0; 
}
