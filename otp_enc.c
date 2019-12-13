/*
Biran Shah
This program opens and checks the plain text and key files to ensure both of its validity, and then sends them to the server, otp_enc_d.
...This program than stdouts the output of the ciphered message
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 

void error(const char *msg) { perror(msg); exit(0); } // Error function used for reporting issues

int main(int argc, char *argv[])
{
	//check number of arguments
	if (argc != 4)
    {
        fprintf(stderr, "%s", "wrong number of arguments\n");
		exit(0);
    }

	//check files for length and valid characters
	char *plainBuffer =0;
    int plainLength;
    FILE * plainFilePTR = fopen(argv[1], "rb");
	//plaintext file open/read/validate
    if (plainFilePTR)
    {
        fseek (plainFilePTR, 0, SEEK_END);	//move file ptr to end
        plainLength = ftell (plainFilePTR);	//get size for file
        fseek (plainFilePTR, 0, SEEK_SET);	//move file ptr back to front
        plainBuffer = malloc (plainLength);	//alloc mem for plain text file contents 
    if (plainBuffer)
    {	//read plaintext file content and store into plainBuffer
        fread (plainBuffer, 1, plainLength, plainFilePTR);	
    }
    fclose (plainFilePTR);
    }
	plainBuffer[plainLength-1] = '.';	//add . for later use
    strcat(plainBuffer, "*");

    //check plaintext for valid content (ie no special chars)
    int i;
    for (i =0; i < plainLength-1; i++)  //ignores terminating null
    {
        //if a space, or upper case letter, then fine, else print error and exit with status to 1
         if( !((plainBuffer[i] == ' ') || (plainBuffer[i]>='A' && plainBuffer[i]<='Z')))
         {	//if erroneous content, exit 
		 	fprintf(stderr, "%s", "this is not a valid file (upper case and spaces only)\n");
            exit(1);  
         }      
    }
	//get mykey size and contents
    char keyBuffer[300000];
    int keyLength;
    int mykey;
	ssize_t getKey;
	//open mykey, then read line, then move file ptr to end to get key size
    mykey = open(argv[2], O_RDONLY);
	getKey = read(mykey, keyBuffer, 300000);      
    keyLength = lseek(mykey, 0, SEEK_END);
	//make sure key length greater plaintext file
    if (!(keyLength > plainLength))
	{  
		fprintf(stderr, "%s", "key is shorter than plaintext\n");
		exit(1);
	}
	keyBuffer[keyLength-1] = '.';	//add . for later use for reading buffer in otp_enc_d

	//get the size of the string needed to send over to otp_enc_d later on
	int bufferSize = keyLength + plainLength;
	bufferSize = bufferSize + 100;	//add extra room for special chars I add 

    //this creates the final buffer to send to the server
	char buffer[bufferSize];
	memset(buffer, '\0', bufferSize);

	strcat(buffer, keyBuffer);
	strcat(buffer, plainBuffer);

//	printf("final buffer is: %s\n", buffer);
    int bufferLength = strlen(buffer);

	int socketFD, portNumber, charsWritten, charsRead;
	struct sockaddr_in serverAddress;
	struct hostent* serverHostInfo;

    
	

	// Set up the server address struct
	memset((char*)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
	portNumber = atoi(argv[3]); // Get the port number, convert to an integer from a string
	serverAddress.sin_family = AF_INET; // Create a network-capable socket
	serverAddress.sin_port = htons(portNumber); // Store the port number
	serverHostInfo = gethostbyname("localhost"); // Convert the machine name into a special form of address
	if (serverHostInfo == NULL) { fprintf(stderr, "CLIENT: ERROR, no such host\n"); exit(0); }
	memcpy((char*)&serverAddress.sin_addr.s_addr, (char*)serverHostInfo->h_addr, serverHostInfo->h_length); // Copy in the address

	// Set up the socket
	socketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
	if (socketFD < 0) error("CLIENT: ERROR opening socket");
	
	// Connect to server
	if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) // Connect socket to address
		error("CLIENT: ERROR connecting");

	// Send message to server
    //loop adapted via multiserver example on lecture 4.3
   
//printf("CLIENT: buffer length: %d\n", bufferLength);

    int status = 0;
    int received;
    //send concatenated mykey and plaintext to otp_enc_d. 
    while (bufferLength > status)
    {
        charsWritten = send(socketFD, buffer, strlen(buffer), 0); // Write to the server
        status = (status + charsWritten);   //to track when all buffer contents have been sent

	    if (charsWritten < 0) error("CLIENT: ERROR writing to socket");
	    if (charsWritten < strlen(buffer)) printf("CLIENT: WARNING: Not all data written to socket!\n");
    }


    //for receiving ciphered text from otp_enc_d
    //from piazza post 133: add seq at end of message and loop until that sequence is received. Here the sequence is an asterik, * 
    char secretCode[bufferLength];
    memset(secretCode, '\0', sizeof(secretCode));
    char packets[10000]; 
    const char ch = '*';
    if((strchr(secretCode,ch)==NULL))   
    {
        do  //keep receiving bits of the incoming sequence until signal, *, found
        {
            //reset buffer for each loop until all data received
            memset(packets, '\0', sizeof(packets));  
            charsRead = recv(socketFD, packets, sizeof(packets)-1,0);
            strcat(secretCode, packets);    //form final data buffer

            if (charsRead < 0) error("ERROR reading from socket"); 

        }   while(strchr(secretCode,ch) == NULL);   //once * found, data done sending
    }

    int encryptLength = strlen(secretCode);
    secretCode[encryptLength - 1] = '\0';   //get rid of the * on the end to send to stdout

  printf("%s", secretCode);
  printf("\n");

	close(socketFD); // Close the socket
	return 0;
}


