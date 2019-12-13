/*
Biran Shah
This program generates a random upper case key with spaces with a user defined length to stdout 
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

int main(int argc, char *argv[])
{
    //check to make sure only arguments for this program are: 1: executable file and 2:key length
    if (argc != 2)
    {
        fprintf(stderr, "%s", "wrong number of arguments\n");
    }

    srand(time(NULL)); //random initializer
    long length = strtol(argv[1], NULL, 10);    //convert first arg ptr to int for key length. reference: https://stackoverflow.com/a/9748402

    char randomletter[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ ";    //define string of upper case + a space for key generation

    int i;
    //get a random num from randomletter string and print to stdout. this is the key
    for (i = 0; i < length; i++)
    {
        //get rand number from the character bank, stdout it. 
        int x = rand()%27;  
       printf("%c",randomletter[x]);   
    }
    printf("\n");   //add new line at end of key

    return 0;

}