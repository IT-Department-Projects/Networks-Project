#include <stdio.h>
#include <stdlib.h>

int main() {
	/*
	* Input MAC Address into STDIN
	*/
	char data[64];
    if (fgets(data, sizeof data, stdin)) {
        // input has worked, do something with data
    	fputs(data, stdout);
    }

    /*
	* Search for Logical Address in Dictionary
	*/

    return 0;
}