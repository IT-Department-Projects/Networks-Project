#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Have two arrays.
 * 1. MAC Address to Index Array -> Time Complexity = O(n)
 * 2. Index to Physical Address Array -> 

 * 1. For testcases, have 5 MAC + Logical Addresses
 * 
*/
int main() {

	char physical[20][20];
	char logical[20][20];
	char spare[20][20];

	strcpy(physical[0], "00-14-22-01-23-45");
	strcpy(physical[1], "00-04-DC-01-23-45");
	strcpy(physical[2], "00-40-96-01-23-45");
	strcpy(physical[3], "00-30-BD-01-23-45");
	strcpy(physical[4], "00-14-22-05-64-45");
	
	strcpy(logical[0], "130.57.64.11");
	strcpy(logical[1], "130.57.64.12");
	strcpy(logical[2], "130.57.64.13");
	strcpy(logical[3], "130.57.65.15");
	strcpy(logical[4], "130.57.65.16");

	strcpy(spare[0], "130.57.66.12");
	strcpy(spare[1], "130.57.67.14");
	strcpy(spare[2], "130.57.68.15");
	strcpy(spare[3], "130.57.66.13");

	for(int i = 0; i < 5; i ++) {
		fputs(physical[i], stdout);
		printf(" -> ");
		fputs(logical[i], stdout);
		printf("\n");
	}

	return 0;
}