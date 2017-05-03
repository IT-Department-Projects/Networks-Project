#include <stdio.h>
#include <stdlib.h>
#include <string.h>           // strcpy, memset(), and memcpy()

#include <unistd.h>           // close()
#include <stdbool.h>

#include <netdb.h>            // struct addrinfo
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_TCP, INET_ADDRSTRLEN
#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)
#include <netinet/tcp.h>      // struct tcphdr

#define __FAVOR_BSD           // Use BSD format of tcp header
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.

#include <net/if.h>           // struct ifreq
#include <linux/if_ether.h>   // ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>
#include <errno.h>            // errno, perror()

// Define some constants.
#define ETH_HDRLEN 14  // Ethernet header length
#define IP4_HDRLEN 20  // IPv4 header length
#define TCP_HDRLEN 20  // TCP header length, excludes options data

#include <netdb.h>
#include <netinet/ip_icmp.h> //Provides declarations for icmp header
#include <netinet/udp.h> //Provides declarations for udp header
#include <netinet/if_ether.h>  //For ETH_P_ALL

#include <net/ethernet.h>
#include <sys/time.h>

#include <net/ethernet.h>

// Function prototypes (Client->Server)
uint16_t checksum (uint16_t *, int);
uint16_t tcp4_checksum (struct ip, struct tcphdr, uint8_t *, int);
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);
int *allocate_intmem (int);

//Function Prototypes (Client->Server)
void ProcessPacket(unsigned char* , int);
void print_ip_header(unsigned char* , int);
void print_tcp_packet(unsigned char * , int );
void PrintData(unsigned char*,int);
void PrintActualPayload(unsigned char*,int);
bool crc(void*, int, uint8_t[]);

int count = 0;

FILE *logfile;
struct sockaddr_in source,dest;
int tcp=0,i,j;

char physical[20][20];
char logical[20][20];
char spare[20][20];

// Allocate memory for an array of chars.
char *allocate_strmem (int len) {
    void *tmp;

    if (len <= 0) {
        fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
        exit (EXIT_FAILURE);
    }

    tmp = (char *) malloc (len * sizeof (char));
    
    if (tmp != NULL) {
        memset (tmp, 0, len * sizeof (char));
        return (tmp);
    } 
    else {
        fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
        exit (EXIT_FAILURE);
    }
}

// Allocate memory for an array of unsigned chars.
uint8_t *allocate_ustrmem (int len) {
    void *tmp;

    if (len <= 0) {
        fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
        exit (EXIT_FAILURE);
    }

    tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
    if (tmp != NULL) {
        memset (tmp, 0, len * sizeof (uint8_t));
        return (tmp);
    } 
    else {
        fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
        exit (EXIT_FAILURE);
    }
}

int main (int argc, char **argv) {

    uint8_t g=7,m;
    int i, j, k, status, frame_length, sd, bytes, *ip_flags, *tcp_flags;
    char *interface, *src_ip, *dst_ip;
    struct ip iphdr;
    struct tcphdr tcphdr;
    char *payload, *url, *directory, *filename;
    int payloadlen;
    uint8_t *src_mac, *dst_mac, *ether_frame,*dat;
    struct addrinfo hints, *res;
    struct sockaddr_in *ipv4;
    struct sockaddr_ll device;
    struct ifreq ifr;
    void *tmp;

    // Allocate memory for various arrays.
    src_mac = allocate_ustrmem (6);
    dst_mac = allocate_ustrmem (6);
    ether_frame = allocate_ustrmem (IP_MAXPACKET);
    interface = allocate_strmem (40);
    src_ip = allocate_strmem (INET_ADDRSTRLEN);
    dst_ip = allocate_strmem (INET_ADDRSTRLEN);
    ip_flags = allocate_intmem (4);
    tcp_flags = allocate_intmem (8);
    payload = allocate_strmem (IP_MAXPACKET);
    url = allocate_strmem (40);
    directory = allocate_strmem (80);
    filename = allocate_strmem (80);

    // Set TCP data.
    //strcpy (url, "www.google.com");  // Could be URL or IPv4 address
    strcpy (url, "localhost");
    strcpy (directory, "/");
    strcpy (filename, "filename");
    //sprintf (payload, "GET %s%s HTTP/1.1\r\nHost: %s\r\n\r\n", directory, filename, url);
    sprintf (payload, "c8-5b-76-c8-d1-db");
    payloadlen = strlen (payload);



    // Interface to send packet through.
    strcpy (interface, "eno1");



    // Submit request for a socket descriptor to look up interface.
    if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
      perror ("socket() failed to get socket descriptor for using ioctl() ");
      exit (EXIT_FAILURE);
    }

    // Use ioctl() to look up interface name and get its MAC address.
    memset (&ifr, 0, sizeof (ifr));
    snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
    if (ioctl(sd, SIOCGIFHWADDR, &ifr) < 0) {
        perror ("socket() failed to get socket descriptor for using ioctl()");
        return (EXIT_FAILURE);
    }

    close (sd);

    // MAC address of my comp - 90:2b:34:4a:01:b9
    // MAC address of Ujjwal's comp - 50:eb:1a:90:61:32
     /*
      src_mac[0]=0x50;
      src_mac[1]=0xeb;
      src_mac[2]=0x1a;
      src_mac[3]=0x90;
      src_mac[4]=0x61;
      src_mac[5]=0x32;
     */


      // Copy source MAC address.
    memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));



      // Report source MAC address to stdout.
    printf ("MAC address for interface %s is ", interface);
    for (i=0; i<5; i++) {
        printf ("%02x:", src_mac[i]);
        dst_mac[i]=src_mac[i];
    }
    printf ("%02x\n", src_mac[5]);
    dst_mac[5]=src_mac[5];




      // Find interface index from interface name and store index in
      // struct sockaddr_ll device, which will be used as an argument of sendto().
    memset (&device, 0, sizeof (device));
    if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
        perror ("if_nametoindex() failed to obtain interface index ");
        exit (EXIT_FAILURE);
    }
    printf ("Index for interface %s is %i\n", interface, device.sll_ifindex);




      // Source IPv4 address: you need to fill this out
    strcpy (src_ip, "127.0.0.1");



      // Fill out hints for getaddrinfo().
    memset (&hints, 0, sizeof (struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = hints.ai_flags | AI_CANONNAME;



      // Resolve target using getaddrinfo(). Gets logical address in the network, and stores it in res->ai_addr
    if ((status = getaddrinfo (url, NULL, &hints, &res)) != 0) {
        fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
        exit (EXIT_FAILURE);
    }
    ipv4 = (struct sockaddr_in *) res->ai_addr;
    tmp = &(ipv4->sin_addr);
    if (inet_ntop (AF_INET, tmp, dst_ip, INET_ADDRSTRLEN) == NULL) {
        status = errno;
        fprintf (stderr, "inet_ntop() failed.\nError message: %s", strerror (status));
        exit (EXIT_FAILURE);
    }
    freeaddrinfo (res);



      // Fill out sockaddr_ll.
    device.sll_family = AF_PACKET;
    memcpy (device.sll_addr, src_mac, 6 * sizeof (uint8_t));
    device.sll_halen = 6;




      // IPv4 header

      // IPv4 header length (4 bits): Number of 32-bit words in header = 5
    iphdr.ip_hl = IP4_HDRLEN / sizeof (uint32_t);

      // Internet Protocol version (4 bits): IPv4
    iphdr.ip_v = 4;

      // Type of service (8 bits)
    iphdr.ip_tos = 0;

      // Total length of datagram (16 bits): IP header + TCP header + TCP data
    iphdr.ip_len = htons (IP4_HDRLEN + TCP_HDRLEN + payloadlen);

      // ID sequence number (16 bits): unused, since single datagram
    iphdr.ip_id = htons (0);

      // Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram

      // Zero (1 bit)
    ip_flags[0] = 0;

      // Do not fragment flag (1 bit)
    ip_flags[1] = 1;

      // More fragments following flag (1 bit)
    ip_flags[2] = 0;

      // Fragmentation offset (13 bits)
    ip_flags[3] = 0;

    iphdr.ip_off = htons ((ip_flags[0] << 15)
      + (ip_flags[1] << 14)
      + (ip_flags[2] << 13)
      +  ip_flags[3]);

      // Time-to-Live (8 bits): default to maximum value
    iphdr.ip_ttl = 255;

      // Transport layer protocol (8 bits): 6 for TCP
    iphdr.ip_p = IPPROTO_TCP;



      // Source IPv4 address (32 bits)
    if ((status = inet_pton (AF_INET, src_ip, &(iphdr.ip_src))) != 1) {
        fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
        exit (EXIT_FAILURE);
    }



      // Destination IPv4 address (32 bits)
    if ((status = inet_pton (AF_INET, dst_ip, &(iphdr.ip_dst))) != 1) {
        fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
        exit (EXIT_FAILURE);
    }



      // IPv4 header checksum (16 bits): set to 0 when calculating checksum
    iphdr.ip_sum = 0;
    iphdr.ip_sum = checksum ((uint16_t *) &iphdr, IP4_HDRLEN);




      // TCP header

      // Source port number (16 bits)
    tcphdr.th_sport = htons (60);

      // Destination port number (16 bits)
    tcphdr.th_dport = htons (80);

      // Sequence number (32 bits)
    tcphdr.th_seq = htonl (0);

      // Acknowledgement number (32 bits)
    tcphdr.th_ack = htonl (0);

      // Reserved (4 bits): should be 0
    tcphdr.th_x2 = 0;

      // Data offset (4 bits): size of TCP header in 32-bit words
    tcphdr.th_off = TCP_HDRLEN / 4;

      // Flags (8 bits)

      // FIN flag (1 bit)
    tcp_flags[0] = 0;

      // SYN flag (1 bit)
    tcp_flags[1] = 0;

      // RST flag (1 bit)
    tcp_flags[2] = 0;

      // PSH flag (1 bit)
    tcp_flags[3] = 1;

      // ACK flag (1 bit)
    tcp_flags[4] = 1;

      // URG flag (1 bit)
    tcp_flags[5] = 0;

      // ECE flag (1 bit)
    tcp_flags[6] = 0;

      // CWR flag (1 bit)
    tcp_flags[7] = 0;

    tcphdr.th_flags = 0;
    for (i=0; i<8; i++) {
        tcphdr.th_flags += (tcp_flags[i] << i);
    }


      // Window size (16 bits)
    tcphdr.th_win = htons (65535);


      // Urgent pointer (16 bits): 0 (only valid if URG flag is set)
    tcphdr.th_urp = htons (0);


      // TCP checksum (16 bits)
    tcphdr.th_sum = tcp4_checksum (iphdr, tcphdr, (uint8_t *) payload, payloadlen);





      // Fill out ethernet frame header.

      // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + TCP header + TCP data + CRC)
    frame_length = 6 + 6 + 2 + IP4_HDRLEN + TCP_HDRLEN + payloadlen + 1;

      //memcpy (ether_frame, g, sizeof (g));

      // Destination and Source MAC addresses
    memcpy (ether_frame, dst_mac, 6 * sizeof (uint8_t));
    memcpy (ether_frame + 6, src_mac, 6 * sizeof (uint8_t));

      // Next is ethernet type code (ETH_P_IP for IPv4).
      // http://www.iana.org/assignments/ethernet-numbers
    ether_frame[12] = ETH_P_IP / 256;
    ether_frame[13] = ETH_P_IP % 256;

      // Next is ethernet frame data (IPv4 header + TCP header + TCP data).

      // IPv4 header
    memcpy (ether_frame + ETH_HDRLEN, &iphdr, IP4_HDRLEN * sizeof (uint8_t));

      // TCP header
    memcpy (ether_frame + ETH_HDRLEN + IP4_HDRLEN, &tcphdr, TCP_HDRLEN * sizeof (uint8_t));

      // TCP data
    memcpy (ether_frame + ETH_HDRLEN + IP4_HDRLEN + TCP_HDRLEN, payload, payloadlen * sizeof (uint8_t)); 
      //Accessing from ether_frame[ETH_HDRLEN + IP4_HDRLEN + TCP_HDRLEN], copies 

    m=0;
    memcpy (ether_frame + ETH_HDRLEN + IP4_HDRLEN + TCP_HDRLEN + payloadlen, &m, sizeof (uint8_t));



    //CRC Implementation on Ethernet frame

    dat=ether_frame;
    m=*dat;
    j=128;


    for(i=1;i<frame_length;i++)
    {
    	j=128;
    	for(k=0;k<8;k++)
    	{
    		uint8_t z=m/128;	//to extract MSB of m
    		m*=2;			
    		m+=((dat[i]/j)%2);	//to extract 1 bit of the next byte (to create a virtual flow of bits)

    		if(z)			//to check if XOR operation is to be performed
    			m=m^g;


    		j/=2;			//needed to continue the 'flow of bits'
    	}
    }

    memcpy (ether_frame + ETH_HDRLEN + IP4_HDRLEN + TCP_HDRLEN + payloadlen, &m, sizeof (uint8_t));


      // Submit request for a raw socket descriptor.
    if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
        perror ("socket() failed ");
        exit (EXIT_FAILURE);
    }

     // Send ethernet frame to socket.
    if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
        perror ("sendto() failed");
        exit (EXIT_FAILURE);
    }

      // Close socket descriptor.
    close (sd);

      // Free allocated memory.
    free (src_mac);
    free (dst_mac);
    free (ether_frame);
    free (interface);
    free (src_ip);
    free (dst_ip);
    free (ip_flags);
    free (tcp_flags);
    free (payload);
    free (url);
    free (directory);
    free (filename);




    	int saddr_size,data_size;
	struct sockaddr saddr;

	char *interface;
	struct ifreq ifr;
	int sd;
	uint8_t *machine;	//,*dst=buffer;
	machine = allocate_ustrmem(6);	

	interface = allocate_strmem (40);
	
	// Interface to send packet through.
  	strcpy (interface, "eno1");

	
  	// Submit request for a socket descriptor to look up interface.
  	if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
		perror ("socket() failed to get socket descriptor for using ioctl() ");
		exit (EXIT_FAILURE);
	}


	// Use ioctl() to look up interface name and get its MAC address.
	memset (&ifr, 0, sizeof (ifr));
	snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
  	if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
		perror ("ioctl() failed to get source MAC address ");
		return (EXIT_FAILURE);
	}
	close (sd);
	
  	// Copy source MAC address.
	memcpy (machine, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));
	
	//free(&ifr);
    //free(interface);

	unsigned char *buffer = (unsigned char *) malloc(65536);//Its Big!

	printf("Starting...\n");
		
	sd=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	//setsockopt(sock_raw , SOL_SOCKET , SO_BINDTODEVICE , "eth0" , strlen("eth0")+1);
	
	if(sd < 0) {
		//Print the error with proper message
    	perror("Socket Error");
    	return 1;
	}
	    
	saddr_size = sizeof saddr;
	while(data_size = recvfrom(sd,buffer,65536,0,&saddr,(socklen_t*)&saddr_size)) {
        //saddr_size = sizeof saddr;
        //Receive a packet
    	if(data_size<0) {
    		printf("Recvfrom error , failed to get packets\n");
        		return 1;
    	}
    
        printf("%d\n",data_size);
    
    	if(crc(buffer,data_size,machine)) {
    		logfile=fopen("log.txt","w");
            if(logfile==NULL) {
		    	printf("Unable to create log.txt file.");
			}
			
    		//Now process the packet
			ProcessPacket(buffer,data_size);
			break;
    	}
    	else
    		//printf("Error detected in Ethernet frame\nCannot process data\n");
    	  ;
	}


	close(sd);
	//free(machine);




	uint8_t g=7,m;
    int i, j, k, status, frame_length, sd, bytes, *ip_flags, *tcp_flags;
    char *interface, *src_ip, *dst_ip;
    struct ip iphdr;
    struct tcphdr tcphdr;
    char *payload, *url, *directory, *filename;
    int payloadlen;
    uint8_t *src_mac, *dst_mac, *ether_frame,*dat;
    struct addrinfo hints, *res;
    struct sockaddr_in *ipv4;
    struct sockaddr_ll device;
    struct ifreq ifr;
    void *tmp;

    // Allocate memory for various arrays.
    src_mac = allocate_ustrmem (6);
    dst_mac = allocate_ustrmem (6);
    ether_frame = allocate_ustrmem (IP_MAXPACKET);
    interface = allocate_strmem (40);
    src_ip = allocate_strmem (INET_ADDRSTRLEN);
    dst_ip = allocate_strmem (INET_ADDRSTRLEN);
    ip_flags = allocate_intmem (4);
    tcp_flags = allocate_intmem (8);
    payload = allocate_strmem (IP_MAXPACKET);
    url = allocate_strmem (40);
    directory = allocate_strmem (80);
    filename = allocate_strmem (80);

    // Set TCP data.
    //strcpy (url, "www.google.com");  // Could be URL or IPv4 address
    strcpy (url, "localhost");
    strcpy (directory, "/");
    strcpy (filename, "filename");
    //sprintf (payload, "GET %s%s HTTP/1.1\r\nHost: %s\r\n\r\n", directory, filename, url);
    sprintf (payload, "c8-5b-76-c8-d1-db");
    payloadlen = strlen (payload);



    // Interface to send packet through.
    strcpy (interface, "eno1");



    // Submit request for a socket descriptor to look up interface.
    if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
      perror ("socket() failed to get socket descriptor for using ioctl() ");
      exit (EXIT_FAILURE);
    }

    // Use ioctl() to look up interface name and get its MAC address.
    memset (&ifr, 0, sizeof (ifr));
    snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
    if (ioctl(sd, SIOCGIFHWADDR, &ifr) < 0) {
        perror ("socket() failed to get socket descriptor for using ioctl()");
        return (EXIT_FAILURE);
    }

    close (sd);
























    return (EXIT_SUCCESS);
}

void ProcessPacket(unsigned char* buffer, int size) {
    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    
        if (iph->protocol == 6) { //Check the TCP Protocol and do accordingly...
            print_tcp_packet(buffer,size);
        }
}

void print_ethernet_header(unsigned char* Buffer, int Size) {
    struct ethhdr *eth = (struct ethhdr *)Buffer;
    
    fprintf(logfile,"\n");
    fprintf(logfile, "Ethernet Header\n");
    fprintf(logfile,"   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5]);
    fprintf(logfile, "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4], eth->h_source[5] );
    fprintf(logfile, "   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
}

void print_ip_header(unsigned char* Buffer, int Size) {
    print_ethernet_header(Buffer , Size);

    unsigned short iphdrlen;
        
    struct iphdr *iph=(struct iphdr *)(Buffer+sizeof(struct ethhdr));
    iphdrlen =iph->ihl*4;
    
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    
    fprintf(logfile, "\n");
    fprintf(logfile, "IP Header\n");
    fprintf(logfile, "   |-IP Version        : %d\n",(unsigned int)iph->version);
    fprintf(logfile, "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    fprintf(logfile, "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    fprintf(logfile, "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    fprintf(logfile, "   |-Identification    : %d\n",ntohs(iph->id));
    //fprintf(logfile ,"   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
    //fprintf(logfile ,"   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
    //fprintf(logfile ,"   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
    fprintf(logfile, "   |-TTL      : %d\n",(unsigned int)iph->ttl);
    fprintf(logfile, "   |-Protocol : %d\n",(unsigned int)iph->protocol);
    fprintf(logfile, "   |-Checksum : %d\n",ntohs(iph->check));
    fprintf(logfile, "   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
    fprintf(logfile, "   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
}

void print_tcp_packet(unsigned char* Buffer, int Size) {
    unsigned short iphdrlen;
    
    struct iphdr *iph = (struct iphdr *)( Buffer + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;
    
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
            
    int header_size = sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
   
    fprintf(logfile , "\n\n***********************TCP Packet*************************\n");
        
    print_ip_header(Buffer,Size);
        
    fprintf(logfile, "\n");
    fprintf(logfile, "TCP Header\n");
    fprintf(logfile, "   |-Source Port      : %u\n",ntohs(tcph->source));
    fprintf(logfile, "   |-Destination Port : %u\n",ntohs(tcph->dest));
    fprintf(logfile, "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    fprintf(logfile, "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    fprintf(logfile, "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    //fprintf(logfile , "   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
    //fprintf(logfile , "   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
    fprintf(logfile, "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    fprintf(logfile, "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    fprintf(logfile, "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    fprintf(logfile, "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    fprintf(logfile, "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    fprintf(logfile, "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    fprintf(logfile, "   |-Window         : %d\n",ntohs(tcph->window));
    fprintf(logfile, "   |-Checksum       : %d\n",ntohs(tcph->check));
    fprintf(logfile, "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    fprintf(logfile, "\n");
    fprintf(logfile, "                        DATA Dump                         ");
    fprintf(logfile, "\n");
        
    fprintf(logfile, "IP Header\n");
    PrintData(Buffer,iphdrlen);
        
    fprintf(logfile, "TCP Header\n");
    PrintData(Buffer+iphdrlen,tcph->doff*4);
        
    fprintf(logfile, "Data Payload\n");
    PrintActualPayload(Buffer + header_size , Size - header_size );
    
    fprintf(logfile, "CRC Code\n");
    PrintData(Buffer + Size - 1 , sizeof(uint8_t) );
                        
    fprintf(logfile, "\n###########################################################");
}


void PrintData(unsigned char* data , int Size) {
   
    int i , j, l=16;
    for(i=0 ; i < Size ; i++) {
        if(i!=0&&i%l==0) { //if one line of hex printing is complete...
            fprintf(logfile,"        ");
            for(j=i-l;j<i;j++) {
                if(data[j]>=32&&data[j]<=128){
                    fprintf(logfile,"%c",(unsigned char)data[j]); //if its a number or alphabet
                    //if(j!=0)
                    	//printf("%c",(unsigned char)data[j]);
                }
                else fprintf(logfile,"."); //otherwise print a dot
            }
            fprintf(logfile,"\n");
        }
        
        if(i%16==0) fprintf(logfile,"  ");
            fprintf(logfile,"%02X",(unsigned int)data[i]);
                
        if(i==Size-1) {//print the last spaces
            for(j=0;j<l-1-i%l;j++) {
                fprintf(logfile,"  "); //extra spaces
            }
            
            fprintf(logfile,"        ");
            
            for(j=i-i%l;j<=i;j++) {
                if(data[j]>=32&&data[j]<=128) {
                    fprintf(logfile,"%c",(unsigned char)data[j]);
                    //printf("%c",(unsigned char)data[j]);
                }
                else {
                    fprintf(logfile,".");
                }
            }
            
            fprintf(logfile,"\n");
        }
    }
    printf("\n");
}


void PrintActualPayload(unsigned char* data , int Size) {
 //    int flag = 0;
    
 //    char *ip;
 //    sprintf (ip, "255.255.255.255");
 //    int ip_len = strlen (ip);
    
 //    for(j = 0; j < ip_len; j++)
 //         fprintf(logfile, "%c", (unsigned char)ip[j]);
 //    fprintf(logfile, "\n");
    
 //    strcpy(physical[0], "00-14-22-01-23-45");
	// strcpy(physical[1], "00-04-DC-01-23-45");
	// strcpy(physical[2], "00-03-BD-01-76-42");
	// strcpy(physical[3], "00-30-BD-01-23-45");
	// strcpy(physical[4], "00-14-22-05-64-45");
	
	// strcpy(logical[0], "130.57.64.11");
	// strcpy(logical[1], "130.57.64.12");
	// strcpy(logical[2], "130.57.64.13");
	// strcpy(logical[3], "130.57.65.15");
	// strcpy(logical[4], "130.57.65.16");

	// strcpy(spare[0], "130.57.66.12");
	// strcpy(spare[1], "130.57.67.14");
	// strcpy(spare[2], "130.57.68.15");
	// strcpy(spare[3], "130.57.66.13");

 //    for(int i = 0; i < 5; i ++) {
 //        if(strncmp(physical[i], data, 16) == 0) {
 //            flag = 1;
 //            fprintf(logfile, "\nSuccess MAC found\n");
            
 //            for(int j = 0; j < 12; j++) {  
 //               fprintf(logfile, "%c", logical[i][j]);
 //            }
 //        }
 //    }
 //  fprintf(logfile, "\n");

 //    if(!flag) {
 //        fprintf(logfile, "\nNew Address Allocated\n");
 //        for(int j = 0; j < 12; j ++) {
 //            fprintf(logfile, "%c", spare[0][j]);
 //            count++;
 //        }
 //        fprintf(logfile,"\n");
 //    } 
    
    int i , j, l=64;
    for(i=0 ; i < Size ; i++) {
        if(i!=0&&i%l==0) { //if one line of hex printing is complete...
        
            fprintf(logfile,"        ");
            
            for(j=i-l;j<i;j++) {
                if(data[j]>=32&&data[j]<=128){
                    fprintf(logfile,"%c",(unsigned char)data[j]); //if its a number or alphabet
                	printf("%c",(unsigned char)data[j]);
                }
                else fprintf(logfile,"."); //otherwise print a dot
            }
            
            fprintf(logfile,"\n");
        }        
        
        if(i==Size-1) {//print the last spaces
            for(j=0;j<l-1-i%l;j++) {
                fprintf(logfile,"  "); //extra spaces
            }
            
            fprintf(logfile,"        ");
            
            for(j=i-i%l;j<=i;j++) {
                if(data[j]>=32&&data[j]<=128) {
                    fprintf(logfile,"%c",(unsigned char)data[j]);
                    //printf("%c",(unsigned char)data[j]);
                }
                else {
                    fprintf(logfile,".");
                }
            }
            
            fprintf(logfile,"\n");
        }
    }
    printf("\n");
}

int errorMAC(void* buffer, int size, uint8_t machine[]) {
/*	char *interface;
	struct ifreq ifr;
	int sd;
	uint8_t i,machine[6],*dst=buffer;
	//machine = (uint8_t)allocate_ustrmem(6);	

	// Interface to send packet through.
  	strcpy (interface, "eno1");

  	// Submit request for a socket descriptor to look up interface.
  	if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
    		perror ("socket() failed to get socket descriptor for using ioctl() ");
    		exit (EXIT_FAILURE);
	}


	// Use ioctl() to look up interface name and get its MAC address.
	memset (&ifr, 0, sizeof (ifr));
	snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
  	if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
		perror ("ioctl() failed to get source MAC address ");
		return (EXIT_FAILURE);
	}
	close (sd);
  
  	// Copy source MAC address.
	memcpy (machine, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));

*/

	uint8_t i,*dst=buffer;
	//src+=6;
	for(i=0;i<6;i++){
		printf("%d %d\n",machine[i],dst[i]);
		//src[i]=(uint8_t)buffer[i];
		//dst[i]=(uint8_t)buffer[i+6];	
		if(machine[i]!=dst[i]){
			//printf("Wrong packet recieved..\n");
			return 1;
		}
	}
	//for(i=0;i<6;i++)
	//	printf("%d %d\n",src[i],dst[i]);
	return 0;
}

bool crc(void* buffer, int size, uint8_t machine[]) {
	if(errorMAC(buffer,size,machine))
		return 0;
	
	uint8_t *data=buffer;
	
	uint8_t g=7,m=data[0];
	//m=m^g;
	int i,k,j=128,z;
	
	
	for(i=1;i<size;i++) {
		j=128;
		for(k=0;k<8;k++) {
			uint8_t z=m/128;	//to extract MSB of m
			m*=2;			
			m+=((data[i]/j)%2);	//to extract 1 bit of the next byte (to create a virtual flow of bits)
				
			if(z)			//to check if XOR operation is to be performed
				m=m^g;
				
				
			j/=2;			//needed to continue the 'flow of bits'
		}
	}
	
	if(m){
		printf("Error detected through CRC encoding\nCannot process\n");
		return 0;
	}
	return 1;
}


// Computing the internet checksum (RFC 1071).
// Note that the internet checksum does not preclude collisions.
uint16_t checksum (uint16_t *addr, int len) {
    int count = len;
    register uint32_t sum = 0;
    uint16_t answer = 0;

    // Sum up 2-byte values until none or only one byte left.
    while (count > 1) {
        sum += *(addr++);
        count -= 2;
    }

    // Add left-over byte, if any.
    if (count > 0) {
        sum += *(uint8_t *) addr;
    }

    // Fold 32-bit sum into 16 bits; we lose information by doing this,
    // increasing the chances of a collision.
    // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // Checksum is one's compliment of sum.
    answer = ~sum;

    return (answer);
}

// Build IPv4 TCP pseudo-header and call checksum function.
uint16_t tcp4_checksum (struct ip iphdr, struct tcphdr tcphdr, uint8_t *payload, int payloadlen) {
    uint16_t svalue;
    char buf[IP_MAXPACKET], cvalue;
    char *ptr;
    int i, chksumlen = 0;

    ptr = &buf[0];  // ptr points to beginning of buffer buf

    // Copy source IP address into buf (32 bits)
    memcpy (ptr, &iphdr.ip_src.s_addr, sizeof (iphdr.ip_src.s_addr));
    ptr += sizeof (iphdr.ip_src.s_addr);
    chksumlen += sizeof (iphdr.ip_src.s_addr);

    // Copy destination IP address into buf (32 bits)
    memcpy (ptr, &iphdr.ip_dst.s_addr, sizeof (iphdr.ip_dst.s_addr));
    ptr += sizeof (iphdr.ip_dst.s_addr);
    chksumlen += sizeof (iphdr.ip_dst.s_addr);

    // Copy zero field to buf (8 bits)
    *ptr = 0; ptr++;
    chksumlen += 1;

    // Copy transport layer protocol to buf (8 bits)
    memcpy (ptr, &iphdr.ip_p, sizeof (iphdr.ip_p));
    ptr += sizeof (iphdr.ip_p);
    chksumlen += sizeof (iphdr.ip_p);

    // Copy TCP length to buf (16 bits)
    svalue = htons (sizeof (tcphdr) + payloadlen);
    memcpy (ptr, &svalue, sizeof (svalue));
    ptr += sizeof (svalue);
    chksumlen += sizeof (svalue);

    // Copy TCP source port to buf (16 bits)
    memcpy (ptr, &tcphdr.th_sport, sizeof (tcphdr.th_sport));
    ptr += sizeof (tcphdr.th_sport);
    chksumlen += sizeof (tcphdr.th_sport);

    // Copy TCP destination port to buf (16 bits)
    memcpy (ptr, &tcphdr.th_dport, sizeof (tcphdr.th_dport));
    ptr += sizeof (tcphdr.th_dport);
    chksumlen += sizeof (tcphdr.th_dport);

    // Copy sequence number to buf (32 bits)
    memcpy (ptr, &tcphdr.th_seq, sizeof (tcphdr.th_seq));
    ptr += sizeof (tcphdr.th_seq);
    chksumlen += sizeof (tcphdr.th_seq);

    // Copy acknowledgement number to buf (32 bits)
    memcpy (ptr, &tcphdr.th_ack, sizeof (tcphdr.th_ack));
    ptr += sizeof (tcphdr.th_ack);
    chksumlen += sizeof (tcphdr.th_ack);

    // Copy data offset to buf (4 bits) and
    // copy reserved bits to buf (4 bits)
    cvalue = (tcphdr.th_off << 4) + tcphdr.th_x2;
    memcpy (ptr, &cvalue, sizeof (cvalue));
    ptr += sizeof (cvalue);
    chksumlen += sizeof (cvalue);

    // Copy TCP flags to buf (8 bits)
    memcpy (ptr, &tcphdr.th_flags, sizeof (tcphdr.th_flags));
    ptr += sizeof (tcphdr.th_flags);
    chksumlen += sizeof (tcphdr.th_flags);

    // Copy TCP window size to buf (16 bits)
    memcpy (ptr, &tcphdr.th_win, sizeof (tcphdr.th_win));
    ptr += sizeof (tcphdr.th_win);
    chksumlen += sizeof (tcphdr.th_win);

    // Copy TCP checksum to buf (16 bits)
    // Zero, since we don't know it yet
    *ptr = 0; ptr++;
    *ptr = 0; ptr++;
    chksumlen += 2;

    // Copy urgent pointer to buf (16 bits)
    memcpy (ptr, &tcphdr.th_urp, sizeof (tcphdr.th_urp));
    ptr += sizeof (tcphdr.th_urp);
    chksumlen += sizeof (tcphdr.th_urp);

    // Copy payload to buf
    memcpy (ptr, payload, payloadlen);
    ptr += payloadlen;
    chksumlen += payloadlen;

    // Pad to the next 16-bit boundary
    for (i=0; i<payloadlen%2; i++, ptr++) {
        *ptr = 0;
        ptr++;
        chksumlen++;
    }

    return checksum ((uint16_t *) buf, chksumlen);
}

// Allocate memory for an array of ints.
int *allocate_intmem (int len) {
    void *tmp;

    if (len <= 0) {
        fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_intmem().\n", len);
        exit (EXIT_FAILURE);
    }

    tmp = (int *) malloc (len * sizeof (int));
    if (tmp != NULL) {
        memset (tmp, 0, len * sizeof (int));
        return (tmp);
    } 
    else {
        fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_intmem().\n");
        exit (EXIT_FAILURE);
    }
}