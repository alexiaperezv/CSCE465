#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <inttypes.h>

// checksum function
unsigned short csum(unsigned short *buf, int len)
{
    unsigned long sum;
    for (sum = 0; len > 0; len--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

int main()
{
    int sd;                 // socket
    struct sockaddr_in sin; // socket transport address
    char buffer[2048];      // buffer

    struct iphdr *iph = (struct iphdr *)buffer;                             // ip header
    struct udphdr *udph = (struct udphdr *)(buffer + sizeof(struct iphdr)); //udp header

    u_int16_t src_port, dst_port; // ports
    u_int32_t src_addr, dst_addr; // ip addresses

    memset(buffer, 0, 2048);         // zero out the buffer
    src_addr = inet_addr("1.2.3.4"); // random source ip
    src_port = 1234;                 // random source port

    printf("Enter destination ip: ");
    char dstInputIP[50];              // string variable to store user input (dest ip)
    scanf("%s", dstInputIP);          // gets destination ip from user input
    dst_addr = inet_addr(dstInputIP); //convert user input ip string to ip address type

    printf("\nEnter destination port: ");
    char dstInputPort[50];         // string variable to store user input (dest port)
    scanf("%s", dstInputPort);     // gets destination port from user input
    dst_port = atoi(dstInputPort); // convert user input port string to unsigned int

    /* STEP 1: CREATE A RAW SOCKET */
    sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sd < 0)
    {
        perror("socket() error");
        exit(2);
    }
    printf("Socket created successfully.\n");

    /* STEP 2: SET SOCKET OPTIONS */
    // tell kernel to not fill up packet structure
    int one = 1;
    const int *val = &one;
    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        perror("setsockpot() error");
        exit(2);
    }
    printf("Socket option IP_HDRINCL set successfully.\n");

    sin.sin_family = AF_INET;       // address family
    sin.sin_addr.s_addr = dst_addr; // ip address
    sin.sin_port = htons(dst_port); // port number

    /* STEP 3: CONSTRUCT PACKET */
    // create IP header
    iph->ihl = 5;                                                // header length is always 5
    iph->version = 4;                                            // IPv4
    iph->tos = 16;                                               // type of service
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr); // total length of ip datagram
    iph->id = htons(54321);                                      // packet id
    iph->ttl = IPDEFTTL;                                         // time to live
    iph->protocol = IPPROTO_UDP;                                 // UDP
    iph->saddr = src_addr;                                       // source ip
    iph->daddr = dst_addr;                                       // dest ip

    // create UDP header
    udph->source = htons(src_port);           // udp source port
    udph->dest = htons(dst_port);             // udp destination port
    udph->len = htons(sizeof(struct udphdr)); // total length of UDP datagram

    /* STEP 4: SEND PACKET THROUGH RAW SOCKET */
    // calculate checksum
    iph->check = csum((unsigned short *)buffer, sizeof(struct iphdr) + sizeof(struct udphdr));

    // send packet
    if (sendto(sd, buffer, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
    {
        perror("sendto() failed");
        exit(3);
    }
    printf("Packet sent successfully.\n");

    // close socket
    close(sd);

    return 0;
}