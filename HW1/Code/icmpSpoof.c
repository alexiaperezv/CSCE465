#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
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

    memset(buffer, 0, 2048); // zero out the buffer

    /* STEP 1: CREATE A RAW SOCKET */
    sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    if (sd < 0)
    {
        perror("socket() error");
        exit(2);
    }
    printf("Socket created successfully.\n");

    /* STEP 2: SET SOCKET OPTIONS */
    sin.sin_family = AF_INET;                    // address family
    sin.sin_addr.s_addr = inet_addr("10.0.2.4"); // Victim VM IP address

    /* STEP 3: CONSTRUCT PACKET */
    struct iphdr *iph = (struct iphdr *)buffer;                                // ip header
    struct icmphdr *icmph = (struct icmphdr *)(buffer + sizeof(struct iphdr)); // icmp header

    char payload[] = "\x31\x32\x33\x34\x35\x36\x37\x38"; // 1-8 ASCII

    // create IP header
    iph->ihl = 5;                                                                   // header length is always 5
    iph->version = 4;                                                               // IPv4
    iph->tos = 0;                                                                   // may not need this                                                                // type of service
    iph->tot_len = sizeof(payload) + sizeof(struct iphdr) + sizeof(struct icmphdr); // total length of ip datagram
    iph->id = 0xefbe;                                                               // packet id
    iph->frag_off = 0;                                                              // offset
    iph->ttl = 10;                                                                  // time to live                                                                  // offset
    iph->protocol = IPPROTO_ICMP;                                                   // ICMP protocol                                                               // checksum set to 0
    iph->saddr = inet_addr("1.2.3.4");                                              // source ip address                                 // source ip
    iph->daddr = sin.sin_addr.s_addr;                                               // find this address                                       // dest ip                         // get checksum value

    // create ICMP header
    icmph->type = ICMP_ECHO;              // type 8 = echo request
    icmph->code = 0;                      // codr for echo request = 0
    icmph->un.echo.id = htons(0xdeef);    // set id to some 2-byte code
    icmph->un.echo.sequence = htons(0x1); // sequence of packets

    // append payload
    memcpy(buffer + sizeof(struct icmphdr) + sizeof(struct iphdr), payload, sizeof(payload));

    /* STEP 4: SEND PACKET THROUGH RAW SOCKET */
    // compute checksum for validaton
    icmph->checksum = csum((u_short *)icmph, sizeof(struct icmphdr) + sizeof(payload));

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