#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <signal.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdint.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <time.h>
#include <stdbool.h>


/* -------------------------------- MACROS ---------------------------------------*/

#define PING_PKT_SIZE 64 // in bytes
#define MIKROSECONDS_IN_SECONDS 1000000
#define BUFF_RECV_SIZE 4096 

/* ------------------------------- DATA TYPES ------------------------------------*/

#pragma pack(push, 1)
typedef struct ping_pkt
{
    struct icmphdr hdr;
    struct timeval timestamp;
    char msg[PING_PKT_SIZE - (sizeof(struct icmphdr) + sizeof(struct timeval))];
} ping_pkt;
#pragma pack(pop)


/* ----------------------------- STATIC VARIABLES ----------------------------- */

/* Raw socket fd */
static int s_raw_sock_fd;

/* Start time in seconds and microseconds */
/* Used by statistics() ,recv_ping_responses_th() and is_icmp_packet_echo_reply() */
static struct timeval s_start_time;

/* The pid can take values higher than 2^16 so we truncate it to a 16 bit value.
This will be ICMP Identifier(16 bits inside icmp packet) */
static uint16_t s_pid_icmp_identifier;

/* Structure describing an destination IP socket address, it will be resolved in received data  */
/* Used by statistics() ,recv_ping_responses_th()   */
static struct sockaddr_in s_from_dest;

/* Hold the s_send_Times of the last 5 packets */
static struct timeval s_send_Times[5];

/* Number of send ICMP packets, used by statistics()*/
static uint32_t s_ping_Sent = 0;

/* Number of ICMP echo replies, used by statistics() and recv_ping_responses_th() */
static uint32_t s_ping_Replies = 0;

/* ----------------------------- STATIC FUNCTION PROTOTYPES ----------------------------- */

/* Signal handler to run upon SIGINT to print ping statistics */
static void statistics(int signo);

/* Called in a thread context and gathers all ICMP responses and matches the correct ping replies
Uses s_raw_sock_fd */
static void *recv_ping_responses_th(void *);

/* Ping the host at dest_addr, uses s_sockfd */
static void ping_host(struct sockaddr_in dest_addr);

/* Checksum validation for ICMP packet */
static uint16_t checksum(uint16_t *data, int len);

/* Parse the received packet and check if it is an echo reply to a ping we sent */
static bool is_icmp_echo_reply(char *buff, int len);

/* Calculate time difference in microseconds */
static inline int32_t time_difference(const struct timeval *end, const struct timeval *start); 

/* ----------------------------- STATIC FUNCTION DEFINITIONS ----------------------------- */

static void statistics(int signo)
{
    struct timeval end_time;
    gettimeofday(&end_time, NULL);
    printf("\n--- %s ping statistics ---\n", inet_ntoa(s_from_dest.sin_addr));

    int32_t microseconds = time_difference(&end_time, &s_start_time);
    
    printf("%d packets transmitted, %d received, %d%% packet loss, time %dms\n", s_ping_Sent,
           s_ping_Replies, (s_ping_Sent - s_ping_Replies) / s_ping_Sent * 100, microseconds / 1000);

    close(s_raw_sock_fd);
    exit(1);
}

static inline int32_t time_difference(const struct timeval *end, const struct timeval *start) 
{
    return( end->tv_sec - start->tv_sec) * MIKROSECONDS_IN_SECONDS + (end->tv_usec - start->tv_usec);
}

/* Checksum validation for ICMP packet */
static uint16_t checksum(uint16_t *data, int len)
{
    int sum = 0;

    for (int i = 0; i < len; i += 2)
    {
        sum += *data++;
    }

    if ((len % 2) == 1)
        /* Cast it to uint8_t * to not access out of bounds memory. Add last byte if the number is odd */
        sum += *(uint8_t *)data;

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return ~sum;
}

static void ping_host(struct sockaddr_in dest_addr)
{
    ping_pkt packet = {0};
    static uint16_t seq_no = 0;

    packet.hdr.type = ICMP_ECHO;
    packet.hdr.un.echo.id = 0;
    packet.hdr.un.echo.id = s_pid_icmp_identifier;

    /* Update sequence number */
    packet.hdr.un.echo.sequence = seq_no;

    /* Set checksum to 0 before calculating the new checksum since we are reusing the same struct */
    packet.hdr.checksum = 0;

    gettimeofday(&packet.timestamp, NULL);

    /* Copy the send time to the timestamp buffer for current packet*/
    memcpy(&s_send_Times[seq_no++ % (sizeof(s_send_Times) / sizeof(s_send_Times[0]))], &packet.timestamp, sizeof(packet.timestamp));

    /* Calculate checksum for ICMP packet*/
    packet.hdr.checksum = checksum((uint16_t*)&packet, sizeof(packet));

    /* Send ICMP packet to destination address */
    if ( sendto(s_raw_sock_fd, &packet, sizeof(ping_pkt), 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0 )
    {
        perror("sento error");
        return;
    }
    s_ping_Sent++;
}

/* Called in a thread context and gathers all icmp responses and matches the correct ping replies
Uses s_raw_sock_fd */
 
static void* recv_ping_responses_th(void *)
{
   int n; 
   /* socklen_t is a type that is used to declare a variable that can hold the length of a socket address,
   which itself is variable depending on the address family */
   socklen_t from_dest_len;

   extern int errno;
   /* buffer for received ICMP packets */
   /* Add static to not allocate it on stack */
   static char recvpacket[BUFF_RECV_SIZE] = {[0 ... sizeof(recvpacket) - 1] = 0};

   from_dest_len = sizeof(s_from_dest);

   /* Infinite loop for accepting only ICMP echo replays */
   for(;;)
   {
        n = recvfrom(s_raw_sock_fd, recvpacket, sizeof(recvpacket), 0, (struct sockaddr*)&s_from_dest, &from_dest_len);
        if(n < 0)
        {
            if(errno == EINTR)
                continue;
           
            perror("recvfrom_dest error");
                continue;
        }

        /* If the received packet isn't an ICMP echo reply we ignore it */
        if(is_icmp_echo_reply(recvpacket, n) == false)
            continue;
        
        s_ping_Replies++;
   }
}

static bool is_icmp_echo_reply(char *buff, int len)
{
    int ip_hdr_len;
    struct ip *ip;
    ping_pkt* recv_pkt;
    double rtt = 0;

    ip = (struct ip*)buff;
    
    /* Reading header length and multiplying with 4(shift left by 2) */
    /* The ip_hl field counts in multiple of 4 bytes(word) */
    ip_hdr_len = ip->ip_hl << 2;  //
    recv_pkt = (ping_pkt*)(buff + ip_hdr_len);
    
    /* Calculate length of ICMP packet */
    len -= ip_hdr_len;

    if(len < 8)
    {
        printf("ICMP packets length is less than 8 bytes\n");
        return false;
    }
    /* Ignore ICMP echo reply's that dont have process id information that matches (ICMP Identifier) */
    if( (recv_pkt->hdr.type == ICMP_ECHOREPLY) && (recv_pkt->hdr.un.echo.id == s_pid_icmp_identifier) )
    {
        struct timeval now;
        gettimeofday(&now, NULL);

        /* Calculate rtt(round trip time) */
        rtt = time_difference(&now, &s_send_Times[recv_pkt->hdr.un.echo.sequence % (sizeof(s_send_Times) / sizeof(s_send_Times[0]))]);

        printf("%d bytes from %s: icmp_seq=%u ttl=%d time=%.2lf ms\n", len,
               inet_ntoa(s_from_dest.sin_addr), recv_pkt->hdr.un.echo.sequence, ip->ip_ttl, rtt / 1000);
    }
    else
        return false;
    return true;
}

int main(int argc, char* argv[])
{
    
    /* Destination IP address (argv[1]) */
    struct sockaddr_in dest_addr;

    /* Domain name (argv[1]) */
    struct hostent *host;

    pthread_t thread_id;  
    
    /* The program is executed by entering the IP address or domain name */
    if(argc != 2)
    {
        printf("Enter IP address or domain name: %s\n", argv[0]);
        exit(1);
    }

    /* Create raw socket for ICMP communication and check for errors */
    if ( (s_raw_sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0 )
    {
        perror("Socket error");
        exit(1);
    }

    /* Ping task require additional privileges, ping command must send and listen for control packets on a network interface */
    /* For creating raw socket we need root privileges for running executable file we dont need them */
    /* Drop privileges from a root user to ordinary user for a purpose of running executable file */
    setuid(getuid());
    
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;

    /* The inet_addr() converts a string representing an IPv4 Internet address (for example, “127.0. 0.1”) into a numeric Internet address */    
    /* To convert a hostname such as google.com, call gethostbyname() */
    if( inet_addr(argv[1]) == INADDR_NONE )
    {
        if( (host = gethostbyname(argv[1])) == NULL )
        {
            perror("gethostbyname error");
            exit(1);
        }
                     
        memcpy((char*) &dest_addr.sin_addr, host->h_addr, host->h_length);
    }
    else
    {

        dest_addr.sin_addr.s_addr = inet_addr(argv[1]);

        if ((host = gethostbyaddr((const char*)&dest_addr.sin_addr.s_addr, sizeof(dest_addr.sin_addr.s_addr), AF_INET)) == NULL)          
        {
            perror("gethostbyaddr error");
            return 1;
        }  
    }       
   
    /* Print ping statistic when the program is interrupted(CTRL + C) */
    signal(SIGINT, statistics);

    /* The gettimeofday() function gets the system’s clock time. 
    The current time is expressed in elapsed seconds and microseconds
    since 00:00:00, January 1, 1970 (Unix Epoch) */
    /* Get time before first ping */
    gettimeofday(&s_start_time, NULL);

    /* process id will be ICMP Identifier(16 bits inside icmp packet)*/
    s_pid_icmp_identifier = getpid();

    /* To send and read ping messages in parallel we need to create a thread */
    pthread_create(&thread_id, NULL, recv_ping_responses_th, NULL);

    printf("PING %s(%s): %lu bytes data in ICMP packets.\n", host->h_name, inet_ntoa(dest_addr.sin_addr), sizeof(ping_pkt));
    
    /* Infinite loop to send ICMP echo request every second */
    for(;;)
    {
        ping_host(dest_addr);
        /* Sleep 1 second */
        sleep(1);
    }
     /* We will never reach here since we can only terminate the program with SIGINIT (CTRL+C) */
    pthread_join(thread_id, NULL);
    return 0;
}