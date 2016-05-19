#define _BSD_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>

/* These two size is number of bytes.
 * Suppose the number 1316 from requirement is UDP payload,
 * so the whole package should +20 for IPv4 header and +8 for UDP header
 */
#define UDP_PAYLOAD_SIZE 1316
#define PKG_SIZE         (UDP_PAYLOAD_SIZE + 20 + 8)


/* Global variables */
uint32_t g_pkg_cnt = 0;
unsigned int g_num_of_packets = 0;
int g_exit_flag = 0;
int g_sockfd;
struct sockaddr_in g_target_addr;

/* Parse cli arguments */
void parse_arguments(int argc, char *argv[],
                    char ** ip, unsigned int *port,
                    unsigned int *num_of_packets, unsigned int *speed);
int create_socket();
void set_target_address(struct sockaddr_in * target_addr, const char *ip, unsigned int port);
/* Bind SIGALRM to custom signal handler function, send UDP on SIGALRM */
void bind_signal_handler();
void start_timer(unsigned int usec);
void print_progress();

int main(int argc, char *argv[])
{
    char *target_ip = NULL;
    unsigned int target_port = 0;
    unsigned int speed = 0; /* kilobits */
    unsigned int interval = 0;
    parse_arguments(argc, argv, &target_ip, &target_port, &g_num_of_packets, &speed);

    float packets_per_second = (float)(speed * 1000) / (PKG_SIZE * 8);
    interval = (unsigned int)((float)(1000*1000) / packets_per_second); /* Microsecond */
    assert(interval > 0 && interval < 1000000);

    set_target_address(&g_target_addr, target_ip, target_port);

    printf("%u packets will be send to %s:%u, with the speed %f packets per second.\n",
           g_num_of_packets, target_ip, target_port, packets_per_second);
    printf("It will take %f seconds, interval between package is about %d microseconds.\n",
           (float)(g_num_of_packets)/packets_per_second, interval);

    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    printf("Start sending at: %d-%d-%d %d:%d:%d\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    srand(t);

    g_sockfd = create_socket();
    g_exit_flag = 0;
    g_pkg_cnt = 0;

    bind_signal_handler();
    start_timer(interval);
    while(0 == g_exit_flag) {
        usleep(500000);
        print_progress();
    }
    printf("\n");
    close(g_sockfd);

    t = time(NULL);
    tm = *localtime(&t);
    printf("Finish sending at: %d-%d-%d %d:%d:%d\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

    exit(EXIT_SUCCESS);
}

/* Validate arguments here if it is needed.
 * return value:
 *   -1: fail
 *    0: success
 *    1: mostly success, but some value is modified to max/min value
*/
int validate_arguments(char ** ip, unsigned int *port,
                       unsigned int *num_of_packets, unsigned int *speed)
{
    int rt = 0;
    if(NULL == *ip) {
        fprintf(stderr, "Target IP invalid.\n");
        return -1;
    }
    if (*port > 65535) {
        *port = 65535; /* Max port number */
        rt  = 1;
    }
    if(num_of_packets == 0) {
        fprintf(stderr, "Num of packets to send invalid.\n");
        return -1;
    }
    if(*speed < 2) {
        /* Suppose at least 1 packet per second */
        *speed = 2;
        rt  = 1;
    }
    else if(*speed > 100000) {
        /* I don't think any stream will be bigger rate than 100Mbps */
        *speed = 100000;
        rt  = 1;
    }
    return rt;
}

void parse_arguments(int argc, char *argv[],
                    char ** ip, unsigned int *port,
                    unsigned int *num_of_packets, unsigned int *speed)
{
    int opt;
    while ((opt = getopt(argc, argv, "a:p:n:s:")) != -1) {
        switch (opt) {
        case 'a':
            *ip = optarg;
            break;
        case 'p':
            *port = atoi(optarg);
            break;
        case 'n':
            *num_of_packets = atoi(optarg);
            break;
        case 's':
            *speed = atoi(optarg);
            break;
        default:
            fprintf(stderr, "Usage: %s -a target_ip -p target_port -n num_of_packets -s speed\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }
    if(-1 == validate_arguments(ip, port, num_of_packets, speed)) {
        fprintf(stderr, "Fail in argument validation.\n");
        exit(EXIT_FAILURE);
    }

}

/* Create socket fd and setsockopt here if needed */
int create_socket()
{
    int sockfd = socket(PF_INET, SOCK_DGRAM, 0);
    if (-1 == sockfd) {
        fprintf(stderr, "socket error, errno %d\n", errno);
        exit(EXIT_FAILURE);
    }
    return sockfd;
}

void set_target_address(struct sockaddr_in * target_addr, const char *ip, unsigned int port)
{
    memset(target_addr, 0, sizeof(struct sockaddr_in));
    int s = inet_pton(AF_INET, ip, &(target_addr->sin_addr));
    if (s<=0) {
        if (s == 0) {
            fprintf(stderr, "Address %s not in presentation format", ip);
        }
        else {
            fprintf(stderr, "inet_pton error, errno %d\n", errno);
        }
        exit(EXIT_FAILURE);
    }
    target_addr->sin_family = AF_INET;
    target_addr->sin_port = htons(port);
}

/* Generate pkt_body part with randon bytes */
void generate_pkt_body(unsigned char *body, unsigned int len)
{
    for(int i=0; i<len; i++) {
        int r = rand();
        body[i] = (unsigned char)r;
    }
}

/* Generate packet header part. Packet header contains following:
 * [pkt_cnt - 4 bytes]
 * [pkt_token - 4 bytes] [pkt_flag1 - 1 byte] [pkt_flag2 - 1 byte]
 * pkt_cnt is transmition counter start from 0.
 * pkt_token is 0x2309.
 * pkt_flag1 bit 0 and bit 1 is 1, bit 3 from pkt_cnt LSB, other bits are 0
 * pkt_flag2 is pkt_flag1 inverted.
*/
int generate_pkt_header(unsigned char * header, uint32_t pkg_cnt)
{
    uint16_t pkg_token = 0x2309;
    uint8_t pkg_flag1 = 3;
    pkg_flag1 = pkg_flag1 | ((pkg_cnt & 1) << 2);
    uint8_t pkg_flag2 = ~pkg_flag1;
    uint32_t cnt = htonl(pkg_cnt);
    memcpy(header, &cnt, 4);
    pkg_token = htons(pkg_token);
    memcpy(header+4, &pkg_token, 2);
    memcpy(header+6, &pkg_flag1, 1);
    memcpy(header+7, &pkg_flag2, 1);
    return 4+2+1+1;
}

void generate_payload(uint32_t pkg_cnt, unsigned char *payload)
{
    memset(payload, 0, UDP_PAYLOAD_SIZE);
    int header_len = generate_pkt_header(payload, pkg_cnt);
    unsigned char *pkg_body = payload + header_len;
    unsigned int body_len = UDP_PAYLOAD_SIZE - header_len;
    generate_pkt_body(pkg_body, body_len);
}

void start_timer(unsigned int usec)
{
    struct itimerval  value;
    value.it_interval.tv_sec = 0;
    value.it_interval.tv_usec = usec;
    value.it_value = value.it_interval;
    if (-1 == setitimer(ITIMER_REAL,&value,NULL)){
        fprintf(stderr, "setitimer error, errno %d\n", errno);
        exit(EXIT_FAILURE);
    }
}

void handle_sigalrm()
{
    if(g_pkg_cnt >= g_num_of_packets) {
        return;
    }
    unsigned char payload[UDP_PAYLOAD_SIZE];
    generate_payload(g_pkg_cnt, payload);
    sendto(g_sockfd, payload, UDP_PAYLOAD_SIZE, 0,
           (const struct sockaddr *)&g_target_addr, sizeof(struct sockaddr_in));
    if(++g_pkg_cnt >= g_num_of_packets) {
        g_exit_flag = 1;
    }
}

void sig_handler(int sig)
{
    switch (sig) {
    case SIGALRM:
        handle_sigalrm();
        break;
    default:
        break;
    }
    return;
}

void bind_signal_handler()
{
    struct sigaction action;
    memset(&action, 0, sizeof(struct sigaction));
    action.sa_handler = sig_handler;
    if(-1 == sigaction(SIGALRM, &action, NULL)) {
        fprintf(stderr, "sigaction error, errno %d\n", errno);
        exit(EXIT_FAILURE);
    }
}

void print_progress()
{
    static int old_percent = -1;
    int percent = g_pkg_cnt * 100 / g_num_of_packets;

    if(percent > old_percent) {
        printf("\r[");
        int done = percent/5;
        int todo = 20-done;
        for(int i=0; i<done; i++) printf("x");
        for(int i=0; i<todo; i++) printf(".");
        printf("] - [%d%%]", percent);
        fflush(stdout);
        old_percent = percent;
    }
}
