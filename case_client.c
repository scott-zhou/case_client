#define _BSD_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>

/* These two size is number of bytes
   Suppose the number 1316 from requirement is UDP payload,
   so the whole package should +20 for IPv4 header and +8 for UDP header
 */
#define UDP_PAYLOAD_SIZE 1316
#define PKG_SIZE         (UDP_PAYLOAD_SIZE + 20 + 8)

/* Parse cli arguments */
void parse_arguments(int argc, char *argv[],
                    char ** ip, unsigned int *port,
                    unsigned int *num_of_packets, unsigned int *speed);

/* Validate arguments
   return value:
     -1: fail
     0 : success
     1 : mostly success, but some value is modified to max/min value
*/
int validate_arguments(char ** ip, unsigned int *port,
                       unsigned int *num_of_packets, unsigned int *speed);

/* Create socket fd and setsockopt here if needed */
int create_socket();

void generate_target_address(struct sockaddr_in * target_addr, const char *ip, unsigned int port);

void generate_payload(uint32_t pkg_cnt, unsigned char *payload);

unsigned int calculate_next_time(struct timeval *t_this, unsigned int pkg_cnt, unsigned int pnum_per_sec, unsigned int interval, unsigned int extra_usec);

int main(int argc, char *argv[])
{
    char *target_ip = NULL;
    unsigned int target_port = 0, num_of_packets = 0;
    unsigned int speed = 0; // kilobits
    unsigned int packets_per_second = 0, interval = 0, extra_wait_per_second = 0;
    parse_arguments(argc, argv, &target_ip, &target_port, &num_of_packets, &speed);
    if(-1 == validate_arguments(&target_ip, &target_port, &num_of_packets, &speed)) {
        fprintf(stderr, "%s fail in argument validation.\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    packets_per_second = (speed * 1000) / (PKG_SIZE * 8);
    interval = (1000*1000) / packets_per_second; /* Microsecond */
    extra_wait_per_second = (1000*1000) - (interval * packets_per_second);
    assert(extra_wait_per_second >= 0);
    assert(extra_wait_per_second < packets_per_second);

    struct sockaddr_in target_addr;
    generate_target_address(&target_addr, target_ip, target_port);

    printf("%u packets will be send to %s:%u, with the speed %u packets per second.\n",
           num_of_packets, target_ip, target_port, packets_per_second);
    printf("It will take %d seconds, interval between package is about %u\n",
           num_of_packets/packets_per_second + (num_of_packets%packets_per_second ? 1 : 0) , interval);

    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    printf("Start sending at: %d-%d-%d %d:%d:%d\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

    int sockfd = create_socket();
    unsigned char payload[UDP_PAYLOAD_SIZE];
    uint32_t pkg_cnt = 0;
    struct timeval time_this;
    gettimeofday(&time_this, NULL);

    do {
        generate_payload(pkg_cnt++, payload);
        sendto(sockfd, payload, UDP_PAYLOAD_SIZE, 0,
               (const struct sockaddr *)&target_addr, sizeof(struct sockaddr_in));
        unsigned int usec = 0;
        usec = calculate_next_time(&time_this, pkg_cnt, packets_per_second, interval, extra_wait_per_second);
        if (usec>0) {
            usleep(usec);
        }
    } while (pkg_cnt < num_of_packets);

    close(sockfd);

    t = time(NULL);
    tm = *localtime(&t);
    printf("Finish sending at: %d-%d-%d %d:%d:%d\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

    exit(EXIT_SUCCESS);
}

void parse_arguments(int argc, char *argv[],
                    char ** ip, unsigned int *port,
                    unsigned int *num_of_packets, unsigned int *speed)
{
    int opt;
    while ((opt = getopt(argc, argv, "a:p:n:s:")) != -1) {
        switch (opt)
            {
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
}

/* TODO: validate arguments here if it is needed */
int validate_arguments(char ** ip, unsigned int *port,
                       unsigned int *num_of_packets, unsigned int *speed)
{
    return 0;
}

int create_socket()
{
    int sockfd = socket(PF_INET, SOCK_DGRAM, 0);
    if (-1 == sockfd) {
        fprintf(stderr, "socket error, errno %d\n", errno);
        exit(EXIT_FAILURE);
    }
    return sockfd;
}

void generate_target_address(struct sockaddr_in * target_addr, const char *ip, unsigned int port)
{
    memset(target_addr, 0, sizeof(struct sockaddr_in));
    int s = inet_pton(AF_INET, ip, &(target_addr->sin_addr));
    if (s<=0) {
        if (s == 0) {
            fprintf(stderr, "Address %s not in presentation format", ip);
        }
        else {
            perror("inet_pton");
        }
        exit(EXIT_FAILURE);
    }
    target_addr->sin_family = AF_INET;
    target_addr->sin_port = htons(port);
}

void generate_pkg_body(unsigned char *body, unsigned int len)
{
}

void generate_payload(uint32_t pkg_cnt, unsigned char *payload)
{
    uint16_t pkg_token = 0x2309;
    uint8_t pkg_flag = 3;
    uint8_t pkg_flag1 = pkg_flag | ((pkg_cnt & 1) << 2);
    uint8_t pkg_flag2 = ~pkg_flag1;
    memset(payload, 0, UDP_PAYLOAD_SIZE);
    uint32_t cnt = htonl(pkg_cnt);
    memcpy(payload, &cnt, 4);
    pkg_token = htons(pkg_token);
    memcpy(payload+4, &pkg_token, 2);
    memcpy(payload+6, &pkg_flag1, 1);
    memcpy(payload+7, &pkg_flag2, 1);
    unsigned char *pkg_body = payload+8;
    unsigned int body_len = UDP_PAYLOAD_SIZE - 8;
    generate_pkg_body(pkg_body, body_len);
}

unsigned int calculate_next_time(struct timeval *t_this, unsigned int pkg_cnt, unsigned int pnum_per_sec, unsigned int interval, unsigned int extra_usec)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    int diff = 1000000*(now.tv_sec - t_this->tv_sec) + now.tv_usec - t_this->tv_usec;
    int next_interval = interval + ((pkg_cnt % pnum_per_sec) <= extra_usec ? 1 : 0);
    t_this->tv_sec = t_this->tv_sec + (t_this->tv_usec + next_interval >= 1000000 ? 1 : 0);
    t_this->tv_usec = (t_this->tv_usec + next_interval) % 1000000;
    next_interval = next_interval - diff;
    return (unsigned int)(next_interval>0 ? next_interval : 0);
}
