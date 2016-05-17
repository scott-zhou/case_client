#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>

/* PKG_SIZE is number of bytes */
#define PKG_SIZE 1316

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

int main(int argc, char *argv[])
{
    char *target_ip = NULL;
    unsigned int target_port = 0;
    unsigned int num_of_packets = 0;
    unsigned int speed = 0; // kilobits
    parse_arguments(argc, argv, &target_ip, &target_port, &num_of_packets, &speed);
    if(-1 == validate_arguments(&target_ip, &target_port, &num_of_packets, &speed)) {
        fprintf(stderr, "%s fail in argument validation.\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    printf("IP: %s\n", target_ip);
    printf("port: %u\n", target_port);
    printf("num_of_packets: %u\n", num_of_packets);
    printf("speed: %u\n", speed);

    unsigned int packets_per_second = (speed * 1000) / (PKG_SIZE * 8);
    unsigned int interval = (1000*1000) / packets_per_second; /* Microsecond */


    exit(0);
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
                fprintf(stderr, "Usage: %s -a target_id -p target_port -n num_of_packets -s speed\n", argv[0]);
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
