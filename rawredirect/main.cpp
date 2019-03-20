#include <sys/socket.h>
#include <netinet/in.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#define MY_LITTLE_ENDIAN 1
struct my_iphdr
{
#ifdef MY_LITTLE_ENDIAN
	unsigned char ihl:4;
	unsigned char version:4;
#else
	unsigned char version:4;
	unsigned char ihl:4;
#endif
	u_int8_t tos;
	u_int16_t tot_len;
	u_int16_t id;
	u_int16_t frag_off;
	u_int8_t ttl;
	u_int8_t protocol;
	u_int16_t check;
	u_int32_t saddr;
	u_int32_t daddr;
	/*The options start here. */
};
struct my_icmphdr
{
	uint8_t type;
	uint8_t code;
	uint16_t check_sum;
	uint16_t id;
	uint16_t seq;
};
char gateway_str[100];
char src_str[100];
char target_str[100];
int gateway=0;
int src=0;
int target=0;
int print_help()
{
	printf("useage:\n");
	printf("    ./this_program -g <gateway-ip> -i <src-ip> -t <dst-ip>\n");
}
int process_opt(int argc,char *argv[])
{
	int opt=1;
	int has_g=0,has_i=0,has_t=0;
	while ((opt = getopt(argc, argv, "g:i:t:h")) != -1) 
	{
		switch (opt) {
		case 'g':
			strcpy(gateway_str,optarg);
			has_g=1;
			break;
		case 'i':
			strcpy(src_str,optarg);
			has_i=1;
			break;
		case 't':
			strcpy(target_str, optarg);
			has_t=1;
			break;
		case 'h':
			print_help();
			exit(0);
			break;
		default:
			printf("ignore unknown <%x>", optopt);
		}
	}
	if(!has_g||!has_i||!has_t)
	{
		print_help();
		exit(0);
	}
	src=inet_addr(src_str);
	gateway=inet_addr(gateway_str);
	src=inet_addr(src_str);
	
}
int main(int argc,char *argv[])
{
	process_opt(argc,argv);
	int raw_recv_fd=socket(PF_PACKET,SOCK_RAW, IPPROTO_RAW);
	int raw_send_fd=socket(AF_INET,SOCK_RAW,IPPROTO_RAW);
}


