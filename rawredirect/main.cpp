#include <sys/socket.h>
#include <netinet/in.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>
#include <net/ethernet.h> 
#include <netpacket/packet.h>
#include <net/if.h>
#include <sys/ioctl.h>

#define MY_LITTLE_ENDIAN 1

typedef unsigned long long u64_t;   //this works on most platform,avoid using the PRId64
typedef long long i64_t;

typedef unsigned int u32_t;
typedef int i32_t;

typedef unsigned short u16_t;
typedef short i16_t;

typedef unsigned char u8_t;
typedef signed char i8_t;

const int max_data_len=1800;
const int buf_len=max_data_len+400;

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
char dev[100];
char gateway_str[100];
char src_str[100];
char target_str[100];
u32_t gateway=0;
u32_t src=0;
u32_t target=0;
int print_help()
{
	printf("useage:\n");
	printf("    ./this_program -d <device> -g <gateway-ip> -i <src-ip> -t <dst-ip>\n");
}
int process_opt(int argc,char *argv[])
{
	int opt=1;
	int has_g=0,has_i=0,has_t=0,has_d=0;
	while ((opt = getopt(argc, argv, "g:i:t:d:h")) != -1) 
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
		case 'd':
			strcpy(dev,optarg);
			has_d=1;
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
	if(!has_g||!has_i||!has_t||!has_d)
	{
		print_help();
		exit(0);
	}
	src=inet_addr(src_str);
	gateway=inet_addr(gateway_str);
	target=inet_addr(target_str);
	
}
int print_packet(char *buf,int len)
{
	printf("{");
	for(int i=0;i<len;i++)
		printf("%02x ",(int)(unsigned char)buf[i]);
	printf("}\n");
}
int on_recv_a_packet(char *buf,int len)
{
	print_packet(buf,len);
	my_iphdr *  iph;
	if(len<(int)sizeof(my_iphdr))
	{
		printf("incomplete ip header\n");
		return -1;
	}	
	iph=(struct my_iphdr *) buf;
	if(iph->version!=4)
	{
		printf("not ipv4\n");
		return -1;	
	}
	u32_t saddr=iph->saddr;
	u32_t daddr=iph->daddr;
	printf("%x %x\n",saddr,target);
	
}
int main(int argc,char *argv[])
{
	process_opt(argc,argv);
	int raw_recv_fd=socket(PF_PACKET , SOCK_DGRAM , htons(ETH_P_IP));
	assert(raw_recv_fd>=0);
	int raw_send_fd=socket(AF_INET,SOCK_RAW,IPPROTO_RAW);
	assert(raw_send_fd>=0);
	int one = 1;
	const int *val = &one;
	if (setsockopt (raw_send_fd, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0) {
		printf("Error setting IP_HDRINCL %d %s\n",errno,strerror(errno));
		exit(-1);
	}
	sockaddr_ll addr_ll;
	ifreq ifr;
	packet_mreq mreq;

	memset(&addr_ll,0,sizeof(addr_ll));
	memset(&ifr,0,sizeof(ifr));
	memset(&mreq,0,sizeof(mreq));

	memcpy(&ifr.ifr_name,dev,IFNAMSIZ);
	ioctl(raw_recv_fd,SIOCGIFINDEX,&ifr);
	
	addr_ll.sll_ifindex = ifr.ifr_ifindex;
	addr_ll.sll_family = AF_PACKET;

	assert(bind(raw_recv_fd, (struct sockaddr *)&addr_ll,sizeof(addr_ll)) ==0);

	mreq.mr_ifindex = ifr.ifr_ifindex;
	mreq.mr_type = PACKET_MR_PROMISC;
	mreq.mr_alen = 6;

	assert(setsockopt(raw_recv_fd,SOL_PACKET,PACKET_ADD_MEMBERSHIP,
				(void*)&mreq,(socklen_t)sizeof(mreq)) ==0);
	int len;
	char buf[buf_len];
	while(1)
	{
		socklen_t len=recvfrom(raw_recv_fd, buf, max_data_len+1, 0 ,(sockaddr*)&addr_ll , &len);
		on_recv_a_packet(buf,len);
	}
	
}


