#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "libiptc/libiptc.h"
//#include <xtables.h>
//#include <iptables.h> /* get_kernel_version */
#include <limits.h> /* INT_MAX in ip_tables.h */
//#include <linux/netfilter_ipv4/ip_tables.h>
#include <net/netfilter/nf_nat.h>
#include <assert.h>
#include <malloc.h>

typedef unsigned int u32_t;
typedef unsigned short u16_t;

char my_ip[]="192.168.22.153";
int my_port=8080;

char dst_ip[]="45.76.100.53";
int dst_port=80;

struct ipt_entry *api_iptc_entry_get(struct sockaddr_in src,
        struct sockaddr_in dst, struct sockaddr_in nto, const char *option)
{
    struct ipt_entry *fw = NULL;

    struct ipt_entry_match *match = NULL;
    struct ipt_tcp *tcpinfo = NULL;

    struct ipt_entry_target *target = NULL;
    struct nf_nat_multi_range *mr = NULL;

    u32_t size1 = XT_ALIGN(sizeof(struct ipt_entry));
    u32_t size2 = XT_ALIGN(sizeof(struct ipt_entry_match) + sizeof(struct ipt_tcp));
    u32_t size3 = XT_ALIGN(sizeof(struct ipt_entry_target) + sizeof(struct nf_nat_multi_range));

    if ( !option ) {
        printf("error: option is null\n");
        return NULL;
    }

    fw = calloc(1,size1 + size2 + size3);
    if ( !fw ) {
        printf("malloc failed");
        return NULL;
    }

    /* Offsets to the other bits */
    fw->target_offset = size1 + size2;
    fw->next_offset = size1 + size2 + size3;

    /* Set up packet matching rules */
    if ( (fw->ip.src.s_addr = src.sin_addr.s_addr) == INADDR_ANY ) {
        fw->ip.smsk.s_addr = 0;
    }
    else {
        fw->ip.smsk.s_addr = inet_addr("255.255.255.255");
    }

    if ( (fw->ip.dst.s_addr = dst.sin_addr.s_addr) == INADDR_ANY ) {
        fw->ip.dmsk.s_addr = 0;
    }
    else {
        fw->ip.dmsk.s_addr = inet_addr("255.255.255.255");
    }

    fw->ip.proto = IPPROTO_TCP;
    fw->nfcache = NFC_UNKNOWN; /*Think this stops caching. */


  /* TCP specific matching(ie. ports) */
  match = (struct ipt_entry_match *)fw->elems;
  match->u.match_size = size2;
  strcpy(match->u.user.name, "tcp");


  tcpinfo = (struct ipt_tcp *)match->data;


  if ( src.sin_port == 0 ) {
    tcpinfo->spts[0] = ntohs(0);
    tcpinfo->spts[1] = ntohs(0xFFFF);
  }
  else {
    tcpinfo->spts[0] = tcpinfo->spts[1] = ntohs(src.sin_port);
  }


  if( dst.sin_port == 0 ) {
    tcpinfo->dpts[0] = ntohs(0);
    tcpinfo->dpts[1] = ntohs(0xFFFF);
  }
  else {
    tcpinfo->dpts[0] = tcpinfo->dpts[1] = ntohs(dst.sin_port);
  }


  /* And the target */
  target = (struct ipt_entry_target *)(fw->elems + size2);
  target->u.target_size = size3;
  strcpy(target->u.user.name, option);


  mr = (struct nf_nat_multi_range *)target->data;
  mr->rangesize = 1;

  //mr->range[0].flags = IP_NAT_RANGE_PROTO_SPECIFIED | IP_NAT_RANGE_MAP_IPS;
  mr->range[0].flags = IP_NAT_RANGE_MAP_IPS;
  if(nto.sin_port!=0) //be aware of endian
  	mr->range[0].flags |= IP_NAT_RANGE_PROTO_SPECIFIED;
  mr->range[0].min.tcp.port = mr->range[0].max.tcp.port = nto.sin_port;
  mr->range[0].min_ip = mr->range[0].max_ip = nto.sin_addr.s_addr;  
  return fw;
} 

int api_iptc_entry_add(const struct ipt_entry *fw, const char *chain)
{
    int ret = -1;
    struct xtc_handle *phandle = NULL;
 
    if ( !fw || !chain ) {
        printf("error: null pointer\n");
        return -1;
    }
 
    if ( (phandle = iptc_init("nat")) &&
         iptc_append_entry(chain, fw, phandle) &&
         iptc_commit(phandle) ) {
        ret = 0;
    }
    else {
        printf("error: %s\n", iptc_strerror(errno));
        ret = -1;
    }
    return ret;
}

int api_iptc_entry_del(const struct ipt_entry *fw, const char *chain)
{
    int ret = -1;

    unsigned char *matchmask = NULL;

    struct xtc_handle *phandle = NULL;

    if ( !fw || !chain ) {
        printf("null pointer\n");
        return -1;
    }

    matchmask = calloc(1,fw->next_offset);
    if ( !matchmask ) {
        return -1;
    }

    if ( !phandle ) {
        phandle = iptc_init("nat");
    }

    if ( (phandle = iptc_init("nat")) &&
         iptc_delete_entry(chain, fw, matchmask, phandle) &&
         iptc_commit(phandle) ) {
        ret = 0;
    }
    else {
        printf("error: %s\n", iptc_strerror(errno));
        ret = -1;
    }

    free(matchmask);
    return ret;
}

int test_snat(int del)
{
    int ret = -1;
    int ix = 0;

    struct ipt_entry *fw = NULL;

    struct sockaddr_in src;
    struct sockaddr_in dst;
    struct sockaddr_in sto;

    src.sin_addr.s_addr = inet_addr("0.0.0.0");
    dst.sin_addr.s_addr = inet_addr(my_ip);
    dst.sin_addr.s_addr = inet_addr("0.0.0.0");
    sto.sin_addr.s_addr = inet_addr(dst_ip);

    src.sin_port = htons(0);
    dst.sin_port = htons(my_port);
    sto.sin_port = htons(dst_port);

    assert(fw = api_iptc_entry_get(src, dst, sto, "DNAT"));
    if(del==0)
	    assert(api_iptc_entry_add(fw, "PREROUTING")==0);
    else
	    assert(api_iptc_entry_del(fw, "PREROUTING")==0);

    src.sin_addr.s_addr = inet_addr("0.0.0.0");
    dst.sin_addr.s_addr = inet_addr(dst_ip);
    sto.sin_addr.s_addr = inet_addr(my_ip);

    src.sin_port = htons(0);
    dst.sin_port = htons(dst_port);
    sto.sin_port = htons(0);

    assert(fw = api_iptc_entry_get(src, dst, sto, "SNAT"));
    if(del==0)
	    assert(api_iptc_entry_add(fw, "POSTROUTING")==0);
    else
	    assert(api_iptc_entry_del(fw, "POSTROUTING")==0);


    free(fw);
    ret = 0;
_E1:
    return ret;
}

int main(int argc,char *argv[])
{
	if(argc<2)
	{
		printf("too few arguments\n");
		return -1;
	}
	if(strcmp(argv[1],"add")==0)
	{
		test_snat(0);
	}
	else if(strcmp(argv[1],"del")==0)
	{
		test_snat(1);
	}
	else printf("unknow option <%s>\n",argv[1]);
	return 0;
}
