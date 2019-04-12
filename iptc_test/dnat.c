#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "libiptc/libiptc.h"
#include <xtables.h>
//#include <iptables.h> /* get_kernel_version */
#include <limits.h> /* INT_MAX in ip_tables.h */
#include <linux/netfilter_ipv4/ip_tables.h>
#include <net/netfilter/nf_nat.h>

typedef unsigned int u32;
typedef unsigned short u16;

#define FAILURE -1
#define SUCCESS 0
#define LOGW printf
#define LOGE printf
#define FREE_POINTER 
#define ASSERT
#define ASSERT_FAIL
struct ipt_entry *api_iptc_entry_get(struct sockaddr_in src,
        struct sockaddr_in dst, struct sockaddr_in nto, const char *option)
{
    struct ipt_entry *fw = NULL;

    struct ipt_entry_match *match = NULL;
    struct ipt_tcp *tcpinfo = NULL;

    struct ipt_entry_target *target = NULL;
    struct nf_nat_multi_range *mr = NULL;

    u32 size1 = XT_ALIGN(sizeof(struct ipt_entry));
    u32 size2 = XT_ALIGN(sizeof(struct ipt_entry_match) + sizeof(struct ipt_tcp));
    u32 size3 = XT_ALIGN(sizeof(struct ipt_entry_target) + sizeof(struct nf_nat_multi_range));

    if ( !option ) {
        LOGW("NULL\n");
        return NULL;
    }

    fw = calloc(1, size1 + size2 + size3);
    if ( !fw ) {
        LOGE("Malloc failure");
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
  mr->range[0].min.tcp.port = mr->range[0].max.tcp.port = nto.sin_port;
  mr->range[0].min_ip = mr->range[0].max_ip = nto.sin_addr.s_addr;  return fw;
} 

int api_iptc_entry_add(const struct ipt_entry *fw, const char *chain)
{
    int ret = FAILURE;
    struct xtc_handle *phandle = NULL;
 
    if ( !fw || !chain ) {
        LOGW("NULL\n");
        return FAILURE;
    }
 
    if ( (phandle = iptc_init("nat")) &&
         iptc_append_entry(chain, fw, phandle) &&
         iptc_commit(phandle) ) {
        ret = SUCCESS;
    }
    else {
        LOGW("%s\n", iptc_strerror(errno));
        ret = FAILURE;
    }
    return ret;
}

int api_iptc_entry_del(const struct ipt_entry *fw, const char *chain)
{
    int ret = FAILURE;

    unsigned char *matchmask = NULL;

    struct xtc_handle *phandle = NULL;

    if ( !fw || !chain ) {
        LOGW("NULL\n");
        return FAILURE;
    }

    matchmask = calloc(1, fw->next_offset);
    if ( !matchmask ) {
        return FAILURE;
    }

    if ( !phandle ) {
        phandle = iptc_init("nat");
    }

    if ( (phandle = iptc_init("nat")) &&
         iptc_delete_entry(chain, fw, matchmask, phandle) &&
         iptc_commit(phandle) ) {
        ret = SUCCESS;
    }
    else {
        LOGW("%s\n", iptc_strerror(errno));
        ret = FAILURE;
    }

    FREE_POINTER(matchmask);
    return ret;
}

int test_snat(int off, u16 times)
{
    int ret = FAILURE;
    int ix = 0;

    struct ipt_entry *fw = NULL;

    struct sockaddr_in src;
    struct sockaddr_in dst;
    struct sockaddr_in sto;

    src.sin_addr.s_addr = inet_addr("0.0.0.0");
    dst.sin_addr.s_addr = inet_addr("0.0.0.0");
    sto.sin_addr.s_addr = inet_addr("1.1.1.3");

    for ( ix = 0; ix < times; ix++ ) {
        src.sin_port = htons(0);
        dst.sin_port = htons(456);
        sto.sin_port = htons(0);

  //      ASSERT_FAIL(NULL, fw = api_iptc_entry_get(src, dst, sto, "DNAT"));
//ASSERT(SUCCESS, api_iptc_entry_add(fw, "PREROUTING"));

        ASSERT_FAIL(NULL, fw = api_iptc_entry_get(src, dst, sto, "SNAT"));
        ASSERT(SUCCESS, api_iptc_entry_add(fw, "POSTROUTING"));

        usleep(300);
        //ASSERT(SUCCESS, api_iptc_entry_del(fw, "POSTROUTING"));
    }

    FREE_POINTER(fw);
    ret = SUCCESS;
_E1:
    return ret;
}

int main()
{
	test_snat(1,1);
	return 0;
}
