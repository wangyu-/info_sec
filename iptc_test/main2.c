#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "libiptc/libiptc.h"
#include <xtables.h>
//#include <iptables.h> /* get_kernel_version */
#include <limits.h> /* INT_MAX in ip_tables.h */
#include <linux/netfilter_ipv4/ip_tables.h>
#include <net/netfilter/nf_nat.h>

//#include "IpRule.h"
 
static int
insert_rule (const char *table,
             const char *chain, 
             unsigned int src,
             int inverted_src,
             unsigned int dest,
             int inverted_dst,
             const char *target)
{
  struct
    {
      struct ipt_entry entry;
      struct xt_standard_target target;
    } entry;
  struct xtc_handle *h;
  int ret = 1;
 
  h = iptc_init (table);
  if (!h)
    {
      fprintf (stderr, "Could not init IPTC library: %s\n", iptc_strerror (errno));
      goto out;
    }
 
  memset (&entry, 0, sizeof (entry));
 
  /* target */
  entry.target.target.u.user.target_size = XT_ALIGN (sizeof (struct xt_standard_target));
  strncpy (entry.target.target.u.user.name, target, sizeof (entry.target.target.u.user.name));
 
  /* entry */
  entry.entry.target_offset = sizeof (struct ipt_entry);
  entry.entry.next_offset = entry.entry.target_offset + entry.target.target.u.user.target_size;
  
  if (src)
    {
      entry.entry.ip.src.s_addr  = src;
      entry.entry.ip.smsk.s_addr = 0xFFFFFFFF;
      if (inverted_src)
        entry.entry.ip.invflags |= IPT_INV_SRCIP;
    }
 
  if (dest)
    {
      entry.entry.ip.dst.s_addr  = dest;
      entry.entry.ip.dmsk.s_addr = 0xFFFFFFFF;
      if (inverted_dst)
        entry.entry.ip.invflags |= IPT_INV_DSTIP;
    }
 
  if (!iptc_append_entry (chain, (struct ipt_entry *) &entry, h))
    {
      fprintf (stderr, "Could not insert a rule in iptables (table %s): %s\n", table, iptc_strerror (errno));
      goto out;
    }
 
  if (!iptc_commit (h))
    {
      fprintf (stderr, "Could not commit changes in iptables (table %s): %s\n", table, iptc_strerror (errno));
      goto out;
    }
 
  ret = 0;
out:
  if (h)
    iptc_free (h);
 
  return ret;
}

struct ipt_entry *api_iptc_entry_get(struct sockaddr_in src,
		struct sockaddr_in dst, struct sockaddr_in nto, const char *option)
{
	struct ipt_entry *fw = NULL;

	struct ipt_entry_match *match = NULL;
	struct ipt_tcp *tcpinfo = NULL;

	struct ipt_entry_target *target = NULL;
	struct nf_nat_multi_range *mr = NULL;

	unsigned int size1 = XT_ALIGN(sizeof(struct ipt_entry));
	unsigned int size2 = XT_ALIGN(sizeof(struct ipt_entry_match) + sizeof(struct ipt_tcp));
	unsigned int size3 = XT_ALIGN(sizeof(struct ipt_entry_target) + sizeof(struct nf_nat_multi_range));

	if ( !option ) {
		printf("NULL\n");
		return NULL;
	}

	fw = calloc(1, size1 + size2 + size3);
	if ( !fw ) {
		printf("Malloc failure");
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

	  mr->range[0].flags = IP_NAT_RANGE_PROTO_SPECIFIED | IP_NAT_RANGE_MAP_IPS;
	  mr->range[0].min.tcp.port = mr->range[0].max.tcp.port = nto.sin_port;
	  mr->range[0].min_ip = mr->range[0].max_ip = nto.sin_addr.s_addr;  return fw;
}  
 
int main (int argc, char **argv)
{
  unsigned int a, b;
 
  inet_pton (AF_INET, "2.2.3.4", &a);
  inet_pton (AF_INET, "4.3.2.1", &b);
 
  insert_rule ("filter",
               "INPUT",
               a,
               0,
               b,
               1,
               "DROP");
  return 0;
}
