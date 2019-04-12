/* 
 * File:   IpRule.h
 * Author: kritpal
 *
 * Created on 22 January, 2016, 4:12 PM
 */

#ifndef IPRULE_H
#define	IPRULE_H

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <inttypes.h>
#define CDCHAIN "cd_chain"
#define IP_BLOCK_CHAIN "ip_block"
#define MAC_FILTER_CHAIN "mac_filter"

struct table_entry {
    char IP[17];
    char ports[20];
    char protocol[5];
    char target[10];
};
void iptc_add_rule(const char *table, const char *chain, const char *protocol, const char *iiface, const char *oiface, const char *src, const char *dest, const char *srcports, const char *destports, const char *target, const char *dnat_to, const int append);

void iptc_delete_rule(const char *table, const char *chain, const char *protocol, const char *iniface, const char *outiface, const char *src, const char *dest, const char *srcports, const char *destports, const char *target, const char *dnat_to);
struct ipt_entry_match *get_tcp_match(const char *sports, const char *dports, unsigned int *nfcache);
struct ipt_entry_match *get_udp_match(const char *sports, const char *dports, unsigned int *nfcache);
struct ipt_entry_target *get_dnat_target(const char *input, unsigned int *nfcache);
struct ipt_entry_target *get_snat_target(const char *input, unsigned int *nfcache);
static u_int16_t parse_port(const char *port);
static void parse_ports(const char *portstring, u_int16_t *ports);
static int service_to_port(const char *name);

static void parse_range(const char *input, struct ip_nat_range *range);
static struct ipt_natinfo *append_range(struct ipt_natinfo *info, const struct ip_nat_range *range);

int matchcmp(const struct ipt_entry_match *match, const char *srcports, const char *destports);

int set_chain(const char *table, const char *chain, int flag);
int flush_counters(const char *table, const char *chain);
unsigned long long read_counter(const char *table, const char *chain, unsigned int src, unsigned int dest, unsigned long long *rx, unsigned long long *tx);
int flush_chain(const char *table, const char *chain, unsigned int src, unsigned int dest, char *target, int all);
int insert_replace_rule(const char *table, const char *chain, unsigned int src, int inverted_src, unsigned int dest, int inverted_dst, const char *target);
int delete_mac_rule(const char *table, const char *chain, char *mac);
int insert_mac_rule(const char *table, const char *chain, unsigned int src, int inverted_src, unsigned int dest, int inverted_dst, const char *target1, char *mac);
int setIpToTable(char *ip, char *target, char *chain);
int removeIPFromTable(char *ip, int reset, char *chain);
int read_chain(const char *table, const char *chain, struct table_entry* tEntry);
int setIpTables(char *chain);
#endif	/* IPRULE_H */

