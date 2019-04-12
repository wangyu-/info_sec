/* 
 * File:   IpRule.c
 * Author: kritpal
 *
 * Created on 22 January, 2016, 4:12 PM
 Originally created for testing purpose.
Made by Kritpal Singh.
For any further query email me @ kritpal.sing@gmail.com
Dependency ..Required Iptables libiptc   -lip4tc
 */
/* 
 * File:   IpRule.c
 * Author: kritpal
 *
 * Created on 22 January, 2016, 4:12 PM
 */
#include <libiptc/libiptc.h>
#include <arpa/inet.h> 
#include <linux/netfilter_ipv4/ip_nat.h>
#include "IpRule.h"
#include "linux/netfilter/xt_mac.h"

#include <netdb.h>
#define fprintf(stderr, args...) 
#define printf(args...) 
typedef struct iptc_handle * iptc_handle_t;

struct ipt_natinfo {
    struct ipt_entry_target t;
    struct ip_nat_multi_range mr;
};
/* fn returns 0 to continue iteration */
#define IPT_MATCH_ITERATE_MY(e, fn, args...)	\
({						\
	unsigned int __i;			\
	int __ret = 0;				\
	struct ipt_entry_match *__match;	\
						\
	for (__i = sizeof(struct ipt_entry);	\
	     __i < (e)->target_offset;		\
	     __i += __match->u.match_size) {	\
		__match = (struct ipt_entry_match *)(e) + __i;	\
						\
		__ret = fn(__match , ## args);	\
		if (__ret != 0)			\
			break;			\
	}					\
	__ret;					\
})

int setIpTables(char *chain) {

    //Delete CDCHAIN from Forward chain.
    flush_chain("filter", "FORWARD", 0, 0, chain, 0);
    //Flush CDCHAIN CHAIN
    flush_chain("filter", chain, 0, 0, NULL, 1);
    //Delete CDCHAIN chain
    set_chain("filter", chain, 0); //0 for delete ,1 for create
    //Create CDCHAIN
    set_chain("filter", chain, 1); //0 for delete ,1 for create
    //ADD CDCHAIN to FORWARD
    insert_replace_rule("filter", "FORWARD", 0, 0, 0, 0, chain);

}

int setIpToTable(char *ip, char *target, char *chain) {
    unsigned int a;
    inet_pton(AF_INET, ip, &a);
    insert_replace_rule("filter", chain, a, 0, 0, 0, target);
    insert_replace_rule("filter", chain, 0, 0, a, 0, target);
    return 0;
}

int removeIPFromTable(char *ip, int reset, char *chain) {

    if (reset) {
        flush_chain("filter", chain, 0, 0, NULL, 1);
    } else {
        unsigned int b;
        inet_pton(AF_INET, ip, &b);
        flush_chain("filter", chain, 0, b, NULL, 0);
        flush_chain("filter", chain, b, 0, NULL, 0);
    }

}

int insert_mac_rule(const char *table, const char *chain, unsigned int src, int inverted_src, unsigned int dest, int inverted_dst, const char *target1, char *mac) {
    struct xtc_handle *h;
    struct ipt_entry *en = NULL;
    struct ipt_entry * e;

    struct ipt_entry_match * match_proto, * match_limit;
    struct ipt_entry_target * target;
    unsigned int size_ipt_entry, size_ipt_entry_match, size_ipt_entry_target, total_length;
    int x, y;
    size_ipt_entry = IPT_ALIGN(sizeof (struct ipt_entry));
    size_ipt_entry_match = IPT_ALIGN(sizeof (struct ipt_entry_match)) + sizeof (struct xt_mac_info) + sizeof (int);
    size_ipt_entry_target = IPT_ALIGN(sizeof (struct ipt_entry_target) + sizeof (IPTC_LABEL_ACCEPT));
    total_length = size_ipt_entry + size_ipt_entry_match + size_ipt_entry_target; //size_ipt_entry + 48 + 40
    //    printf("size of ipt ebtry=%u,match=%u,target=%u,total=%u\n", size_ipt_entry, size_ipt_entry_match, size_ipt_entry_target, total_length);
    //memory allocation for all structs that represent the netfilter rule we want to insert
    e = (struct ipt_entry *) calloc(1, total_length);
    if (e == NULL) {
        printf("malloc failure");
        //exit(1);
        return 0;
    }

    //offsets to the other bits:
    //target struct begining
    e->target_offset = size_ipt_entry + size_ipt_entry_match; //+ size_ipt_tcp + size_rateinfo + size_physdevinfo;
    //next "e" struct, end of the current one
    e->next_offset = total_length;
    if (src) {
        e->ip.src.s_addr = src;
        e->ip.smsk.s_addr = 0xFFFFFFFF;
        if (inverted_src)
            e->ip.invflags |= IPT_INV_SRCIP;
    }

    if (dest) {
        e->ip.dst.s_addr = dest;
        e->ip.dmsk.s_addr = 0xFFFFFFFF;
        if (inverted_dst)
            e->ip.invflags |= IPT_INV_DSTIP;
    }
    match_limit = (struct ipt_entry_match *) (e->elems); //+ match_proto->u.match_size
    match_limit->u.user.match_size = size_ipt_entry_match; //size_ipt_entry_match*3; //+ size_rateinfo;
    strcpy(match_limit->u.user.name, "mac"); //set name of the module, we will use in this match
    struct xt_mac_info *info = (struct xt_mac_info *) match_limit->data;
    unsigned int i = 0;
    for (i = 0; i < 6; i++) {
        long number;
        char *end;

        number = strtol(mac + i * 3, &end, 16);

        if (end == mac + i * 3 + 2
                && number >= 0
                && number <= 255)
            info->srcaddr[i] = number;
        //        printf("mac=%02X:\n", info->srcaddr[i]);
        info->invert = 0;
    }
    target = (struct ipt_entry_target *) (e->elems + size_ipt_entry_match); //+ size_ipt_tcp + size_rateinfo + size_physdevinfo
    target->u.user.target_size = size_ipt_entry_target; // size_ipt_entry_target;
    strcpy(target->u.user.name, target1);

    //All the functions, mentioned below could be found in "Querying libiptc HOWTO" manual
    h = (struct xtc_handle *) iptc_init(table);
    if (!h) {
        printf("Error initializing: %s\n", iptc_strerror(errno));
        goto ERROR;
    }
    //TODO:Need to check if rule is already added.


    x = iptc_append_entry(chain, e, (iptc_handle*) h);
    if (!x) {
        printf("Error append_entry: %s\n", iptc_strerror(errno));
        goto ERROR;
    }
    printf("%d,chain=%s,target=%s\n", target->u.user.target_size, chain, table);
    y = iptc_commit((iptc_handle*) h);
    if (!y) {
        printf("Error no=%d,commit: %s\n", errno, iptc_strerror(errno));
        goto ERROR;
    }
    iptc_free((iptc_handle*) h);
    if (e != NULL) {
        free(e);
        e = NULL;
    }
    return 1;
ERROR:
    if(h !=NULL)iptc_free((iptc_handle*) h);
    if (e != NULL) {
        free(e);
        e = NULL;
    }
    return 0;
}

int delete_mac_rule(const char *table, const char *chain, char *mac) {
    struct xtc_handle *h;
    struct ipt_entry *en = NULL;
    struct ipt_entry * e;

    struct ipt_entry_match * match_proto, * match_limit;
    struct ipt_entry_target * target;
    unsigned int size_ipt_entry, size_ipt_entry_match, size_ipt_entry_target, total_length;
    int y;
    size_ipt_entry = IPT_ALIGN(sizeof (struct ipt_entry));
    size_ipt_entry_match = IPT_ALIGN(sizeof (struct ipt_entry_match)) + sizeof (struct xt_mac_info) + sizeof (int);
    size_ipt_entry_target = IPT_ALIGN(sizeof (struct ipt_entry_target) + sizeof (IPTC_LABEL_ACCEPT));
    total_length = size_ipt_entry + size_ipt_entry_match + size_ipt_entry_target; //size_ipt_entry + 48 + 40
    //    printf("size of ipt ebtry=%u,match=%u,target=%u,total=%u\n", size_ipt_entry, size_ipt_entry_match, size_ipt_entry_target, total_length);
    //memory allocation for all structs that represent the netfilter rule we want to insert
    h = (struct xtc_handle *) iptc_init(table);
    if (!h) {
        printf("Error initializing: %s\n", iptc_strerror(errno));
        return 0;
    }
    int found = 0, it = 1;
    for (en = (struct ipt_entry *) iptc_first_rule(chain, (iptc_handle*) h); en; en = (struct ipt_entry *) iptc_next_rule(en, (iptc_handle*) h), it++) {
        struct xt_entry_match *match;
        unsigned int __i;
        for (__i = size_ipt_entry; __i < (en)->target_offset; __i += match->u.match_size) {
            match = (struct xt_entry_match*) (en + __i);
            struct xt_mac_info *inf = (struct xt_mac_info*) match->data;
            char mm[60];
            sprintf((char*) mm, "%02X:%02X:%02X:%02X:%02X:%02X", inf->srcaddr[0], inf->srcaddr[1], inf->srcaddr[2], inf->srcaddr[3], inf->srcaddr[4], inf->srcaddr[5]);
            //            printf("mm=%s,mac=%s\n", mm, mac);
            if (strcasecmp(mm, mac) == 0) {
                found = 1;
                printf("found old entry\n");
                break;
            }

        }
        if (found) {
            break;
        }

    }
    if (found) {
        //        printf("it=%d\n", it);
        if (!(iptc_delete_num_entry(chain, it - 1, (iptc_handle*) h))) {
            printf("delete: %s\n", iptc_strerror(errno));
            goto ERROR;
        }


        y = iptc_commit((iptc_handle*) h);
        if (!y) {
            printf("Error no=%d,commit: %s\n", errno, iptc_strerror(errno));
            goto ERROR;
        }
        iptc_free((iptc_handle*) h);

        return 1;
    }
ERROR:
    iptc_free((iptc_handle*) h);
    return 0;
}

int insert_replace_rule(const char *table, const char *chain, unsigned int src, int inverted_src, unsigned int dest, int inverted_dst, const char *target) {
    int found = 0;

    struct {
        struct ipt_entry entry;
        struct xt_standard_target target;
    } entry;
    const struct ipt_entry *en = NULL;
    struct xtc_handle *h;
    int ret = 1;

    h = (struct xtc_handle*) iptc_init(table);
    if (!h) {
        fprintf(stderr, "Could not init IPTC library: %s\n", iptc_strerror(errno));
        goto out;
    }

    memset(&entry, 0, sizeof (entry));

    /* target */
    entry.target.target.u.user.target_size = XT_ALIGN(sizeof (struct xt_standard_target));
    strncpy(entry.target.target.u.user.name, target, sizeof (entry.target.target.u.user.name));

    /* entry */
    entry.entry.target_offset = sizeof (struct ipt_entry);
    entry.entry.next_offset = entry.entry.target_offset + entry.target.target.u.user.target_size;

    if (src) {
        entry.entry.ip.src.s_addr = src;
        entry.entry.ip.smsk.s_addr = 0xFFFFFFFF;
        if (inverted_src)
            entry.entry.ip.invflags |= IPT_INV_SRCIP;
    }

    if (dest) {
        entry.entry.ip.dst.s_addr = dest;
        entry.entry.ip.dmsk.s_addr = 0xFFFFFFFF;
        if (inverted_dst)
            entry.entry.ip.invflags |= IPT_INV_DSTIP;
    }

    for (en = (const ipt_entry*) iptc_first_rule(chain, (iptc_handle*) h); en; en = (const ipt_entry*) iptc_next_rule(en, (iptc_handle*) h)) {
        const char *target1 = NULL;
        target1 = iptc_get_target(en, (iptc_handle*) h);

        if (en->ip.src.s_addr == src && en->ip.dst.s_addr == dest && strcmp(target, target1) == 0) {
            printf("Ip Found no need to add rule for SRC=%d and dest=%d\n", en->ip.src.s_addr, en->ip.dst.s_addr);
            found = 1;
            break;
        }

    }
    if (!found) {
        if (!iptc_insert_entry(chain, (struct ipt_entry *) &entry, 0, (iptc_handle*) h)) {
            fprintf(stderr, "Could not insert a rule in iptables (table %s): %s\n", table, iptc_strerror(errno));
            goto out;
        }

        if (!iptc_commit((iptc_handle*) h)) {
            fprintf(stderr, "Could not commit changes for insert/replace rule in iptables (table %s): %s\n", table, iptc_strerror(errno));
            goto out;
        }
    }
    ret = 0;
out:
    if (h)
        iptc_free((iptc_handle*) h);

    return ret;
}

//int main(int argc, char **argv) {
//    unsigned int a, b, c;
//
//    //    inet_pton(AF_INET, "1.2.3.4", &a);
//    inet_pton(AF_INET, "20.10.10.101", &a);
//    inet_pton(AF_INET, "20.10.10.100", &b);
//    inet_pton(AF_INET, "20.10.10.111", &c);
//    //    flush_chain("filter", "FORWARD", 0, 0, "ACCOUNTING", 0);
//    //    flush_chain("filter", "ACCOUNTING", b, 0, NULL, 0);
//    //    flush_chain("filter", "ACCOUNTING", 0, b, NULL, 0);
//    //    set_chain("filter", "ACCOUNTING", 1);//0 for delete ,1 for create
//    /*To insert/replace a new rule*/
//    //    insert_replace_rule("filter", "FORWARD", 0, 0, 0, 0, "ACCOUNTING");
//    //        insert_replace_rule("filter", "FORWARD", 0, 0, 0, 0, "ACCOUNTING_OUT");
//    insert_replace_rule("filter", "ACCOUNTING", 0, 0, b, 0, "RETURN");
//    //        insert_replace_rule("filter", "ACCOUNTING", b, 0, 0, 0, "RETURN");
//    //    insert_replace_rule("filter", "ACCOUNTING_IN", 0, 0, a, 0, "RETURN");
//    //    insert_replace_rule("filter", "ACCOUNTING_OUT", a, 0, 0, 0, "RETURN");
//    //    insert_replace_rule("filter", "ACCOUNTING_IN", 0, 0, b, 0, "RETURN");
//    //    insert_replace_rule("filter", "ACCOUNTING_OUT", b, 0, 0, 0, "RETURN");
//    /**To read byte and packets count*/
//    //        unsigned long long rx = 0; // = read_counter("filter", "ACCOUNTING_IN", 0, c);
//    //    unsigned long long tx = 0; // = read_counter("filter", "ACCOUNTING_OUT", c, 0);
//    //    int ret = read_counter("filter", "ACCOUNTING", b, b, &rx, &tx);
//    //    if (ret) {
//    //        printf("RX=%llu,TX=%llu\n", rx, tx);
//    //    }
//    //    flush_chain("filter", "ACCOUNTING_IN", 0, b, 0);
//    //    flush_chain("filter", "ACCOUNTING_OUT", b, 0, 0);
//    //    flush_counters("filter", "ACCOUNTING_IN");
//    //    flush_counters("filter", "ACCOUNTING_OUT");
//
//    return 0;
//}

int set_chain(const char *table, const char *chain, int flag) {
    struct xtc_handle *h;
    int ret = 1;
    h = (struct xtc_handle *) iptc_init(table);
    if (!h) {
        fprintf(stderr, "Could not init IPTC library: %s\n", iptc_strerror(errno));
        return 0;
    }
    if (flag) {//Create chain
        if (iptc_is_chain(chain, (iptc_handle*) h)) {
            fprintf(stderr, "chain present   iptables (Chain %s): %s\n", chain, iptc_strerror(errno));
            iptc_free((iptc_handle*) h);
            return 1;
        }

        if (!iptc_create_chain(chain, (iptc_handle*) h)) {
            fprintf(stderr, "Could not create new chain in iptables (Chain %s): %s\n,%d\n", chain, iptc_strerror(errno), errno);
            iptc_free((iptc_handle*) h);
            return 0;
        }
    } else {//Delete chain
        if (!iptc_is_chain(chain, (iptc_handle*) h)) {
            fprintf(stderr, "chain not present   iptables (Chain %s): %s\n", chain, iptc_strerror(errno));
            iptc_free((iptc_handle*) h);
            return 1;
        }
        if (!iptc_delete_chain(chain, (iptc_handle*) h)) {
            fprintf(stderr, "chain not deleted iptables (Chain %s): %s\n", chain, iptc_strerror(errno));
            iptc_free((iptc_handle*) h);
            return 0;
        }
    }
    if (!iptc_commit((iptc_handle*) h)) {
        fprintf(stderr, "Could not commit new chain in iptables (table %s): %s\n", table, iptc_strerror(errno));

    }
    iptc_free((iptc_handle*) h);
    return 1;
}

int flush_chain(const char *table, const char *chain, unsigned int src, unsigned int dest, char * target, int all) {
    struct xtc_handle *h;
    int ret = 1;
    int found = 0;
    //    const char *chain = NULL;
    const struct ipt_entry *en = NULL;
    struct ipt_counters *counters, cZero;
    h = (struct xtc_handle *) iptc_init(table);
    if (!h) {
        fprintf(stderr, "Could not init IPTC library: %s\n", iptc_strerror(errno));
        return 0;
    }
    if (!all) {
        int i = 1;
        for (en = (const struct ipt_entry *) iptc_first_rule(chain, (iptc_handle*) h); en; en = (const struct ipt_entry *) iptc_next_rule(en, (iptc_handle*) h), i++) {
            if (src != 0) {
                if (en->ip.src.s_addr == src) {
                    found = 1;
                    printf("Ip Found for SRC=%d at i=%d \n", en->ip.src.s_addr, i);
                    if (!(iptc_delete_num_entry(chain, i - 1, (iptc_handle*) h))) {
                        iptc_free((iptc_handle*) h);
                        return 0;
                    }
                    break;
                }
            } else if (dest != 0) {
                if (en->ip.dst.s_addr == dest) {
                    printf("Ip Found  for dest=%d\n", en->ip.dst.s_addr);
                    found = 1;
                    if (!(iptc_delete_num_entry(chain, i - 1, (iptc_handle*) h))) {
                        iptc_free((iptc_handle*) h);
                        return 0;
                    }
                    break;
                }
            } else if (target != NULL) {
                const char *target1 = NULL;
                target1 = iptc_get_target(en, (iptc_handle*) h);
                if (strcmp(target, target1) == 0) {
                    found = 1;
                    printf("Found rule at i=%d\n", i);
                    if (!(iptc_delete_num_entry(chain, i - 1, (iptc_handle*) h))) {
                        iptc_free((iptc_handle*) h);
                        return 0;
                    }
                    break;
                }
            }
        }

    } else {
        if (!(iptc_flush_entries(chain, (iptc_handle*) h))) {
            iptc_free((iptc_handle*) h);
            return 0;
        }
    }
    if (!found) {
        ret = 0;
    }
    if (!iptc_commit((iptc_handle*) h)) {
        fprintf(stderr, "Could not commit changes in iptables (table %s): %s\n", table, iptc_strerror(errno));

    }
    iptc_free((iptc_handle*) h);
    return ret;
}

int flush_counters(const char *table, const char *chain) {
    struct xtc_handle *h;
    int ret = 1;
    h = (struct xtc_handle *) iptc_init(table);
    if (!h) {
        fprintf(stderr, "Could not init IPTC library: %s\n", iptc_strerror(errno));
        return 0;
    }
    if (!iptc_zero_entries(chain, (iptc_handle*) h)) {
        iptc_free((iptc_handle*) h);
        return 0;
    }
    if (!iptc_commit((iptc_handle*) h)) {
        fprintf(stderr, "Could not commit changes in iptables (table %s): %s\n", table, iptc_strerror(errno));
        iptc_free((iptc_handle*) h);
        return 0;
    }
    iptc_free((iptc_handle*) h);
    return 1;
}

unsigned long long read_counter(const char *table, const char *chain, unsigned int src, unsigned int dest, unsigned long long *rx, unsigned long long *tx) {
    struct xtc_handle *h;
    int ret = 1;
    //    const char *chain = NULL;
    const struct ipt_entry *en = NULL;
    struct ipt_counters *counters, cZero;
    h = (struct xtc_handle *) iptc_init(table);
    if (!h) {
        fprintf(stderr, "Could not init IPTC library: %s\n", iptc_strerror(errno));
        return 0;
    }

    int i = 1;
    int flag = 0;
    for (en = (const struct ipt_entry *) iptc_first_rule(chain, (iptc_handle*) h); en; en = (const struct ipt_entry *) iptc_next_rule(en, (iptc_handle*) h), i++) {

        if (en->ip.src.s_addr == src) {//To get TX value
            printf("Ip Found for SRC=%d \n", en->ip.src.s_addr);
            if (!(counters = iptc_read_counter(chain, i, (iptc_handle*) h))) {
                iptc_free((iptc_handle*) h);
                return 0;
            }
            *tx = counters->bcnt;
            if (!(iptc_zero_counter(chain, i, (iptc_handle*) h))) {
                iptc_free((iptc_handle*) h);
                return 0;
            }
            flag++;
        }

        if (en->ip.dst.s_addr == dest) {//TO get rx value
            printf("Ip Found  for dest=%d\n", en->ip.dst.s_addr);
            if (!(counters = iptc_read_counter(chain, i, (iptc_handle*) h))) {
                iptc_free((iptc_handle*) h);
                return 0;
            }
            *rx = counters->bcnt;
            if (!(iptc_zero_counter(chain, i, (iptc_handle*) h))) {
                iptc_free((iptc_handle*) h);
                return 0;
            }
            flag++;
        }

    }
    if (flag >= 2) {
        if (!iptc_commit((iptc_handle*) h)) {
            fprintf(stderr, "Could not commit changes in iptables (table %s): %s\n", table, iptc_strerror(errno));

        }
        iptc_free((iptc_handle*) h);
        return 1;
    }
    iptc_free((iptc_handle*) h);
    return 0;


}

void iptc_add_rule(const char *table, const char *chain, const char *protocol, const char *iniface, const char *outiface, const char *src, const char *dest, const char *srcports, const char *destports, const char *target, const char *dnat_to, const int append) {
    iptc_handle_t handle;
    struct ipt_entry *chain_entry;
    struct ipt_entry_match *entry_match = NULL;
    struct ipt_entry_target *entry_target;
    ipt_chainlabel labelit;
    long match_size;
    int result = 0;

    chain_entry = (struct ipt_entry *) calloc(1, sizeof (*chain_entry));

    if (src) {
        chain_entry->ip.src.s_addr = inet_addr(src);
        chain_entry->ip.smsk.s_addr = inet_addr("255.255.255.255");
    }
    if (dest) {
        chain_entry->ip.dst.s_addr = inet_addr(dest);
        chain_entry->ip.dmsk.s_addr = inet_addr("255.255.255.255");
    }

    if (iniface) strncpy(chain_entry->ip.iniface, iniface, IFNAMSIZ);
    if (outiface) strncpy(chain_entry->ip.outiface, outiface, IFNAMSIZ);

    if (strcmp(protocol, "TCP") == 0) {
        chain_entry->ip.proto = IPPROTO_TCP;
        entry_match = get_tcp_match(srcports, destports, &chain_entry->nfcache);
    } else if (strcmp(protocol, "UDP") == 0) {
        chain_entry->ip.proto = IPPROTO_UDP;
        entry_match = get_udp_match(srcports, destports, &chain_entry->nfcache);
    } else {
        printf("Unsupported protocol: %s", protocol);
        return;
    }

    if (strcmp(target, "") == 0
            || strcmp(target, IPTC_LABEL_ACCEPT) == 0
            || strcmp(target, IPTC_LABEL_DROP) == 0
            || strcmp(target, IPTC_LABEL_QUEUE) == 0
            || strcmp(target, IPTC_LABEL_RETURN) == 0) {
        size_t size;

        size = IPT_ALIGN(sizeof (struct ipt_entry_target)) + IPT_ALIGN(sizeof (int));
        entry_target = (struct ipt_entry_target *) calloc(1, size);
        entry_target->u.user.target_size = size;
        strncpy(entry_target->u.user.name, target, IPT_FUNCTION_MAXNAMELEN);
    } else if (strcmp(target, "DNAT") == 0) {
        entry_target = get_dnat_target(dnat_to, &chain_entry->nfcache);
        printf("dnat\n");
    } else if (strcmp(target, "SNAT") == 0) {
        entry_target = get_snat_target(dnat_to, &chain_entry->nfcache);
        printf("snat\n");
    }

    if (entry_match)
        match_size = entry_match->u.match_size;
    else
        match_size = 0;
    struct ipt_entry *tmp_ipt = chain_entry;
    chain_entry = (struct ipt_entry *) realloc(chain_entry, sizeof (*chain_entry) + match_size + entry_target->u.target_size);
    if (chain_entry == NULL) {
        free(tmp_ipt);
    }
    memcpy(chain_entry->elems + match_size, entry_target, entry_target->u.target_size);
    chain_entry->target_offset = sizeof (*chain_entry) + match_size;
    chain_entry->next_offset = sizeof (*chain_entry) + match_size + entry_target->u.target_size;
    printf("target->offset=%d,next_offset=%d,target_size=%d\n", chain_entry->target_offset, chain_entry->next_offset, entry_target->u.user.target_size);
    if (entry_match) {
        memcpy(chain_entry->elems, entry_match, match_size);
        printf("%d\n", __LINE__);
    }
    printf("%d\n", __LINE__);
    handle = iptc_init(table);
    if (!handle) {
        printf("libiptc error: Can't initialize table %s, %s", table, iptc_strerror(errno));
        free(chain_entry);
        free(entry_target);
        if (entry_match) free(entry_match);
        return;
    }

    strncpy(labelit, chain, sizeof (ipt_chainlabel));
    printf("%d\n", __LINE__);
    result = iptc_is_chain(chain, handle);
    if (!result) {
        printf("libiptc error: Chain %s does not exist!", chain);
        free(chain_entry);
        free(entry_target);
        if (entry_match) free(entry_match);
        return;
    }
    printf("%d,labeit=%s\n", __LINE__, labelit);
    if (append)
        result = iptc_append_entry(labelit, chain_entry, handle);
    else
        result = iptc_insert_entry(labelit, chain_entry, 0, handle);
    printf("%d\n", __LINE__);
    if (!result) {
        printf("libiptc error: Can't add, %s", iptc_strerror(errno));
        free(chain_entry);
        free(entry_target);
        if (entry_match) free(entry_match);
        return;
    }
    printf("%d\n", __LINE__);
    result = iptc_commit(handle);
    if (!result) {
        printf("libiptc error: Commit error, %s", iptc_strerror(errno));
        free(chain_entry);
        free(entry_target);
        if (entry_match) free(entry_match);
        return;
    } else
        printf("added new rule to block successfully");

    if (entry_match) free(entry_match);
    free(entry_target);
    free(chain_entry);
}

void iptc_delete_rule(const char *table, const char *chain, const char *protocol, const char *iniface, const char *outiface, const char *src, const char *dest, const char *srcports, const char *destports, const char *target, const char *dnat_to) {
    iptc_handle_t handle;
    const struct ipt_entry *e;
    ipt_chainlabel labelit;
    int i, result;
    unsigned long int s_src, s_dest;

    if (src) s_src = inet_addr(src);
    if (dest) s_dest = inet_addr(dest);

    handle = iptc_init(table);
    if (!handle) {
        printf("libiptc error: Can't initialize table %s, %s", table, iptc_strerror(errno));
        return;
    }

    strncpy(labelit, chain, sizeof (ipt_chainlabel));
    result = iptc_is_chain(chain, handle);
    if (!result) {
        printf("libiptc error: Chain %s does not exist!", chain);
        return;
    }
    for (e = iptc_first_rule(chain, handle), i = 0; e; e = iptc_next_rule(e, handle), i++) {
        if (src && e->ip.src.s_addr != s_src) continue;
        else if (dest && e->ip.dst.s_addr != s_dest) continue;
        else if (iniface && strcmp(e->ip.iniface, iniface) != 0) continue;
        else if (outiface && strcmp(e->ip.outiface, outiface) != 0) continue;
        else if (protocol && strcmp(protocol, "TCP") == 0 && e->ip.proto != IPPROTO_TCP) continue;
        else if (protocol && strcmp(protocol, "UDP") == 0 && e->ip.proto != IPPROTO_UDP) continue;
        else if ((srcports || destports) && IPT_MATCH_ITERATE_MY(e, matchcmp, srcports, destports) == 0) continue;
        else if (target && strcmp(target, iptc_get_target(e, handle)) != 0) continue;
        else if (dnat_to && strcmp(target, "DNAT") == 0) {
            struct ipt_entry_target *t;
            struct ip_nat_multi_range *mr;
            struct ip_nat_range *r, range;

            t = (struct ipt_entry_target *) (e + e->target_offset);
            mr = (struct ip_nat_multi_range *) ((void *) &t->data);

            if (mr->rangesize != 1) continue; // we have only single dnat_to target now
            r = mr->range;
            parse_range(dnat_to, &range);
            if (r->flags == range.flags
                    && r->min_ip == range.min_ip
                    && r->max_ip == range.max_ip
                    && r->min.all == range.min.all
                    && r->max.all == range.max.all) {
                break;
            }
        } else break;
    }
    if (!e) return;
    result = iptc_delete_num_entry(chain, i, handle);
    if (!result) {
        printf("libiptc error: Delete error, %s", iptc_strerror(errno));
        return;
    }
    result = iptc_commit(handle);
    if (!result) {
        printf("libiptc error: Commit error, %s", iptc_strerror(errno));
        return;
    } else
        printf("deleted rule from block successfully");
}

int matchcmp(const struct ipt_entry_match *match, const char *srcports, const char *destports) {
    u_int16_t temp[2];

    if (strcmp(match->u.user.name, "tcp") == 0) {
        struct ipt_tcp *tcpinfo = (struct ipt_tcp *) match->data;

        if (srcports) {
            parse_ports(srcports, temp);
            if (temp[0] != tcpinfo->spts[0] || temp[1] != tcpinfo->spts[1]) return 0;
        }
        if (destports) {
            parse_ports(destports, temp);
            if (temp[0] != tcpinfo->dpts[0] || temp[1] != tcpinfo->dpts[1]) return 0;
        }
        return 1;
    } else if (strcmp(match->u.user.name, "udp") == 0) {
        struct ipt_udp *udpinfo = (struct ipt_udp *) match->data;

        if (srcports) {
            parse_ports(srcports, temp);
            if (temp[0] != udpinfo->spts[0] || temp[1] != udpinfo->spts[1]) return 0;
        }
        if (destports) {
            parse_ports(destports, temp);
            if (temp[0] != udpinfo->dpts[0] || temp[1] != udpinfo->dpts[1]) return 0;
        }
        return 1;
    } else return 0;
}

/* These functions are used to create structs */

struct ipt_entry_match *
get_tcp_match(const char *sports, const char *dports, unsigned int *nfcache) {
    struct ipt_entry_match *match;
    struct ipt_tcp *tcpinfo;
    size_t size;

    size = IPT_ALIGN(sizeof (*match)) + IPT_ALIGN(sizeof (*tcpinfo));
    match = (struct ipt_entry_match *) calloc(1, size);
    match->u.match_size = size;
    strncpy(match->u.user.name, "tcp", IPT_FUNCTION_MAXNAMELEN);

    tcpinfo = (struct ipt_tcp *) match->data;
    tcpinfo->spts[1] = tcpinfo->dpts[1] = 0xFFFF;
    printf("sports=%s,dports=%s\n", sports, dports);
    if (sports) {
        *nfcache |= NFC_IP_SRC_PT;
        parse_ports(sports, tcpinfo->spts);
        printf("%d\n", __LINE__);
    }
    if (dports) {
        *nfcache |= NFC_IP_DST_PT;
        parse_ports(dports, tcpinfo->dpts);
        printf("%d\n", __LINE__);
    }

    return match;
}

struct ipt_entry_match *
get_udp_match(const char *sports, const char *dports, unsigned int *nfcache) {
    struct ipt_entry_match *match;
    struct ipt_udp *udpinfo;
    size_t size;

    size = IPT_ALIGN(sizeof (*match)) + IPT_ALIGN(sizeof (*udpinfo));
    match = (struct ipt_entry_match *) calloc(1, size);
    match->u.match_size = size;
    strncpy(match->u.user.name, "udp", IPT_FUNCTION_MAXNAMELEN);

    udpinfo = (struct ipt_udp *) match->data;
    udpinfo->spts[1] = udpinfo->dpts[1] = 0xFFFF;
    printf("sports=%s,dports=%s\n", sports, dports);
    if (sports) {
        *nfcache |= NFC_IP_SRC_PT;
        parse_ports(sports, udpinfo->spts);
        printf("%d\n", __LINE__);
    }
    if (dports) {
        *nfcache |= NFC_IP_DST_PT;
        parse_ports(dports, udpinfo->dpts);
        printf("%d\n", __LINE__);
    }

    return match;
}

struct ipt_entry_target *
get_dnat_target(const char *input, unsigned int *nfcache) {
    struct ipt_entry_target *target;
    struct ipt_natinfo *info;
    struct ip_nat_range range;

    char *buffer;
    size_t size;

    /* Can't cache this */
    *nfcache |= NFC_UNKNOWN;

    buffer = strdup(input);
    size = IPT_ALIGN(sizeof (*target)) + IPT_ALIGN(sizeof (struct ip_nat_multi_range));
    target = (struct ipt_entry_target *) calloc(1, size);
    target->u.target_size = size;
    strncpy(target->u.user.name, "DNAT", IPT_FUNCTION_MAXNAMELEN);

    info = (struct ipt_natinfo *) target;
    printf("buffer range=%s\n", buffer);
    parse_range(buffer, &range);
    target = &(append_range(info, &range)->t);
    printf("range=%d\n", range.flags);
    printf("%d\n", __LINE__);
    free(buffer);

    return target;
}

struct ipt_entry_target *
get_snat_target(const char *input, unsigned int *nfcache) {
    struct ipt_entry_target *target;
    struct ipt_natinfo *info;
    struct ip_nat_range range;

    char *buffer;
    size_t size;

    /* Can't cache this */
    *nfcache |= NFC_UNKNOWN;

    buffer = strdup(input);
    size = IPT_ALIGN(sizeof (*target)) + IPT_ALIGN(sizeof (struct ip_nat_multi_range));
    target = (struct ipt_entry_target *) calloc(1, size);
    target->u.target_size = size;
    strncpy(target->u.user.name, "SNAT", IPT_FUNCTION_MAXNAMELEN);

    info = (struct ipt_natinfo *) target;
    printf("buffer range=%s\n", buffer);
    parse_range(buffer, &range);
    target = &(append_range(info, &range)->t);
    printf("range=%d\n", range.flags);
    printf("%d\n", __LINE__);
    free(buffer);

    return target;
}

/* Copied and modified from libipt_tcp.c and libipt_udp.c */

static u_int16_t
parse_port(const char *port) {
    unsigned int portnum;

    if ((portnum = service_to_port(port)) != -1) {
        return (u_int16_t) portnum;
    } else {
        return atoi(port);
    }
}

static void
parse_ports(const char *portstring, u_int16_t *ports) {
    char *buffer;
    char *cp;

    buffer = strdup(portstring);
    if ((cp = strchr(buffer, ':')) == NULL)
        ports[0] = ports[1] = parse_port(buffer);
    else {
        *cp = '\0';
        cp++;

        ports[0] = buffer[0] ? parse_port(buffer) : 0;
        ports[1] = cp[0] ? parse_port(cp) : 0xFFFF;
    }
    free(buffer);
}

static int
service_to_port(const char *name) {
    struct servent *service;

    if ((service = getservbyname(name, "tcp")) != NULL)
        return ntohs((unsigned short) service->s_port);

    return -1;
}

/* Copied and modified from libipt_DNAT.c */

static void
parse_range(const char *input, struct ip_nat_range *range) {
    char *colon, *dash, *buffer;
    in_addr_t ip;

    buffer = strdup(input);
    memset(range, 0, sizeof (*range));
    colon = strchr(buffer, ':');

    if (colon) {
        int port;

        range->flags |= IP_NAT_RANGE_PROTO_SPECIFIED;

        port = atoi(colon + 1);
        dash = strchr(colon, '-');
        if (!dash) {
            range->min.all
                    = range->max.all
                    = htons(port);
        } else {
            int maxport;

            maxport = atoi(dash + 1);
            range->min.all = htons(port);
            range->max.all = htons(maxport);
        }
        /* Starts with a colon? No IP info...*/
        if (colon == buffer) {
            free(buffer);
            return;
        }
        *colon = '\0';
    }

    range->flags |= IP_NAT_RANGE_MAP_IPS;
    dash = strchr(buffer, '-');
    if (colon && dash && dash > colon)
        dash = NULL;

    if (dash)
        *dash = '\0';

    ip = inet_addr(buffer);
    range->min_ip = ip;
    if (dash) {
        ip = inet_addr(dash + 1);
        range->max_ip = ip;
    } else
        range->max_ip = range->min_ip;

    free(buffer);
    return;
}

static struct ipt_natinfo *
append_range(struct ipt_natinfo *info, const struct ip_nat_range *range) {
    unsigned int size;

    /* One ip_nat_range already included in ip_nat_multi_range */
    size = IPT_ALIGN(sizeof (*info) + info->mr.rangesize * sizeof (*range));

    info = (struct ipt_natinfo *) realloc(info, size);

    info->t.u.target_size = size;
    info->mr.range[info->mr.rangesize] = *range;
    info->mr.rangesize++;
    printf("range size=%d\n", info->mr.rangesize);
    return info;
}

int read_chain(const char *table, const char *chain, struct table_entry* tEntry) {
    struct xtc_handle *h;
    int ret = 1;
    int found = 0;
    //    const char *chain = NULL;
    const struct ipt_entry *en = NULL;
    struct ipt_counters *counters, cZero;
    h = (struct xtc_handle *) iptc_init(table);
    if (!h) {
        fprintf(stderr, "Could not init IPTC library: %s\n", iptc_strerror(errno));
        return 0;
    }

    int i = 1;
    for (en = (const struct ipt_entry *) iptc_first_rule(chain, (iptc_handle*) h); en; en = (const struct ipt_entry *) iptc_next_rule(en, (iptc_handle*) h), i++) {
        // found = 1;

        // printf("Ip Found for SRC=%d at i=%d \n", en->ip.src.s_addr, i);
        //        char ip[50];
        //        inet_ntop(AF_INET, &(en->ip.dst.s_addr), ip, INET_ADDRSTRLEN);
        //printf("Ip Found  for dest=%s\n", ip);
        // found = 1;
        const char *target1 = NULL;
        target1 = iptc_get_target(en, (iptc_handle*) h);
        // if (strcmp(target, target1) == 0) {
        //found = 1;
        //        printf("Found target = %s rule at i=%d\n", target1, i);
        struct ipt_entry_match *entry_match = (struct ipt_entry_match *) en->elems;
        //printf("Match =%s\n", entry_match->u.user.name);
        u_int16_t temp[2];
        char ports[16];
        if (strstr(entry_match->u.user.name, "udp")) {
            struct ipt_udp *udpinfo = (struct ipt_udp *) entry_match->data;
            char *cp;
            if (udpinfo->dpts[1] == udpinfo->dpts[0]) {
                sprintf(ports, "%d", udpinfo->dpts[0]);
            } else {
                sprintf(ports, "%d:%d", udpinfo->dpts[0], udpinfo->dpts[1]);
            }
            printf("udp dest port=%s\n", ports);
        } else if (strstr(entry_match->u.user.name, "tcp")) {
            struct ipt_tcp *tcpinfo = (struct ipt_tcp *) entry_match->data;
            char *cp;
            if (tcpinfo->dpts[1] == tcpinfo->dpts[0]) {
                sprintf(ports, "%d", tcpinfo->dpts[0]);
            } else {
                sprintf(ports, "%d:%d", tcpinfo->dpts[0], tcpinfo->dpts[1]);
            }
            printf("tcp dest port=%s\n", ports);
        }
        struct ipt_entry_target *t;
        struct ipt_natinfo *info;
        int size_ipt_entry_match = IPT_ALIGN(sizeof (struct ipt_entry_match)) + sizeof (struct ipt_tcp) + sizeof (int);
        t = (struct ipt_entry_target *) (en->elems + size_ipt_entry_match);
        info = (struct ipt_natinfo *) t;
        char minIp[50], maxIp[50];
        inet_ntop(AF_INET, &(info->mr.range[0].min_ip), minIp, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(info->mr.range[0].max_ip), maxIp, INET_ADDRSTRLEN);
        printf("IP Min=%s , Max=%s \n", minIp, maxIp);
        sprintf((*(tEntry + i - 1)).IP, "%s", minIp);
        sprintf((*(tEntry + i - 1)).ports, "%s", ports);
        sprintf((*(tEntry + i - 1)).protocol, "%s", entry_match->u.user.name);
        sprintf((*(tEntry + i - 1)).target, "%s", target1);
    }



    //    if (!iptc_commit((iptc_handle*) h)) {
    //        fprintf(stderr, "Could not commit changes in iptables (table %s): %s\n", table, iptc_strerror(errno));
    //
    //    }
    iptc_free((iptc_handle*) h);
    if (i == 1) {//No entry to read;
        return 0;
    }
    return i;
}

int main(int argc,char** argv){
    struct table_entry *forwardEntry;
        system("iptables -F mac_filter 1>/dev/null 2>&1");
setIpTables(CDCHAIN); //Set CDCHAIN
    setIpTables(IP_BLOCK_CHAIN);
    setIpToTable(argv[1], "DROP", IP_BLOCK_CHAIN);
setIpToTable(argv[1], "RETURN", CDCHAIN); //Where argv[1] is an IP in 10.10.10.1 format.
removeIPFromTable(argv[1], 0, CDCHAIN); //to remove ip from chain
    flush_chain("filter", "INPUT", 0, 0, MAC_FILTER_CHAIN, 0);
    flush_chain("filter", MAC_FILTER_CHAIN, 0, 0, NULL, 1);
    insert_replace_rule("filter", "INPUT", 0, 0, 0, 0, MAC_FILTER_CHAIN);
     insert_mac_rule("filter", MAC_FILTER_CHAIN, 0, 0, 0, 0, "DROP", argv[1]); //Where argv[1] is a MAC in 11:22:33:22:33:11 format.
     read_chain("nat", "port_forward", forwardEntry)
     return 0;
}

