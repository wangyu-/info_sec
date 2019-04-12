#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "libiptc/libiptc.h"
 
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
 
  if (!iptc_delete_entry (chain, (struct ipt_entry *) &entry,0, h))
    {
      fprintf (stderr, "Could not delete a rule in iptables (table %s): %s\n", table, iptc_strerror (errno));
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
