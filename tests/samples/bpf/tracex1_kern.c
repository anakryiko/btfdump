#ifdef bpf
#define __has_bpf__ 1
#endif

#undef bpf

#include "vmlinux.h"

#ifdef __has_bpf__
#define bpf 1
#endif

#define IFNAMSIZ 16
#define LINUX_VERSION_CODE 0

#define PT_REGS_PARM1(x) ((x)->di)
#define PT_REGS_PARM2(x) ((x)->si)
#define PT_REGS_PARM3(x) ((x)->dx)
#define PT_REGS_PARM4(x) ((x)->cx)
#define PT_REGS_PARM5(x) ((x)->r8)
#define PT_REGS_RET(x) ((x)->sp)
#define PT_REGS_FP(x) ((x)->bp)
#define PT_REGS_RC(x) ((x)->ax)
#define PT_REGS_SP(x) ((x)->sp)
#define PT_REGS_IP(x) ((x)->ip)

static int (*bpf_probe_read)(void *dst, int size, void *unsafe_ptr) =
        (void *) BPF_FUNC_probe_read;
static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) =
        (void *) BPF_FUNC_trace_printk;

#define SEC(NAME) __attribute__((section(NAME), used))
#define _(P) ({typeof(P) val = 0; bpf_probe_read(&val, sizeof(val), &P); val;})
#define R(P) do { void *x; bpf_probe_read(x, sizeof(1), (void*)&P); } while (0);

struct T {
	int t1;
	int t2;
};
typedef struct { int x; } W;
struct S {
	const volatile struct {
		const int a;
		const union {
			char b;
			struct {
				char c;
				int d;
			} e;
		};
	};
	struct T f[10];
	struct V {
		const char *g;
		void (*h)(int);
	} v;
	W w;
	struct {
		struct T x[5];
	} y[7];
};

SEC("__reloc_test")
int reloc_test(struct S* s) {
	struct S arr[2];

	//R(arr[1].w);
	R(s[1]);

	R(s->a);
	//R(s->b);
	//R(s->e.c);
	//R(s->e.d);
	//R(s->e);
	R(s->f[3]);
	R(s->f[2].t1);
	//R(s->v);
	R(s->v.g);
	R(s->v.h);
	R(s->w);
	//R(s->w.x);
	R(s->y[1]);
	R(s->y[2].x[3]);
	R(s->y[3].x[4].t2);

	return 0;
}

SEC("kprobe/__netif_receive_skb_core")
int bpf_prog1(struct pt_regs *ctx)
{
	/* attaches to kprobe netif_receive_skb,
	 * looks for packets on loobpack device and prints them
	 */
	char devname[IFNAMSIZ];
	struct net_device *dev;
	struct sk_buff *skb;
	int len;

	/* non-portable! works for the given kernel only */
	skb = (struct sk_buff *) PT_REGS_PARM1(ctx);
	dev = _(skb->dev);
	len = _(skb->len);

	bpf_probe_read(devname, sizeof(devname), dev->name);

	if (devname[0] == 'l' && devname[1] == 'o') {
		char fmt[] = "skb %p len %d\n";
		/* using bpf_trace_printk() for DEBUG ONLY */
		bpf_trace_printk(fmt, sizeof(fmt), skb, len);
	}

	//R(skb[2].__pkt_type_offset);
	R(skb->tcp_tsorted_anchor);
	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
