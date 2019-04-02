static int (*bpf_probe_read)(void *dst, int size, void *unsafe_ptr) =
        (void *) 4;

#define SEC(NAME) __attribute__((section(NAME), used))
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
			struct {
				long q;
				int r;
			} p;
			struct {
				long q2;
				int r2;
			} p2;
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
	R(s->e.d);
	R(s->e);
	R(s->p);
	R(s->p.q);
	R(s->p.r);
	R(s->p2);
	R(s->p2.q2);
	R(s->p2.r2);
	R(s->f[3]);
	R(s->f[2].t1);
	R(s->v);
	R(s->v.g);
	R(s->v.h);
	R(s->w);
	R(s->w.x);
	R(s->y[1]);
	R(s->y[2].x[3]);
	R(s->y[3].x[4].t2);

	return 0;
}
