static int (*bpf_probe_read)(void *dst, int size, void *unsafe_ptr) =
        (void *) 4;

#define SEC(NAME) __attribute__((section(NAME), used))
#define R(P) do { void *x; bpf_probe_read(x, sizeof(1), (void*)&P); } while (0);

struct T {
	int t1;
	int t2;
};

struct S {
	int bit1: 1;
	int bit2: 1;
	int bit3: 1;
	int x;
	struct T t;
	struct {
		int t1;
		int t2;
		int t3;
	};
};

SEC("__simple_reloc_test")
int simple_reloc_test(struct S* s) {
	R(s->x);
	R(s->t);
	R(s->t.t1);
	R(s->t.t2);

	R(s->t1);
	R(s->t2);
	R(s->t3);
	return 0;
}

