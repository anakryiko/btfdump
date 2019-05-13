static int (*bpf_probe_read)(void *dst, int size, void *unsafe_ptr) =
        (void *) 4;

#define SEC(NAME) __attribute__((section(NAME), used))
#define R(P) do { void *x; bpf_probe_read(x, sizeof(1), (void*)&P); } while (0);

struct S {
	union {
		int a;
		union {
			char b;
			union {
				long q;
				int r;
			} p;
		};
	};
};

extern unsigned __kernel_version;

SEC("__reloc_test")
int reloc_test(struct S* s) {
	R(s->p);
	R(s->p.q);
	R(s->p.r);

	return 0;
}

