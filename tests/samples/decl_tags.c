#define __tag(x) __attribute__((btf_decl_tag(x)))

struct tagged_decl {
	int a __tag("member_a");
	int b;
	long c __tag("member_c") __tag("member_c_too");
	int d: 3;
} __tag("whole_struct");

typedef int tagged_typedef __tag("on_typedef");

union tagged_union {
	int u __tag("member_u");
	long v;
} __tag("whole_union");

struct tagged_decl decl;
tagged_typedef td;
union tagged_union un;
