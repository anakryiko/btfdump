typedef unsigned int u32;

typedef void (*fn)(int);

typedef struct {
	int x, y, z;
} anon_struct_t;

void f(void (*fn)(int)) {
}

enum E {
	V1 = 0,
	V2 = 1,
};

enum E e = V1;

struct S;
union U;
struct S;

u32 func(enum E bla, const struct S* fwd_s, volatile union U* fwd_u) {
	return bla;
}

struct SimpleStruct {
	int a;
	u32 b;
	void (*f)(int a, enum E b);
	enum E arr[10];
};

union SimpleUnion {
	int a;
	struct SimpleStruct s;
	char arr[128];
};

union NestedAnonUnion {
	struct {
		int a;
		union {
			int b;
			int c;
		} d;
		struct {
			int x;
			char y;
			u32 z;
		};
	} A;
	int B;
	union SimpleUnion C;
	union {
		struct SimpleStruct Q;
		union SimpleUnion T;
	};
};


int main() {
	static struct SimpleStruct s1;
	static union SimpleUnion s2;
	static union NestedAnonUnion s3;
	static anon_struct_t s4;
	return 0;
}
