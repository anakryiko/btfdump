struct s0;

struct s1 {
	struct { struct s0* a; } (*a)();
};

struct s0 {
	struct s1 a[10];
};

typedef struct { struct s0* a; } (* fn)(struct s0 a, struct s1 b);

struct s2 {
	struct s0* _a;
	struct s1* _b;
	fn* _c;
	fn a;
	struct { struct s0* a; } (*b)(struct { struct s0 a; struct s1 b; } a);
};

int main() {
	static struct s2 s2;
	return 0;
}

