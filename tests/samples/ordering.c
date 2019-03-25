struct s1;

typedef void (*f1)(struct s1);
typedef struct s1 (*f2)();

struct s2;

// struct s4 has weak edge to struct s3
struct s4 {
	struct s3* a;
};

struct s3 {
	struct s2* x1;
};

// struct s2 has strong edge to struct s3
struct s2 {
	struct s3 a;
};

struct t1;

typedef struct t1 t1_t;

struct t1 {
	const struct t2* t;
};

struct t2 {
	t1_t t;
};

int main() {
	static f1 f1 = 0;
	static f2 f2 = 0;
	static struct s4 s4;
	static struct s2 s2;
	static struct s3 s3;
	static struct t1 t1;
	static struct t2 t2;
	return 0;
}
