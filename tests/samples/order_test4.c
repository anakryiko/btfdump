
typedef struct s0 s0_t;

struct s0 {};
struct s1 {
	s0_t* s0p;
};

struct s2 {
	s0_t s0;
};

struct s3 {
	struct s2 s3;
};

int main() {
	static struct s1 s1;
	static struct s2 s2;
	static struct s3 s3;
	return 0;
}

