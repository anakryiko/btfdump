
struct s3 {};

struct s1 {
	struct s3* s3;
	struct s2* s2;
	struct s4* s4;
};

struct s2 {
	const struct s1 s1;
	volatile struct s3 s3;
};

struct s4 {
	struct s2 s2;
	struct s1 s1;
};	

int main() {
	static struct s3 s3;
	static struct s1 s1;
	static struct s2 s2;
	static struct s4 s4;
	return 0;
}

