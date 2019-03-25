struct weak;

struct s0 {};

struct s1 {
	struct s0 a;
	struct weak* w;
};

struct s2 {
	struct s1 a;
	struct weak* w;
};

struct s3 {
	struct s1 a;
	struct s2 b;
	struct weak* w;
};

struct weak {
	struct s1* a;
	struct s2* b;
	struct s3* c;
	struct weak* w;
};

int main() {
	static struct s1 s1;
	static struct s2 s2;
	static struct s3 s3;
	static struct weak w;
	return 0;
}

