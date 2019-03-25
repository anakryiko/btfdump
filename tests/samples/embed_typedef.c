struct weak;

struct s0 {};

typedef struct {
	struct s0 a;
	struct weak* w;
} s1_t;

struct s2 {
	s1_t a;
	struct weak* w;
};

struct s3 {
	s1_t a;
	struct s2 b;
	struct weak* w;
};

struct weak {
	s1_t* a;
	struct s2* b;
	struct s3* c;
	struct weak* w;
};

int main() {
	static s1_t s1;
	static struct s2 s2;
	static struct s3 s3;
	static struct weak w;
	return 0;
}

