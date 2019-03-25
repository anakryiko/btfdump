typedef struct s0 s0_t;

struct s1 {
	s0_t* a;
};

struct s0 { 
	struct s1 a;
};

struct s2 {
	s0_t* a;
	s0_t  b;
	struct s1* c;
	struct s1 d;
};


int main() {
	static struct s2 s2;
	static struct s1 s1;
	return 0;
}

