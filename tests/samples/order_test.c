struct t1 {
	const struct t2* t;
};

typedef struct t1 t1_t;

struct t2 {
	t1_t t;
};

int main() {
	static struct t1 t1;
	static struct t2 t2;
	return 0;
}

