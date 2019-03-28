struct s {
	unsigned int: 4;
	int a: 4;
	long: 57;
	long c;
};

struct empty {};

struct p {
	unsigned int: 4;
	int a: 4;
	long c;
	struct {
		char x;
		int y;
	} __attribute__((packed)) d;
} __attribute__((packed));

union u {
	int a: 4;
	char b;
	char c: 1;
};

int main() {
	static struct empty empty;
	static struct s s;
	static struct p p;
	static union u u;
	return 0;
}
