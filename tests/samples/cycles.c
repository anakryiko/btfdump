struct list_head {
        struct list_head *next;
        struct list_head *prev;
};

struct hlist_head {
        struct hlist_node *first;
};

struct hlist_node {
        struct hlist_node *next;
        struct hlist_node **pprev;
};

struct a;

struct b {
	struct a *p;
};

struct a {
	struct b *p;
};


struct X {
	const struct X * const arr[10];
	struct {
		struct X* x1;
	};
	struct Y {
		struct X* x2;
		struct Y* y2;
	} y;
};

int main() {
	static struct list_head s1;
	static struct hlist_head s2;
	static struct a a;
	static struct b b;
	static struct X x;
	static struct Y y;
	return 0;
}
