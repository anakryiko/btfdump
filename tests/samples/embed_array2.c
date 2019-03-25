struct weak;

struct s0 {};

struct s2 {
	struct { struct s0 a; }  a[2];
	struct weak* w;
};

struct s3 {
	struct { struct s0 a; } a[3];
	struct s2 b;
	struct weak* w;
};

struct weak {
	struct { struct s0 a; } *arr[10];
	struct s2* b;
	struct s3* c;
	struct weak* w;
};

int main() {
	static struct s2 s2;
	static struct s3 s3;
	static struct weak w;
	return 0;
}

