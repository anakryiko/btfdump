struct s {
	char a[0];
	char b[1];
	const char volatile c[2];
	const volatile char * const volatile (* const volatile restrict z)[10];
	char d[];
};

struct s2 {
	char a[0];
	char b[1];
	const char c[2];
	const char d[];
};

int main() {
	static struct s s;
	static struct s2 s2;
	return 0;
}
	
