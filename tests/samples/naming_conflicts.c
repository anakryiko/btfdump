enum T {V=0};
typedef void (*T)();

int main() {
	static enum T t1 = V;
	static T t5 = 0;
	return 0;
}
