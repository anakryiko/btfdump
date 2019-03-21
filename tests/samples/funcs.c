typedef int (*fnproto)();

static fnproto v = 0;

int func() {
	return 0;
}

int func_with_args(int a, int b) {
	return (int)v;
}


