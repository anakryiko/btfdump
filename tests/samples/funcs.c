typedef int (*fnproto)();

static fnproto v = 0;

int func() {
	return 0;
}

int func_with_args(int a, int b) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpointer-to-int-cast"
	return (int)v;
#pragma clang diagnostic pop
}


