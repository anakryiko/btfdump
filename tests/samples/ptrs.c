typedef int *int_ptr;
typedef int **int_pptr;
typedef const int * const * volatile const cint_cptr_cvptr;
typedef const volatile int * const volatile restrict * volatile restrict const cint_cptr_cvptr2;

typedef int (*fn_ptr1)(int);
typedef char * const * (*fn_ptr2)();

typedef int* ptr_arr1[10];

typedef char * (*fn_ptr_arr1[10])(int **p);
typedef int (*fn_ptr_arr2[10])(void*);
typedef char * (* const (* const fn_ptr_arr3[5])()) (char * (*)(int));

char *(*f1())(int) {
	return 0;
}

int main() {
	static int_ptr s1;
	static int_pptr s2;
	static cint_cptr_cvptr s3;
	static cint_cptr_cvptr2 s3_2;
	static fn_ptr1 s4;
	static fn_ptr2 s5;
	static ptr_arr1 s6;
	static fn_ptr_arr1 s7;
	static fn_ptr_arr2 s8;
	static fn_ptr_arr3 s9;
	
	f1();
	
	return 0;
}
