#define __user __attribute__((btf_type_tag("user")))
#define __rcu __attribute__((btf_type_tag("rcu")))
#define __percpu __attribute__((btf_type_tag("percpu")))

struct tagged {
	int __user *user_ptr;
	void __rcu *rcu_ptr;
	const char __user *const_user_ptr;
	int __percpu *percpu_ptr;
	int __user *__user *user_ptr_ptr;
	int __user *user_arr[4];
	int (*fn)(char __user *, void __rcu *);
};

struct tagged tagged;
