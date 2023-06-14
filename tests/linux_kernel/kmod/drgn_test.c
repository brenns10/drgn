/*
 * ipipanic.c: Send an IPI to another CPU which calls panic()
 */
#include <linux/module.h>
#include <linux/smp.h>
#include <linux/version.h>

/* f39650de687e3 ("kernel.h: split out panic and oops helpers") */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,14,0)
#include <linux/kernel.h>
#else
#include <linux/panic.h>
#endif

static void do_ipipanic(void *unused)
{
	panic("ipipanic: trigger panic");
}

static int __init init_ipipanic(void)
{
	int cpu = get_cpu();
	int dst;

	for_each_online_cpu(dst) {
		if (dst != cpu) {
			smp_call_function_single(dst, do_ipipanic, NULL, true);
		}
	}
	put_cpu();
	return 0;
}

module_init(init_ipipanic);

MODULE_AUTHOR("Stephen Brennan <stephen@brennan.io>");
MODULE_DESCRIPTION("Send an IPI to another CPU which calls panic()");
MODULE_LICENSE("GPL");
