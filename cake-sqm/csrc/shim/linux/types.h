/* sch_cake.c resolves this to the shim; a libc header that asks for the real kernel header while
 * kshim.h is pulling in libc (glibc errno.h wants <linux/errno.h>, bionic sys/types.h wants
 * <linux/types.h>) gets the real one. */
#ifdef KSHIM_IN_LIBC
#include_next <linux/types.h>
#else
#include "kshim.h"
#endif
