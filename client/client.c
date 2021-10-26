#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#define SIG_PROC_PROT 70
#define SIG_PROC_UNPROT 71

#define IOCTL_ARGP_SIZE 128

#define IOCTL_PROC_PROT 0xDEAD0001
#define IOCTL_PROC_UNPROT 0xDEAD0002

int sample_kill(char * arg) {
    int fd = 0, r;
    pid_t pid = atoi(arg);
    char cmd[512];

    /* find the process (`sleep 2000 &`) */
    printf("current process list\n");
    sprintf(cmd, "ps aux | grep %d | grep -v grep", pid);
    r = system(cmd);
    sleep(5);

    /* enable the protection */
    printf("protect the process\n");
    kill(pid, SIG_PROC_PROT);
    r = system(cmd);
    printf("you can not kill the process\n");
    sleep(5);
    kill(pid, SIGKILL);
    r = system(cmd);
    sleep(5);

    /* disable the protection */
    printf("unprotect the process\n");
    kill(pid, SIG_PROC_UNPROT);
    r = system(cmd);
    printf("now you can kill the process\n");
    sleep(5);
    kill(pid, SIGKILL);
    r = system(cmd);

    return 0;
}

int sample_ioctl(char * arg) {
    int fd = 0, r;
    pid_t pid = atoi(arg);
    char cmd[512];

    /* find the process (`sleep 2000 &`) */
    printf("current process list\n");
    sprintf(cmd, "ps aux | grep %d | grep -v grep", pid);
    r = system(cmd);
    sleep(5);

    /* enable the protection */
    printf("protect the process\n");
    if (ioctl(fd, IOCTL_PROC_PROT, arg) != 0) {
        printf("IOCTL_PROC_PROT error\n");
        return -1;
    }
    r = system(cmd);
    printf("you can not kill the process\n");
    sleep(5);
    kill(pid, SIGKILL);
    r = system(cmd);
    sleep(5);

    /* disable the protection */
    printf("unprotect the process\n");
    if (ioctl(fd, IOCTL_PROC_UNPROT, arg) != 0) {
        printf("IOCTL_PROC_UNPROT error\n");
        return -1;
    }
    r = system(cmd);
    printf("now you can kill the process\n");
    sleep(5);
    kill(pid, SIGKILL);
    r = system(cmd);

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc == 3) {
        char * argp = (char *) malloc(IOCTL_ARGP_SIZE);
        memset(argp, 0, IOCTL_ARGP_SIZE);
        strcpy(argp, argv[2]);
        if (strcmp("kill", argv[1])) {
            sample_kill(argp);
            return 0;
        } else if (strcmp("ioctl", argv[1])) {
            sample_ioctl(argp);
            return 0;
        }
    }

    printf("usage: %s [$pid] [kill|ioctl]\n", argv[0]);
    return -1;
}
