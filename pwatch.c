/*
 * Copyright 2016 Jakub Klama <jceel@FreeBSD.org>
 * All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted providing that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>
#include <err.h>
#include <sysexits.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <machine/reg.h>

#define	MAXFDS	16

FILE *output = NULL;
int read_fds[MAXFDS];
int write_fds[MAXFDS];
int nread = 0;
int nwrite = 0;
bool exited = false;
pid_t pid = -1;


static inline bool
can_read(int fd)
{
	int i;

	for (i = 0; i < nread; i++) {
		if (read_fds[i] == fd)
			return (true);
	}

	return (false);
}

static inline bool
can_write(int fd)
{
	int i;

	for (i = 0; i < nwrite; i++) {
		if (write_fds[i] == fd)
			return (true);
	}

	return (false);
}

static void
fetch_string(caddr_t addr, size_t len)
{
	struct ptrace_io_desc iod;
	const char *result;
	int err;

	result = malloc(len);

	iod.piod_op = PIOD_READ_D;
	iod.piod_offs = (void *)addr;
	iod.piod_addr = (void *)result;
	iod.piod_len = len;

	err = ptrace(PT_IO, pid, (caddr_t)&iod, 0);
	if (err != 0) {
		free((void *)result);
		return;
	}

	fwrite(result, len, 1, output);
}

static void
handle_read(struct reg *regs)
{
	if (!can_read(regs->r_rdi))
		return;

	fetch_string((caddr_t)regs->r_rsi, regs->r_rdx);
}

static void
handle_write(struct reg *regs)
{
	if (!can_write(regs->r_rdi))
		return;

	fetch_string((caddr_t)regs->r_rsi, regs->r_rdx);
}

void
sigint(int signo __unused)
{
	exited = true;
	kill(pid, SIGSTOP);
}

int
main(int argc, char *argv[])
{
	struct ptrace_lwpinfo lwpinfo;
	struct reg regs;
	int ch;
	int ret;
	int status;
	int custom = 0;

	while ((ch = getopt(argc, argv, "p:r:w:o:h")) != -1) {
		switch (ch) {
		case 'p':
			pid = atoi(optarg);
			break;
		case 'r':
			read_fds[nread++] = atoi(optarg);
			custom = 1;
			break;
		case 'w':
			write_fds[nwrite++] = atoi(optarg);
			custom = 1;
			break;
		case 'o':
			output = fopen(optarg, "w");
			break;
		case 'h':
			break;
		}
	}

	if (!custom) {
		write_fds[0] = STDOUT_FILENO;
		write_fds[1] = STDERR_FILENO;
		nwrite = 2;
	}

	if (!output)
		output = stdout;

	ret = ptrace(PT_ATTACH, pid, NULL, 0);
	if (ret != 0)
		err(EX_SOFTWARE, "unable to attach");


	signal(SIGINT, &sigint);

	waitpid(pid, &status, 0);

	do {
		ret = ptrace(PT_SYSCALL, pid, (caddr_t)1, 0);
		if (ret != 0)
			err(EX_SOFTWARE, "unable to step");

		if (waitpid(pid, &status, 0) < 0)
			err(EX_SOFTWARE, "waitpid failed");

		ret = ptrace(PT_LWPINFO, pid, (caddr_t)&lwpinfo,
		    sizeof(struct ptrace_lwpinfo));
		if (ret != 0)
			err(EX_SOFTWARE, "unable to get lwpinfo");

		ret = ptrace(PT_GETREGS, pid, (caddr_t)&regs, 0);
		if (ret != 0)
			err(EX_SOFTWARE, "unable to get regs");

		if (lwpinfo.pl_flags & PL_FLAG_SCE) {
			if (regs.r_rax == SYS_write || regs.r_rax == SYS_sendto)
				handle_write(&regs);
		}

		if (lwpinfo.pl_flags & PL_FLAG_SCX) {
			if (regs.r_rax == SYS_read || regs.r_rax == SYS_recvfrom)
				handle_read(&regs);
		}
	} while (!exited);

	if (ptrace(PT_DETACH, pid, 0, 0) != 0)
		err(EX_SOFTWARE, "unable to detach");

	kill(pid, SIGCONT);
	return (0);
}