#include <stdio.h>  
#include <unistd.h> //for sleep  
#include <stdlib.h> //for exit  
#include <pthread.h>//for pthread  
#include <errno.h>  //for errno  
#include <sys/syscall.h> //for gettid  
#include <sys/ptrace.h>
#include <sys/user.h> /* For user_regs_struct */ 
#include <sys/wait.h>  
#include <time.h>
#define gettid() syscall(__NR_gettid)  

pid_t  ctid = 0;
void *func(void *para)
{
	printf("Hello world.\n");
	printf("child process tid: %u\n", gettid()); 
	ctid = gettid();
	printf("child process pid: %u\n", getpid());
	sleep(-1);  // 该进程一直sleep，等待  
	return NULL;
}
#define STACK_SIZE (1024 * 1024)
void* debugger(void* ptr)
{

	void *vstack = malloc(STACK_SIZE);
	pid_t v;

	if ( (v = fork()) < 0)//auto myproc=[](void* )
	{
		perror("fork");
	}
	if(v==0)
	{
		printf("debugger process pid: %u\n", getpid());
		printf("attach tid: %u\n", ctid);

		long ptv = ptrace(PTRACE_ATTACH, ctid, NULL, NULL);
		if (ptv == -1) {
			perror("failed monitor sieze");
		}

		/*ptv = ptrace(PTRACE_INTERRUPT, v, NULL, NULL);
		if (ptv == -1) {
			perror("failed to interrupt main thread");
		}*/
		wait(NULL);
		struct user_regs_struct regs = { 0 };


		if (ptrace((__ptrace_request)PT_GETREGS, ctid, 0, &regs) == -1)
		{
			perror("ptrace:");
			printf("Failed ptrace(PT_GETREGS, processId:%d) errno:%d \n",
				ctid, errno);

		}
		printf("RIP=%d\n", regs.rip);
		ptrace(PTRACE_CONT, ctid, NULL, NULL);
		ptrace(PTRACE_DETACH, ctid, NULL, NULL);
		_exit(0);
		//return 0;
	};

	/*if (clone(myproc, vstack + STACK_SIZE, CLONE_VFORK | CLONE_VM, NULL) == -1) { // you'll want to check these flags
		perror("failed to spawn child task");
		return NULL;
	}
	printf("Dbg child exited\n");*/
	return NULL;

}


int maint(void* ptr)
{

	return 0;
}

int main(int args, char* argv[])
{


	/*pid_t v;
	void *vstack = malloc(STACK_SIZE);
	if (clone(maint, vstack + STACK_SIZE,  CLONE_PARENT_SETTID | CLONE_FILES | CLONE_FS | CLONE_IO, NULL, &v) == -1) { // you'll want to check these flags
		perror("failed to spawn child task");
		return 3;
	}*/

	if (args == 1)
	{
		pthread_t tid;
		int ret = pthread_create(&tid, NULL, func, NULL);
		if (ret != 0)
		{
			exit(errno);
		}

		printf("Sleep for 1 sec\n");
		sleep(1);

		pthread_t deb;
		pthread_create(&deb, NULL, debugger, NULL);
		pthread_join(tid, NULL);
	}




	if (args == 2)
	{
		printf("Attach\n");
		ctid = atoi(argv[1]);
		pthread_t deb;
		pthread_create(&deb, NULL, debugger, NULL);
		pthread_join(deb, NULL);
	}


	

	//debugger(0);
	return 0;
}

int main3()
{
	pid_t child;
	long orig_eax;
	child = fork();
	if (child == 0) {
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		//execl("/bin/ls", "ls", NULL);
		sleep(10);
	}
	else {
		ptrace(PTRACE_ATTACH, child,
			NULL,
			NULL);
		perror("ptrace:");
		printf("parent\n");
		wait(NULL);
		printf("wait ok\n");
		ptrace(PTRACE_CONT, child, NULL, NULL);
		perror("CONT");
		ptrace(PTRACE_INTERRUPT, child, NULL, NULL);
		perror("PTRACE_INTERRUPT");
		struct user_regs_struct regs;
		if (ptrace((__ptrace_request)PT_GETREGS, child, 0, (caddr_t)&regs) == -1)
		{
			perror("ptrace:");
			printf("Failed ptrace(PT_GETREGS, processId:%d) errno:%d \n",
				ctid, errno);

		}
		printf("rip %lx\n", regs.rip);
		ptrace(PTRACE_CONT, child, NULL, NULL);
	}
	return 0;
}



int main_thread(void *ptr) {
	// "main" thread is now running under the monitor
	printf("Hello from main!");
	while (1) {
		int c = getchar();
		if (c == EOF) { break; }
		sleep(1);
		putchar(c);
	}
	return 0;
}

int main4(int argc, char *argv[]) {
	void *vstack = malloc(STACK_SIZE);
	pid_t v;
	if (clone(main_thread, vstack + STACK_SIZE, CLONE_PARENT_SETTID | CLONE_FILES | CLONE_FS | CLONE_IO, NULL, &v) == -1) { // you'll want to check these flags
		perror("failed to spawn child task");
		return 3;
	}
	printf("Target: %d; %d\n", v, getpid());
	long ptv = ptrace(PTRACE_SEIZE, v, NULL, NULL);
	if (ptv == -1) {
		perror("failed monitor sieze");
		exit(1);
	}
	struct user_regs_struct regs;
	fprintf(stderr, "beginning monitor...\n");
	while (1) {
		sleep(1);
		long ptv = ptrace(PTRACE_INTERRUPT, v, NULL, NULL);
		if (ptv == -1) {
			perror("failed to interrupt main thread");
			break;
		}
		int status;
		if (waitpid(v, &status, __WCLONE) == -1) {
			perror("target wait failed");
			break;
		}
		if (!WIFSTOPPED(status)) { // this section is messy. do it better.
			fputs("target wait went wrong", stderr);
			break;
		}

		ptv = ptrace(PTRACE_GETREGS, v, NULL, &regs);
		if (ptv == -1) {
			perror("failed to peek at registers of thread");
			break;
		}
		fprintf(stderr, "%d -> RIP %x RSP %x\n", time(NULL), regs.rip, regs.rsp);
		ptv = ptrace(PTRACE_CONT, v, NULL, NULL);
		if (ptv == -1) {
			perror("failed to resume main thread");
			break;
		}
	}
	return 2;
}