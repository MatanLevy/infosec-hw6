#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <stdbool.h>
int pid = 24760;


int main(int argc, char **argv) {
    // Make the malware stop waiting for our output by forking a child process:
    if (fork() != 0) {
        // Kill the parent process so we stop waiting from the malware
        return 0;
    } else {
        // Close the output stream so we stop waiting from the malware
        fclose(stdout);
    }
    if (ptrace(PTRACE_ATTACH,pid,NULL,NULL) == -1){
        perror("attach");
        return 1;
    }
    int status;
    struct user_regs_struct regs;
    bool readCalled = false;
    while (waitpid(pid,&status,0) && ! WIFEXITED(status)) {
        ptrace(PTRACE_GETREGS,pid,NULL,&regs);
        if (regs.orig_eax == 3) {
            readCalled = true;
        }
        ptrace(PTRACE_SYSCALL,pid,NULL,NULL);
        if (readCalled) {
            readCalled = false;
            fprintf(stderr, "system call %ld from pid %d\n", regs.orig_eax, pid);
            regs.orig_eax = 0;
            ptrace(PTRACE_SETREGS,pid,NULL,&regs);
        }
    }

    if (ptrace(PTRACE_DETACH,pid,NULL,NULL) == -1)  {
        perror("attach");
        return 1;
    }
    return 0;
}
