#include <ck-hypervisor/external.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

int call_external(const char *cmd, std::vector<const char *> args) {
  args.push_back(nullptr);

  int pid = -1, wstatus = -1;
  if ((pid = fork()) == 0) {
    execvp(cmd, (char *const *)&args[0]);
    _exit(1);
  }
  if (waitpid(pid, &wstatus, 0) < 0)
    return -1;
  return WEXITSTATUS(wstatus);
}

static pid_t forked_fork(void) { return syscall(__NR_fork); }

int forked_call_external(const char *cmd, std::vector<const char *> args) {
  args.push_back(nullptr);

  int pid = -1, wstatus = -1;
  if ((pid = forked_fork()) == 0) {
    execvp(cmd, (char *const *)&args[0]);
    _exit(1);
  }
  if (waitpid(pid, &wstatus, 0) < 0)
    return -1;
  return WEXITSTATUS(wstatus);
}
