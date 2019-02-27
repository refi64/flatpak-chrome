#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <sched.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>


char *g_prog = NULL;
int enable_debug = 0;


void debug(const char *str, ...) {
  if (enable_debug) {
    va_list va;
    va_start(va, str);

    char *out;
    vasprintf(&out, str, va);

    va_end(va);

    fprintf(stderr, "[fake-sandbox: %s] %s\n", g_prog, out);
  }
}


void check_debug() {
  const char *debug_env = getenv("FLATPAK_CHROME_FAKE_SANDBOX_DEBUG");
  if (debug_env != NULL && debug_env[0] == '1') {
    enable_debug = 1;
  }
}


int child(int fd) {
  char msg = 0;
  int ret = 0;

  debug("waiting for chroot request");

  for (;;) {
    errno = 0;
    if (read(fd, &msg, 1) != -1 || errno != EINTR) {
      break;
    }
  }

  debug("received chroot request");

  if (errno) {
    perror("read from chroot message pipe");
    ret = 1;
    goto end;
  } else if (msg == '\0') {
    debug("chroot pipe early exit");
    goto end;
  } else if (msg != 'C') {
    fprintf(stderr, "chroot message pipe returned invalid message: %d (%c)\n", (int) msg, msg);
    ret = 1;
    goto end;
  }

  debug("sending chroot reply");

  if (write(fd, "O", 1) == -1) {
    perror("write to chroot message pipe");
    ret = 1;
    goto end;
  }

  debug("sent chroot reply");

end:
  close(fd);
  return ret;
}


int get_max_fds() {
  struct rlimit rlim;
  getrlimit(RLIMIT_NOFILE, &rlim);
  return rlim.rlim_cur;
}


int *gather_fds_to_redirect(int max_fds) {
  /*
    Certain file descriptors need to always be redirected via flatpak-spawn. This finds all
    of those and returns them in a null-terminated array.
  */

  int *fds = calloc(max_fds, sizeof(int));
  int cur_fd = 0;

  DIR *dir = opendir("/proc/self/fd");
  if (dir == NULL) {
    perror("opening /proc/self/fd");
    free(fds);
    return NULL;
  }

  struct dirent *dp;
  while ((dp = readdir(dir)) != NULL && cur_fd < max_fds) {
    int fd = strtol(dp->d_name, NULL, 10);
    if (fd != dirfd(dir) && fd > 2) {
      fds[cur_fd++] = fd;
    }
  }

  closedir(dir);
  return fds;
}

#define BUFFER_SIZE 64

int run_command(char **argv) {
  debug("run_command inside sandbox: %s", argv[2]);

  int msgpipe[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, msgpipe) == -1) {
    perror("socketpair creating chroot message pipe");
    return 1;
  }

  int parent_end = msgpipe[0],
      child_end = msgpipe[1];

  pid_t forked = fork();
  if (forked == -1) {
    perror("forking child");
    close(parent_end);
    close(child_end);
    return 1;
  } else if (forked == 0) {
    close(parent_end);
    return child(child_end);
  }

  close(child_end);

  char envbuf[BUFFER_SIZE];

  snprintf(envbuf, BUFFER_SIZE, "%d", parent_end);
  setenv("SBX_D", envbuf, 1);

  snprintf(envbuf, BUFFER_SIZE, "%ld", (long) forked);
  setenv("SBX_HELPER_PID", envbuf, 1);

  setenv("SBX_CHROME_API_PRV", "1", 1);
  setenv("SBX_PID_NS", "", 1);
  setenv("SBX_NET_NS", "", 1);

  execv(argv[2], &argv[2]);

  perror("execv failed");
  close(parent_end);
  return 1;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "wrong # of arguments for chrome-sandbox (Flatpak fake)");
    return 1;
  }

  g_prog = argv[1];
  check_debug();

  if (strcmp(argv[1], "--get-api") == 0) {
    puts("1");
    return 0;
  } else if (strcmp(argv[1], "--adjust-oom-score") == 0) {
    // XXX
    return 0;
  } else if (strcmp(argv[1], "--wrap-spawned") == 0) {
    g_prog = argv[2];
    return run_command(argv);
  }

  debug("starting sandbox");

  int max_fds = get_max_fds();
  int *fds_to_redirect = gather_fds_to_redirect(max_fds);
  if (fds_to_redirect == NULL) {
    return 1;
  }

  char dbus_addr[BUFFER_SIZE];
  snprintf(dbus_addr, BUFFER_SIZE, "unix:path=/run/user/%lu/bus", (unsigned long) getuid());
  setenv("DBUS_SESSION_BUS_ADDRESS", dbus_addr, 1);

  #define COMMAND_SPAWN_SIZE (sizeof(spawn) / sizeof(spawn[0]))

  /* const char **command = malloc(sizeof(char *) * (argc + COMMAND_SPAWN_SIZE + max_fds)); */

  const int command_len =
    2            // flatpak-spawn --env=LD_PRELOAD=...
    + 10         // TODO: remove
    + max_fds    // --forward-fd arguments
    + 2          // chrome-sandbox --wrap-spawned
    + (argc - 1) // command to run
    + 1          // null terminator
  ;

  /* const char **command = malloc(sizeof(char *) + ); */
  const char **command = calloc(command_len, sizeof(char *));
  int command_index = 0;

  /* command[command_index++] = "/usr/bin/flatpak-spawn"; */
  /* command[command_index++] = "--env=LD_PRELOAD=/app/lib/fake-sandbox-preload.so"; */
  command[command_index++] = "/usr/bin/env";
  /* command[command_index++] = "--sandbox"; */
  /* command[command_index++] = "/usr/bin/strace"; */
  /* command[command_index++] = "-f"; */
  /* command[command_index++] = "-ELD_PRELOAD=/app/lib/fake-sandbox-preload.so"; */
  command[command_index++] = "LD_PRELOAD=/app/lib/fake-sandbox-preload.so";


  for (int i = 0; fds_to_redirect[i] != 0; i++) {
    char *buf = malloc(BUFFER_SIZE);
    snprintf(buf, BUFFER_SIZE, "--forward-fd=%d", fds_to_redirect[i]);

    command[command_index++] = buf;
  }


  /* command[command_index++] = "/usr/bin/strace"; */
  /* command[command_index++] = "-f"; */
  /* command[command_index++] = "-ELD_PRELOAD=/app/lib/fake-sandbox-preload.so"; */

  command[command_index++] = "/app/chrome/chrome-sandbox";
  command[command_index++] = "--wrap-spawned";

  for (int i = 1; i < argc; i++) {
    command[command_index++] = argv[i];
  }

  /* for (int i = 1; i < argc; i++) { */
  /*   command[i + COMMAND_SPAWN_SIZE + n_fds_to_redirect - 1] = argv[i]; */
  /* } */

  /* command[COMMAND_SPAWN_SIZE + n_fds_to_redirect + argc - 1] = NULL; */

  for (const char **p = command; *p != NULL; p++) {
    debug("* %s", *p);
  }

  execv(command[0], (char * const *) command);

  perror("execv failed");
  return 1;
}
