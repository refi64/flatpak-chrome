#define _GNU_SOURCE

#include <glib.h>
#include <gio/gio.h>

#include <dirent.h>
#include <errno.h>
#include <sched.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>


char *g_prog = NULL;
int enable_debug = 1;


void debug(const char *str, ...) {
  if (enable_debug) {
    va_list va;
    va_start(va, str);

    char *out;
    vasprintf(&out, str, va);

    va_end(va);

    g_printerr("[fake-sandbox: %s] %s\n", g_prog, out);
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
    g_printerr("chroot message pipe returned invalid message: %d (%c)\n", (int) msg, msg);
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


GArray *gather_fds_to_redirect() {
  /*
    Certain file descriptors need to always be redirected via flatpak-spawn. This finds all
    of those and returns them.
  */

  g_autoptr(GArray) fds = g_array_new(FALSE, FALSE, sizeof(int));

  DIR *dir = opendir("/proc/self/fd");
  if (dir == NULL) {
    perror("opening /proc/self/fd");
    free(fds);
    return NULL;
  }

  struct dirent *dp;
  while ((dp = readdir(dir)) != NULL) {
    int fd = strtol(dp->d_name, NULL, 10);
    if (fd != dirfd(dir) && fd > 2) {
      g_array_append_val(fds, fd);
    }
  }

  closedir(dir);
  return g_steal_pointer(&fds);
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
    g_printerr("wrong # of arguments for chrome-sandbox (Flatpak fake)");
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

  g_autoptr(GArray) fds_to_redirect = gather_fds_to_redirect();
  if (fds_to_redirect == NULL) {
    return 1;
  }

  g_autofree char *dbus_addr = g_strdup_printf("unix:path=/run/user/%lu/bus", (gulong) getuid());
  setenv("DBUS_SESSION_BUS_ADDRESS", dbus_addr, 1);
  g_clear_pointer(&dbus_addr, g_free);

  g_autoptr(GPtrArray) command = g_ptr_array_new_with_free_func(g_free);

  /* g_ptr_array_add(command, g_strdup("/usr/bin/env")); */
  g_ptr_array_add(command, g_strdup("/usr/bin/flatpak-spawn"));
  /* g_ptr_array_add(command, g_strdup("--sandbox")); */
  /* g_ptr_array_add(command, g_strdup("--env=LD_PRELOAD=/app/lib/fake-sandbox-preload.so")); */
  /* g_ptr_array_add(command, g_strdup("LD_PRELOAD=/app/lib/fake-sandbox-preload.so")); */

  for (int i = 0; i < fds_to_redirect->len; i++) {
    g_ptr_array_add(command, g_strdup_printf("--forward-fd=%d",
                                             g_array_index(fds_to_redirect, int, i)));
  }

  g_ptr_array_add(command, g_strdup("/usr/bin/strace"));
  g_ptr_array_add(command, g_strdup("-f"));
  g_ptr_array_add(command, g_strdup("-ELD_PRELOAD=/app/lib/fake-sandbox-preload.so"));

  g_ptr_array_add(command, g_strdup("/app/chrome/chrome-sandbox"));
  g_ptr_array_add(command, g_strdup("--wrap-spawned"));

  for (int i = 1; i < argc; i++) {
    g_ptr_array_add(command, g_strdup(argv[i]));
  }

  for (int i = 0; i < command->len; i++) {
    debug("* %s", g_ptr_array_index(command, i));
  }

  g_ptr_array_add(command, NULL);

  pid_t child = fork();
  if (child == -1) {
    perror("forking child");
    return 1;
  } else if (child == 0) {
    execv(g_ptr_array_index(command, 0), (char * const *) command->pdata);
    perror("execv failed");
    return 1;
  } else {
    int wstatus;
    if (waitpid(child, &wstatus, 0) == -1) {
      perror("waitpid");
      return 1;
    }

    if (WIFEXITED(wstatus)) {
      return WEXITSTATUS(wstatus);
    } else if (WIFSIGNALED(wstatus)) {
      g_printerr("child died due to signal %d\n", WTERMSIG(wstatus));
      return 1;
    } else {
      g_printerr("child died due to unknown reason\n");
      return 1;
    }
  }
}
