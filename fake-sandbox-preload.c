#define _GNU_SOURCE

/*
  fake-sandbox-preload.so is injected into Chrome via LD_PRELOAD in order to override
  Chrome's sandbox detection so it'll accept our flatpak-spawn-powered fake
  chrome-sandbox (fake-sandbox.c).
*/

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>


/*
  open64 overrides will cause pthread to get stuck in a nanosleep:
  https://bugs.chromium.org/p/chromium/issues/detail?id=536815

  To remediate this, open64 calls will use the direct openat syscall until dlsym is
  confirmed to be safe by another overriden function.
*/

static int dlsym_safe = 0;


// Helper macros

#define atomic_set(ptr, value) __atomic_store_n(ptr, value, __ATOMIC_RELAXED)
#define atomic_get(ptr) __atomic_load_n(ptr, __ATOMIC_RELAXED)

#define load_original(ptr, name) do { \
    if (*(ptr) == NULL) { \
      *(ptr) = dlsym(RTLD_NEXT, name); \
      atomic_set(&dlsym_safe, 1); \
    } \
  } while (0)



// __xstat64 is overrided so Chrome thinks the fake sandbox is SUID.

typedef int (* original_xstat64_t)(int ver, const char *path, struct stat64 *buf);
static __thread original_xstat64_t original_xstat64 = NULL;

int __xstat64(int ver, const char *path, struct stat64 *buf) {
  load_original(&original_xstat64, "__xstat64");

  int result = original_xstat64(ver, path, buf);
  if (strcmp(path, "/app/chrome/chrome-sandbox") == 0) {
    buf->st_uid = 0;
    buf->st_mode |= S_ISUID;
  }

  return result;
}


/*
  All the rest of this code is to circumvent nacl_helper's sandboxing checks.

  Normally, the chrome-sandbox will wait until the sandboxed program requests it be
  chrooted so that all filesystem access is restricted. flatpak-spawn already restricts
  filesystem access, but not to the extent that nacl_helper expects.

  First, it ensures /proc/self/exe can be accessed. Then, it sends the chroot command to
  the sandbox, followed by another check to ensure /proc/self/exe is now inaccessible.
  After all this, it ensures getpid() == 1, meaning the pid sandbox is active.

  In order to work around this, write is overriden to track when the chroot message is
  sent, open64 is overriden to return that /proc/self/exe is inaccessible after the
  message is sent, and getpid is overriden to return 1 after open64 signals it to.
*/


/*
  This is used by write to check the state of the sandbox request.
*/

enum {
  SANDBOX_REQUEST_UNSENT,
  SANDBOX_REQUEST_SENT,
};

static int sandbox_request_state = SANDBOX_REQUEST_UNSENT;


/*
  This is used to check if SBX_D (the sandbox communication socket) has been parsed yet.
  SANDBOX_FD_UNSET means it hasn't, SANDBOX_FD_IGNORE means it's never going to (because
  this isn't nacl_helper), and SANDBOX_FD_INVALID means
*/

enum {
  SANDBOX_FD_UNSET = 0,
  SANDBOX_FD_IGNORE = -1,
  SANDBOX_FD_INVALID = -2,
};

static __thread long sandbox_fd = SANDBOX_FD_UNSET;


typedef ssize_t (* original_write_t)(int fd, const void *buf, size_t len);
static __thread original_write_t original_write = NULL;

ssize_t write(int fd, const void *buf, size_t len) {
  load_original(&original_write, "write");

  if (sandbox_fd == SANDBOX_FD_UNSET) {
    const char *sandbox_fd_str = getenv("SBX_D");
    if (sandbox_fd_str != NULL) {
      char *ep;
      int fd = strtol(sandbox_fd_str, &ep, 10);
      sandbox_fd = *ep == '\0' ? fd : SANDBOX_FD_INVALID;
    } else {
      // Not our target process, so ignore.
      sandbox_fd = SANDBOX_FD_IGNORE;
    }
  }

  /* We want to track when the sandbox request is send to lie about being able to access
     /proc/self/exe later in open64 */
  if (sandbox_fd > 0 && len == 1 && ((char *)buf)[0] == 'C' && sandbox_fd == fd) {
    atomic_set(&sandbox_request_state, SANDBOX_REQUEST_SENT);
  }

  return original_write(fd, buf, len);
}


typedef int (* original_open64_t) (const char *path, int flags, ...);
static __thread original_open64_t original_open64 = NULL;


int open64(const char *path, int flags, ...) {
  int mode = 0;

  // Load the mode if needed.
  if (__OPEN_NEEDS_MODE(flags)) {
    va_list va;
    va_start(va, flags);
    mode = va_arg(va, int);
    va_end(va);
  }

  // Use the syscall if dlsym hasn't been confirmed to be safe.
  if (!atomic_get(&dlsym_safe)) {
    // On x64 systems, off64_t and off_t are the same at the ABI level, so O_LARGEFILE
    // isn't needed.
    return syscall(__NR_openat, AT_FDCWD, path, flags, mode);
  }

  load_original(&original_open64, "open64");

  if (atomic_get(&sandbox_request_state) == SANDBOX_REQUEST_SENT &&
      strcmp(path, "/proc/self/exe") == 0) {
    errno = ENOENT;
    return -1;
  }

  if (__OPEN_NEEDS_MODE(flags)) {
    return original_open64(path, flags, mode);
  } else {
    return original_open64(path, flags);
  }
}


typedef pid_t (* original_getpid_t) ();
static __thread original_getpid_t original_getpid = NULL;

// If we're supposed to be in the sandbox, pretend we're PID 1.
pid_t getpid() {
  load_original(&original_getpid, "getpid");

  if (getenv("SBX_CHROME_API_PRV") != NULL) {
    return 1;
  } else {
    return original_getpid();
  }
}


/* typedef ssize_t (* original_sendmsg_t)(int sockfd, const struct msghdr *msg, int flags); */
/* static __thread original_sendmsg_t original_sendmsg = NULL; */


/* ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) { */
/*   load_original(&original_sendmsg, "sendmsg"); */

/*   errno = 0; */
/*   ssize_t r = original_sendmsg(sockfd, msg, flags); */
  /* printf("\n*****sendmsg: %s %d %zd %s\n", program_invocation_short_name, sockfd, r, strerror(errno)); */
/*   return r; */
/* } */
