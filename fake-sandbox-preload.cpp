#include <atomic>
#include <mutex>
#include <string_view>

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

using namespace std::literals::string_view_literals;


// Some helpers to assist with loading the original functions.
namespace loading_detail {
  std::atomic<bool> dlsym_safe;

  template <typename T>
  T load_func(T& ptr, std::string_view name) {
    if (!ptr) {
      ptr = reinterpret_cast<T>(dlsym(RTLD_NEXT, name.data()));
      dlsym_safe.store(true);
    }

    return ptr;
  }
}

#define DECLARE_OVERRIDE(ret, func, ...) \
  namespace func##_loading_detail { \
    using type = ret (*)(__VA_ARGS__); \
    thread_local type original = nullptr; \
  }; \
  func##_loading_detail::type func##_load() { \
    return loading_detail::load_func(func##_loading_detail::original, #func); \
  } \
  extern "C" ret func(__VA_ARGS__)


// __xstat64 is overriden so Chrome thinks the fake sandbox is SUID.
DECLARE_OVERRIDE(int, __xstat64, int ver, const char *path, struct stat64 *buf) {
  auto original = __xstat64_load();

  int result = original(ver, path, buf);
  if ("/app/chrome/chrome-sandbox"sv == path) {
    buf->st_uid = 0;
    buf->st_mode |= S_ISUID;
  }

  return result;
}

// Chrome expects recvmsg to return a proper pid, not...pid 0.
DECLARE_OVERRIDE(ssize_t, recvmsg, int fd, struct msghdr* msg, int flags) {
  auto original = recvmsg_load();

  ssize_t res = original(fd, msg, flags);
  if (res == -1) {
    return res;
  }

  if (msg->msg_controllen > 0) {
    for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
      if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_CREDENTIALS) {
        pid_t& pid = reinterpret_cast<struct ucred*>(CMSG_DATA(cmsg))->pid;
        if (pid == 0) {
          /* XXX: Zygote also tries to track these processes, so this needs to somehow be
             wired to the flatpak-spawn PID */
          pid = 2;
        }
        break;
      }
    }
  }

  return res;
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

namespace sandbox_tracking_detail {
  // This is used by the write override to check the state of the sandbox request.
  std::atomic<bool> chroot_request_sent;
  /*
    This is used to check if SBX_D (the sandbox communication socket) has been parsed yet.
    If it's 0, it means it's unset; -1 means it will never be set (due to an error parsing
    SBX_D or because this isn't a sandboxed process).
  */
  int fd;
  std::mutex fd_mutex;
  constexpr int fd_unset = 0,
                fd_ignore = -1;
}

DECLARE_OVERRIDE(ssize_t, write, int fd, const void *buf, size_t len) {
  auto original = write_load();

  // XXX: Small potential data race here, though worst-case scenario this is run twice.
  if (sandbox_tracking_detail::fd == sandbox_tracking_detail::fd_unset) {
    std::lock_guard<std::mutex> guard{sandbox_tracking_detail::fd_mutex};

    if (const char* sbx_d = getenv("SBX_D")) {
      try {
        sandbox_tracking_detail::fd = std::stoi(sbx_d);
      } catch (std::exception& ex) {
        // Error, so ignore.
        sandbox_tracking_detail::fd = sandbox_tracking_detail::fd_ignore;
      }
    } else {
      // Not our target process, so ignore.
      sandbox_tracking_detail::fd = sandbox_tracking_detail::fd_ignore;
    }
  }

  /* We want to track when the sandbox request is sent to lie about being able to access
     /proc/self/exe later in open64 */
  if (sandbox_tracking_detail::fd == fd && len == 1 && static_cast<const char*>(buf)[0] == 'C') {
    sandbox_tracking_detail::chroot_request_sent.store(true);
  }

  return original(fd, buf, len);
}

DECLARE_OVERRIDE(int, open64, const char *path, int flags, ...) {
  int mode = 0;

  // Load the mode if needed.
  if (__OPEN_NEEDS_MODE(flags)) {
    va_list va;
    va_start(va, flags);
    mode = va_arg(va, int);
    va_end(va);
  }

  // Use the syscall if dlsym hasn't been confirmed to be safe.
  if (!loading_detail::dlsym_safe.load()) {
    // On x64 systems, off64_t and off_t are the same at the ABI level, so O_LARGEFILE
    // isn't needed.
    return syscall(__NR_openat, AT_FDCWD, path, flags, mode);
  }

  auto original = open64_load();

  if (sandbox_tracking_detail::chroot_request_sent.load() && "/proc/self/exe"sv == path) {
    errno = ENOENT;
    return -1;
  }

  if (__OPEN_NEEDS_MODE(flags)) {
    return original(path, flags, mode);
  } else {
    return original(path, flags);
  }
}

// If we're supposed to be in the sandbox, pretend we're PID 1.
DECLARE_OVERRIDE(pid_t, getpid) {
  auto original = getpid_load();

  if (getenv("SBX_CHROME_API_PRV")) {
    return 1;
  } else {
    return original();
  }
}
