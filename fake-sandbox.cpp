#include <algorithm>
#include <array>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <system_error>
#include <tuple>
#include <vector>

#include <sys/socket.h>

#include <dirent.h>
#include <errno.h>
#include <unistd.h>

using namespace std::literals::string_literals;

namespace debug_detail {
  std::string prog{"<unset>"};
  bool enable = true;
}

std::ostream& log() {
  std::cerr << "[fake-sandbox: " << debug_detail::prog << "] ";
  return std::cerr;
}

class nullstream : public std::ostream {
public:
  nullstream(): std::ostream{&nbuf} {}

  static nullstream& get() { return instance; }
private:
  class nullbuf : public std::streambuf {
  public:
    int overflow(int c) { return c; }
  };

  nullbuf nbuf;

  static nullstream instance;
};

nullstream nullstream::instance;

std::error_code errno_code() {
  return {errno, std::generic_category()};
}

namespace env {
  std::optional<std::string> get(std::string key) {
    if (auto value = getenv(key.c_str())) {
      return {value};
    } else {
      return {};
    }
  }

  bool set(std::string key, std::string value, bool replace=true) {
    if (setenv(key.c_str(), value.c_str(), replace) == -1) {
      auto err = errno_code();
      log() << "failed to set " << key << "=" << value << ": " << err.message() << std::endl;
      return false;
    } else {
      return true;
    }
  }
}

std::ostream& debug() {
  if (debug_detail::enable) {
    return log();
  } else {
    return nullstream::get();
  }
}

class unique_fd {
public:
  unique_fd(): fd_{-1} {}
  unique_fd(int fd): fd_{fd} {}
  unique_fd(const unique_fd& other)=delete;
  unique_fd(unique_fd&& other): fd_{-1} { std::swap(fd_, other.fd_); }
  ~unique_fd() { if (fd_ != -1) close(fd_); }

  operator bool() { return fd_ != -1; }
  int get() { return fd_; }

  int steal() {
    int save = fd_;
    fd_ = -1;
    return save;
  }
private:
  int fd_;
};

std::tuple<unique_fd, unique_fd> create_socket_pair() {
  std::array<int, 2> fds;

  if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds.data()) == -1) {
    auto err = errno_code();
    log() << "socketpair: " << err.message() << std::endl;
    return {unique_fd{}, unique_fd{}};
  }

  return {unique_fd{fds[0]}, unique_fd{fds[1]}};
}

template <typename It>
void exec(It start, It stop) {
  std::vector<const char*> args;
  std::transform(start, stop, std::back_inserter(args), [](const auto& s) { return s.c_str(); });
  args.push_back(nullptr);

  execv(args[0], const_cast<char* const*>(args.data()));

  auto err = errno_code();
  log() << "exec of " << args[0] << " failed: " << err.message() << std::endl;
}

int parent(std::vector<std::string> args, pid_t child_pid, unique_fd fd) {
  env::set("SBX_D", std::to_string(fd.steal()));
  env::set("SBX_HELPER_PID", std::to_string(child_pid));

  env::set("SBX_CHROME_API_PRV", "1");
  env::set("SBX_PID_NS", "");
  env::set("SBX_NET_NS", "");

  exec(args.begin() + 2, args.end());
  return 1;
}

int child(unique_fd fd) {
  char msg = 0;

  debug() << "waiting for chroot request" << std::endl;

  for (;;) {
    errno = 0;
    if (read(fd.get(), &msg, 1) != -1 || errno != EINTR) {
      break;
    }
  }

  if (errno) {
    auto err = errno_code();
    log() << "read from chroot message pipe: " << err.message() << std::endl;
    return 1;
  } else if (msg == '\0') {
    log() << "chroot pipe early exit" << std::endl;
    return 1;
  } else if (msg != 'C') {
    log() << "chroot message pipe returned invalid message: " << static_cast<int>(msg)
          << " (" << msg << ")" << std::endl;
    return 1;
  }

  debug() << "sending chroot reply" << std::endl;

  if (write(fd.get(), "O", 1) == -1) {
    auto err = errno_code();
    log() << "write to chroot message pipe: " << err.message() << std::endl;
    return 1;
  }

  debug() << "sent" << std::endl;
  return 0;
}

int run_command(std::vector<std::string> args) {
  debug() << "running command inside sandbox";

  auto [parent_end, child_end] = create_socket_pair();
  if (!parent_end || !child_end) {
    return 1;
  }

  pid_t forked = fork();
  if (forked == -1) {
    auto err = errno_code();
    log() << "fork: " << err.message() << std::endl;
    return 1;
  } else if (forked == 0) {
    return child(std::move(child_end));
  } else {
    return parent(args, forked, std::move(parent_end));
  }
}

struct dir_deleter {
  void operator()(DIR* dir) {
    if (dir) {
      closedir(dir);
    }
  }
};

std::optional<std::vector<int>> gather_fds_to_redirect() {
  /*
    Certain file descriptors need to always be redirected via flatpak-spawn. This finds all
    of those and returns them.
  */

  std::vector<int> fds;

  std::unique_ptr<DIR, dir_deleter> dir{opendir("/proc/self/fd")};
  if (!dir) {
    auto err = errno_code();
    log() << "failed to open /proc/self/fd: " << err.message() << std::endl;
    return {};
  }

  struct dirent* dp;
  while ((dp = readdir(dir.get()))) {
    int fd = 0;
    try {
      fd = std::stoi(dp->d_name);
    } catch (std::exception& ex) {
      continue;
    }

    if (fd != dirfd(dir.get()) && fd > 2) {
      fds.push_back(fd);
    }
  }

  return fds;
}

int flatpak_spawn(std::vector<std::string> args, std::vector<int> fds_to_redirect) {
  debug() << "starting sandbox" << std::endl;

  uid_t uid = getuid();
  env::set("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/"s + std::to_string(uid) + "/bus");

  std::vector<std::string> command;
  command.push_back("/usr/bin/flatpak-spawn");
  /* command.push_back("--verbose"); */
  command.push_back("--watch-bus");
  command.push_back("--sandbox");
  command.push_back("--env=LD_PRELOAD=/app/lib/fake-sandbox-preload.so");

  for (int fd : fds_to_redirect) {
    command.push_back("--forward-fd="s + std::to_string(fd));
  }

  /* command.push_back("/usr/bin/env"); */
  /* command.push_back("LD_PRELOAD=/app/lib/fake-sandbox-preload.so"); */

  /* command.push_back("/usr/bin/strace"); */
  /* command.push_back("-f"); */
  /* command.push_back("-ELD_PRELOAD=/app/lib/fake-sandbox-preload.so"); */

  command.push_back("/app/chrome/chrome-sandbox");
  command.push_back("--wrap-spawned");

  command.reserve(command.size() + args.size() - 1);
  std::copy(args.begin() + 1, args.end(), std::back_inserter(command));

  for (const std::string& part : command) {
    debug() << "* " << part << std::endl;
  }

  exec(command.begin(), command.end());
  return 1;
}

int main(int argc, char** argv) {
  if (argc < 2) {
    std::cerr << "wrong # of arguments for chrome-sandbox (Flatpak stub)" << std::endl;
    return 1;
  }

  if (auto debug_env_opt = env::get("FLATPAK_CHROME_FAKE_SANDBOX_DEBUG")) {
    if ((*debug_env_opt)[0] == '1') {
      debug_detail::enable = true;
    }
  }

  std::vector<std::string> args{argv, argv + argc};

  if (args[1] == "--get-api") {
    std::cout << 1 << std::endl;
    return 0;
  } else if (args[1] == "--adjust-oom-score") {
    debug() << "XXX ignoring --adjust-oom-score" << std::endl;
    return 0;
  } else if (args[1] == "--wrap-spawned") {
    debug_detail::prog = args[2];
    return run_command(std::move(args));
  } else {
    debug_detail::prog = args[1];

    if (auto fds_to_redirect_opt = gather_fds_to_redirect()) {
      return flatpak_spawn(std::move(args), std::move(*fds_to_redirect_opt));
    } else {
      return 1;
    }
  }
}
