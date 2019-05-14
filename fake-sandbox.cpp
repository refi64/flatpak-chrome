#include <algorithm>
#include <array>
#include <cstddef>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <vector>

#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>

using namespace std::literals::string_literals;

constexpr std::byte operator""_b(unsigned long long value) {
  return static_cast<std::byte>(value);
}

#define HANDLE_EINTR(...) \
  ({ \
    decltype(__VA_ARGS__) _res; \
    for (;;) { \
      errno = 0; \
      _res = (__VA_ARGS__); \
      if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) { \
        break; \
      } \
    } \
    _res; \
  })

namespace serializer {
  template <typename T>
  struct output_iterator_type {
    using type = typename std::iterator_traits<T>::value_type;
  };

  template <typename T>
  struct output_iterator_type<std::back_insert_iterator<T>> {
    using type = typename T::value_type;
  };

  struct tag {
    template <typename SerializedIt>
    static void check() {
      static_assert(std::is_same_v<typename output_iterator_type<SerializedIt>::type,
                                   std::byte>);
    }
  };

  template <typename Int>
  struct integral_type_tag : tag {
    static_assert(std::is_integral_v<Int>);

    template <typename SerializedIt>
    static SerializedIt serialize(Int value, SerializedIt target) {
      check<SerializedIt>();
      auto u_value = static_cast<std::make_unsigned_t<Int>>(value);

      for (int b = 0; b < sizeof(Int); b++) {
        *target++ = static_cast<std::byte>((u_value << (b * 8)) & 0xFF);
      }

      return target;
    }

    template <typename SerializedIt>
    static SerializedIt deserialize(Int& result, SerializedIt first, SerializedIt last) {
      check<SerializedIt>();
      auto u_result = static_cast<std::make_unsigned_t<Int>>(0);

      auto it = first;
      for (int b = 0; b < sizeof(Int); b++) {
        if (it == last) {
          return it;
        }

        u_result |= std::to_integer<decltype(u_result)>(*it++ << (b * 8));
      }

      result = u_result;
      return it;
    }
  };

  template <typename ElementTag>
  struct iterator_tag : tag {
    static_assert(std::is_base_of_v<tag, ElementTag>);

    template <typename StructureIt, typename SerializedIt>
    static SerializedIt serialize_iter(StructureIt first, StructureIt last,
                                       SerializedIt target) {
      check<SerializedIt>();

      target = integral_type_tag<size_t>::serialize(last - first, target);
      for (auto it = first; it != last; it++) {
        target = ElementTag::serialize(*it, target);
      }

      return target;
    }

    template <typename StructureItFactory, typename SerializedIt>
    static SerializedIt deserialize_iter_with_factory(StructureItFactory factory,
                                                      SerializedIt first, SerializedIt last) {
      check<SerializedIt>();

      size_t len;
      auto it = integral_type_tag<size_t>::deserialize(len, first, last);
      if (it == last) {
        return last;
      }

      auto result = factory(len);

      for (size_t i = 0; i < len; i++) {
        it = ElementTag::deserialize(*result++, it, last);
        if (it == last) {
          return last;
        }
      }

      return it;
    }

    template <typename StructureIt, typename SerializedIt>
    static SerializedIt deserialize_iter(StructureIt result, SerializedIt first,
                                         SerializedIt last) {
      return deserialize_iter_with_factory([&](size_t len) { return result; });
    }
  };

  template <typename ElementTag>
  struct container_tag : tag {
    static_assert(std::is_base_of_v<tag, ElementTag>);

    template <typename Structure, typename SerializedIt>
    static SerializedIt serialize(const Structure& value, SerializedIt target) {
      check<SerializedIt>();
      return iterator_tag<ElementTag>::serialize_iter(value.cbegin(), value.cend(), target);
    }

    template <typename Structure, typename SerializedIt>
    static SerializedIt deserialize(Structure& target, SerializedIt first, SerializedIt last) {
      check<SerializedIt>();
      auto factory = [&](size_t len) {
        target.resize(target.size() + len);
        return target.begin();
      };
      return iterator_tag<ElementTag>::deserialize_iter_with_factory(factory, first, last);
    }
  };
}

namespace ipc_detail {
  constexpr int sandbox_supervisor_fd = 235;

  using sandbox_supervisor_args_serializer_tag = serializer::container_tag<
      serializer::container_tag<serializer::integral_type_tag<char>>>;
  using sandbox_supervisor_fds_to_redirect_serializer_tag = serializer::container_tag<
    serializer::integral_type_tag<int>>;
}

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
  ~unique_fd() { destroy(); }

  operator bool() { return fd_ != -1; }
  int get() { return fd_; }

  void reset(int fd=-1) { destroy(); fd_ = fd; }

  int steal() {
    int save = fd_;
    fd_ = -1;
    return save;
  }
private:
  void destroy() {
    if (fd_ != -1) {
      close(fd_);
    }

    fd_ = -1;
  }

  int fd_;
};

enum class fd_pair_category { pipe, socket };

std::tuple<unique_fd, unique_fd> create_fd_pair(fd_pair_category category) {
  std::array<int, 2> fds;
  int ret = 0;
  std::string_view category_str;

  switch (category) {
  case fd_pair_category::pipe:
    ret = pipe(fds.data());
    category_str = "pipe";
    break;
  case fd_pair_category::socket:
    ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fds.data());
    category_str = "socket";
    break;
  }

  if (ret == -1) {
    auto err = errno_code();
    log() << "create_fd_pair(" << category_str << "): " << err.message() << std::endl;
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

int run_command(std::vector<std::string> args, pid_t child_pid, unique_fd fd) {
  env::set("SBX_D", std::to_string(fd.steal()));
  env::set("SBX_HELPER_PID", std::to_string(child_pid));

  env::set("SBX_CHROME_API_PRV", "1");
  env::set("SBX_PID_NS", "");
  env::set("SBX_NET_NS", "");

  exec(args.begin() + 2, args.end());
  return 1;
}

int sandbox_helper_stub(unique_fd fd) {
  debug() << "waiting for chroot request" << std::endl;

  char msg = 0;
  if (HANDLE_EINTR(read(fd.get(), &msg, 1)) == -1) {
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

int run_command_with_sandbox_helper(std::vector<std::string> args) {
  debug() << "running command inside sandbox" << std::endl;

  auto [parent_end, child_end] = create_fd_pair(fd_pair_category::socket);
  if (!parent_end || !child_end) {
    return 1;
  }

  pid_t forked = fork();
  if (forked == -1) {
    auto err = errno_code();
    log() << "fork: " << err.message() << std::endl;
    return 1;
  } else if (forked == 0) {
    return sandbox_helper_stub(std::move(child_end));
  } else {
    return run_command(args, forked, std::move(parent_end));
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

using remapped_fd_set = std::vector<std::array<unique_fd, 2>>;

remapped_fd_set remap_redirected_fds(std::vector<int> fds_to_redirect) {
  remapped_fd_set remapped;

  for (int fd : fds_to_redirect) {
    fd_pair_category category = fd_pair_category::socket;
    struct stat st;
    if (fstat(fd, &st) != -1 && S_ISFIFO(st.st_mode)) {
      category = fd_pair_category::pipe;
    }

    auto [parent_end, child_end] = create_fd_pair(category);
    if (!parent_end || !child_end) {
      continue;
    }

    unique_fd source{dup(fd)};
    if (!source) {
      auto err = errno_code();
      log() << "dup(" << fd << "): " << err.message() << std::endl;
      continue;
    }

    /* We want to connect source to parent_end, and dup child_end onto the original fd. */
    if (dup2(child_end.get(), fd) == -1) {
      auto err = errno_code();
      log() << "dup2(" << child_end.get() << ", " << fd << "): " << err.message() << std::endl;
      continue;
    }

    debug() << "mapping (" << source.get() << ", " << parent_end.get() << ")" << std::endl;
    remapped.push_back({std::move(source), std::move(parent_end)});
  }

  return remapped;
}

void flatpak_spawn(std::vector<std::string> args, std::vector<int> fds_to_redirect) {
  debug() << "starting sandbox" << std::endl;

  if (prctl(PR_SET_PDEATHSIG, SIGKILL) == -1) {
    auto err = errno_code();
    log() << "warning: prctl on child: " << err.message() << std::endl;
  }

  if (auto home_opt = env::get("HOME")) {
    if (chdir(home_opt->c_str()) == -1) {
      auto err = errno_code();
      log() << "warning: chdir(/app) failed: " << err.message() << std::endl;
    }
  }

  uid_t uid = getuid();
  env::set("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/"s + std::to_string(uid) + "/bus");

  std::vector<std::string> command;
  command.push_back("/usr/bin/flatpak-spawn");
  command.push_back("--watch-bus");
  command.push_back("--sandbox");
  command.push_back("--env=LD_PRELOAD=/app/lib/fake-sandbox-preload.so");

  for (int fd : fds_to_redirect) {
    command.push_back("--forward-fd="s + std::to_string(fd));
  }

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
  auto err = errno_code();
  log() << "exec: " << err.message() << std::endl;
}

int sandbox_supervisor(unique_fd fd) {
  debug_detail::prog = "sandbox-supervisor";

  if (prctl(PR_SET_PDEATHSIG, SIGKILL) == -1) {
    auto err = errno_code();
    log() << "warning: prctl on parent: " << err.message() << std::endl;
  }

  std::unordered_map<pid_t, unique_fd> forked_processes;

  for (;;) {
    std::vector<pid_t> to_erase;

    for (auto& [pid, reply] : forked_processes) {
      int wstatus;
      int r = waitpid(pid, &wstatus, WNOHANG);
      if (r == -1) {
        auto err = errno_code();
        log() << "waitpid(" << pid << "): " << err.message() << std::endl;
        continue;
      } else if (r == 0) {
        continue;
      }

      int ret = 0;
      if (WIFEXITED(wstatus)) {
        ret = WEXITSTATUS(ret);
      } else if (WIFSIGNALED(wstatus)) {
        ret = 128 + WTERMSIG(ret);
      } else {
        log() << "waitpid(" << pid << ") returned a bad status " << wstatus << std::endl;
        ret = 1;
      }

      if (HANDLE_EINTR(write(reply.get(), &ret, sizeof(ret))) == -1) {
        auto err = errno_code();
        log() << "write(" << reply.get() << ", " << ret << "): " << err.message() << std::endl;
      }

      to_erase.push_back(pid);
    }

    for (pid_t pid : to_erase) {
      if (auto it = forked_processes.find(pid); it != forked_processes.end()) {
        forked_processes.erase(it);
      }
    }

    std::vector<std::byte> msg_buffer(4 * 1024 * 1024, 0_b);
    std::vector<std::byte> ctl_buffer(CMSG_SPACE(256 * sizeof(int)), 0_b);

    struct iovec iov{reinterpret_cast<void*>(msg_buffer.data()), msg_buffer.size()};

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctl_buffer.data();
    msg.msg_controllen = ctl_buffer.size();

    int ret = HANDLE_EINTR(recvmsg(fd.get(), &msg, 0));
    if (ret == -1) {
      auto err = errno_code();
      log() << "recvmsg(sandbox_supervisor_fd): " << err.message() << std::endl;
      return 1;
    }

    std::vector<std::string> args;
    std::vector<int> fds_to_redirect;

    auto pos = ipc_detail::sandbox_supervisor_args_serializer_tag::deserialize(
                  args, msg_buffer.cbegin(), msg_buffer.cend());
    ipc_detail::sandbox_supervisor_fds_to_redirect_serializer_tag::deserialize(
      fds_to_redirect, pos, msg_buffer.cend());

    struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg) {
      log() << "got sandbox spawn request without any control info" << std::endl;
      continue;
    }

    int* sent_fds = reinterpret_cast<int*>(CMSG_DATA(cmsg));

    std::vector<unique_fd> fds_to_redirect_ownership;
    fds_to_redirect_ownership.reserve(fds_to_redirect.size());
    unique_fd reply{sent_fds[0]};

    for (int i = 0; i < fds_to_redirect.size(); i++) {
      unique_fd sent_fd{sent_fds[i + 1]};
      int& desired_fd = fds_to_redirect[i];
        debug() << "dup2(" << sent_fd.get() << ", " << desired_fd << ")"
              << std::endl;

      if (dup2(sent_fd.get(), desired_fd) == -1) {
        auto err = errno_code();
        log() << "warning: dup2(" << sent_fd.get() << ", " << desired_fd << "): "
              << err.message() << std::endl;
      }

      fds_to_redirect_ownership.emplace_back(desired_fd);
    }

    pid_t forked = fork();
    if (forked == -1) {
      auto err = errno_code();
      log() << "fork: " << err.message() << std::endl;
      int ret = 1;
      HANDLE_EINTR(write(reply.get(), &ret, sizeof(ret)));
    } else if (forked == 0) {
      flatpak_spawn(std::move(args), std::move(fds_to_redirect));
      return 1;
    } else {
      forked_processes.emplace(forked, std::move(reply));
    }
  }
}

int start_zygote_and_sandbox_supervisor(std::vector<std::string> args,
                                        std::vector<int> fds_to_redirect) {
  auto [parent_end, child_end] = create_fd_pair(fd_pair_category::socket);
  if (!parent_end || !child_end) {
    return 1;
  }

  debug() << "starting sandbox supervisor with zygote" << std::endl;

  if (dup2(child_end.get(), ipc_detail::sandbox_supervisor_fd) == -1) {
    auto err = errno_code();
    log() << "dup2 onto sandbox_supervisor_fd: " << err.message() << std::endl;
    return 1;
  }

  fds_to_redirect.push_back(ipc_detail::sandbox_supervisor_fd);

  pid_t forked = fork();
  if (forked == -1) {
    auto err = errno_code();
    log() << "fork: " << err.message() << std::endl;
    return 1;
  } else if (forked == 0) {
    return sandbox_supervisor(std::move(parent_end));
  } else {
    flatpak_spawn(std::move(args), std::move(fds_to_redirect));
    return 1;
  }
}

int ask_sandbox_supervisor_to_spawn(std::vector<std::string> args,
                                    std::vector<int> fds_to_redirect) {
  debug() << "sending request to sandbox supervisor" << std::endl;

  auto [read_end, write_end] = create_fd_pair(fd_pair_category::pipe);
  if (!read_end || !write_end) {
    return 1;
  }

  std::vector<std::byte> msg_buffer;
  ipc_detail::sandbox_supervisor_args_serializer_tag::serialize(
    args, std::back_inserter(msg_buffer));
  ipc_detail::sandbox_supervisor_fds_to_redirect_serializer_tag::serialize(
    fds_to_redirect, std::back_inserter(msg_buffer));

  size_t cmsg_base_size = (fds_to_redirect.size() + 1) * sizeof(int);
  std::vector<std::byte> ctl_buffer(CMSG_SPACE(cmsg_base_size), 0_b);

  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  struct cmsghdr* cmsg;
  struct iovec iov{reinterpret_cast<void*>(msg_buffer.data()), msg_buffer.size()};

  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = reinterpret_cast<char*>(ctl_buffer.data());
  msg.msg_controllen = ctl_buffer.size();
  cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(cmsg_base_size);

  auto it = reinterpret_cast<int*>(CMSG_DATA(cmsg));
  *it++ = write_end.get();
  std::copy(fds_to_redirect.begin(), fds_to_redirect.end(), it);

  if (HANDLE_EINTR(sendmsg(ipc_detail::sandbox_supervisor_fd, &msg, 0)) == -1) {
    auto err = errno_code();
    log() << "sendmsg on supervisor spawn message: " << err.message() << std::endl;
    return 1;
  }

  log() << "waiting for supervisor spawn" << std::endl;

  int ret = -1;
  int r = HANDLE_EINTR(read(read_end.get(), &ret, sizeof(ret)));
  if (r < sizeof(ret)) {
    if (r == -1) {
      auto err = errno_code();
      log() << "read from supervisor spawn: " << err.message() << std::endl;
    } else {
      log() << "read from supervisor spawn: message too small" << std::endl;
    }
    return 1;
  } else if (ret > 128) {
    raise(ret - 128);
    return 0;  // appease the compiler
  } else {
    return ret;
  }
}

namespace uint32_pair {
  struct accessor {
    uint32_t first;
    uint32_t second;
  };

  static_assert(sizeof(accessor) == sizeof(uint64_t));

  uint64_t pack(uint32_t first, uint32_t second) {
    accessor acc{first, second};
    return *reinterpret_cast<uint64_t*>(&acc);
  }

  std::tuple<uint32_t, uint32_t> unpack(uint64_t value) {
    accessor acc = *reinterpret_cast<accessor*>(&value);
    return {acc.first, acc.second};
  }
}

int epoll_loop(pid_t child, remapped_fd_set remapped) {
  unique_fd epfd{epoll_create1(0)};
  if (!epfd) {
    auto err = errno_code();
    log() << "epoll_create1: " << err.message() << std::endl;
    return 1;
  }

  for (auto& pair : remapped) {
    for (int i = 0; i < pair.size(); i++) {
      int fd = pair[i].get();
      int other = pair[-~-i].get(); // -~- will flip 0 and 1

      epoll_event event;
      event.events = EPOLLIN;
      event.data.u64 = uint32_pair::pack(fd, other);

      if (epoll_ctl(epfd.get(), EPOLL_CTL_ADD, fd, &event)) {
        auto err = errno_code();
        log() << "epoll_ctl(EPOLL_CTL_ADD " << fd << "): " << err.message() << std::endl;
        continue;
      }
    }
  }

  std::vector<char> iov_buffer(4 * 1024 * 1024, 0);
  std::vector<char> ctl_buffer(4 * 1024 * 1024, 0);

  for (;;) {
    int status;
    pid_t wait_result = waitpid(child, &status, WNOHANG);
    if (wait_result > 0) {
      if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        if (code > 128) {
          // flatpak-spawn returns a code >128 when the child dies.
          raise(code - 128);
        } else {
          return code;
        }
      } else if (WIFSIGNALED(status)) {
        raise(WTERMSIG(status));
      } else {
        log() << "waitpid returned a bad status " << status << std::endl;
        return 1;
      }
    } else if (wait_result == -1) {
      auto err = errno_code();
      log() << "warning: waitpid(" << child << "): " << err.message() << std::endl;
    }

    std::array<epoll_event, 1024> events;
    int ready = epoll_wait(epfd.get(), events.data(), events.size(), -1);
    if (ready <= 0) {
      if (ready == -1) {
        auto err = errno_code();
        log() << "epoll_wait: " << err.message() << std::endl;
      }
      continue;
    }

    for (int i = 0; i < ready; i++) {
      const epoll_event& event = events[i];
      auto [source_fd, target_fd] = uint32_pair::unpack(event.data.u64);

      if (event.events & EPOLLIN) {
        memset(iov_buffer.data(), 0, iov_buffer.size() * sizeof(iov_buffer[0]));
        memset(ctl_buffer.data(), 0, ctl_buffer.size() * sizeof(iov_buffer[0]));

        struct iovec iov{reinterpret_cast<void*>(iov_buffer.data()), iov_buffer.size()};

        struct msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = ctl_buffer.data();
        msg.msg_controllen = ctl_buffer.size();

        for (;;) {
          int ret = recvmsg(source_fd, &msg, MSG_DONTWAIT);
          if (ret <= 0) {
            if (ret == -1) {
              if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                auto err = errno_code();
                log() << "recvmsg(" << source_fd << "): " << err.message() << std::endl;
              }
            }
            break;
          }

          iov.iov_len = ret;
          msg.msg_flags = 0;
          if (HANDLE_EINTR(sendmsg(target_fd, &msg, 0)) == -1) {
            auto err = errno_code();
            log() << "sendmsg(" << target_fd << "): " << err.message() << std::endl;
            break;
          }
        }
      }

      if (event.events & EPOLLERR) {
        log() << "warning: EPOLLERR on (" << source_fd << ", " << target_fd << ")" << std::endl;
        epoll_ctl(epfd.get(), EPOLL_CTL_DEL, source_fd, nullptr);
      }

      if (event.events & EPOLLHUP) {
        epoll_ctl(epfd.get(), EPOLL_CTL_DEL, source_fd, nullptr);
      }
    }
  }
}

int spawn_sandbox(std::vector<std::string> args, std::vector<int> fds_to_redirect) {
  auto remapped = remap_redirected_fds(fds_to_redirect);

  if (prctl(PR_SET_PDEATHSIG, SIGKILL) == -1) {
    auto err = errno_code();
    log() << "warning: prctl on parent: " << err.message() << std::endl;
  }

  pid_t forked = fork();
  if (forked == -1) {
    auto err = errno_code();
    log() << "fork: " << err.message() << std::endl;
    return 1;
  } else if (forked == 0) {
    if (std::find(args.begin(), args.end(), "--type=zygote") != args.end()) {
      return start_zygote_and_sandbox_supervisor(std::move(args), std::move(fds_to_redirect));
    } else {
      return ask_sandbox_supervisor_to_spawn(std::move(args), std::move(fds_to_redirect));
    }
  } else {
    debug_detail::prog += " (epoll loop)";
    return epoll_loop(forked, std::move(remapped));
  }
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
    return run_command_with_sandbox_helper(std::move(args));
  } else {
    debug_detail::prog = args[1];

    if (auto fds_to_redirect_opt = gather_fds_to_redirect()) {
      return spawn_sandbox(std::move(args), std::move(*fds_to_redirect_opt));
    } else {
      return 1;
    }
  }
}
