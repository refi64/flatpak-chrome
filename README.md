# Chrome Flatpak

Official proprietary Chrome binaries, running sandboxed inside a Flatpak environment.

## How it works

- The setuid sandbox is replaced with a program that uses Flatpak's sandbox portal.
- LD_PRELOAD is used to override Chrome's setuid sandbox permission checks and made a few
  behavior tweaks.
- Since a sandboxed process can't spawn another sandboxed process due to losing D-Bus access, a
  "sandbox supervisor" is spawned along with the zygote that takes in sandbox requests from its
  child processes.
- The zygote wants to be able to monitor child processes, but with `flatpak-spawn --sandbox`
  they will not be true children (since they're in a parallel process namespace). Therefore,
  an "epoll broker" is spawned, which bridges the file descriptors into the current process
  namespace. **NOTE:** This is not fully functional yet, see TODO.

## Known issues

- **This cannot yet be legally distributed**, as it bundles Chrome itself inside the Flatpak
  instead of using extra-data. This is likely a pretty easy change, but I haven't made it
  yet simply because leaving it inside is easier to debug for now.
- **CRITICAL:** Random freezing and crashes, seems to be somehow related to the child pid fix
  but not entirely sure yet.
- SIGTERMs on close.
- Code needs more comments. It started out nicely, but some of the more recent additions got a
  bit messy.
- iframes sometimes randomly crash. Based on glancing at the log messages, this may be due to
  shared memory issues.
- Can sometimes randomly freeze when trying to close the window.
- The epoll broker can use quite a bit of CPU (~25% on my Core i3-7100u).
- PNaCl does not work (so e.g. Google Earth will never load). This is lower priority than the
  other bullet points here since PNaCl is deprecated anyway.
