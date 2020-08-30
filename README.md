# lp

`lp` is a tool to list processes. It's similar to `ps`, but tuned for my
everyday needs:

* `lp` tells me some things that I often care about which `ps` cannot tell me,
  such as the number of open file descriptors for a process.

* `lp` is not cluttered with things I rarely care about, such as the controlling
  tty of a process.

* `lp` is not encumbered with multiple flag regimes to maintain compatibility
  with decades of slightly different Unix tools (see: `ps -ef` vs. `ps aux`).

* More often than not, I use `ps` with `grep`, which has two annoying aspects:

  - The output elides the header row.
  - Unless you take care by writing something like `grep [m]yprocess`, the
    output will usually include both the process(es) you care about *and* the
    `grep` process.

  `lp` fixes this pragmatically by providing a few flags to filter the process
  list.

See `lp -h` for usage information.

`lp` is Linux-only for the time being.
