
<h4 align="left">
  🏠&nbsp;<a href="https://github.com/hakavlad/tird">Homepage</a> &nbsp;
  📜&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/MANPAGE.md">man&nbsp;page</a> &nbsp;
  📑&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/SPECIFICATION.md">Specification</a> &nbsp;
  📄&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/INPUT_OPTIONS.md">Input&nbsp;Options</a> &nbsp;
  📖&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/tutorial/README.md">Tutorial</a> &nbsp;
  ❓&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/FAQ.md">FAQ</a> &nbsp;
  📥&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/INSTALLATION.md">Installation</a>
</h4>

---

# Time-Lock Encryption

Find the `Time cost` for a given duration on your hardware.

**1. Obtain the average time of one iteration.**

A. Run with `Time cost` = 100 and measure the total time: `t_total`.

B. Compute the average time per iteration:

```
t_avg = t_total / 100
```

**2. Find the `Time cost` for the target duration (in seconds, `seconds_target`).**

Required number of iterations (`Time cost`):

```
t_cost = seconds_target / t_avg
```
