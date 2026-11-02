| workload | condition | ops/s or build s | slowdown % | added ns/op | agent cores | agent RSS MB | kernel drops % | alerts delivered % |
|---|---|---|---|---|---|---|---|---|
| idle | none | 0 |  |  | 0.00 | 0 |  |  |
| idle | noop-syscall-tp | 0 |  |  | 0.00 | 181 |  |  |
| idle | noop-precise | 0 |  |  | 0.00 | 192 |  |  |
| idle | falco-default | 0 |  |  | 0.01 | 355 | 0.0 |  |
| idle | falco-telemetry | 0 |  |  | 0.01 | 354 | 0.0 |  |
| getppid-1 | none | 24,503,561 | +0.0 | +0 | 0.00 | 0 |  |  |
| getppid-1 | noop-syscall-tp | 18,100,429 | +35.4 | +14 | 0.00 | 181 |  |  |
| getppid-1 | noop-precise | 24,793,032 | -1.2 | -0 | 0.00 | 192 |  |  |
| getppid-1 | falco-default | 15,749,781 | +55.6 | +23 | 0.01 | 355 | 0.0 |  |
| getppid-1 | falco-telemetry | 15,628,364 | +56.8 | +23 | 0.01 | 354 | 0.0 |  |
| exec-1 | none | 7,401 | +0.0 | +0 | 0.00 | 0 |  |  |
| exec-1 | noop-syscall-tp | 7,296 | +1.4 | +1947 | 0.00 | 181 |  |  |
| exec-1 | noop-precise | 7,359 | +0.6 | +762 | 0.00 | 192 |  |  |
| exec-1 | falco-default | 6,975 | +6.1 | +8241 | 0.06 | 355 | 0.0 |  |
| exec-1 | falco-telemetry | 6,878 | +7.6 | +10273 | 0.17 | 354 | 0.0 | 100.0 |
| exec-16 | none | 58,291 | +0.0 | +0 | 0.00 | 0 |  |  |
| exec-16 | noop-syscall-tp | 56,991 | +2.3 | +6264 | 0.00 | 181 |  |  |
| exec-16 | noop-precise | 58,367 | -0.1 | -354 | 0.00 | 192 |  |  |
| exec-16 | falco-default | 56,410 | +3.3 | +9157 | 0.60 | 355 | 0.0 |  |
| exec-16 | falco-telemetry | 55,623 | +4.8 | +13169 | 1.17 | 441 | 8.7 | 68.7 |
| connect-1 | none | 87,947 | +0.0 | +0 | 0.00 | 0 |  |  |
| connect-1 | noop-syscall-tp | 86,914 | +1.2 | +135 | 0.00 | 181 |  |  |
| connect-1 | noop-precise | 88,236 | -0.3 | -37 | 0.00 | 192 |  |  |
| connect-1 | falco-default | 81,100 | +8.4 | +960 | 0.15 | 355 | 0.0 |  |
| connect-1 | falco-telemetry | 79,171 | +11.1 | +1260 | 1.14 | 452 | 30.6 | 53.4 |
| connect-16 | none | 937,482 | +0.0 | +0 | 0.00 | 0 |  |  |
| connect-16 | noop-syscall-tp | 931,532 | +0.6 | +109 | 0.00 | 181 |  |  |
| connect-16 | noop-precise | 956,408 | -2.0 | -338 | 0.00 | 192 |  |  |
| connect-16 | falco-default | 885,482 | +5.9 | +1002 | 1.00 | 356 | 39.2 |  |
| connect-16 | falco-telemetry | 877,745 | +6.8 | +1162 | 1.19 | 452 | 48.0 | 6.1 |
| udp-1 | none | 578,751 | +0.0 | +0 | 0.00 | 0 |  |  |
| udp-1 | noop-syscall-tp | 572,810 | +1.0 | +18 | 0.00 | 181 |  |  |
| udp-1 | noop-precise | 578,612 | +0.0 | +0 | 0.00 | 192 |  |  |
| udp-1 | falco-default | 517,021 | +11.9 | +206 | 0.14 | 356 | 0.0 |  |
| udp-1 | falco-telemetry | 516,592 | +12.0 | +208 | 0.33 | 452 | 11.9 |  |
| udp-16 | none | 7,964,682 | +0.0 | +0 | 0.00 | 0 |  |  |
| udp-16 | noop-syscall-tp | 7,846,082 | +1.5 | +30 | 0.00 | 181 |  |  |
| udp-16 | noop-precise | 7,923,988 | +0.5 | +10 | 0.00 | 192 |  |  |
| udp-16 | falco-default | 6,747,551 | +18.0 | +362 | 1.00 | 356 | 36.4 |  |
| udp-16 | falco-telemetry | 6,628,455 | +20.2 | +405 | 1.00 | 452 | 38.0 |  |
| open-1 | none | 2,204,468 | +0.0 | +0 | 0.00 | 0 |  |  |
| open-1 | noop-syscall-tp | 2,043,340 | +7.9 | +36 | 0.00 | 181 |  |  |
| open-1 | noop-precise | 2,139,575 | +3.0 | +14 | 0.00 | 192 |  |  |
| open-1 | falco-default | 1,298,940 | +69.7 | +316 | 1.00 | 356 | 25.4 |  |
| open-1 | falco-telemetry | 1,297,746 | +69.9 | +317 | 0.91 | 452 | 0.0 |  |
| open-shadow-1 | none | 2,070,585 | +0.0 | +0 | 0.00 | 0 |  |  |
| open-shadow-1 | noop-syscall-tp | 1,935,653 | +7.0 | +34 | 0.00 | 181 |  |  |
| open-shadow-1 | noop-precise | 2,025,864 | +2.2 | +11 | 0.00 | 192 |  |  |
| open-shadow-1 | falco-default | 1,333,799 | +55.2 | +267 | 1.11 | 356 | 48.7 | 4.6 |
| open-shadow-1 | falco-telemetry | 1,326,764 | +56.1 | +271 | 1.15 | 452 | 48.3 | 6.3 |

| workload | condition | ops/s or build s | slowdown % | added ns/op | agent cores | agent RSS MB | kernel drops % | alerts delivered % |
|---|---|---|---|---|---|---|---|---|
| kbuild | none | 50.33 | +0.0 |  | 0.00 | 0 |  |  |
| kbuild | noop-syscall-tp | 50.48 | +0.3 |  | 0.00 | 182 |  |  |
| kbuild | noop-precise | 50.30 | -0.1 |  | 0.00 | 192 |  |  |
| kbuild | falco-default | 51.48 | +2.3 |  | 0.48 | 356 | 0.0 |  |
| kbuild | falco-telemetry | 51.20 | +1.7 |  | 0.32 | 356 | 0.0 |  |

