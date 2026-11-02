| workload | condition | ops/s or build s | slowdown % | added ns/op | agent cores | agent RSS MB | kernel drops % | alerts delivered % |
|---|---|---|---|---|---|---|---|---|
| idle | none | 0 |  |  | 0.00 | 0 |  |  |
| idle | noop-precise | 0 |  |  | 0.00 | 192 |  |  |
| idle | falco-default | 0 |  |  | 0.01 | 346 | 0.0 |  |
| idle | pano | 0 |  |  | 0.00 | 22 |  |  |
| getppid-1 | none | 24,835,829 | +0.0 | +0 | 0.00 | 0 |  |  |
| getppid-1 | noop-precise | 24,631,988 | +0.8 | +0 | 0.00 | 192 |  |  |
| getppid-1 | falco-default | 15,700,527 | +58.2 | +23 | 0.00 | 346 | 0.0 |  |
| getppid-1 | pano | 24,832,366 | +0.0 | +0 | 0.00 | 22 | 0.0 |  |
| exec-1 | none | 7,310 | +0.0 | +0 | 0.00 | 0 |  |  |
| exec-1 | noop-precise | 7,358 | -0.7 | -900 | 0.00 | 192 |  |  |
| exec-1 | falco-default | 6,902 | +5.9 | +8089 | 0.06 | 347 | 0.0 |  |
| exec-1 | pano | 7,256 | +0.8 | +1029 | 0.00 | 22 | 0.0 | 100.0 |
| exec-16 | none | 58,328 | +0.0 | +0 | 0.00 | 0 |  |  |
| exec-16 | noop-precise | 57,738 | +1.0 | +2803 | 0.00 | 192 |  |  |
| exec-16 | falco-default | 55,256 | +5.6 | +15250 | 0.59 | 347 | 0.0 |  |
| exec-16 | pano | 57,925 | +0.7 | +1908 | 0.00 | 22 | 0.0 | 100.0 |
| connect-1 | none | 87,565 | +0.0 | +0 | 0.00 | 0 |  |  |
| connect-1 | noop-precise | 87,331 | +0.3 | +31 | 0.00 | 192 |  |  |
| connect-1 | falco-default | 80,682 | +8.5 | +974 | 0.15 | 347 | 0.0 |  |
| connect-1 | pano | 86,379 | +1.4 | +157 | 0.01 | 23 | 0.0 | 100.0 |
| connect-16 | none | 938,290 | +0.0 | +0 | 0.00 | 0 |  |  |
| connect-16 | noop-precise | 949,588 | -1.2 | -203 | 0.00 | 192 |  |  |
| connect-16 | falco-default | 888,641 | +5.6 | +953 | 1.00 | 347 | 39.6 |  |
| connect-16 | pano | 933,965 | +0.5 | +79 | 0.05 | 25 | 0.0 | 100.0 |
| udp-1 | none | 567,714 | +0.0 | +0 | 0.00 | 0 |  |  |
| udp-1 | noop-precise | 571,944 | -0.7 | -13 | 0.00 | 192 |  |  |
| udp-1 | falco-default | 509,904 | +11.3 | +200 | 0.14 | 347 | 0.0 |  |
| udp-1 | pano | 561,563 | +1.1 | +19 | 0.00 | 25 | 0.0 |  |
| udp-16 | none | 7,885,008 | +0.0 | +0 | 0.00 | 0 |  |  |
| udp-16 | noop-precise | 7,844,919 | +0.5 | +10 | 0.00 | 192 |  |  |
| udp-16 | falco-default | 6,700,894 | +17.7 | +359 | 1.00 | 347 | 36.1 |  |
| udp-16 | pano | 7,718,645 | +2.2 | +44 | 0.00 | 25 | 0.0 |  |
| open-1 | none | 2,184,991 | +0.0 | +0 | 0.00 | 0 |  |  |
| open-1 | noop-precise | 2,143,173 | +2.0 | +9 | 0.00 | 192 |  |  |
| open-1 | falco-default | 1,291,542 | +69.2 | +317 | 1.00 | 347 | 25.6 |  |
| open-1 | pano | 2,198,167 | -0.6 | -3 | 0.00 | 25 | 0.0 |  |
| open-shadow-1 | none | 2,072,351 | +0.0 | +0 | 0.00 | 0 |  |  |
| open-shadow-1 | noop-precise | 2,023,336 | +2.4 | +12 | 0.00 | 192 |  |  |
| open-shadow-1 | falco-default | 1,339,530 | +54.7 | +264 | 1.11 | 347 | 48.8 | 4.4 |
| open-shadow-1 | pano | 1,689,399 | +22.7 | +109 | 0.00 | 25 | 0.0 | 0.0 |

| workload | condition | ops/s or build s | slowdown % | added ns/op | agent cores | agent RSS MB | kernel drops % | alerts delivered % |
|---|---|---|---|---|---|---|---|---|
| kbuild | none | 50.30 | +0.0 |  | 0.00 | 0 |  |  |
| kbuild | noop-precise | 50.38 | +0.1 |  | 0.00 | 192 |  |  |
| kbuild | falco-default | 51.55 | +2.5 |  | 0.48 | 348 | 0.0 |  |
| kbuild | pano | 50.36 | +0.1 |  | 0.00 | 22 |  |  |

