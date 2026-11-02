| workload | condition | ops/s or build s | slowdown % | added ns/op | agent cores | agent RSS MB | kernel drops % | alerts delivered % |
|---|---|---|---|---|---|---|---|---|
| idle | none | 0 |  |  | 0.00 | 0 |  |  |
| idle | noop-precise | 0 |  |  | 0.00 | 192 |  |  |
| idle | falco-default | 0 |  |  | 0.01 | 350 | 0.0 |  |
| idle | pano | 0 |  |  | 0.22 | 31 |  |  |
| getppid-1 | none | 24,872,843 | +0.0 | +0 | 0.00 | 0 |  |  |
| getppid-1 | noop-precise | 24,598,604 | +1.1 | +0 | 0.00 | 192 |  |  |
| getppid-1 | falco-default | 15,725,853 | +58.2 | +23 | 0.01 | 350 | 0.0 |  |
| getppid-1 | pano | 24,724,962 | +0.6 | +0 | 0.00 | 31 | 0.0 |  |
| exec-1 | none | 7,334 | +0.0 | +0 | 0.00 | 0 |  |  |
| exec-1 | noop-precise | 7,328 | +0.1 | +106 | 0.00 | 192 |  |  |
| exec-1 | falco-default | 6,930 | +5.8 | +7947 | 0.07 | 350 | 0.0 |  |
| exec-1 | pano | 7,257 | +1.1 | +1437 | 0.00 | 31 | 0.0 | 100.0 |
| exec-16 | none | 57,434 | +0.0 | +0 | 0.00 | 0 |  |  |
| exec-16 | noop-precise | 57,950 | -0.9 | -2476 | 0.00 | 192 |  |  |
| exec-16 | falco-default | 56,178 | +2.2 | +6228 | 0.60 | 350 | 0.0 |  |
| exec-16 | pano | 57,551 | -0.2 | -562 | 0.01 | 31 | 0.0 | 100.0 |
| connect-1 | none | 87,912 | +0.0 | +0 | 0.00 | 0 |  |  |
| connect-1 | noop-precise | 87,556 | +0.4 | +46 | 0.00 | 192 |  |  |
| connect-1 | falco-default | 80,792 | +8.8 | +1002 | 0.15 | 350 | 0.0 |  |
| connect-1 | pano | 85,967 | +2.3 | +257 | 0.01 | 31 | 0.0 | 100.0 |
| connect-16 | none | 947,903 | +0.0 | +0 | 0.00 | 0 |  |  |
| connect-16 | noop-precise | 940,757 | +0.8 | +128 | 0.00 | 192 |  |  |
| connect-16 | falco-default | 877,128 | +8.1 | +1362 | 1.00 | 350 | 30.1 |  |
| connect-16 | pano | 934,039 | +1.5 | +251 | 0.05 | 33 | 0.0 | 100.0 |
| udp-1 | none | 579,797 | +0.0 | +0 | 0.00 | 0 |  |  |
| udp-1 | noop-precise | 578,685 | +0.2 | +3 | 0.00 | 192 |  |  |
| udp-1 | falco-default | 514,975 | +12.6 | +217 | 0.15 | 351 | 0.0 |  |
| udp-1 | pano | 573,374 | +1.1 | +19 | 0.00 | 33 | 0.0 |  |
| udp-16 | none | 7,976,066 | +0.0 | +0 | 0.00 | 0 |  |  |
| udp-16 | noop-precise | 7,929,848 | +0.6 | +12 | 0.00 | 192 |  |  |
| udp-16 | falco-default | 6,746,571 | +18.2 | +366 | 1.00 | 351 | 36.3 |  |
| udp-16 | pano | 7,928,181 | +0.6 | +12 | 0.00 | 33 | 0.0 |  |
| open-1 | none | 2,193,029 | +0.0 | +0 | 0.00 | 0 |  |  |
| open-1 | noop-precise | 2,152,913 | +1.9 | +8 | 0.00 | 192 |  |  |
| open-1 | falco-default | 1,289,363 | +70.1 | +320 | 1.00 | 351 | 25.2 |  |
| open-1 | pano | 2,206,521 | -0.6 | -3 | 0.00 | 33 | 0.0 |  |
| open-shadow-1 | none | 2,080,088 | +0.0 | +0 | 0.00 | 0 |  |  |
| open-shadow-1 | noop-precise | 2,020,672 | +2.9 | +14 | 0.00 | 192 |  |  |
| open-shadow-1 | falco-default | 1,341,310 | +55.1 | +265 | 1.11 | 351 | 48.8 | 4.4 |
| open-shadow-1 | pano | 1,665,373 | +24.9 | +120 | 0.00 | 33 | 0.0 | 100.0 |
| unix-1 | none | 437,637 | +0.0 | +0 | 0.00 | 0 |  |  |
| unix-1 | noop-precise | 433,255 | +1.0 | +23 | 0.00 | 192 |  |  |
| unix-1 | falco-default | 316,147 | +38.4 | +878 | 0.45 | 351 | 0.0 |  |
| unix-1 | pano | 435,841 | +0.4 | +9 | 0.00 | 33 | 0.0 |  |
| signal-1 | none | 9,848,990 | +0.0 | +0 | 0.00 | 0 |  |  |
| signal-1 | noop-precise | 9,838,445 | +0.1 | +0 | 0.00 | 192 |  |  |
| signal-1 | falco-default | 7,741,372 | +27.2 | +28 | 0.01 | 351 | 0.0 |  |
| signal-1 | pano | 9,205,906 | +7.0 | +7 | 0.00 | 33 | 0.0 |  |

| workload | condition | ops/s or build s | slowdown % | added ns/op | agent cores | agent RSS MB | kernel drops % | alerts delivered % |
|---|---|---|---|---|---|---|---|---|
| kbuild | none | 50.63 | +0.0 |  | 0.00 | 0 |  |  |
| kbuild | noop-precise | 50.46 | -0.3 |  | 0.00 | 192 |  |  |
| kbuild | falco-default | 51.71 | +2.1 |  | 0.48 | 349 | 0.0 |  |
| kbuild | pano | 50.74 | +0.2 |  | 0.06 | 31 |  |  |

