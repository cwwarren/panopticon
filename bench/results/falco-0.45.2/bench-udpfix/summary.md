| workload | condition | ops/s or build s | slowdown % | added ns/op | agent cores | agent RSS MB | kernel drops % | alerts delivered % |
|---|---|---|---|---|---|---|---|---|
| idle | none | 0 |  |  | 0.00 | 0 |  |  |
| idle | falco-telemetry | 0 |  |  | 0.01 | 352 | 0.0 |  |
| getppid-1 | none | 24,133,797 | +0.0 | +0 | 0.00 | 0 |  |  |
| getppid-1 | falco-telemetry | 15,517,588 | +55.5 | +23 | 0.01 | 352 | 0.0 |  |
| exec-1 | none | 7,202 | +0.0 | +0 | 0.00 | 0 |  |  |
| exec-1 | falco-telemetry | 6,832 | +5.4 | +7512 | 0.17 | 352 | 0.0 | 100.0 |
| exec-16 | none | 58,173 | +0.0 | +0 | 0.00 | 0 |  |  |
| exec-16 | falco-telemetry | 55,399 | +5.0 | +13776 | 1.17 | 445 | 9.4 | 67.3 |
| connect-1 | none | 85,970 | +0.0 | +0 | 0.00 | 0 |  |  |
| connect-1 | falco-telemetry | 78,508 | +9.5 | +1106 | 1.15 | 458 | 30.7 | 52.3 |
| connect-16 | none | 915,253 | +0.0 | +0 | 0.00 | 0 |  |  |
| connect-16 | falco-telemetry | 866,800 | +5.6 | +977 | 1.13 | 458 | 48.3 | 5.4 |
| udp-1 | none | 561,950 | +0.0 | +0 | 0.00 | 0 |  |  |
| udp-1 | falco-telemetry | 511,840 | +9.8 | +174 | 0.45 | 458 | 20.7 |  |
| udp-16 | none | 7,697,774 | +0.0 | +0 | 0.00 | 0 |  |  |
| udp-16 | falco-telemetry | 6,694,385 | +15.0 | +312 | 1.00 | 458 | 38.3 |  |
| open-1 | none | 2,164,867 | +0.0 | +0 | 0.00 | 0 |  |  |
| open-1 | falco-telemetry | 1,287,202 | +68.2 | +315 | 0.90 | 458 | 0.0 |  |
| open-shadow-1 | none | 2,027,569 | +0.0 | +0 | 0.00 | 0 |  |  |
| open-shadow-1 | falco-telemetry | 1,319,982 | +53.6 | +264 | 1.15 | 457 | 48.2 | 6.4 |

