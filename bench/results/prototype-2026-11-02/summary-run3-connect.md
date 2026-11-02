| workload | condition | ops/s or build s | slowdown % | added ns/op | agent cores | agent RSS MB | kernel drops % | alerts delivered % |
|---|---|---|---|---|---|---|---|---|
| connect-1 | none | 87,475 | +0.0 | +0 | 0.00 | 0 |  |  |
| connect-1 | noop-precise | 87,051 | +0.5 | +56 | 0.00 | 192 |  |  |
| connect-1 | pano | 86,239 | +1.4 | +164 | 0.01 | 32 | 0.0 | 100.0 |
| connect-16 | none | 952,033 | +0.0 | +0 | 0.00 | 0 |  |  |
| connect-16 | noop-precise | 946,928 | +0.5 | +91 | 0.00 | 192 |  |  |
| connect-16 | pano | 929,057 | +2.5 | +416 | 0.05 | 34 | 0.0 | 100.0 |

