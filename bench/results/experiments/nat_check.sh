#!/usr/bin/env bash
set -euo pipefail
sudo bpftrace -e 'fexit:nf_nat:nf_nat_setup_info
/args.ct->tuplehash[0].tuple.src.u3.ip != args.ct->tuplehash[1].tuple.dst.u3.ip ||
 args.ct->tuplehash[0].tuple.src.u.all != args.ct->tuplehash[1].tuple.dst.u.all/ {
  $o = args.ct->tuplehash[0].tuple;
  $r = args.ct->tuplehash[1].tuple;
  printf("proto=%d socket %s:%d -> %s:%d  wire src %s:%d\n", $o.dst.protonum,
    ntop($o.src.u3.ip), bswap($o.src.u.all), ntop($o.dst.u3.ip), bswap($o.dst.u.all),
    ntop($r.dst.u3.ip), bswap($r.dst.u.all));
}' >/tmp/pano-exp/nat.log 2>&1 &
bt=$!
for _ in $(seq 100); do grep -q Attached /tmp/pano-exp/nat.log && break; sleep 0.1; done
script='wget -q -T 3 -O /dev/null http://1.1.1.1/ || true'
echo "--- docker"; docker run --rm docker.io/library/redis:7-alpine sh -c "$script"
echo "--- k3s pod"
sudo k3s kubectl run pano-nat --image=docker.io/library/redis:7-alpine --image-pull-policy=IfNotPresent \
  --restart=Never --command -- sh -c "$script" >/dev/null
sudo k3s kubectl wait --for=jsonpath='{.status.phase}'=Succeeded pod/pano-nat --timeout=60s >/dev/null || true
sudo k3s kubectl delete pod pano-nat --wait=false >/dev/null
sleep 1
sudo pkill -INT -x bpftrace
wait "$bt" || true
grep -E 'proto=' /tmp/pano-exp/nat.log | grep -E '1\.1\.1\.1|1\.0\.0\.1|:53 ' | sort -u | head -n 20
