| action | panopticon records |
|---|---|
| exec | exec:/usr/bin/gnutrue |
| memfd-exec | admin:anon_inode, exec:/memfd:pano-memfd (deleted) |
| reparent-exec | exec:/usr/bin/gnutrue |
| setuid-exec | exec:/usr/lib/cargo/bin/sudo |
| tcp4-connect | accept:127.0.0.1:43522, connect:127.0.0.1:34955, listen:0.0.0.0:0 |
| tcp6-connect | accept:[::1]:51816, connect:[::1]:37855, listen:[::]:0 |
| udp4-sendto | bind, udp_send:127.0.0.1:9 |
| tcp-listen | listen:0.0.0.0:0 |
| packet-socket | raw_socket |
| unix-connect-docker | unix_connect |
| open-shadow | file:open:/etc/shadow |
| file-create | file:close_write+on_child:/etc/pano-canary, file:create:/etc/pano-canary, file:modify+on_child:/etc/pano-canary |
| file-chmod-suid | file:attrib+on_child:/etc/pano-canary |
| file-chown | file:attrib+on_child:/etc/pano-canary |
| file-rename | file:moved_from:/etc/pano-canary, file:moved_to:/etc/pano-canary.renamed |
| file-hardlink | file:create:/etc/pano-canary.link, file:delete:/etc/pano-canary.link, file_repeat:moved_from:/etc/pano-canary, file_repeat:moved_to:/etc/pano-canary.renamed |
| file-symlink | — |
| file-timestomp | file:attrib+on_child:/etc/pano-canary |
| file-truncate | file:modify+on_child:/etc/pano-canary |
| file-setxattr | file:attrib+on_child:/etc/pano-canary |
| file-unlink | file:delete:/etc/pano-canary |
| uring-open-shadow | admin:anon_inode, file:open:/etc/shadow |
| uring-file-create | admin:anon_inode, file:close_write+on_child:/etc/pano-canary-uring, file:create:/etc/pano-canary-uring, file:delete:/etc/pano-canary-uring, file:modify+on_child:/etc/pano-canary-uring |
| uring-connect | accept:127.0.0.1:47506, admin:anon_inode, connect:127.0.0.1:42399, listen:0.0.0.0:0 |
| module-load | admin:module_load |
| sysctl-write | admin:sysctl_write |
| bpf-prog-load | admin:bpf_load |
| mount-tmpfs | admin:mount, admin:umount |
| unshare-ns | admin:ns_create |
| setns | admin:setns |
| setuid | admin:setuid |
| capset | admin:capset |
| ptrace-attach | admin:kill, admin:ptrace |
| proc-mem-write | admin:kill, admin:ptrace |
| process-vm-writev | admin:kill, admin:ptrace |
| pidfd-getfd | admin:kill, admin:ptrace |
| kill | admin:kill |
| mprotect-exec | — |
| mmap-exec-file | — |
| kexec-attempt | — |
| settime-attempt | — |
| container-docker | accept:10.42.0.224:45572, accept:10.42.0.224:54350, accept:10.42.0.224:54910, accept:10.42.0.224:54922, accept:127.0.0.1:41734, accept:[::ffff:10.42.0.224]:35920, accept:[::ffff:10.42.0.224]:41120, accept:[::ffff:10.42.0.224]:43250, accept:[::ffff:10.42.0.224]:46232, accept:[::ffff:10.42.0.224]:52398, accept:[::ffff:10.42.0.224]:59946, accept:[::ffff:127.0.0.1]:46476, accept:[::ffff:127.0.0.1]:51006, admin:capset, admin:mount, admin:ns_create, admin:pivot_root, admin:sysctl_write, admin:umount, bind, connect:1.1.1.1:443, connect:1.1.1.1:80, connect:127.0.0.1:8080, container, dns_answer:192.168.1.1:53, dns_query:192.168.1.1:53, exec:/bin/busybox, exec:/usr/bin/ssl_client, file:open:/var/lib/docker/rootfs/overlayfs/f4d6f9456c2619cb3e1cadee1f3e7ade473da903e5f45141c15cbcdab484085e/etc/shadow |
| container-k3s | accept:10.42.0.224:54938, accept:127.0.0.1:35248, accept:127.0.0.1:53530, accept:127.0.0.1:60372, accept:192.168.1.18:35538, accept:[::ffff:10.42.0.224]:35926, accept:[::ffff:10.42.0.224]:43262, accept:[::ffff:10.42.0.224]:43270, accept:[::ffff:10.42.0.224]:43274, accept:[::ffff:10.42.0.224]:43286, accept:[::ffff:10.42.0.224]:43292, accept:[::ffff:10.42.0.224]:46242, accept:[::ffff:10.42.0.224]:46248, accept:[::ffff:10.42.0.224]:59958, accept:[::ffff:10.42.0.224]:59962, accept:[::ffff:10.42.0.224]:59966, accept:[::ffff:10.42.0.224]:59978, accept:[::ffff:10.42.1.103]:47642, accept:[::ffff:10.42.1.103]:47644, accept:[::ffff:127.0.0.1]:51022, accept:[::ffff:127.0.0.1]:51030, accept:[::ffff:127.0.0.1]:51038, accept:[::ffff:127.0.0.1]:51040, accept:[::ffff:127.0.0.1]:51052, accept:[::ffff:127.0.0.1]:51064, admin:bpf_load, admin:capset, admin:mount, admin:ns_create, admin:pivot_root, admin:setgid, admin:setns, admin:setuid, admin:sysctl_write, admin:umount, bind, connect:1.1.1.1:443, connect:1.1.1.1:80, connect:10.43.103.193:8123, connect:127.0.0.1:8080, connect:192.168.1.18:4240, container, dns_answer:10.43.0.10:53, dns_answer:192.168.1.1:53, dns_query:10.43.0.10:53, dns_query:192.168.1.1:53, exec:/bin/busybox, exec:/pause, exec:/usr/bin/ssl_client, file:create:/run/k3s/containerd/io.containerd.runtime.v2.task/k8s.io/a2d3d8e55d0d7ce1f55d78fdc18904b48666527d47c49124d15f45f0a2731572/rootfs/etc/resolv.conf, file:open:/run/k3s/containerd/io.containerd.runtime.v2.task/k8s.io/a2d3d8e55d0d7ce1f55d78fdc18904b48666527d47c49124d15f45f0a2731572/rootfs/etc/shadow, raw_socket, udp_send:10.42.1.103:34650, udp_send:10.42.1.103:35470, udp_send:10.42.1.203:33405, udp_send:10.42.1.203:40716, udp_send:10.42.1.203:43878, udp_send:10.42.1.203:51464, udp_send:10.42.1.203:55886 |
