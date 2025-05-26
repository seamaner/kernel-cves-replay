Kernel Privilege Escalation CVE Analysis and Related Files - the bzImage kernel file and the expoit. Based on these files and Qemu, it's easy to setup a debug environment and test the exploit.  

**Done**   
  
- CVE-2024-41009  bpf ringbuf         5.8 - 6.9     
  buf-overlapping -> buf metadata -> ringbuf meta -> function pointer -> stack pivot -> ROP  
  
- CVE-2023-4623   tc-hfsc     UAF     2.6.3 ~ 6.5    
  write-what-where(u64)  -> modprobe_path (/sbin/modprobe -> /tmp/zzzdprobe) -> invalid elf trigger   

- CVE-2023-4622   AF_UNIX     UAF     4.2 ~ 6.4  

- CVE-2021-22555  netfilter   UAF     2.6 ~ 5.12            

**TODO**  

- CVE-2024-1085  netfilter UAF
- CVE-2024-0193  netfilter UAF

- CVE-2023-6932 2.6.12 ~ 6.7 ipv4/igmp uaf    using timer -- didnot
```
-       if (!mod_timer(&im->timer, jiffies+tv+2))
-               refcount_inc(&im->refcnt);
+       if (refcount_inc_not_zero(&im->refcnt)) {
+               if (mod_timer(&im->timer, jiffies + tv + 2))
+                       ip_ma_put(im);
+       }
```

- CVE-2023-6817 netfilter
- CVE-2023-6111 netfilter 
- CVE-2023-5345 SMBFS      Double-free
- CVE-2023-52620 netfilter UAF
- CVE-2023-52447 BPF       UAF    v5.8 - v6.6
- CVE-2023-5197  netfilter UAF
- CVE-2023-4569 netfilter UAF
- CVE-2023-4244 netfilter UAF
- CVE-2023-4208 net/sched UAF
- CVE-2023-4207 net/sched UAF
- CVE-2023-4147 netfilter UAF
- CVE-2023-4015 netfilter UAF
- CVE-2023-4004 netfilter UAF
- CVE-2023-3777 netfilter UAF
- CVE-2023-3776 netfilter UAF
- CVE-2023-3611 net/sched OOB  3.0+ ~ 6.3+
- CVE-2023-3609 net/sched UAF
- CVE-2023-3390 netfilter UAF
- CVE-2023-32233 netfiler UAF
- CVE-2023-31436 net/sched OOB similar to 2023-3611
- CVE-2023-0461 net/tls    UAF
- CVE-2024-50264 - CVE-2025-21756 https://hoefler.dev/articles/vsock.html (kasl bypass)
- CVE-2024-26809 - nftable double free
```
	m = rcu_dereference_protected(priv->match, true);
	if (m) {
		...
		nft_set_pipapo_match_destroy(ctx, set, m);
		...
	}
	if (priv->clone) {
		m = priv->clone;
		if (priv->dirty)
			nft_set_pipapo_match_destroy(ctx, set, m);
```
  
[msg_msg](https://n132.github.io/2024/02/09/IPS.html)  
[https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html](https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html)  

