# dot-block

* https://chatgpt.com/share/6906b46b-4674-8010-9320-6869e887505d
* https://github.com/hagezi/dns-blocklists

```bash
$ openssl s_client -connect dot.destructuring-bind.org:853 -alpn dot -servername dot.destructuring-bind.org
```

On linux (doesnt work on mac):

```bash
$ dig @dot.destructuring-bind.org -p 853 +tls example.com A
```

Local dev:

```bash
$ dig @127.0.0.1 -p 8053 www.google.com A +tcp

; <<>> DiG 9.10.6 <<>> @127.0.0.1 -p 8053 www.google.com A +tcp
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 65534
;; flags: qr rd ra; QUERY: 1, ANSWER: 6, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
;; QUESTION SECTION:
;www.google.com.                        IN      A

;; ANSWER SECTION:
www.google.com.         300     IN      A       142.251.29.147
www.google.com.         300     IN      A       142.251.29.103
www.google.com.         300     IN      A       142.251.29.105
www.google.com.         300     IN      A       142.251.29.106
www.google.com.         300     IN      A       142.251.29.99
www.google.com.         300     IN      A       142.251.29.104

;; Query time: 17 msec
;; SERVER: 127.0.0.1#8053(127.0.0.1)
;; WHEN: Sun Nov 02 17:42:50 GMT 2025
;; MSG SIZE  rcvd: 223
```
