xdpdump-rs
==========

Rust implementation of the [Netronome/bpf-samples](https://github.com/Netronome/bpf-samples)
xdpdump application.


Simple `tcpdump` like application based on XDP, supporting multiple XDP modes:
 * Generic: `XDP_FLAGS_SKB_MODE` or `xdpgeneric`
 * Driver: `XDP_FLAGS_DRV_MODE` or `xdpdrv`
 * Hardware: `XDP_FLAGS_HW_MODE` or `xdpoffload`

```
$ sudo ./xdpdump -i lo -S -x
140480.837100 IP  127.0.0.1:9229 > 127.0.0.1:35702 TCP seq 0, length 0
0000:   00 00 00 00  00 00 00 00  00 00 00 00  08 00 45 00   ..............E.
0010:   00 28 00 00  40 00 40 06  3c ce 7f 00  00 01 7f 00   .(..@.@.<.......
0020:   00 01 24 0d  8b 76 00 00  00 00 9c f7  24 96 50 14   ..$..v......$.P.
0030:   00 00 40 bd  00 00                                   ..@...
140480.993289 IP  127.0.0.1:0 > 127.0.0.1:0 ICMP, length 64
0000:   00 00 00 00  00 00 00 00  00 00 00 00  08 00 45 00   ..............E.
0010:   00 54 f8 7a  40 00 40 01  44 2c 7f 00  00 01 7f 00   .T.z@.@.D,......
0020:   00 01 08 00  43 f2 00 1a  00 02 67 96  29 60 00 00   ....C.....g.)`..
0030:   00 00 63 28  01 00 00 00  00 00 10 11  12 13 14 15   ..c(............
0040:   16 17 18 19  1a 1b 1c 1d  1e 1f 20 21  22 23 24 25   .......... !"#$%
0050:   26 27 28 29  2a 2b 2c 2d  2e 2f 30 31  32 33 34 35   &'()*+,-./012345
0060:   36 37                                                67
140480.993370 IP  127.0.0.1:0 > 127.0.0.1:0 ICMP, length 64
0000:   00 00 00 00  00 00 00 00  00 00 00 00  08 00 45 00   ..............E.
0010:   00 54 f8 7b  00 00 40 01  84 2b 7f 00  00 01 7f 00   .T.{..@..+......
0020:   00 01 00 00  4b f2 00 1a  00 02 67 96  29 60 00 00   ....K.....g.)`..
0030:   00 00 63 28  01 00 00 00  00 00 10 11  12 13 14 15   ..c(............
0040:   16 17 18 19  1a 1b 1c 1d  1e 1f 20 21  22 23 24 25   .......... !"#$%
0050:   26 27 28 29  2a 2b 2c 2d  2e 2f 30 31  32 33 34 35   &'()*+,-./012345
0060:   36 37                                                67
```
