# Neighbor Discovery Proxy
This project is an implementaion of [RFC 4861 section 7.2.8](https://datatracker.ietf.org/doc/html/rfc4861#section-7.2.8) written in Rust.

It is similar to another project called [ndppd](https://github.com/DanielAdolfsson/ndppd),
but it provides an extra recipe called "rewrite", which may help people build IPv6-compatible overlay networks.

Any ideas and issues are welcome.

## usage
```
Proxying Neighbor Discovery packets among interfaces.

Usage: ndproxy [OPTIONS]

Options:
  -c, --config <CONFIG>  path to config file [default: /etc/ndproxy.toml]
  -h, --help             Print help
  -V, --version          Print version
```

You can find an example of configuration file [here](https://github.com/6-6-6/ndproxy/blob/master/example.config.toml).

## extra recipe: rewrite the prefix
Let's say your network has multiple upstreams and relies on [Network Prefix Translation (RFC 6296)](https://datatracker.ietf.org/doc/html/rfc6296)
(or [NETMAP](https://www.netfilter.org/documentation/HOWTO/netfilter-extensions-HOWTO-4.html#ss4.4)).

For instance:
```
        2001:db8:1::/64                  2001:db8:ffff::/64
              ↑                                  ↑        ↑
        ISP1, translated via NETMAP        ISP2, NPTv6   Other Users
              |-------- fec1:2:3:4::/64 ---------|
                              ↑
                      your local devices
```

To make your local devices available to both of your upstreams while not disturbing other users,
you may want a config like:

```
[ndp]

[ndp.ISP1]
type = "forward"
proxied_prefix = "2001:db8:1::/64"
rewrite_method = "netmap"
local_prefix = "fec1:2:3:4::/64"
<redacted>

[ndp.ISP2]
type = "forward"
proxied_prefix = "2001:db8:ffff::/64"
rewrite_method = "npt"
local_prefix= "fec1:2:3:4::/64"
<redacted>
```

While running, ndproxy will monitor Neighobor Solicitations from both of your upstreams.

When it captures a valid NS, it will translate the [Target Address](https://datatracker.ietf.org/doc/html/rfc4861#section-4.3) of the NS
to your own private address, and perform Neighbor Discovery locally.

If the requested neighbor exists, ndproxy will send a proxied Neighbor Advertisement back to the related interface.

## performance
Just a random result, but I am happy getting it :)

As of `v0.4.0`, `ndproxy` seems to be faster than `ndppd`.

I have ran `ndproxy` and `ndppd` on a poor-performance machine with similar configuration:
```
# cat ndproxy.toml
[ndp]
[ndp.conf1]
type = "forward"
proxied_prefix = <redacted>
proxied_ifaces = [ "wan0" ]
forwarded_ifaces = "lan0"
rewrite_method = "netmap"
local_prefix = <redacted2>

# cat ndppd.conf
route-ttl 30000
proxy wan0 {
    router yes
    timeout 500
    ttl 30000
    rule <redacted> {
	iface lan0
    }
}
```
and got
```
# ps ax -o comm=,time=,etime=|grep ndp
ndproxy         00:00:03       28:12
ndppd           00:00:07       28:12
```
