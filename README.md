# Neighbor Discovery Proxy
This project is an implementaion of [RFC 4861 section 7.2.8](https://datatracker.ietf.org/doc/html/rfc4861#section-7.2.8) written in Rust.

It is similar to another project called [ndppd](https://github.com/DanielAdolfsson/ndppd),
but it provides an extra recipe called "rewrite", which may help people build IPv6-compatible overlay networks.

## usage
```
Usage:
  ./ndproxy [OPTIONS]

proxies your neighbor discovery messages.

Optional arguments:
  -h,--help             Show this help message and exit
  -c,--conf CONF        The location of your config file. Default:
                        ./ndproxy.toml
```

You can find an example of configuration file [here](https://github.com/6-6-6/ndproxy/blob/master/example.config.toml).

## extra recipe: rewrite the prefix
Let's say your network has multiple upstreams and relies on Network Prefix Translation.

For instance:
```
        2001:db8:1::/64                  2001:db8:ffff::/64
              ↑                                  ↑        ↑
             ISP1                               ISP2    Other Users
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
rewrite = "fec1:2:3:4::/64"
<redacted>

[ndp.ISP2]
type = "forward"
proxied_prefix = "2001:db8:ffff::/64"
rewrite = "fec1:2:3:4::/64"
<redacted>
```

While running, ndproxy will monitor Neighobor Solicitations from both of your upstreams.

When it captures a valid NS, it will translate the [Target Address](https://datatracker.ietf.org/doc/html/rfc4861#section-4.3) of the NS
to your own private address, and perform Neighbor Discovery locally.

If the requested neighbor exists, ndproxy will send a proxied Neighbor Advertisement back to the related interface.
