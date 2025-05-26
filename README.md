# NetDNS2 - Native PHP DNS Resolver and Updater #

### The main features for this package include: ###

  * PSR-4 style autoloading, and namespace symantics (as of version 1.6.0)
  * Increased performance; most requests are 2-10x faster than Net\_DNS
  * Support for IPv4 and IPv6, UDP, TCP, and TLS (DoT) sockets.
  * Includes a separate, more intuitive "Updater" class for handling dynamic update
  * Support zone signing using TSIG and SIG(0) for updates and zone transfers
  * Includes a local cache using shared memory or flat file to improve performance
  * includes many more RR's, including DNSSEC RR's.


## Installing NetDNS2 ##

You can require it directly via Composer: https://packagist.org/packages/pear/net_dns2

```
composer require pear/net_dns2
```

Or download the source above.

## Requirements ##

* PHP 8.1+
* The PHP INI setting `mbstring.func_overload` equals 0, 1, 4, or 5.


## Using NetDNS2 ##

See the NetDNS2 Website for more details - https://netdns2.com/

