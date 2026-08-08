# Caddy-Trojan -- A Caddy Module for Trojan Proxy

## Build with xcaddy
```
$ xcaddy build --with github.com/imgk/caddy-trojan
```

##  Config (Caddyfile)
```
{
	order trojan before file_server
	servers :443 {
		listener_wrappers {
			trojan
		}
	}
	trojan {
		caddy
		# memory

		no_proxy
		# env_proxy
		# socks_proxy server user passwd
		# socks_proxy server
		# http_proxy server user passwd
		# http_proxy server
		# named_proxy proxy_name proxy_type args...

		users pass1234 word5678
	}
}
:443, example.com {
	tls your@email.com #optional,recommended
	trojan {
		connect_method
		websocket
	}
	file_server {
		root /var/www/html
	}
}
```
##  Config (JSON)
```
{
  "apps": {
    "http": {
      "servers": {
        "srv0": {
          "listen": [":443"],
          "listener_wrappers": [{
            "wrapper": "trojan",
            "proxy_name": "proxy_2"
          }],
          "routes": [{
            "handle": [{
              "handler": "trojan",
              "connect_method": true,
              "websocket": true,
              "proxy_name": "proxy_3"
            },
            {
              "handler": "file_server",
              "root": "/var/www/html"
            }]
          }]
        }
      }
    },
    "trojan": {
      "named_proxy": {
        "proxy_1": {
          "proxy": "none"
        },
        "proxy_2": {
          "proxy": "socks",
          "server": "127.0.0.1:1080"
        },
        "proxy_3": {
          "proxy": "http",
          "server": "127.0.0.1:8080"
        }
      },
      "proxy": { //optional
        "proxy": "none"
      },
      "upstream": { //optional
        "upstream": "caddy"
      },
      "users": ["pass1234","word5678"]
    },
    "tls": {
      "certificates": {
        "automate": ["example.com"]
      },
      "automation": {
        "policies": [{
          "issuers": [{
            "module": "acme",
            "email": "your@email.com" //optional,recommended
          },
          {
            "module": "acme",
            "ca": "https://acme.zerossl.com/v2/DV90",
            "email": "your@email.com" //optional,recommended
          }]
        }]
      }
    }
  }
}
```

## Manage Users

1. Add user.
```
curl -X POST -H "Content-Type: application/json" -d '{"password": "test1234"}' http://localhost:2019/trojan/users/add
```

## Rate Limiting / DoS Hardening

Password validation applies a uniform 250ms delay on every connection (hit and
miss alike, to keep validation timing-constant). This means an unauthenticated
peer can hold a server goroutine + file descriptor for ~250ms per connection by
sending 58 bytes after the TLS handshake. Caddy itself has no built-in
per-IP connection limiting, so add one at the edge:

1. Bound connection lifetime in the server block so stalled peers are dropped:
```
servers :443 {
	listener_wrappers {
		trojan
	}
	read_timeout 30s
	write_timeout 30s
	idle_timeout 1m
}
```
2. For per-IP connection concurrency limits, build caddy with a limiting
plugin, e.g. [mholt/caddy-limit](https://github.com/mholt/caddy-limit):
```
xcaddy build --with github.com/mholt/caddy-limit
```
```
servers :443 {
	...
	conn_limit 20
}
```
3. As a last line of defense, use a firewall / fail2ban at the host level to
cap new connections per source IP on port 443.

## Docker

```
git clone https://github.com/imgk/caddy-trojan
cd caddy-trojan/Dockerfiles
docker build -t caddy-trojan .
docker run --env MYPASSWD=MY_PASSWORD --env MYDOMAIN=MY_DOMAIN.COM -itd --name caddy-trojan --restart always -p 80:80 -p 443:443 caddy-trojan
```
