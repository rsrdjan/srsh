## srsh
### Secure Reverse Shell

Simple TLS-enabled reverse shell framework (agent and server)

## Installation
```
git clone https://github.com/rsrdjan/srsh.git
cd srsh
make cert && make server && make agent && make clean
```

`make cert` invocates `openssl` command-line tool to generate self-signed x509 certificate and private key (both needed for `srsh-server`) in interactive mode.

## Usage

#### Server

```
srsh-server -c certfile -k privkeyfile [-p port]
```
Loads `certfile` and `privkeyfile` previously generated with `make cert` and starts listening on `port`. If `port` is omitted, 1982 is the default one. 

#### Agent

```
srsh-agent [-p port] ip/fqdn
```
Connects to `ip/fqdn` on `port`. If `port` is omitted, 1982 is the default one. Agent forks and goes into background.

## Notes

Developed and tested on [OpenBSD](https://www.openbsd.org). Enjoy.