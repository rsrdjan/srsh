## srsh
### Secure Reverse Shell

Simple TLS-enabled reverse shell framework (agent and server)

## Installation
```
git clone https://github.com/rsrdjan/srsh.git
cd srsh
make all
```
You can `make` individual components or `all`. Individual components are:

`make cert` - invocates `openssl` command-line tool to generate self-signed x509 certificate and private key (both needed for `srsh-server`) in interactive mode. Certificate outputs to `cert.crt` file and private key to `priv.key` file.

`make server` - builds server

`make agent` - builds agent

`make clean` - removes object files

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

List of changes is contained in [changelog](CHANGELOG.md).

Tested on [OpenBSD](https://www.openbsd.org) and Linux. Enjoy.
