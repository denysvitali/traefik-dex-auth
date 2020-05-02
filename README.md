# traefik-dex-auth (TDA)

## Description

An authentication middleware, similar to (and inspired by) [traefik-forward-auth](https://github.com/thomseddon/traefik-forward-auth)
which uses DEX as an authentication provider. Mainly designed to be run in Kubernetes.

## Project Status
**Warning:** the code still needs to be audited / reviewed in order to be considered "safe".
I'm personally using it, expect some improvements in the future.

## Compiling

### Go binary
```bash
go build -o traefik-dex-auth main.go
```

### Docker Image
```bash
docker build . -t dvitali/traefik-dex-auth:latest
```

## Usage

Refer to the Kubernetes deployment files in [deploy/](deploy/) or to 
the help screen that you'll find by running `./traefik-dex-auth -h`.

```
Usage: traefik-dex-auth [--clientid CLIENTID] [--clientsecret CLIENTSECRET] [--dexurl DEXURL] [--tdaurl TDAURL] [--cookiedomain COOKIEDOMAIN] [--hmackey HMACKEY] [--sessionkey SESSIONKEY] [--logginglevel LOGGINGLEVEL]

Options:
  --clientid CLIENTID    Client ID used to identify this service with Dex [default: traefik-dex-auth]
  --clientsecret CLIENTSECRET
                         Client Secret set in the Dex config
  --dexurl DEXURL        Base URL of your Dex instance (e.g: http://127.0.0.1:5556)
  --tdaurl TDAURL        Url of the Traefik Dex Auth instance (e.g: https://auth.example.com)
  --cookiedomain COOKIEDOMAIN
                         Domain of application for the authentication cookie (e.g: .example.com)
  --hmackey HMACKEY      HMAC Key, used to authenticate redirection cookies
  --sessionkey SESSIONKEY
                         Session Key, used to authenticate sessions
  --logginglevel LOGGINGLEVEL
                         Logging level (debug, info, warning, error, fatal)
  --help, -h             display this help and exit

```