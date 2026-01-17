# octodns-porkbun

Porkbun DNS provider for [octoDNS](https://github.com/octodns/octodns), powered by [oinker](https://github.com/major/oinker).

[![CI](https://github.com/major/octodns-porkbun/actions/workflows/ci.yml/badge.svg)](https://github.com/major/octodns-porkbun/actions/workflows/ci.yml)
[![PyPI version](https://badge.fury.io/py/octodns-porkbun.svg)](https://pypi.org/project/octodns-porkbun/)
[![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)

## Installation

```bash
pip install octodns-porkbun
```

## Configuration

```yaml
providers:
  porkbun:
    class: octodns_porkbun.PorkbunProvider
    api_key: env/PORKBUN_API_KEY
    secret_key: env/PORKBUN_SECRET_KEY
```

### Environment Variables

If `api_key` or `secret_key` are not provided in the config, the provider will fall back to environment variables:

- `PORKBUN_API_KEY`
- `PORKBUN_SECRET_KEY`

## Supported Record Types

- A
- AAAA
- ALIAS
- CAA
- CNAME
- HTTPS
- MX
- NS
- SRV
- SSHFP
- SVCB
- TLSA
- TXT

## Example Usage

```yaml
providers:
  porkbun:
    class: octodns_porkbun.PorkbunProvider
    api_key: env/PORKBUN_API_KEY
    secret_key: env/PORKBUN_SECRET_KEY

  config:
    class: octodns.source.YamlProvider
    directory: ./zones

zones:
  example.com.:
    sources:
      - config
    targets:
      - porkbun
```

## Development

```bash
# Install dependencies
uv sync --dev

# Run checks
make check

# Run individual checks
make lint
make typecheck
make test
```

## License

MIT
