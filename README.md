# go-url-secret-finder

*go-url-secret-finder* is a tool designed to scan websites for API keys exposed in the source code using regular expressions defined in a configuration file **(config.json)**.

## Usage

```bash
go run main.go -list urls.txt
```

## Available Options

| Flag | Default | Description |
|------|---------|-------------|
| `-list` | (required) | File containing list of URLs |
| `-config` | `config.json` | Path to config JSON file |
| `-results` | `results` | Directory for output files |
| `-threads` | NumCPU | Number of concurrent workers |
| `-timeout` | `10` | HTTP request timeout (seconds) |
| `-max-redirects` | `10` | Maximum redirects to follow |
| `-buffer` | `1000` | URL channel buffer size |
| `-verbose` | `false` | Print errors to terminal |
| `-match` | `false` | Print only matching URLs |

## Example

```bash
# Basic scan
go run main.go -list urls.txt

# With custom settings
go run main.go -list urls.txt -threads 20 -timeout 15 -verbose -match

# Custom config and output directory
go run main.go -list urls.txt -config custom.json -results output/
```

## Build

```bash
go build -o scanner .
./scanner -list urls.txt
```
