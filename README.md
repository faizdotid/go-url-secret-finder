# go-url-secret-finder
*go-url-secret-finder* is a tool designed to scan websites for API keys exposed in the source code using regular expressions defined in a configuration file **(config.json)**.

## Usage
`go run main.go -f file.txt`

## Available options
- `-list` List containing of your **urls**
- `-thread` Your threads (default **10**)
- `-timeout` Timeout request to sites (default **10**)
- `-verbose` Print output into terminal
- `-match` Print only match url

## Example
```bash
go run main.go -list urls.txt -thread 20 -timeout 15 -verbose -match
```
