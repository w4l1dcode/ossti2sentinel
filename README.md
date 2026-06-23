# ossti2sentinel

`ossti2sentinel` ingests open source threat intelligence feeds and ships normalized IOC records to Microsoft Sentinel.

## Feeds

- MalwareBazaar recent SHA256 hashes
- URLHaus online URLs
- Known malicious Visual Studio Code extension IDs
- Known malicious browser extension IDs

## Configuration

The CLI reads YAML config from `ossti2sentinel.yml` by default. A different file can be passed with `-config`.

```yaml
log:
  level: INFO

microsoft:
  app_id: ""
  secret_key: ""
  tenant_id: ""
  subscription_id: ""
  resource_group: ""
  workspace_name: ""
  dcr:
    endpoint: ""
    rule_id: ""
    stream_name: ""

virustotal:
  api_key: "<optional-api-key>"
```

Most settings can also be provided as environment variables, including `MS_APP_ID`, `MS_SECRET_KEY`, `MS_TENANT_ID`, `MS_SUB_ID`, `MS_DCR_ENDPOINT`, `MS_DCR_RULE`, and `MS_DCR_STREAM`.

## Usage

```bash
go run ./cmd/... -config=ossti2sentinel.yml
```

Override the configured log level:

```bash
go run ./cmd/... -config=ossti2sentinel.yml -log=debug
```

## Development

```bash
go test ./...
go build -o ossti2sentinel ./cmd/...
```

## References
- https://github.com/mthcht/awesome-lists/tree/main/Lists
- https://bazaar.abuse.ch/browse/
- https://urlhaus.abuse.ch