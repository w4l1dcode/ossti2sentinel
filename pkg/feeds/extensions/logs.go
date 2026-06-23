package extensions

import "time"

// BuildLogs turns the parsed malicious extension feeds into normalized log records.
func BuildLogs(
	vscodeExtensions []VSCodeEntry,
	browserExtensions []BrowserEntry,
	fetchedAt time.Time,
) []map[string]string {
	logs := make([]map[string]string, 0, len(vscodeExtensions)+len(browserExtensions))
	logs = append(logs, buildVSCodeLogs(vscodeExtensions, fetchedAt)...)
	logs = append(logs, buildBrowserLogs(browserExtensions, fetchedAt)...)

	return logs
}
