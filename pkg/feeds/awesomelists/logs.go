package awesomelists

import (
	"github.com/w4l1dcode/ossti2sentinel/pkg/feeds"
	"time"
)

// BuildLogs turns the parsed malicious extension feeds into normalized log records.
func BuildLogs(
	vscodeExtensions []VSCodeEntry,
	browserExtensions []BrowserEntry,
	fetchedAt time.Time,
) []map[string]string {
	return feeds.MergeLogRecords(
		buildVSCodeLogs(vscodeExtensions, fetchedAt),
		buildBrowserLogs(browserExtensions, fetchedAt),
	)
}
