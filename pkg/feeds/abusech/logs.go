package abusech

import (
	"github.com/w4l1dcode/ossti2sentinel/pkg/feeds"
	"time"
)

// BuildLogs turns the parsed Abuse.ch feeds into normalized log records.
func BuildLogs(
	hashes []MalwareBazaarHash,
	urls []URLHausEntry,
	fetchedAt time.Time,
) []map[string]string {
	return feeds.MergeLogRecords(
		buildMalwareBazaarLogs(hashes, fetchedAt),
		buildURLHausLogs(urls, fetchedAt),
	)
}
