package abusech

import "time"

// BuildLogs turns the parsed Abuse.ch feeds into normalized log records.
func BuildLogs(
	hashes []MalwareBazaarHash,
	urls []URLHausEntry,
	fetchedAt time.Time,
) []map[string]string {
	logs := make([]map[string]string, 0, len(hashes)+len(urls))
	logs = append(logs, buildMalwareBazaarLogs(hashes, fetchedAt)...)
	logs = append(logs, buildURLHausLogs(urls, fetchedAt)...)

	return logs
}
