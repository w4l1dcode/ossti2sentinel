package feeds

import "time"

// NewLogRecord creates the base normalized Sentinel log record used by feed packages.
func NewLogRecord(fetchedAt time.Time, threatCategory string) map[string]string {
	timestamp := fetchedAt.UTC().Format(time.RFC3339)

	return map[string]string{
		"TimeGenerated":    timestamp,
		"fetched_at_utc":   timestamp,
		"source":           "",
		"confidence":       "unknown",
		"threat_category":  threatCategory,
		"ioc_type":         "",
		"ioc":              "",
		"AdditionalFields": "{}",
	}
}
