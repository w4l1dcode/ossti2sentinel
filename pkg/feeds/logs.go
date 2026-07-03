package feeds

import (
	"encoding/json"
	"time"
)

// LogRecordFields contains feed-specific values for a normalized Sentinel log record.
type LogRecordFields struct {
	ThreatCategory   string
	Source           string
	IOCType          string
	IOC              string
	AdditionalFields map[string]string
}

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

// BuildLogRecords turns parsed feed entries into normalized Sentinel log records.
func BuildLogRecords[T any](
	entries []T,
	fetchedAt time.Time,
	buildFields func(T) LogRecordFields,
) []map[string]string {
	logs := make([]map[string]string, 0, len(entries))

	for _, entry := range entries {
		fields := buildFields(entry)
		logRecord := NewLogRecord(fetchedAt, fields.ThreatCategory)
		logRecord["source"] = fields.Source
		logRecord["ioc_type"] = fields.IOCType
		logRecord["ioc"] = fields.IOC

		if fields.AdditionalFields != nil {
			if b, err := json.Marshal(fields.AdditionalFields); err == nil {
				logRecord["AdditionalFields"] = string(b)
			}
		}

		logs = append(logs, logRecord)
	}

	return logs
}

// MergeLogRecords combines normalized Sentinel log record slices.
func MergeLogRecords(logGroups ...[]map[string]string) []map[string]string {
	total := 0
	for _, logs := range logGroups {
		total += len(logs)
	}

	merged := make([]map[string]string, 0, total)
	for _, logs := range logGroups {
		merged = append(merged, logs...)
	}

	return merged
}
