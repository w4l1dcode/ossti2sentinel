package aikido

import (
	"github.com/w4l1dcode/ossti2sentinel/pkg/feeds"
	"time"
)

func BuildLogs(predictions []MalwarePrediction, fetchedAt time.Time) []map[string]string {
	return feeds.BuildLogRecords(predictions, fetchedAt, func(prediction MalwarePrediction) feeds.LogRecordFields {
		return feeds.LogRecordFields{
			ThreatCategory: "malware",
			Source:         "aikido_malware_predictions",
			IOCType:        "npm_package",
			IOC:            prediction.PackageName,
			AdditionalFields: map[string]string{
				"package_name": prediction.PackageName,
				"version":      prediction.Version,
				"reason":       prediction.Reason,
				"feed_url":     malwarePredictionsURL,
			},
		}
	})
}
