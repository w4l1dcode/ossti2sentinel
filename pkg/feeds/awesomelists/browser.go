package awesomelists

import (
	"context"
	"encoding/csv"
	"fmt"
	"github.com/w4l1dcode/ossti2sentinel/pkg/feeds"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

const browserCSVURL = "https://raw.githubusercontent.com/mthcht/awesome-lists/main/Lists/Browser%20Extensions/browser_extensions_list.csv"

// BrowserEntry represents a malicious browser extension entry.
type BrowserEntry struct {
	Name         string
	IDWildcard   string
	ExtensionID  string
	Category     string
	Type         string
	MetadataLink string
	Comment      string
	CRXSHA256    string
}

// FetchBrowser fetches malicious browser extension entries.
func FetchBrowser(ctx context.Context, client *http.Client) ([]BrowserEntry, error) {
	resp, err := feeds.GetFeed(ctx, client, browserCSVURL, "awesome-lists browser extensions")
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Fatalf("Failed to close body: %v", err)
			return
		}
	}(resp.Body)

	entries, err := parseBrowser(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading awesome-lists browser extensions response: %w", err)
	}

	return entries, nil
}

func parseBrowser(r io.Reader) ([]BrowserEntry, error) {
	reader := csv.NewReader(r)
	reader.FieldsPerRecord = -1
	reader.TrimLeadingSpace = true

	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("reading CSV header: %w", err)
	}

	columns := make(map[string]int, len(header))
	for i, col := range header {
		columns[strings.TrimSpace(strings.TrimPrefix(col, "\ufeff"))] = i
	}

	if _, ok := columns["browser_extension_id"]; !ok {
		return nil, fmt.Errorf("missing required browser_extension_id column")
	}

	value := func(record []string, name string) string {
		i, ok := columns[name]
		if !ok || i >= len(record) {
			return ""
		}
		return strings.TrimSpace(record[i])
	}

	var entries []BrowserEntry
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		extensionID := value(record, "browser_extension_id")
		if extensionID == "" {
			continue
		}

		entries = append(entries, BrowserEntry{
			Name:         value(record, "browser_extension"),
			IDWildcard:   value(record, "browser_extension_id_wildcard"),
			ExtensionID:  extensionID,
			Category:     value(record, "metadata_category"),
			Type:         value(record, "metadata_type"),
			MetadataLink: value(record, "metadata_link"),
			Comment:      value(record, "metadata_comment"),
			CRXSHA256:    value(record, "crx_file_sha256"),
		})
	}

	return entries, nil
}

func buildBrowserLogs(entries []BrowserEntry, fetchedAt time.Time) []map[string]string {
	return feeds.BuildLogRecords(entries, fetchedAt, func(extension BrowserEntry) feeds.LogRecordFields {
		return feeds.LogRecordFields{
			ThreatCategory: "malicious_extension",
			Source:         "awesome_lists_browser_malicious_extensions",
			IOCType:        "browser_extension_id",
			IOC:            extension.ExtensionID,
			AdditionalFields: map[string]string{
				"application":                   "browser",
				"browser_extension":             extension.Name,
				"browser_extension_id":          extension.ExtensionID,
				"browser_extension_id_wildcard": extension.IDWildcard,
				"metadata_category":             extension.Category,
				"metadata_type":                 extension.Type,
				"metadata_link":                 extension.MetadataLink,
				"metadata_comment":              extension.Comment,
				"crx_file_sha256":               extension.CRXSHA256,
				"feed_url":                      browserCSVURL,
			},
		}
	})
}
