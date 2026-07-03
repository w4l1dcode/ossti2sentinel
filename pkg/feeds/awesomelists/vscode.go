package awesomelists

import (
	"bufio"
	"context"
	"fmt"
	"github.com/w4l1dcode/ossti2sentinel/pkg/feeds"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

const vscodeExtensionIDsURL = "https://raw.githubusercontent.com/mthcht/awesome-lists/main/Lists/VSCODE%20Extensions/feeds/ioc_all_extension_ids.txt"

// VSCodeEntry represents a malicious Visual Studio Code extension ID.
type VSCodeEntry struct {
	ExtensionID string
}

// FetchVSCode fetches malicious Visual Studio Code extension IDs.
func FetchVSCode(ctx context.Context, client *http.Client) ([]VSCodeEntry, error) {
	resp, err := feeds.GetFeed(ctx, client, vscodeExtensionIDsURL, "awesome-lists VS Code extensions")
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

	entries, err := parseVSCode(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading awesome-lists VS Code extensions response: %w", err)
	}

	return entries, nil
}

func parseVSCode(r io.Reader) ([]VSCodeEntry, error) {
	scanner := bufio.NewScanner(r)
	var entries []VSCodeEntry

	for scanner.Scan() {
		line := strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "\ufeff"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		entries = append(entries, VSCodeEntry{ExtensionID: line})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return entries, nil
}

func buildVSCodeLogs(entries []VSCodeEntry, fetchedAt time.Time) []map[string]string {
	return feeds.BuildLogRecords(entries, fetchedAt, func(extension VSCodeEntry) feeds.LogRecordFields {
		return feeds.LogRecordFields{
			ThreatCategory: "malicious_extension",
			Source:         "awesome_lists_vscode_malicious_extension_ids",
			IOCType:        "vscode_extension_id",
			IOC:            extension.ExtensionID,
			AdditionalFields: map[string]string{
				"application":  "visual_studio_code",
				"extension_id": extension.ExtensionID,
				"feed_url":     vscodeExtensionIDsURL,
			},
		}
	})
}
