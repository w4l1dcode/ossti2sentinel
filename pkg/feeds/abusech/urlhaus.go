package abusech

import (
	"bufio"
	"context"
	"fmt"
	"github.com/w4l1dcode/ossti2sentinel/pkg/feeds"
	"io"
	"log"
	"net/http"
	neturl "net/url"
	"strings"
	"time"
)

const urlHausOnlineTextURL = "https://urlhaus.abuse.ch/downloads/text_online/"

// URLHausEntry represents a single URL entry from URLHaus.
type URLHausEntry struct {
	RawURL string
	Scheme string
	Host   string
	Path   string
	Port   string
	Domain string // host without port
}

// FetchURLHausOnline fetches the online URLs list from URLHaus.
func FetchURLHausOnline(ctx context.Context, client *http.Client) ([]URLHausEntry, error) {
	resp, err := feeds.GetFeed(ctx, client, urlHausOnlineTextURL, "URLHaus")
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

	scanner := bufio.NewScanner(resp.Body)
	var entries []URLHausEntry

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parsed, err := neturl.Parse(line)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			continue
		}

		host := parsed.Host
		domain := host
		port := ""

		if h, p, ok := strings.Cut(host, ":"); ok {
			domain = h
			port = p
		}

		entries = append(entries, URLHausEntry{
			RawURL: line,
			Scheme: parsed.Scheme,
			Host:   host,
			Path:   parsed.EscapedPath(),
			Port:   port,
			Domain: domain,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading URLHaus response: %w", err)
	}

	return entries, nil
}

func buildURLHausLogs(urls []URLHausEntry, fetchedAt time.Time) []map[string]string {
	return feeds.BuildLogRecords(urls, fetchedAt, func(url URLHausEntry) feeds.LogRecordFields {
		return feeds.LogRecordFields{
			ThreatCategory: "malware",
			Source:         "abusech_urlhaus_online",
			IOCType:        "url",
			IOC:            url.RawURL,
			AdditionalFields: map[string]string{
				"hash_type":  "",
				"url_scheme": url.Scheme,
				"url_host":   url.Host,
				"url_domain": url.Domain,
				"url_path":   url.Path,
				"url_port":   url.Port,
			},
		}
	})
}
