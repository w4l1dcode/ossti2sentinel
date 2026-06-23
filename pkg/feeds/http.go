package feeds

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

// GetFeed performs a GET request for a feed URL and validates a successful HTTP response.
func GetFeed(ctx context.Context, client *http.Client, url, source string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating %s request: %w", source, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing %s request: %w", source, err)
	}

	if resp.StatusCode != http.StatusOK {
		defer func(Body io.ReadCloser) {
			err := Body.Close()
			if err != nil {
				log.Fatalf("Failed to close body: %v", err)
				return
			}
		}(resp.Body)
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("%s HTTP %d: %s", source, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return resp, nil
}
