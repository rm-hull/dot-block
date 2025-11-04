package internal

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
)

func DownloadBlocklist(url string) ([]string, error) {

	log.Printf("Retrieving blocklist: %s", url)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch from %s: %w", url, err)
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("failed to close body: %v", err)
		}
	}()

	if resp.StatusCode > 299 {
		return nil, fmt.Errorf("error response from %s: %s", url, resp.Status)
	}

	lastModified := resp.Header.Get("Last-Modified")
	if lastModified == "" {
		lastModified = "unknown"
	}
	log.Printf("Remote last modified: %s", lastModified)

	filesize := "unknown size"
	if resp.ContentLength >= 0 {
		filesize = humanize.Bytes(uint64(resp.ContentLength))
	}
	log.Printf("Downloading content (%s)...", filesize)

	blocklist := make([]string, 0, 100_000)
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			log.Println(" ", line)
		} else if len(strings.TrimSpace(line)) == 0 {
			continue
		} else {
			blocklist = append(blocklist, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}

	log.Printf("Loaded %d hostnames", len(blocklist))
	return blocklist, nil
}
