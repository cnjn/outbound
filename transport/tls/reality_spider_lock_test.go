package tls

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// waitForMapsUnlocked polls until the maps mutex can be taken. Polling rather
// than locking on a goroutine keeps a wedged mutex a clean test failure instead
// of a hung test (and of a cleanup that blocks on the lock it wants to restore).
func waitForMapsUnlocked(t *testing.T) {
	t.Helper()
	limit := time.Now().Add(2 * time.Second)
	for {
		if maps.TryLock() {
			maps.Unlock()
			return
		}
		if time.Now().After(limit) {
			t.Fatal("the maps lock stayed held after a panic inside the harvest")
		}
		time.Sleep(time.Millisecond)
	}
}

// TestSpiderMapsLockReleasedOnPanic is the lock-safety regression for the
// spider's harvested-path bookkeeping: the recover that contains a panic in
// the spider goroutines sits outside the maps critical section, so a panic
// raised while the lock is held used to be recovered without the lock ever
// being released, wedging every later spider access for the process lifetime.
// The harvest below is driven with a nil path set, which panics on the first
// retained href ("assignment to entry in nil map"); the lock must be free
// afterwards, and the same helpers must keep merging paths on the normal path.
func TestSpiderMapsLockReleasedOnPanic(t *testing.T) {
	const serverName = "spider-lock.example"
	prefix := []byte("https://" + serverName)

	maps.Lock()
	savedMaps, savedBytes := maps.maps, maps.bytes
	maps.Unlock()
	t.Cleanup(func() {
		if !maps.TryLock() {
			// The assertion already reported the wedge; the globals cannot be
			// restored while the lock is held, and blocking here would hang
			// the run instead of reporting it.
			return
		}
		maps.maps, maps.bytes = savedMaps, savedBytes
		maps.Unlock()
	})

	// Non-panic path: seeding, merging and picking a path still work.
	paths, first := spiderPathsFor(serverName, "/seed")
	if first == "" || !paths["/seed"] {
		t.Fatalf("spiderPathsFor() = %q, %v; want the seeded path", first, paths)
	}
	if got := spiderHarvest(serverName, paths, prefix, []byte(`<a href="/a">x</a>`)); got == "" || !paths["/a"] {
		t.Fatalf("spiderHarvest() = %q, paths = %v; want /a merged in", got, paths)
	}
	if got := spiderNextPath(paths); got == "" {
		t.Fatal("spiderNextPath() returned an empty path")
	}

	// Panic path: a nil path set panics inside the locked harvest.
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("spiderHarvest with a nil path set did not panic")
			}
		}()
		_ = spiderHarvest(serverName, nil, prefix, []byte(`<a href="/b">x</a>`))
	}()

	waitForMapsUnlocked(t)
}

// TestSpiderMapsStayLiveUnderConcurrentHarvests drives the helpers the handshake
// uses from many goroutines at once. The panic test above pins that the lock is
// released on a fault; this one pins that ordinary concurrent spider traffic
// finishes and leaves the lock free, which is the property the wedge broke.
func TestSpiderMapsStayLiveUnderConcurrentHarvests(t *testing.T) {
	const (
		serverName = "spider-concurrent.example"
		writers    = 8
		rounds     = 20
	)
	prefix := []byte("https://" + serverName)

	maps.Lock()
	savedMaps, savedBytes := maps.maps, maps.bytes
	maps.Unlock()
	t.Cleanup(func() {
		if !maps.TryLock() {
			return
		}
		maps.maps, maps.bytes = savedMaps, savedBytes
		maps.Unlock()
	})

	var wg sync.WaitGroup
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range rounds {
				href := fmt.Sprintf("/c-%d-%d", i, j)
				paths, _ := spiderPathsFor(serverName, href)
				if got := spiderHarvest(serverName, paths, prefix, []byte(`<a href="`+href+`">x</a>`)); got == "" {
					t.Errorf("spiderHarvest() returned no path for %s", href)
					return
				}
				if got := spiderNextPath(paths); got == "" {
					t.Errorf("spiderNextPath() returned an empty path for %s", href)
					return
				}
			}
		}()
	}
	wg.Wait()
	waitForMapsUnlocked(t)

	paths, _ := spiderPathsFor(serverName, "/final")
	for i := range writers {
		for j := range rounds {
			if href := fmt.Sprintf("/c-%d-%d", i, j); !paths[href] {
				t.Fatalf("path %s was harvested but is missing from the retained set", href)
			}
		}
	}
}
