package mcp

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mxschmitt/playwright-go"
)

type lifecyclePoolPage struct {
	playwright.Page
	closed atomic.Int32
}

func (p *lifecyclePoolPage) Close(...playwright.PageCloseOptions) error {
	p.closed.Add(1)
	return nil
}

type lifecyclePoolBrowser struct {
	playwright.Browser
	entered chan struct{}
	release chan struct{}
	page    *lifecyclePoolPage
}

func (b *lifecyclePoolBrowser) NewPage(...playwright.BrowserNewPageOptions) (playwright.Page, error) {
	close(b.entered)
	<-b.release
	return b.page, nil
}

func TestCreateAgentSessionRefusesAPoolClosedAfterLookup(t *testing.T) {
	pool := &ProfileSessionPool{sessions: make(map[string]*WebSession)}
	server := &SessionPool{maxPerProfile: 10}
	session, err := server.createSession(pool, "owned-profile")
	if session != nil || err == nil || !strings.Contains(err.Error(), "pool is closed") {
		t.Fatalf("closed pool must refuse creation without panic: session=%v error=%v", session, err)
	}
}

func TestAgentPoolCloseWaitsForPageCreationThenClosesItsOwnedPage(t *testing.T) {
	page := &lifecyclePoolPage{}
	browser := &lifecyclePoolBrowser{entered: make(chan struct{}), release: make(chan struct{}), page: page}
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(browser.release) }) })
	pool := &ProfileSessionPool{browser: browser, connectURL: "owned-endpoint", sessions: make(map[string]*WebSession)}
	server := &SessionPool{maxPerProfile: 10}
	created := make(chan error, 1)
	go func() { _, err := server.createSession(pool, "owned-profile"); created <- err }()
	select {
	case <-browser.entered:
	case <-time.After(time.Second):
		t.Fatal("owned page creation did not enter")
	}
	closed := make(chan int, 1)
	go func() { closed <- pool.closeAllPages("owned-test-close") }()
	release.Do(func() { close(browser.release) })
	select {
	case err := <-created:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("page creation did not finish")
	}
	select {
	case count := <-closed:
		if count != 1 || page.closed.Load() != 1 || pool.connectedTo("owned-endpoint") {
			t.Fatalf("close must retire the pool and close its single agent page: count=%d", count)
		}
	case <-time.After(time.Second):
		t.Fatal("pool closure did not finish")
	}
}

func TestAgentPoolConnectionChecksRaceWithClosure(t *testing.T) {
	pool := &ProfileSessionPool{browser: &lifecyclePoolBrowser{}, connectURL: "owned-endpoint", sessions: make(map[string]*WebSession)}
	var wait sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for index := 0; index < 1000; index++ {
				pool.connectedTo("owned-endpoint")
			}
		}()
	}
	for index := 0; index < 1000; index++ {
		pool.closeAllPages("owned-race-close")
	}
	wait.Wait()
	if pool.connectedTo("owned-endpoint") {
		t.Fatal("a retired pool cannot be reused")
	}
}
