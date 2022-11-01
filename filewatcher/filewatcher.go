package filewatcher

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"sync"
	"time"

	"github.com/go-logr/logr"
)

type Options struct {
	Contents []byte // Static contents that never change, for unified handling
	FilePath string
	Interval time.Duration
	OnChange func(contents []byte)
	Logr     logr.Logger
}

// New creates and new Watcher and starts the background watch goroutine if needed.
// The first poll is done immediately and any error there will be immediately
// returned and not further polling done in this case.
// The OnChange callback is not called for this first poll.
// The background goroutine can be cancelled through the passed context.
func New(ctx context.Context, opt Options) (*Watcher, error) {
	if opt.FilePath == "" && opt.Contents == nil {
		return nil, fmt.Errorf("no file path provided and not static contents")
	}
	log := opt.Logr
	// TODO: Since v1 this is a concrete type and we can no longer compare with
	//       nil. Unfortunately, there is no clean way to check this against a
	//       zero type either and we do not want to change the signature of
	//       the option if not needed, so instead we check if the LogSink is nil
	//       to determine if it is uninitialized.
	//       See https://github.com/go-logr/logr/issues/152
	if log.GetSink() == nil {
		log = logr.Discard()
	}
	w := &Watcher{
		opt: opt,
		log: log.WithValues("file", opt.FilePath),
	}
	// Return static contents for simpler unified code
	if opt.FilePath == "" && opt.Contents != nil {
		w.lastContents = opt.Contents
		return w, nil
	}
	// First time must not return an error
	if err := w.checkOnce(); err != nil {
		return nil, err
	}
	go func() {
		_ = w.watch(ctx)
	}()
	return w, nil
}

// Watcher is file watcher that polls a file for changes in the background.
// For convenience, it also supports single content loads without a background watcher.
type Watcher struct {
	opt Options
	log logr.Logger

	mu           sync.Mutex
	lastContents []byte
	lastErr      error
}

// Contents returns the current file contents
func (w *Watcher) Contents() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lastContents
}

// Err returns the last error encountered when polling.
func (w *Watcher) Err() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lastErr
}

func (w *Watcher) watch(ctx context.Context) error {
	w.log.V(1).Info("starting watcher")
	defer w.log.V(1).Info("stopping watcher")

	interval := w.opt.Interval
	if interval == 0 {
		return fmt.Errorf("interval is 0")
	}
	t := time.NewTicker(interval)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			_ = w.checkOnce()
		}
	}
}

func (w *Watcher) checkOnce() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	contents, err := ioutil.ReadFile(w.opt.FilePath)
	if err != nil {
		w.lastErr = err
		w.log.V(0).Error(err, "error reading file")
		return err
	}
	if bytes.Equal(contents, w.lastContents) {
		w.log.V(2).Info("not changed")
		return nil // not changed
	}
	w.log.V(1).Info("contents changed")
	isFirstTime := w.lastContents == nil
	w.lastContents = contents
	if !isFirstTime && w.opt.OnChange != nil {
		w.opt.OnChange(contents)
	}
	return nil
}
