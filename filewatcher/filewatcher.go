package filewatcher

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"sync"
	"time"

	"github.com/go-logr/logr"
	logrtesting "github.com/go-logr/logr/testing"
)

type Options struct {
	FilePath string
	Interval time.Duration
	OnChange func(contents []byte)
	Logr     logr.Logger
}

func New(opt Options) (*Watcher, error) {
	if opt.FilePath == "" {
		return nil, fmt.Errorf("no file path provided")
	}
	log := opt.Logr
	if log == nil {
		log = logrtesting.NullLogger{}
	}
	w := &Watcher{
		opt: opt,
		log: log.WithValues("file", opt.FilePath),
	}
	// First time must not return an error
	if err := w.checkOnce(); err != nil {
		return nil, err
	}
	return w, nil
}

type Watcher struct {
	opt Options
	log logr.Logger

	mu           sync.Mutex
	lastContents []byte
	lastErr      error
}

func (w *Watcher) Contents() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lastContents
}

func (w *Watcher) Err() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lastErr
}

func (w *Watcher) Watch(ctx context.Context) error {
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
