package filewatcher

import (
	"context"
	"io/ioutil"
	"os"
	"testing"
	"time"
)

func TestWatcher_static_contents(t *testing.T) {
	opt := Options{
		Contents: []byte("hello"),
		OnChange: func(contents []byte) {
			t.Fatal("Did not expect OnChange to get called with static content")
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w, err := New(ctx, opt)
	if err != nil {
		t.Fatal(err)
	}

	if string(w.Contents()) != "hello" {
		t.Errorf("expected 'hello' contents, got: %q", string(w.Contents()))
	}
}

func TestWatcher_file_with_watcher(t *testing.T) {
	// Extra safetynet
	timer := time.AfterFunc(3*time.Second, func() {
		t.Fatal("Timeout waiting for change")
	})
	defer timer.Stop()

	f1 := writeTempFile(t, "v1")
	defer os.Remove(f1.Name())

	waitForChange := make(chan struct{}, 1)
	opt := Options{
		FilePath: f1.Name(),
		Interval: 10 * time.Millisecond,
		OnChange: func(contents []byte) {
			if string(contents) == "v1" {
				t.Fatal("Did not expect OnChange to get called with initial content")
			}
			if string(contents) != "v2" {
				t.Fatal("Unexpected file contents after change")
			}
			waitForChange <- struct{}{}
			return
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	w, err := New(ctx, opt)
	if err != nil {
		t.Fatal(err)
	}

	if string(w.Contents()) != "v1" {
		t.Errorf("expected 'v1' initial contents, got: %q", string(w.Contents()))
	}

	// New file that atomically replaces the old one
	f2 := writeTempFile(t, "v2")
	defer os.Remove(f2.Name())
	if err := os.Rename(f2.Name(), f1.Name()); err != nil {
		t.Fatal(err)
	}

	t.Log("Before waitForChange")
	<-waitForChange
	t.Log("After waitForChange")
	if string(w.Contents()) != "v2" {
		t.Errorf("expected 'v2' initial contents, got: %q", string(w.Contents()))
	}
}

func writeTempFile(t *testing.T, contents string) *os.File {
	f, err := ioutil.TempFile("", "test-watcher-")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Created temp file:", f.Name())
	if _, err := f.WriteString(contents); err != nil {
		t.Fatal("error writing file", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal("error closing file", err)
	}
	return f
}
