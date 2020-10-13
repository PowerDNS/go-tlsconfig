package tlsconfig

import (
	"io"
	"os"
	"sync"
)

var (
	keyLogMutex sync.Mutex
	keyLogCache = make(map[string]*os.File)
)

// keyLogFile is used to implement the InsecureKeyLogFile option.
func keyLogFile(filePath string) (io.Writer, error) {
	keyLogMutex.Lock()
	defer keyLogMutex.Unlock()

	if f, exists := keyLogCache[filePath]; exists {
		return f, nil
	}

	f, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return nil, err
	}

	keyLogCache[filePath] = f
	return f, nil
}
