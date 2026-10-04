package extract

import "time"

// IsolatedConfig configures NewIsolated.
type IsolatedConfig struct {
	Path        string        // absolute path of the child binary, whose main calls ChildMain; required
	Args        []string      // arguments before the child's own flags; none for a binary whose main is ChildMain
	MediaTypes  []string      // media types extracted in the child; empty means application/pdf
	MaxBytes    int64         // extract_max_bytes: the largest input, and the child's Native.MaxBytes; required
	Timeout     time.Duration // per document; zero means one minute
	Concurrency int           // children running at once; zero means GOMAXPROCS
}
