package git

import (
	"io"

	"github.com/go-git/go-git/v6/config"
	"github.com/go-git/go-git/v6/storage"
	"github.com/go-git/go-git/v6/utils/trace"
)

// untrustedStorer wraps a repository storer and sanitizes its local config
// on every read, so credential-affecting directives can never reach remote
// or transport code while an untrusted repository is open. Rejected
// directives are recorded and reported through the security trace instead
// of being silently ignored.
type untrustedStorer struct {
	storage.Storer
	opts     config.UntrustedConfigOptions
	rejected []config.RejectedConfig
}

// newUntrustedStorer wraps s. It returns s unchanged when every sensitive
// directive is explicitly allowed, since there is nothing to filter.
func newUntrustedStorer(s storage.Storer, opts config.UntrustedConfigOptions) storage.Storer {
	if opts.AllowURLRewrites && opts.AllowCredentials && opts.AllowHTTP {
		return s
	}
	return &untrustedStorer{Storer: s, opts: opts}
}

// Config returns the repository-local config with the sensitive directives
// permitted by the open options removed.
func (u *untrustedStorer) Config() (*config.Config, error) {
	cfg, err := u.Storer.Config()
	if err != nil {
		return nil, err
	}

	rejected := config.SanitizeUntrusted(cfg, u.opts)
	u.record(rejected)

	return cfg, nil
}

// record deduplicates rejected directives against what earlier config reads
// already reported and emits each new one to the security trace.
func (u *untrustedStorer) record(rejected []config.RejectedConfig) {
	seen := make(map[string]struct{}, len(u.rejected))
	for _, r := range u.rejected {
		seen[r.String()] = struct{}{}
	}

	for _, r := range rejected {
		key := r.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		u.rejected = append(u.rejected, r)
		trace.Security.Printf("untrusted repository config rejected: %s", key)
	}
}

// RejectedConfig returns the sensitive config directives that have been
// dropped since the repository was opened.
func (u *untrustedStorer) RejectedConfig() []config.RejectedConfig {
	return append([]config.RejectedConfig(nil), u.rejected...)
}

// Close forwards closing to the wrapped storer when it implements io.Closer.
func (u *untrustedStorer) Close() error {
	if closer, ok := u.Storer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// closeStorage releases a storer's resources when it can be closed.
func closeStorage(s storage.Storer) {
	if closer, ok := s.(io.Closer); ok {
		_ = closer.Close()
	}
}
