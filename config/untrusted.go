package config

import (
	"fmt"
)

// Sensitive sections that can steer credentials, proxies or network
// connections to an attacker-controlled endpoint. They are parsed from
// trusted configuration (global and system scope) but must never be taken
// from the config of a repository whose ownership could not be verified.
const (
	// urlSectionRewrite holds url.<base>.insteadOf and pushInsteadOf
	// rewrites of remote URLs.
	urlSectionRewrite = "url"
	// credentialSection holds credential helper and per-URL credential
	// selectors.
	credentialSection = "credential"
	// httpSection holds http.proxy, http.extraHeader and related
	// connection settings.
	httpSection = "http"
)

// RejectedConfig records a single configuration item that was not applied
// because the repository is untrusted. It lets callers learn which
// directives were dropped instead of the directives being silently ignored.
type RejectedConfig struct {
	// Section is the config section name, lower-cased as git stores it
	// (e.g. "url", "credential", "http").
	Section string
	// Subsection is the subsection name when present, such as the URL base
	// of a [url "..." ] stanza. Empty for sections without a subsection.
	Subsection string
	// Key is the option key that was rejected (e.g. "insteadOf").
	Key string
	// Reason explains why the item was rejected.
	Reason string
}

func (r RejectedConfig) String() string {
	if r.Subsection != "" {
		return fmt.Sprintf("%s.%s.%s: %s", r.Section, r.Subsection, r.Key, r.Reason)
	}
	return fmt.Sprintf("%s.%s: %s", r.Section, r.Key, r.Reason)
}

// UntrustedConfigOptions controls which sensitive directives are stripped
// from the local config of an untrusted repository. The zero value strips
// every credential-affecting directive, matching the safe default.
type UntrustedConfigOptions struct {
	// AllowURLRewrites keeps [url "<base>"] insteadOf and pushInsteadOf
	// rewrites active. This is intended for environments that rely on
	// legitimate local mirror rewrites and have assessed the untrusted
	// repository separately.
	AllowURLRewrites bool
	// AllowCredentials keeps [credential] helper and selector directives
	// active.
	AllowCredentials bool
	// AllowHTTP keeps [http] connection directives such as proxy and
	// extraHeader active.
	AllowHTTP bool
}

// SanitizeUntrusted removes credential-affecting directives from a local
// repository config that cannot be trusted because its directory ownership
// does not match the current user. The returned slice reports every dropped
// item so callers can surface it instead of the drop being silent.
//
// Only the repository-local config is sanitized. Global and system configs
// live outside the repository and are trusted in the same way git trusts
// them for safe.directory entries.
func SanitizeUntrusted(cfg *Config, opts UntrustedConfigOptions) []RejectedConfig {
	if cfg == nil {
		return nil
	}

	var rejected []RejectedConfig

	if !opts.AllowURLRewrites {
		rejected = append(rejected, dropURLRewrites(cfg)...)
	}
	if !opts.AllowCredentials {
		rejected = append(rejected, dropSection(cfg, credentialSection)...)
	}
	if !opts.AllowHTTP {
		rejected = append(rejected, dropSection(cfg, httpSection)...)
	}

	return rejected
}

// dropURLRewrites removes url.* rewrite rules and restores any remote URLs
// that were rewritten while unmarshalling, so a remote points back at the
// literal URL recorded in its own stanza.
func dropURLRewrites(cfg *Config) []RejectedConfig {
	var rejected []RejectedConfig

	for _, u := range cfg.URLs {
		if u == nil || u.raw == nil {
			continue
		}
		for _, key := range u.raw.Options {
			rejected = append(rejected, RejectedConfig{
				Section:    urlSectionRewrite,
				Subsection: u.Name,
				Key:        key.Key,
				Reason:     "url rewrite rules are disabled for untrusted repositories",
			})
		}
	}

	cfg.URLs = make([]*URL, 0)

	for _, remote := range cfg.Remotes {
		if remote == nil || !remote.insteadOfRulesApplied {
			continue
		}
		remote.URLs = append([]string(nil), remote.originalURLs...)
		remote.originalURLs = nil
		remote.insteadOfRulesApplied = false
	}

	if cfg.Raw != nil {
		cfg.Raw.RemoveSection(urlSectionRewrite)
	}

	return rejected
}

// dropSection removes every option in every subsection of the named section
// from both the parsed config and its raw representation.
func dropSection(cfg *Config, section string) []RejectedConfig {
	if cfg.Raw == nil || !cfg.Raw.HasSection(section) {
		return nil
	}

	var rejected []RejectedConfig

	raw := cfg.Raw.Section(section)
	for _, sub := range raw.Subsections {
		for _, opt := range sub.Options {
			rejected = append(rejected, RejectedConfig{
				Section:    section,
				Subsection: sub.Name,
				Key:        opt.Key,
				Reason:     section + " directives are disabled for untrusted repositories",
			})
		}
	}
	for _, opt := range raw.Options {
		rejected = append(rejected, RejectedConfig{
			Section: section,
			Key:     opt.Key,
			Reason:  section + " directives are disabled for untrusted repositories",
		})
	}

	cfg.Raw.RemoveSection(section)

	return rejected
}
