package git

import (
	"github.com/go-git/go-git/v6/config"
	"github.com/go-git/go-git/v6/internal/pathutil"
	"github.com/go-git/go-git/v6/plumbing/object"
)

// VerifyOptionsFromConfig builds the trust material for scheme-agnostic
// object signature verification from a repository configuration.
//
// The gpg.ssh.allowedSignersFile setting supplies the trusted SSH public keys
// (see object.ParseAllowedSigners). Paths beginning with "~" are expanded to
// the current user's home directory.
//
// X.509/CMS trust roots are not configured by core Git; set
// object.VerifyOptions.X509Roots on the returned value (for example with
// object.LoadX509RootsFile), or leave it nil to use the system verifier pool.
func VerifyOptionsFromConfig(cfg *config.Config) (*object.VerifyOptions, error) {
	opts := &object.VerifyOptions{}
	if cfg == nil {
		return opts, nil
	}

	if allowedSignersFile := cfg.GPG.SSH.AllowedSignersFile; allowedSignersFile != "" {
		path, err := pathutil.ReplaceTildeWithHome(allowedSignersFile)
		if err != nil {
			return nil, err
		}
		signers, err := object.LoadAllowedSignersFile(path)
		if err != nil {
			return nil, err
		}
		opts.SSHAllowedSigners = signers
	}

	return opts, nil
}
