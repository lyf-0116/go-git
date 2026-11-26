//go:build unix

package git

import (
	"os"
	"syscall"
)

func hasOwnershipConcept() bool { return true }

// checkIsCurrentUserOwner reports whether path is owned by the effective
// user of the process, comparing its stat uid with geteuid(2).
func checkIsCurrentUserOwner(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false, nil
	}

	return int(stat.Uid) == os.Geteuid(), nil
}
