//go:build !unix && !windows

package git

// Platforms without a multi-user file ownership model (Plan 9, js, wasip1
// and others) have no dubious-ownership condition to detect, mirroring git
// which only implements the check on POSIX and Windows.

func hasOwnershipConcept() bool { return false }

func checkIsCurrentUserOwner(string) (bool, error) { return true, nil }
