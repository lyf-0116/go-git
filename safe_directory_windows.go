//go:build windows

package git

import (
	"golang.org/x/sys/windows"
)

func hasOwnershipConcept() bool { return true }

// checkIsCurrentUserOwner reports whether the directory owner SID equals
// the SID of the current process token user. This mirrors git's Windows
// ownership check in mingw's get_path_owner.
func checkIsCurrentUserOwner(path string) (bool, error) {
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
	)
	if err != nil {
		return false, err
	}
	if sd == nil {
		return false, nil
	}

	owner, _, err := sd.Owner()
	if err != nil {
		return false, err
	}

	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false, err
	}

	return windows.EqualSid(owner, tokenUser.User.Sid), nil
}
