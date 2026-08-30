//go:build !windows

package smb

import (
	"fmt"

	"github.com/medianexapp/go-smb2"
)

func newSSPIKrb5Initiator(targetSPN string) (smb2.Initiator, error) {
	return nil, fmt.Errorf("implicit Windows authentication is only supported on Windows")
}
