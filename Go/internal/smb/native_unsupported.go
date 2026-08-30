//go:build !windows

package smb

import "fmt"

func (s *SMBSession) canUseNativeWindowsFallback() bool {
	return false
}

func (s *SMBSession) enableNativeWindowsFallback() error {
	return fmt.Errorf("Windows-native SMB fallback is only available on Windows")
}

func (s *SMBSession) closeNativeWindowsFallback() {
}

func (s *SMBSession) listSharesNative() (map[string]ShareInfo, error) {
	return nil, fmt.Errorf("Windows-native SMB fallback is only available on Windows")
}

func (s *SMBSession) listContentsNative(dirPath string) (map[string]FileInfo, error) {
	return nil, fmt.Errorf("Windows-native SMB fallback is only available on Windows")
}

func (s *SMBSession) getFileSecurityDescriptorNative(filePath string) ([]byte, error) {
	return nil, fmt.Errorf("Windows-native SMB fallback is only available on Windows")
}

func (s *SMBSession) getShareRootSecurityDescriptorNative(shareName string) ([]byte, error) {
	return nil, fmt.Errorf("Windows-native SMB fallback is only available on Windows")
}
