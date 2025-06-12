//go:build windows

package systeminfo

import (
	"fmt"

	"golang.org/x/sys/windows"
)

func getDiskInfo() string {
	var freeBytesAvailable, totalBytes, totalFreeBytes uint64
	h := windows.StringToUTF16Ptr("C:\\")
	windows.GetDiskFreeSpaceEx(h, &freeBytesAvailable, &totalBytes, &totalFreeBytes)

	total := float64(totalBytes) / 1024 / 1024 / 1024
	free := float64(totalFreeBytes) / 1024 / 1024 / 1024
	used := total - free

	return fmt.Sprintf("Total: %.2f GB, Used: %.2f GB, Free: %.2f GB", total, used, free)
}
