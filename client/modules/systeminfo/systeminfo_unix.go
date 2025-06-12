//go:build !windows

package systeminfo

import (
	"fmt"
	"os"
	"syscall"
)

func getDiskInfo() string {
	var stat syscall.Statfs_t
	wd, err := os.Getwd()
	if err != nil {
		return "unknown"
	}

	err = syscall.Statfs(wd, &stat)
	if err != nil {
		return "unknown"
	}

	// Calculate disk sizes in GB
	total := float64(stat.Blocks) * float64(stat.Bsize) / 1024 / 1024 / 1024
	free := float64(stat.Bfree) * float64(stat.Bsize) / 1024 / 1024 / 1024
	used := total - free

	return fmt.Sprintf("Total: %.2f GB, Used: %.2f GB, Free: %.2f GB", total, used, free)
}
