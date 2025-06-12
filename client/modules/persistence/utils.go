package persistence

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// copyFile, copies a file to another location
func copyFile(src, dst string) error {
	// Create destination directory
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return fmt.Errorf("destination directory creation failed: %v", err)
	}

	// Open source file
	source, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("source file opening failed: %v", err)
	}
	defer source.Close()

	// Create destination file
	destination, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("destination file creation failed: %v", err)
	}
	defer destination.Close()

	// Copy file
	if _, err := io.Copy(destination, source); err != nil {
		return fmt.Errorf("file copying failed: %v", err)
	}

	// Grant execution permission
	if err := os.Chmod(dst, 0755); err != nil {
		return fmt.Errorf("file permission change failed: %v", err)
	}

	return nil
}

// appendToFile, adds content to a file
func appendToFile(filePath, content string) error {
	// Check if file exists
	if !fileExists(filePath) {
		return fmt.Errorf("file not found: %s", filePath)
	}

	// Open file
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	// Check if content already exists
	existingContent, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	if !contains(string(existingContent), content) {
		// Add content
		if _, err := file.WriteString(content); err != nil {
			return err
		}
	}

	return nil
}

// fileExists, checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// contains, checks if a string contains another string
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

// getExecutablePath, returns the path of the running program
func getExecutablePath() string {
	execPath, err := os.Executable()
	if err != nil {
		return os.Args[0]
	}
	return execPath
}
