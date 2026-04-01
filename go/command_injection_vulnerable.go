package main

import "os/exec"

// Matches: go-exec-sh
func vulnerableShExec(userInput string) error {
	cmd := exec.Command("sh", "-c", userInput)
	return cmd.Run()
}

// Matches: go-exec-command-userinput
func vulnerableCommand(userInput string) error {
	cmd := exec.Command(userInput, "-la")
	return cmd.Run()
}

// Safe: allowlisted command
func safeCommand(filename string) error {
	cmd := exec.Command("ls", "-la", filename)
	return cmd.Run()
}
