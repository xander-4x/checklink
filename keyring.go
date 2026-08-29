package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/zalando/go-keyring"
	"golang.org/x/term"
)

const keyringService = "checklink"

// resolveSecret looks up a named secret: a real (or .env-loaded)
// environment variable always wins — that's the explicit, visible override.
// If unset, it falls back to whatever was saved in the OS keychain via
// -set-key. Returns "" if neither has it, same as a plain os.Getenv miss.
func resolveSecret(name string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	v, err := keyring.Get(keyringService, name)
	if err != nil {
		return ""
	}
	return v
}

// setKeyInteractive prompts for a secret's value (hidden input on a real
// terminal; a plain line read when stdin is piped) and saves it to the OS
// keychain under keyringService.
func setKeyInteractive(name string) error {
	fmt.Fprintf(os.Stderr, "Enter value for %s: ", name)
	value, err := readSecretLine()
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return err
	}
	if value == "" {
		return fmt.Errorf("empty value, nothing stored")
	}
	if err := keyring.Set(keyringService, name, value); err != nil {
		return fmt.Errorf("could not save to OS keychain: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Saved %s to the OS keychain.\n", name)
	return nil
}

func deleteKey(name string) error {
	if err := keyring.Delete(keyringService, name); err != nil {
		return fmt.Errorf("could not delete %s from OS keychain: %w", name, err)
	}
	fmt.Fprintf(os.Stderr, "Deleted %s from the OS keychain.\n", name)
	return nil
}

func readSecretLine() (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	// stdin isn't a terminal (piped input, e.g. from a script) — nothing to
	// hide from a screen in that case, just read a line.
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimSpace(line), nil
}
