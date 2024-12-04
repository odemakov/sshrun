package sshrun

import (
	"testing"
	"time"
)

func TestPrepareSSHConfig(t *testing.T) {
	defaultConfig := &RunConfig{
		DefaultPrivateKey: "default_private_key",
		DefaultPassword:   "default_password",
		LogLevel:          DefaultLogLevel,
	}

	pool := NewPool(defaultConfig)

	tests := []struct {
		name     string
		input    *SSHConfig
		expected *SSHConfig
	}{
		{
			name: "Default values",
			input: &SSHConfig{
				User: "user",
				Host: "host",
			},
			expected: &SSHConfig{
				User:       "user",
				Host:       "host",
				Port:       DefaultPort,
				Password:   "default_password",
				PrivateKey: "default_private_key",
				Timeout:    DefaultTimeout,
			},
		},
		{
			name: "Custom values",
			input: &SSHConfig{
				User:       "user",
				Host:       "host",
				Port:       2222,
				Password:   "custom_password",
				PrivateKey: "custom_private_key",
				Timeout:    20 * time.Second,
			},
			expected: &SSHConfig{
				User:       "user",
				Host:       "host",
				Port:       2222,
				Password:   "custom_password",
				PrivateKey: "custom_private_key",
				Timeout:    20 * time.Second,
			},
		},
		{
			name: "Partial custom values",
			input: &SSHConfig{
				User: "user",
				Host: "host",
				Port: 2222,
			},
			expected: &SSHConfig{
				User:       "user",
				Host:       "host",
				Port:       2222,
				Password:   "default_password",
				PrivateKey: "default_private_key",
				Timeout:    DefaultTimeout,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool.prepareSSHConfig(tt.input)
			if tt.input.Port != tt.expected.Port {
				t.Errorf("expected Port %d, got %d", tt.expected.Port, tt.input.Port)
			}
			if tt.input.Password != tt.expected.Password {
				t.Errorf("expected Password %s, got %s", tt.expected.Password, tt.input.Password)
			}
			if tt.input.PrivateKey != tt.expected.PrivateKey {
				t.Errorf("expected PrivateKey %s, got %s", tt.expected.PrivateKey, tt.input.PrivateKey)
			}
			if tt.input.Timeout != tt.expected.Timeout {
				t.Errorf("expected Timeout %s, got %s", tt.expected.Timeout, tt.input.Timeout)
			}
		})
	}
}
