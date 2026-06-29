package sshrun

import (
	"net"
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

// hangingServer starts a TCP listener that accepts connections but never writes,
// simulating a host where TCP connects but the SSH handshake never completes.
func hangingServer(t *testing.T, addr string) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() { time.Sleep(10 * time.Second); conn.Close() }()
		}
	}()
	return l
}

// TestHandshakeTimeout verifies that createClient respects Timeout for the SSH
// handshake, not just the TCP connect. Without the deadline fix, a server that
// accepts TCP but never sends a banner causes ssh.Dial to hang indefinitely.
func TestHandshakeTimeout(t *testing.T) {
	l := hangingServer(t, "127.0.0.1:0")
	defer l.Close()

	timeout := 200 * time.Millisecond
	pool := NewPool(&RunConfig{})
	cfg := &SSHConfig{
		User:     "user",
		Host:     "127.0.0.1",
		Port:     l.Addr().(*net.TCPAddr).Port,
		Password: "pass",
		Timeout:  timeout,
	}

	start := time.Now()
	_, err := pool.createClient(cfg)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error from hanging SSH server, got nil")
	}
	if elapsed > 2*timeout {
		t.Errorf("createClient took %v; expected < %v — SSH handshake deadline not applied", elapsed, 2*timeout)
	}
}

// TestConcurrentDialsRunInParallel verifies that concurrent getSession calls for
// different hosts are not serialized by the global mutex. Previously, the mutex
// was held across ssh.Dial, so one unreachable host would block all others until
// its TCP timeout expired — causing context deadline exceeded on healthy hosts.
func TestConcurrentDialsRunInParallel(t *testing.T) {
	l1 := hangingServer(t, "127.0.0.1:0")
	defer l1.Close()

	l2, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skip("127.0.0.2 not available on this system")
	}
	defer l2.Close()
	go func() {
		for {
			conn, err := l2.Accept()
			if err != nil {
				return
			}
			go func() { time.Sleep(10 * time.Second); conn.Close() }()
		}
	}()

	timeout := 300 * time.Millisecond
	pool := NewPool(&RunConfig{})

	cfg1 := &SSHConfig{
		User: "user", Host: "127.0.0.1", Port: l1.Addr().(*net.TCPAddr).Port,
		Password: "pass", Timeout: timeout,
	}
	cfg2 := &SSHConfig{
		User: "user", Host: "127.0.0.2", Port: l2.Addr().(*net.TCPAddr).Port,
		Password: "pass", Timeout: timeout,
	}

	errCh := make(chan error, 2)
	start := time.Now()

	go func() {
		pool.prepareSSHConfig(cfg1)
		_, err := pool.getSession(cfg1)
		errCh <- err
	}()
	go func() {
		pool.prepareSSHConfig(cfg2)
		_, err := pool.getSession(cfg2)
		errCh <- err
	}()

	<-errCh
	<-errCh
	elapsed := time.Since(start)

	// Parallel: both complete in ~timeout. Serial (old mutex bug): ~2*timeout.
	if elapsed > timeout+timeout/2 {
		t.Errorf("concurrent dials took %v; expected < %v — mutex likely serialized them", elapsed, timeout+timeout/2)
	}
}
