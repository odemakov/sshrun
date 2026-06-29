package sshrun

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const (
	DefaultPort     = 22
	DefaultTimeout  = 10 * time.Second
	DefaultLogLevel = slog.LevelError
)

type RunConfig struct {
	DefaultPrivateKey string
	DefaultPassword   string
	LogLevel          slog.Level
	HostKeyCallback   ssh.HostKeyCallback
}

type SSHConfig struct {
	User       string
	Host       string
	Port       int
	Password   string
	PrivateKey string
	Timeout    time.Duration
}

type Pool struct {
	config  *RunConfig
	connMap map[string]*ssh.Client
	lock    sync.Mutex
}

func NewPool(config *RunConfig) *Pool {
	logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: func() slog.Level {
			if config.LogLevel != 0 {
				return config.LogLevel
			}
			return DefaultLogLevel
		}(),
	}))
	return &Pool{
		config:  config,
		connMap: make(map[string]*ssh.Client),
	}
}

// SSHError represents an error related to SSH operations.
type SSHError struct {
	Msg string
}

func (e *SSHError) Error() string {
	return e.Msg
}

// CommandError represents an error that occurred during command execution.
type CommandError struct {
	Msg string
}

func (e *CommandError) Error() string {
	return e.Msg
}

var logger = slog.Default()

// RunCombined: execute the command, return combined stdout and stderr to the callback function
func (p *Pool) RunCombined(sshCfg *SSHConfig, cmd string, callback func(string)) (int, error) {
	return p.Run(sshCfg, cmd, func(stdout string) {
		callback(stdout)
	}, func(stderr string) {
		callback(stderr)
	})
}

// RunCombinedContext: execute the command with context support for cancellation
func (p *Pool) RunCombinedContext(ctx context.Context, sshCfg *SSHConfig, cmd string, callback func(string)) (int, error) {
	return p.RunContext(ctx, sshCfg, cmd, func(stdout string) {
		callback(stdout)
	}, func(stderr string) {
		callback(stderr)
	})
}

// RunContext: execute the command with context support, return stdout and stderr to the callback functions
func (p *Pool) RunContext(ctx context.Context, sshCfg *SSHConfig, cmd string, stdoutCallback func(string), stderrCallback func(string)) (int, error) {
	if stdoutCallback == nil && stderrCallback == nil {
		return 0, &CommandError{Msg: "Both stdoutCallback and stderrCallback are nil"}
	}
	p.prepareSSHConfig(sshCfg)
	client, err := p.getSession(sshCfg)
	if err != nil {
		return 0, &SSHError{Msg: err.Error()}
	}
	session, err := client.NewSession()
	if err != nil {
		return 0, &SSHError{Msg: err.Error()}
	}
	defer func() { _ = session.Close() }()

	stdoutChan, stderrChan, err := p.setupPipes(session)
	if err != nil {
		return 0, err
	}

	err = session.Start(cmd)
	if err != nil {
		return 0, &SSHError{Msg: err.Error()}
	}

	// Watch for context cancellation
	cancelled := make(chan struct{})
	var closeOnce sync.Once
	closeCancelled := func() {
		closeOnce.Do(func() { close(cancelled) })
	}

	go func() {
		select {
		case <-ctx.Done():
			logger.Debug("Context cancelled, terminating session")
			_ = session.Signal(ssh.SIGINT)
			_ = session.Close()
			closeCancelled()
		case <-cancelled:
			// Session completed normally
		}
	}()

	wg := &sync.WaitGroup{}
	wg.Add(2)

	go p.readChannel(stdoutChan, stdoutCallback, wg)
	go p.readChannel(stderrChan, stderrCallback, wg)

	wg.Wait()

	// Check if context was cancelled
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
		closeCancelled()
	}

	return p.waitForSession(session)
}

// Run: execute the command, return stdout and stderr to the callback functions
func (p *Pool) Run(sshCfg *SSHConfig, cmd string, stdoutCallback func(string), stderrCallback func(string)) (int, error) {
	return p.RunContext(context.Background(), sshCfg, cmd, stdoutCallback, stderrCallback)
}

func (p *Pool) prepareSSHConfig(sshCfg *SSHConfig) {
	if sshCfg.Port == 0 {
		sshCfg.Port = DefaultPort
	}
	if sshCfg.Timeout == 0 {
		sshCfg.Timeout = DefaultTimeout
	}
	if sshCfg.PrivateKey == "" {
		sshCfg.PrivateKey = p.config.DefaultPrivateKey
	}
	if sshCfg.Password == "" {
		sshCfg.Password = p.config.DefaultPassword
	}
}

func (p *Pool) setupPipes(session *ssh.Session) (chan string, chan string, error) {
	stdoutPipe, err := session.StdoutPipe()
	if err != nil {
		return nil, nil, &SSHError{Msg: err.Error()}
	}
	stderrPipe, err := session.StderrPipe()
	if err != nil {
		return nil, nil, &SSHError{Msg: err.Error()}
	}

	stdoutChan := make(chan string, 100)
	stderrChan := make(chan string, 100)

	go func() {
		scanner := bufio.NewScanner(stdoutPipe)
		for scanner.Scan() {
			stdoutChan <- scanner.Text()
		}
		close(stdoutChan)
	}()

	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			stderrChan <- scanner.Text()
		}
		close(stderrChan)
	}()

	return stdoutChan, stderrChan, nil
}

func (p *Pool) readChannel(ch chan string, callback func(string), wg *sync.WaitGroup) {
	defer wg.Done()
	for line := range ch {
		if callback != nil {
			callback(line + "\n")
		}
	}
}

func (p *Pool) waitForSession(session *ssh.Session) (int, error) {
	err := session.Wait()
	exitCode := 0
	if err != nil {
		if exitError, ok := err.(*ssh.ExitError); ok {
			exitCode = exitError.ExitStatus()
			return exitCode, &CommandError{Msg: err.Error()}
		}
		return 0, &SSHError{Msg: err.Error()}
	}
	return exitCode, nil
}

// Put: releases a client connection
func (p *Pool) Put(cfg *SSHConfig) {
	p.prepareSSHConfig(cfg)
	key := connKey(cfg)
	p.lock.Lock()
	defer p.lock.Unlock()

	logger.Debug("Releasing connection", "key", key)
	if client, exists := p.connMap[key]; exists {
		logger.Debug("Connection released", "key", key)
		_ = client.Close()
		delete(p.connMap, key)
	}
}

// ClosePool: closes all connections in the pool
func (p *Pool) ClosePool() {
	p.lock.Lock()
	defer p.lock.Unlock()

	logger.Debug("Closing all connections in the pool")
	for host, client := range p.connMap {
		_ = client.Close()
		delete(p.connMap, host)
		logger.Debug("Closed connection", "host", host)
	}
}

func connKey(cfg *SSHConfig) string {
	return cfg.User + "@" + cfg.Host + ":" + strconv.Itoa(cfg.Port)
}

// getSession: retrieves or establishes an SSH session
func (p *Pool) getSession(sshCfg *SSHConfig) (*ssh.Client, error) {
	key := connKey(sshCfg)
	logger.Debug("Attempting to get connection", "user", sshCfg.User, "host", sshCfg.Host, "port", sshCfg.Port)

	// Check cache without holding lock during dial — holding the mutex across
	// ssh.Dial would block all other node checks while one host is unreachable.
	p.lock.Lock()
	if client, exists := p.connMap[key]; exists {
		p.lock.Unlock()
		logger.Debug("Reusing existing connection", "host", sshCfg.Host)
		return client, nil
	}
	p.lock.Unlock()

	client, err := p.createClient(sshCfg)
	if err != nil {
		return nil, err
	}
	logger.Debug("Created new connection", "user", sshCfg.User, "host", sshCfg.Host, "port", sshCfg.Port)

	// Re-acquire lock to store; handle race where another goroutine connected same host first.
	p.lock.Lock()
	defer p.lock.Unlock()
	if existing, exists := p.connMap[key]; exists {
		_ = client.Close()
		return existing, nil
	}
	p.connMap[key] = client
	return client, nil
}

// createClient: create SSH client
func (p *Pool) createClient(cfg *SSHConfig) (*ssh.Client, error) {
	var authMethod ssh.AuthMethod
	if cfg.PrivateKey != "" {
		privateKeyFile, err := os.ReadFile(cfg.PrivateKey)
		if err != nil {
			return nil, err
		}
		privateKey, err := ssh.ParsePrivateKey(privateKeyFile)
		if err != nil {
			return nil, err
		}
		authMethod = ssh.PublicKeys(privateKey)
	} else {
		authMethod = ssh.Password(cfg.Password)
	}

	hkc := p.config.HostKeyCallback
	if hkc == nil {
		var err error
		hkc, err = knownhosts.New(os.ExpandEnv("$HOME/.ssh/known_hosts"))
		if err != nil {
			return nil, fmt.Errorf("host key verification: %w", err)
		}
	}

	sshConfig := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            []ssh.AuthMethod{authMethod},
		HostKeyCallback: hkc,
	}

	addr := cfg.Host + ":" + strconv.Itoa(cfg.Port)
	logger.Debug("Dialing", "user", sshConfig.User, "host", cfg.Host, "port", cfg.Port, "timeout", cfg.Timeout)

	// Dial TCP with timeout, then apply the same deadline to the SSH handshake.
	// ssh.Dial's Timeout only covers TCP connect; the handshake can hang indefinitely.
	conn, err := net.DialTimeout("tcp", addr, cfg.Timeout)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(cfg.Timeout)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, sshConfig)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = c.Close()
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}
