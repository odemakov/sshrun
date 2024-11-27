package sshrun

import (
	"bufio"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	DefaultPort     = 22
	DefaultTimeout  = 10 * time.Second
	DefaultLogLevel = slog.LevelError
)

type RunConfig struct {
	PrivateKey string
	Password   string
	LogLevel   slog.Level
}

type SSHConfig struct {
	User		string
	Host		string
	Port		int
	Password	string
	PrivateKey  string
	Timeout     time.Duration
}

type Pool struct {
	config  *RunConfig
	connMap map[string]*ssh.Client
	lock	sync.Mutex
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

// Run: execute the command, return stdout and stderr to the callback functions
func (p *Pool) Run(sshCfg *SSHConfig, cmd string, stdoutCallback func(string), stderrCallback func(string)) (int, error) {
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
	defer session.Close()

	stdoutChan, stderrChan, err := p.setupPipes(session)
	if err != nil {
		return 0, err
	}

	err = session.Start(cmd)
	if err != nil {
		return 0, &SSHError{Msg: err.Error()}
	}

	wg := &sync.WaitGroup{}
	wg.Add(2)

	go p.readChannel(stdoutChan, stdoutCallback, wg)
	go p.readChannel(stderrChan, stderrCallback, wg)

	wg.Wait() // Ensure all output has been processed before proceeding.

	return p.waitForSession(session)
}

func (p *Pool) prepareSSHConfig(sshCfg *SSHConfig) {
	if sshCfg.Port == 0 {
		sshCfg.Port = DefaultPort
	}
	if sshCfg.Timeout == 0 {
		sshCfg.Timeout = DefaultTimeout
	}
	if sshCfg.PrivateKey == "" {
		sshCfg.PrivateKey = p.config.PrivateKey
	}
	if sshCfg.Password == "" {
		sshCfg.Password = p.config.Password
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
func (p *Pool) Put(host string) {
	p.lock.Lock()
	defer p.lock.Unlock()

	logger.Debug("Releasing connection", "host", host)
	if client, exists := p.connMap[host]; exists {
		logger.Debug("Connection released", "host", host)
		client.Close()
		delete(p.connMap, host)
	}
}

// ClosePool: closes all connections in the pool
func (p *Pool) ClosePool() {
	p.lock.Lock()
	defer p.lock.Unlock()

	logger.Debug("Closing all connections in the pool")
	for host, client := range p.connMap {
		client.Close()
		delete(p.connMap, host)
		logger.Debug("Closed connection", "host", host)
	}
}

// getSession: retrieves or establishes an SSH session
func (p *Pool) getSession(sshCfg *SSHConfig) (*ssh.Client, error) {
	p.lock.Lock()
	defer p.lock.Unlock()

	logger.Debug("Attempting to get connection", "user", sshCfg.User, "host", sshCfg.Host, "port", sshCfg.Port)

	// Check if a connection to the host exists
	if client, exists := p.connMap[sshCfg.Host]; exists {
		logger.Debug("Reusing existing connection", "host", sshCfg.Host)
		return client, nil
	}

	// Create a new SSH client
	client, err := p.createClient(sshCfg)
	if err == nil {
		logger.Debug("Created new connection", "user", sshCfg.User, "host", sshCfg.Host, "port", sshCfg.Port)
		p.connMap[sshCfg.Host] = client
		return client, nil
	} else {
		return nil, err
	}
}

// CreateClient: create SSH client
func (p *Pool) createClient(cfg *SSHConfig) (*ssh.Client, error) {
	var authMethod ssh.AuthMethod
	if cfg.PrivateKey != "" {
		// open file
		privateKeyFile, err := os.ReadFile(cfg.PrivateKey)
		if err != nil {
			return nil, err
		}
		// read private key
		privateKey, err := ssh.ParsePrivateKey(privateKeyFile)
		if err != nil {
			return nil, err
		}
		authMethod = ssh.PublicKeys(privateKey)
	} else {
		authMethod = ssh.Password(cfg.Password)
	}

	sshConfig := &ssh.ClientConfig{
		User:			cfg.User,
		Auth:			[]ssh.AuthMethod{authMethod},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:		 cfg.Timeout,
	}
	logger.Debug("Dialing", "user", sshConfig.User, "host", cfg.Host, "port", cfg.Port, "timeout", sshConfig.Timeout)
	client, err := ssh.Dial("tcp", cfg.Host+":"+strconv.Itoa(cfg.Port), sshConfig)
	if err != nil {
		return nil, err
	}
	return client, nil
}
