package sshrun

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
    DefaultPort = 22
    DefaultTimeout = 10 * time.Second
)

type RunConfig struct {
    Debug      bool
    PrivateKey string
    Password   string
}

type SSHConfig struct {
    User        string
    Host        string
    Port        int
    Password    string
    PrivateKey  string
    Timeout     time.Duration
}

type Pool struct {
    config  *RunConfig
    connMap map[string]*ssh.Client
    lock    sync.Mutex
}

type Result struct {
    ExitCode int
    Stdout   string
    Stderr   string
}

func NewPool(config *RunConfig) *Pool {
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
    return fmt.Sprintf("SSH error: %s", e.Msg)
}

// CommandError represents an error that occurred during command execution.
type CommandError struct {
    Cmd string
    Msg string
}

func (e *CommandError) Error() string {
    return fmt.Sprintf("Command '%s' execution error: %s", e.Cmd, e.Msg)
}

// Run: execute the command
func (p *Pool) Run(sshCfg *SSHConfig, cmd string) (Result, error) {
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
    client, err := p.get(sshCfg)
    if err != nil {
        return Result{}, &SSHError{Msg: err.Error()}
    }
    session, err := client.NewSession()
    if err != nil {
        return Result{}, &SSHError{Msg: err.Error()}
    }
    defer session.Close()

    // run the command, get stderr, stdout and error_code
    var stdout, stderr bytes.Buffer
    session.Stdout = &stdout
    session.Stderr = &stderr
    exitCode := 0
    err = session.Run(cmd)
    if err != nil {
        if exitError, ok := err.(*ssh.ExitError); ok {
            exitCode = exitError.ExitStatus()
            return Result{ExitCode: exitCode, Stdout: stdout.String(), Stderr: stderr.String()}, &CommandError{Cmd: cmd, Msg: err.Error()}
        }
        return Result{}, &SSHError{Msg: err.Error()}
    }
    return Result{ExitCode: exitCode, Stdout: stdout.String(), Stderr: stderr.String()}, nil
}

// Put: releases a client connection
func (p *Pool) Put(host string) {
    p.lock.Lock()
    defer p.lock.Unlock()

    p.logDebug("Releasing connection for host: %s", host)
    if client, exists := p.connMap[host]; exists {
        p.logDebug("Connection released for host: %s", host)
        client.Close()
        delete(p.connMap, host)
    }
}

// ClosePool: closes all connections in the pool
func (p *Pool) ClosePool() {
    p.lock.Lock()
    defer p.lock.Unlock()

    p.logDebug("Closing all connections in the pool")
    for host, client := range p.connMap {
        client.Close()
        delete(p.connMap, host)
        p.logDebug("Closed connection for host: %s", host)
    }
}

// Get: retrieves or establishes an SSH session
func (p *Pool) get(sshCfg *SSHConfig) (*ssh.Client, error) {
    p.lock.Lock()
    defer p.lock.Unlock()

    p.logDebug("Attempting to get connection %s@%s:%d", sshCfg.User, sshCfg.Host, sshCfg.Port)

    // Check if a connection to the host exists
    if client, exists := p.connMap[sshCfg.Host]; exists {
        p.logDebug("Reusing existing connection for host: %s", sshCfg.Host)
        return client, nil
    }

    // Create a new SSH client
    client, err := p.createClient(sshCfg)
    if err == nil {
        log.Printf("Created new connection %s@%s:%d", sshCfg.User, sshCfg.Host, sshCfg.Port)
        p.connMap[sshCfg.Host] = client
    } else {
        log.Printf("Failed to create connection for host: %s, error: %v", sshCfg.Host, err)
    }
    return client, err
}

// CreateClient: create SSH client
func (p *Pool) createClient(cfg *SSHConfig) (*ssh.Client, error) {
    var authMethod ssh.AuthMethod
    if cfg.PrivateKey != "" {
        // open private key
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
        User: cfg.User,
        Auth: []ssh.AuthMethod{authMethod},
        HostKeyCallback: ssh.InsecureIgnoreHostKey(),
        Timeout: cfg.Timeout,
    }
    p.logDebug("Dialing %s@%s:%d timeout:%v", sshConfig.User, cfg.Host, cfg.Port, sshConfig.Timeout)
    client, err := ssh.Dial("tcp", cfg.Host+":"+strconv.Itoa(cfg.Port), sshConfig)
    if err != nil {
        return nil, err
    }
    return client, nil
}

// logDebug: logs debug messages if debug mode is enabled
func (p *Pool) logDebug(format string, v ...interface{}) {
    if p.config.Debug {
        log.Printf(format, v...)
    }
}
