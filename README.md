# sshrun

`sshrun` is a simple package that implements an SSH connection pool, allowing users to run commands concurrently up to the server's SSHD `MaxSessions` limit. It opens a single connection to the host and reuses it for multiple sessions, optimizing resource usage and connection management. The package also provides a debug mode to log detailed debug messages, aiding in troubleshooting and performance monitoring.

## Usage example

```go
package main

import (
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/odemakov/sshrun"
)
func main() {
    // get home directory of current user
    homeDir, err := os.UserHomeDir()
    if err != nil {
        log.Fatalf("Failed to get home directory: %v", err)
    }

    runCfg := &sshrun.RunConfig{
        Debug: false,
        PrivateKey: filepath.Join(homeDir, ".ssh", "id_rsa"),
    }
    sshPool := sshrun.NewPool(runCfg)

    sshCfg := &sshrun.SSHConfig{
        User: "mak",
        Host: "dev-02",
    }

    // exec 15 concurrent commands in go routines
    var wg sync.WaitGroup
    for i := 0; i < 15; i++ {
        wg.Add(1)
        go func(i int) {
            defer wg.Done()
            log.Printf("Running command in goroutine %d", i)
            result, err := sshPool.Run(sshCfg, "uname -a; sleep 1; exit 0")
            if err != nil {
                switch e := err.(type) {
                case *sshrun.SSHError:
                    log.Printf("Goroutine %d - SSH error: %s", i, e.Msg)
                case *sshrun.CommandError:
                    log.Printf("Goroutine %d - Command error: %s", i, e.Msg)
                default:
                    log.Printf("Goroutine %d - Unknown error: %v", i, err)
                }
            } else {
                log.Printf("Goroutine %d - Stdout: %s", i, result.Stdout)
                log.Printf("Goroutine %d - Stderr: %s", i, result.Stderr)
                log.Printf("Goroutine %d - Error code: %d", i, result.ErrorCode)
            }
        }(i)
    }
    wg.Wait()

    sshPool.ClosePool()
}
```
