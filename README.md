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
        DebugLevel: slog.LevelDebug,
        DefaultPrivateKey: filepath.Join(homeDir, ".ssh", "id_rsa"),
    }
    sshPool := sshrun.NewPool(runCfg)

    sshCfg := &sshrun.SSHConfig{
        User: "mak",
        Host: "dev-02",
    }

    // Exec 15 concurrent commands. Default MaxSessions value for the SSHD server is 10, so
    // with 15 workers, 5 of them will fail.
    var wg sync.WaitGroup
    for i := 0; i < 100; i++ {
        log.Printf("Running command in loop %d", i)
        //result, err := sshPool.Run(sshCfg, "for i in {1..100}; do echo $i; sleep 1; done",
        result, err := sshPool.Run(sshCfg, "uptime",
            func(stdout string) {
                log.Printf("Loop %d - Stdout: %s", i, stdout)
            },
            func(stderr string) {
                log.Printf("Loop %d - Stderr: %s", i, stderr)
            })
        if err != nil {
            switch e := err.(type) {
            case *sshrun.SSHError:
                log.Printf("Loop %d - SSH error: %s", i, e.Msg)
            case *sshrun.CommandError:
                log.Printf("Loop %d - Command error: %s", i, e.Msg)
            default:
                log.Printf("Loop %d - Unknown error: %v", i, err)
            }
        } else {
            log.Printf("Loop %d - Error code: %d", i, result)
        }
    }
    wg.Wait()

    sshPool.ClosePool()
}
```
