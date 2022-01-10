package system

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/eviltomorrow/canary/pkg/znet"
	"github.com/eviltomorrow/canary/pkg/ztime"
)

var (
	Pid         = os.Getpid()
	Pwd         string
	LaunchTime  = time.Now()
	HostName    string
	OS          = runtime.GOOS
	Arch        = runtime.GOARCH
	RunningTime = func() string {
		return ztime.FormatDuration(time.Since(LaunchTime))
	}
	IP string
)

func init() {
	path, err := os.Executable()
	if err != nil {
		panic(fmt.Errorf("get execute path failure, nest error: %v", err))
	}
	path = strings.ReplaceAll(path, "bin/canary-server", "")
	path = strings.ReplaceAll(path, "bin/canary-ctl", "")

	Pwd, err = filepath.Abs(path)
	if err != nil {
		panic(fmt.Errorf("get current folder failure, nest error: %v", err))
	}
	HostName, err = os.Hostname()
	if err != nil {
		panic(fmt.Errorf("get host name failure, nest error: %v", err))
	}
	IP, err = znet.GetLocalIP()
	if err != nil {
		panic(fmt.Errorf("get local ip failure, nest error: %v", err))
	}
}
