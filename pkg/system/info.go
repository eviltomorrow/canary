package system

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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
	var err error
	Pwd, err = filepath.Abs(".")
	if err != nil {
		panic(fmt.Errorf("get curent folder failure, nest error: %v", err))
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
