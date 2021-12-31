package system

import "runtime"

var (
	CurrentVersion string
	GoVersion      = runtime.Version()
	GoOSArch       = runtime.GOOS + "/" + runtime.GOARCH
	GitSha         string
	GitTag         string
	GitBranch      string
	BuildTime      string
)
