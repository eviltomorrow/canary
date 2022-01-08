package main

import (
	"github.com/eviltomorrow/canary/pkg/cmd"
	"github.com/eviltomorrow/robber-core/pkg/system"
)

var (
	GitSha      = ""
	GitTag      = ""
	GitBranch   = ""
	BuildTime   = ""
	MainVersion = "v1.0"
)

func setVersion() {
	system.MainVersion = MainVersion
	system.GitSha = GitSha
	system.GitTag = GitTag
	system.GitBranch = GitBranch
	system.BuildTime = BuildTime
}

func main() {
	setVersion()
	cmd.NewServer()
}
