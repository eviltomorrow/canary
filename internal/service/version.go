package service

import (
	"context"
	"fmt"

	"github.com/eviltomorrow/canary/pkg/pb"
	"github.com/eviltomorrow/canary/pkg/system"
	"google.golang.org/protobuf/types/known/emptypb"
)

type System struct {
	pb.UnimplementedSystemServer
}

func (g *System) Version(ctx context.Context, _ *emptypb.Empty) (*pb.VersionResponse, error) {
	resp := &pb.VersionResponse{
		CurrentVersion: system.CurrentVersion,
		GoVersion:      system.GoVersion,
		GoOsArch:       system.GoOSArch,
		GitSha:         system.GitSha,
		GitTag:         system.GitTag,
		GitBranch:      system.GitBranch,
		BuildTime:      system.BuildTime,
	}
	return resp, nil
}

func (g *System) Info(ctx context.Context, _ *emptypb.Empty) (*pb.InfoResponse, error) {
	resp := &pb.InfoResponse{
		Pid:         fmt.Sprintf("%d", system.Pid),
		Pwd:         system.Pwd,
		LaunchTime:  system.LaunchTime.Format("2006-01-02"),
		Hostname:    system.HostName,
		Os:          system.OS,
		Arch:        system.Arch,
		RunningTime: system.RunningTime(),
		Ip:          system.IP,
	}
	return resp, nil
}
