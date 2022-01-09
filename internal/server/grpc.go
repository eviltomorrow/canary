package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"path/filepath"

	"github.com/eviltomorrow/canary/pkg/middleware"
	"github.com/eviltomorrow/canary/pkg/pb"
	"github.com/eviltomorrow/canary/pkg/system"
	"github.com/eviltomorrow/canary/pkg/zlog"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
	"google.golang.org/protobuf/types/known/emptypb"
)

var (
	Host     string
	Port     int
	CertsDir string

	server *grpc.Server
)

type GRPC struct {
	pb.UnimplementedSystemServer
}

func (g *GRPC) Version(ctx context.Context, _ *emptypb.Empty) (*pb.VersionResponse, error) {
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

func (g *GRPC) Info(ctx context.Context, _ *emptypb.Empty) (*pb.InfoResponse, error) {
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

func StartupGRPC() error {
	cert, err := tls.LoadX509KeyPair(filepath.Join(CertsDir, "server.crt"), filepath.Join(CertsDir, "server.pem"))
	if err != nil {
		return err
	}
	certPool := x509.NewCertPool()
	ca, err := ioutil.ReadFile(filepath.Join(CertsDir, "ca.crt"))
	if err != nil {
		return err
	}

	if ok := certPool.AppendCertsFromPEM(ca); !ok {
		return fmt.Errorf("panic: append certs from PEM failure")
	}

	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		},
	})
	listen, err := net.Listen("tcp", fmt.Sprintf("%s:%d", Host, Port))
	if err != nil {
		return err
	}

	server = grpc.NewServer(
		grpc.Creds(creds),
		grpc.ChainUnaryInterceptor(
			middleware.UnaryServerRecoveryInterceptor,
			middleware.UnaryServerLogInterceptor,
		),
		grpc.ChainStreamInterceptor(
			middleware.StreamServerRecoveryInterceptor,
			middleware.StreamServerLogInterceptor,
		),
	)
	reflection.Register(server)
	pb.RegisterSystemServer(server, &GRPC{})

	go func() {
		if err := server.Serve(listen); err != nil {
			zlog.Fatal("GRPC Server startup failure", zap.Error(err))
		}
	}()
	return nil
}

func ShutdownGRPC() error {
	if server == nil {
		return nil
	}
	server.Stop()
	return nil
}
