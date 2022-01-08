package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/eviltomorrow/canary/internal/certificate"
	"github.com/eviltomorrow/canary/pkg/middleware"
	"github.com/eviltomorrow/canary/pkg/zlog"
	"github.com/eviltomorrow/robber-core/pkg/system"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

var (
	Host     string
	Port     int
	CertsDir string

	server *grpc.Server
)

func checkAndCreate() error {
	findFile := func(path string) error {
		fi, err := os.Stat(path)
		if err != nil {
			return err
		}
		if fi.IsDir() {
			return fmt.Errorf("panic: [%s] is a folder", path)
		}
		return nil
	}
	for _, path := range []string{filepath.Join(CertsDir, "ca.crt"), filepath.Join(CertsDir, "ca.pem")} {
		if err := findFile(path); err != nil {
			return err
		}
	}

	var ok = true
	for _, path := range []string{filepath.Join(CertsDir, "server.crt"), filepath.Join(CertsDir, "server.pem")} {
		err := findFile(path)
		if err == nil {
			continue
		}
		if !os.IsNotExist(err) {
			return err
		}
		ok = false
		break
	}
	if !ok {
		caCert, err := certificate.ReadCertificate(filepath.Join(CertsDir, "ca.crt"))
		if err != nil {
			return err
		}
		caKey, err := certificate.ReadPKCS1PrivateKey(filepath.Join(CertsDir, "ca.pem"))
		if err != nil {
			return err
		}

		serverKey, serverCert, err := certificate.GenerateCertificate(caKey, caCert, 2048, &certificate.ApplicationInformation{
			CertificateConfig: &certificate.CertificateConfig{
				IsCA: false,
				IP: []net.IP{
					net.ParseIP(system.IP),
				},
				ExpirationTime: 24 * time.Hour * 365 * 3,
			},
			CommonName:           "www.roigo.top",
			CountryName:          "China",
			ProvinceName:         "BeiJing",
			LocalityName:         "BeiJing",
			OrganizationName:     "Roigo &Inc",
			OrganizationUnitName: "developer",
		})
		if err != nil {
			return err
		}
		if err := certificate.WriteCertificate(filepath.Join(CertsDir, "server.crt"), serverCert); err != nil {
			return err
		}
		if err := certificate.WritePKCS1PrivateKey(filepath.Join(CertsDir, "server.pem"), serverKey); err != nil {
			return err
		}
	}
	return nil
}

func StartupGRPC() error {
	if err := checkAndCreate(); err != nil {
		return err
	}

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
