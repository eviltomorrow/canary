package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/eviltomorrow/canary/pkg/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

func WithoutTLS() (credentials.TransportCredentials, error) {
	return insecure.NewCredentials(), nil
}

func WithTLS(hostname string, caCert string, clientKey, clientCert string) (credentials.TransportCredentials, error) {
	certificate, err := tls.LoadX509KeyPair(clientCert, clientKey)
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	ca, err := ioutil.ReadFile(caCert)
	if err != nil {
		return nil, err
	}

	if ok := certPool.AppendCertsFromPEM(ca); !ok {
		return nil, fmt.Errorf("panic: append certs from PEM failure")
	}

	creds := credentials.NewTLS(&tls.Config{
		ServerName:   hostname,
		Certificates: []tls.Certificate{certificate},
		RootCAs:      certPool,
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
	return creds, nil
}

func NewFile(host string, port int, cred credentials.TransportCredentials, timeout time.Duration) (pb.FileClient, func() error, error) {
	conn, err := dial(host, port, cred, timeout)
	if err != nil {
		return nil, nil, err
	}
	return pb.NewFileClient(conn), func() error { return conn.Close() }, nil
}

func NewSystem(host string, port int, cred credentials.TransportCredentials, timeout time.Duration) (pb.SystemClient, func() error, error) {
	conn, err := dial(host, port, cred, timeout)
	if err != nil {
		return nil, nil, err
	}
	return pb.NewSystemClient(conn), func() error { return conn.Close() }, nil
}

func dial(host string, port int, cred credentials.TransportCredentials, timeout time.Duration) (*grpc.ClientConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := grpc.DialContext(
		ctx,
		fmt.Sprintf("%s:%d", host, port),
		grpc.WithBlock(),
		grpc.WithTransportCredentials(cred),
	)
	if err != nil {
		return nil, err
	}
	return conn, nil
}
