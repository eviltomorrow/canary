package cmd

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/eviltomorrow/canary/internal/certificate"
	"github.com/eviltomorrow/canary/pkg/system"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Init canary cert",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		if err := cfg.Load(path, nil); err != nil {
			log.Fatalf("[Fatal] Load config failure, nest error: %v\r\n", err)
		}
		if err := os.MkdirAll(filepath.Join(cfg.System.RootDir, "certs"), 0755); err != nil {
			log.Fatalf("[Fatal] Create certs path failure, nest error: %v\r\n", err)
		}
		if isServer {
			if err := loadAndCreateCertificate(true, filepath.Join(cfg.System.RootDir, "certs"), "ca"); err != nil {
				log.Fatalf("[Fatal] Create ca certificate failure, nest error: %v\r\n", err)
			}
			fmt.Printf("[OK] Create ca cert/key success!\r\n")

			if err := loadAndCreateCertificate(false, filepath.Join(cfg.System.RootDir, "certs"), "server"); err != nil {
				log.Fatalf("[Fatal] Create server certificate failure, nest error: %v\r\n", err)
			}
			fmt.Printf("[OK] Create server cert/key success!\r\n")

		} else {
			if err := loadAndCreateCertificate(false, filepath.Join(cfg.System.RootDir, "certs"), "client"); err != nil {
				log.Fatalf("[Fatal] Create client certificate failure, nest error: %v\r\n", err)
			}
			fmt.Printf("[OK] Create client cert/key success!\r\n")
		}
	},
}

func init() {
	initCmd.Flags().StringVarP(&path, "config", "c", "config.toml", "Canary's config file")
	ctlCmd.AddCommand(initCmd)
	serverCmd.AddCommand(initCmd)
}

func loadAndCreateCertificate(isCA bool, certsDir, name string) error {
	findFile := func(path string) error {
		fi, err := os.Stat(path)
		if err != nil {
			return err
		}
		if fi.IsDir() {
			return fmt.Errorf("panic: path is a folder, nest path: %v", path)
		}
		return nil
	}

	var exist = true
	for _, path := range []string{filepath.Join(certsDir, fmt.Sprintf("%s.crt", name)), filepath.Join(certsDir, fmt.Sprintf("%s.pem", name))} {
		err := findFile(path)
		if err == nil {
			continue
		}
		if os.IsNotExist(err) {
			exist = false
			break
		}
		return err
	}

	if !exist {
		var (
			caCert *x509.Certificate
			caKey  *rsa.PrivateKey
			err    error
		)
		if !isCA {
			caCert, err = certificate.ReadCertificate(filepath.Join(certsDir, "ca.crt"))
			if err != nil {
				return err
			}
			caKey, err = certificate.ReadPKCS1PrivateKey(filepath.Join(certsDir, "ca.pem"))
			if err != nil {
				return err
			}
		}

		key, cert, err := certificate.GenerateCertificate(caKey, caCert, 2048, &certificate.ApplicationInformation{
			CertificateConfig: &certificate.CertificateConfig{
				IsCA: isCA,
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
			OrganizationUnitName: "Developer",
		})
		if err != nil {
			return err
		}
		if err := certificate.WriteCertificate(filepath.Join(certsDir, fmt.Sprintf("%s.crt", name)), cert); err != nil {
			return err
		}
		if err := certificate.WritePKCS1PrivateKey(filepath.Join(certsDir, fmt.Sprintf("%s.pem", name)), key); err != nil {
			return err
		}
	}
	return nil
}
