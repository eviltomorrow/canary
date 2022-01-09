package cmd

import (
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
	},
}

func init() {
	initCmd.Flags().StringVarP(&path, "config", "c", "config.toml", "Canary's config file")
	serverCmd.AddCommand(initCmd)
}

func loadAndCreateCertficate(isCa bool, certsDir, name string) error {
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
		caCert, err := certificate.ReadCertificate(filepath.Join(certsDir, "ca.crt"))
		if err != nil {
			return err
		}
		caKey, err := certificate.ReadPKCS1PrivateKey(filepath.Join(certsDir, "ca.pem"))
		if err != nil {
			return err
		}
	}
	return nil
}

func createCertficateCS(name string) error {
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
