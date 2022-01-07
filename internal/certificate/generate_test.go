package certificate

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var (
	testCertsPath = "../../tests/certs"
)

func TestGenCA(t *testing.T) {
	_assert := assert.New(t)
	var appInfo = &ApplicationInformation{
		CertificateConfig: &CertificateConfig{
			IsCA:           true,
			ExpirationTime: 24 * time.Hour,
		},
		CommonName:           "www.roigo.top",
		CountryName:          "BeiJing",
		ProvinceName:         "BeiJing",
		LocalityName:         "BeiJing",
		OrganizationName:     "roigo",
		OrganizationUnitName: "developer",
	}

	privKey, cert, err := GenerateCertificate(nil, nil, 2048, appInfo)
	_assert.Nil(err)

	err = WritePKCS1PrivateKey(filepath.Join(testCertsPath, "ca.pem"), privKey)
	_assert.Nil(err)

	err = WriteCertificate(filepath.Join(testCertsPath, "ca.crt"), cert)
	_assert.Nil(err)
}

func TestGenServer(t *testing.T) {
	_assert := assert.New(t)

	caCert, err := ReadCertificate(filepath.Join(testCertsPath, "ca.crt"))
	_assert.Nil(err)

	caKey, err := ReadPKCS1PrivateKey(filepath.Join(testCertsPath, "ca.pem"))
	_assert.Nil(err)

	var appInfo = &ApplicationInformation{
		CertificateConfig: &CertificateConfig{
			IsCA:           false,
			ExpirationTime: 24 * time.Hour,
		},
		CommonName:           "www.roigo.top",
		CountryName:          "BeiJing",
		ProvinceName:         "BeiJing",
		LocalityName:         "BeiJing",
		OrganizationName:     "roigo",
		OrganizationUnitName: "developer",
	}

	serverKey, serverCert, err := GenerateCertificate(caKey, caCert, 2048, appInfo)
	_assert.Nil(err)

	err = WritePKCS1PrivateKey(filepath.Join(testCertsPath, "server.pem"), serverKey)
	_assert.Nil(err)

	err = WriteCertificate(filepath.Join(testCertsPath, "server.crt"), serverCert)
	_assert.Nil(err)
}

func TestGenClient(t *testing.T) {
	_assert := assert.New(t)

	caCert, err := ReadCertificate(filepath.Join(testCertsPath, "ca.crt"))
	_assert.Nil(err)

	caKey, err := ReadPKCS1PrivateKey(filepath.Join(testCertsPath, "ca.pem"))
	_assert.Nil(err)

	var appInfo = &ApplicationInformation{
		CertificateConfig: &CertificateConfig{
			IsCA:           false,
			ExpirationTime: 24 * time.Hour,
		},
		CommonName:           "www.roigo.top",
		CountryName:          "BeiJing",
		ProvinceName:         "BeiJing",
		LocalityName:         "BeiJing",
		OrganizationName:     "roigo",
		OrganizationUnitName: "developer",
	}

	clientKey, clientCert, err := GenerateCertificate(caKey, caCert, 2048, appInfo)
	_assert.Nil(err)

	err = WritePKCS1PrivateKey(filepath.Join(testCertsPath, "client.pem"), clientKey)
	_assert.Nil(err)

	err = WriteCertificate(filepath.Join(testCertsPath, "client.crt"), clientCert)
	_assert.Nil(err)
}
