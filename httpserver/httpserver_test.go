package httpserver

// audit-snitch-server - Monitor admins actions on servers
// Copyright (C) 2017  Exosite
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

import (
	"testing"
	"encoding/base64"
	"crypto/x509"
)

func TestSign(t *testing.T) {
	apiKey, err := base64.StdEncoding.DecodeString("")
	if err != nil {
		t.Fatal(err.Error())
	}
	privateKey, _, err := ecKeyFromPem([]byte(`-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDCxCmdVA7alnAjegR7BrvZLfHsm70n7D13VnITyEIJ2CyV5QBpdgjl5
3cWq5LVqaEygBwYFK4EEACKhZANiAAQGOgKnkt+WwWsKOcmxg+GXpgKgyaNsqRSw
yPwWM2scAKB66g55c9eIX3nXqKeTlwGwNLtL8pHKTKTySHh4du77u0JRGm+x1X2P
8xT/9vI/M52ewhXDQAYjcQbZvJ1voHA=
-----END EC PRIVATE KEY-----
`))
	if err != nil {
		t.Fatal(err.Error())
	}
	publicCert, _, err := certFromPem([]byte(`-----BEGIN CERTIFICATE-----
MIICPjCCAcSgAwIBAgIJAMOE1DsXeh8UMAoGCCqGSM49BAMCMF0xCzAJBgNVBAYT
AlVTMRIwEAYDVQQIDAlNaW5uZXNvdGExFDASBgNVBAcMC01pbm5lYXBvbGlzMRAw
DgYDVQQKDAdFeG9zaXRlMRIwEAYDVQQDDAlTbml0Y2ggQ0EwHhcNMTcwNzExMTgz
OTQyWhcNMjcwNzA5MTgzOTQyWjBdMQswCQYDVQQGEwJVUzESMBAGA1UECAwJTWlu
bmVzb3RhMRQwEgYDVQQHDAtNaW5uZWFwb2xpczEQMA4GA1UECgwHRXhvc2l0ZTES
MBAGA1UEAwwJU25pdGNoIENBMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEBjoCp5Lf
lsFrCjnJsYPhl6YCoMmjbKkUsMj8FjNrHACgeuoOeXPXiF9516ink5cBsDS7S/KR
ykyk8kh4eHbu+7tCURpvsdV9j/MU//byPzOdnsIVw0AGI3EG2bydb6Bwo1AwTjAd
BgNVHQ4EFgQUyLYLeL1YfyDeIx3bZM4AcpxvErowHwYDVR0jBBgwFoAUyLYLeL1Y
fyDeIx3bZM4AcpxvErowDAYDVR0TBAUwAwEB/zAKBggqhkjOPQQDAgNoADBlAjBm
xNz84ZkVC2tlrvik827TrmJ5ejqy5vQi65f98XN9bmlcqsLYzQ3CuWdxOrtmltEC
MQDPY8hKfXX5fnTvclrVt5KLP9X2O6lzLDsxgRKCBSp0CI6McGYIbrC+tSFHJiV8
5TM=
-----END CERTIFICATE-----
`))
	if err != nil {
		t.Fatal(err.Error())
	}
	svr := &HttpServer{
		apiKey: apiKey,
		privateKey: privateKey,
		publicCert: publicCert,
	}

	csr, _, err := csrFromPem([]byte(`-----BEGIN CERTIFICATE REQUEST-----
MIIBPTCB5AIBADAVMRMwEQYDVQQDDAp0ZXN0Y2xpZW50MFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAEOxhC49//vzLBKJCPGWprb20GFtmLfDwiGHDb2JwGBj4IPPY/
7P5xUIzw+JL5xUyvFiRVN+mQ+lCQCOAqxoXnBaBtMGsGCSqGSIb3DQEJDjFeMFww
DAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBeAwHQYDVR0OBBYEFC6OMrPFdtrq
TE+Yk9+1tFeSGfJTMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAKBggq
hkjOPQQDAgNIADBFAiB7770LYsG1+Enw82wFSto+IMJgOXfWRjMNI+8Sh/d2TwIh
ALwTke1j2DjQIcNaIYEeqwLhMJfJYEoQF4m1XMVgIsWF
-----END CERTIFICATE REQUEST-----
`))
	if err != nil {
		t.Fatal(err.Error())
	}
	crtBytes, err := svr.createCert(csr)
	if err != nil {
		t.Fatal(err.Error())
	}

	crts, err := x509.ParseCertificates(crtBytes)
	if err != nil {
		t.Fatal(err.Error())
	}

	csrName := csr.Subject
	crtName := crts[0].Subject
	if csrName.CommonName != crtName.CommonName {
		t.Fatal("Expected CN=", csrName.CommonName, ", got ", crtName.CommonName, " instead!")
	}
	if crtName.Country != nil || len(crtName.Country) != 0 {
		t.Fatal("C is not empty!")
	}
	if crtName.Province != nil || len(crtName.Province) != 0 {
		t.Fatal("ST is not empty!")
	}
	if crtName.Locality != nil || len(crtName.Locality) != 0 {
		t.Fatal("L is not empty!")
	}
	if crtName.Organization != nil || len(crtName.Organization) != 0 {
		t.Fatal("O is not empty!")
	}
	if crtName.OrganizationalUnit != nil || len(crtName.OrganizationalUnit) != 0 {
		t.Fatal("OU is not empty!")
	}
}
