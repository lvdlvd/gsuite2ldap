package main

import (
	"crypto/tls"
	"fmt"
	"log"
)

// localhostCert is a PEM-encoded TLS cert with SAN DNS names
// "127.0.0.1" and "[::1]", expiring at the last second of 2049 (the end
// of ASN.1 time).
var localhostCert = []byte(`-----BEGIN CERTIFICATE-----
MIIBOTCB5qADAgECAgEAMAsGCSqGSIb3DQEBBTAAMB4XDTcwMDEwMTAwMDAwMFoX
DTQ5MTIzMTIzNTk1OVowADBaMAsGCSqGSIb3DQEBAQNLADBIAkEAsuA5mAFMj6Q7
qoBzcvKzIq4kzuT5epSp2AkcQfyBHm7K13Ws7u+0b5Vb9gqTf5cAiIKcrtrXVqkL
8i1UQF6AzwIDAQABo08wTTAOBgNVHQ8BAf8EBAMCACQwDQYDVR0OBAYEBAECAwQw
DwYDVR0jBAgwBoAEAQIDBDAbBgNVHREEFDASggkxMjcuMC4wLjGCBVs6OjFdMAsG
CSqGSIb3DQEBBQNBAJH30zjLWRztrWpOCgJL8RQWLaKzhK79pVhAx6q/3NrF16C7
+l1BRZstTwIGdoGId8BRpErK1TXkniFb95ZMynM=
-----END CERTIFICATE-----
`)

// localhostKey is the private key for localhostCert.
var localhostKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIBPQIBAAJBALLgOZgBTI+kO6qAc3LysyKuJM7k+XqUqdgJHEH8gR5uytd1rO7v
tG+VW/YKk3+XAIiCnK7a11apC/ItVEBegM8CAwEAAQJBAI5sxq7naeR9ahyqRkJi
SIv2iMxLuPEHaezf5CYOPWjSjBPyVhyRevkhtqEjF/WkgL7C2nWpYHsUcBDBQVF0
3KECIQDtEGB2ulnkZAahl3WuJziXGLB+p8Wgx7wzSM6bHu1c6QIhAMEp++CaS+SJ
/TrU0zwY/fW4SvQeb49BPZUF3oqR8Xz3AiEA1rAJHBzBgdOQKdE3ksMUPcnvNJSN
poCcELmz2clVXtkCIQCLytuLV38XHToTipR4yMl6O+6arzAjZ56uq7m7ZRV0TwIh
AM65XAOw8Dsg9Kq78aYXiOEDc5DL0sbFUu/SlmRcCg93
-----END RSA PRIVATE KEY-----
`)

func handleStartTLS(w ldap.ResponseWriter, m *ldap.Message) {
	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		log.Fatal(err)
	}

	tlsconfig := &tls.Config{
		MinVersion:   tls.VersionSSL30,
		MaxVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ServerName:   "127.0.0.1",
	}
	tlsConn := tls.Server(m.Client.GetConn(), tlsconfig)
	res := ldap.NewExtendedResponse(ldap.LDAPResultSuccess)
	res.SetResponseName(ldap.NoticeOfStartTLS)
	w.Write(res)

	if err := tlsConn.Handshake(); err != nil {
		log.Printf("StartTLS Handshake error %v", err)
		res.SetDiagnosticMessage(fmt.Sprintf("StartTLS Handshake error : \"%s\"", err.Error()))
		res.SetResultCode(ldap.LDAPResultOperationsError)
		w.Write(res)
		return
	}

	m.Client.SetConn(tlsConn)
	log.Println("StartTLS OK")
}
