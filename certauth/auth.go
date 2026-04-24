package certauth

import (
	"crypto/tls"
	"strings"
)

// HasOU checks if any of the peer certificates have the specified OU.
func HasOU(tlsConnection *tls.ConnectionState, ou string) bool {
	if tlsConnection == nil || len(tlsConnection.PeerCertificates) == 0 {
		return false
	}
	cert := tlsConnection.PeerCertificates[0]
	for _, v := range cert.Subject.OrganizationalUnit {
		if v == ou || strings.Contains(v, ou) {
			return true
		}
	}
	return false
}
