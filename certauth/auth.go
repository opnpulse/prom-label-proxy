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

// CertClaims holds the required identity fields parsed from the client certificate's OU fields.
// Expected OU format: "Key=Value" entries, e.g. "ClusterName=hub", "Owner=acme", "EnableTenant=true".
type CertClaims struct {
	ClusterName  string
	Owner        string
	EnableTenant bool
}

// ExtractClaims parses ClusterName, Owner, and EnableTenant from the OU fields of the first
// peer certificate. Returns the claims and true only when all three fields are present.
func ExtractClaims(tlsConn *tls.ConnectionState) (CertClaims, bool) {
	if tlsConn == nil || len(tlsConn.PeerCertificates) == 0 {
		return CertClaims{}, false
	}
	cert := tlsConn.PeerCertificates[0]

	var claims CertClaims
	var hasClusterName, hasOwner, hasEnableTenant bool

	for _, ou := range cert.Subject.OrganizationalUnit {
		k, v, ok := splitKV(ou)
		if !ok {
			continue
		}
		switch k {
		case "ClusterName":
			claims.ClusterName = v
			hasClusterName = true
		case "Owner":
			claims.Owner = v
			hasOwner = true
		case "EnableTenant":
			claims.EnableTenant = strings.EqualFold(v, "true")
			hasEnableTenant = true
		}
	}

	return claims, hasClusterName && hasOwner && hasEnableTenant
}

func splitKV(s string) (key, val string, ok bool) {
	idx := strings.IndexByte(s, '=')
	if idx < 0 {
		return "", "", false
	}
	return s[:idx], s[idx+1:], true
}
