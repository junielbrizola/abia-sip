// Copyright 2025 LiveKit, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sip

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
)

func ConfigureTLS(c *tls.Config) {
	// sipgo sets ServerName to the SIP destination host on a cloned outbound
	// config. VerifyConnection can use it to validate both DNS names and IP SANs.
	// Keep this callback on the outbound config only; the listener has its own
	// server-side TLS configuration.
	verifyConnection := c.VerifyConnection
	c.InsecureSkipVerify = true
	c.VerifyPeerCertificate = nil
	c.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("SIP TLS peer did not present a certificate")
		}
		if cs.ServerName == "" {
			return errors.New("SIP TLS destination server name is empty")
		}

		intermediates := x509.NewCertPool()
		for _, cert := range cs.PeerCertificates[1:] {
			intermediates.AddCert(cert)
		}
		opts := x509.VerifyOptions{
			Roots:         c.RootCAs,
			Intermediates: intermediates,
			DNSName:       cs.ServerName,
		}
		if _, err := cs.PeerCertificates[0].Verify(opts); err != nil {
			return err
		}

		if verifyConnection != nil {
			return verifyConnection(cs)
		}
		return nil
	}
}

// defaultALPNProtocols is the default set of ALPN protocols for SIP over TLS.
var defaultALPNProtocols = []string{"sip"}

// tlsALPNProtocols returns the ALPN protocols to use for TLS negotiation.
// If alpn is nil (not configured), it returns the default ["sip"].
// If alpn is non-nil, it returns the configured value (which may be empty to disable ALPN).
func tlsALPNProtocols(alpn []string) []string {
	if alpn == nil {
		return defaultALPNProtocols
	}
	return alpn
}
