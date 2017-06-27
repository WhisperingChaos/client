package client

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net/http"

	"github.com/WhisperingChaos/config"
	errtype "github.com/WhisperingChaos/printbuf"
)

type TLSclientOpts struct {
	Disable               bool     // trust anybody and send packets in plain text - used for debugging
	EnableManMiddleAttack bool     // implicitly trusts the server's certificate - doesn't check its CA
	RootCAStorePath       []string // client provided root Certificate Authority store.  Use to verify the server's certificate`
	X509CertificatePath   string   // client's certificate derived from its public key and when not self signed, one or more intermediate certificates
	X509KeyPath           string   // client's private key
}

type Opts struct {
	TimeOutInterval config.Duration
}

type ConfigFail struct {
	errtype.T
}

type CertFail struct {
	errtype.T
}

func Config(opts Opts, tlsOpts TLSclientOpts, client *http.Client) (err error) {
	trans := new(http.Transport)
	trans.TLSHandshakeTimeout = opts.TimeOutInterval.Duration
	trans.ResponseHeaderTimeout = opts.TimeOutInterval.Duration
	if !tlsOpts.Disable {
		err = tlsOptsLoad(tlsOpts, trans)
	}
	return
}

/*
// private ---------------------------------------------------------------------
func retryStatusList(resp *resty.Response) (ok bool, err error) {
	retryStatus := map[int]bool{
		404: true,
		408: true,
		429: true,
		500: true,
		503: true,
		504: true,
	}
	_, ok = retryStatus[resp.StatusCode()]
	return
}
*/
func tlsOptsLoad(opts TLSclientOpts, trans *http.Transport) error {
	var certFail CertFail
	var cfg tls.Config

	if cert, err := tls.LoadX509KeyPair(opts.X509CertificatePath, opts.X509KeyPath); err != nil {
		certFail.Sprintln(err.Error())
		return certFail
	} else {
		// provide client connection's certificate chain for consumption by server
		cfg.Certificates = append(cfg.Certificates, cert)
	}
	if len(opts.RootCAStorePath) > 0 {
		// process user supplied root CA to validate server's certificate
		pool := x509.NewCertPool()
		var atLeastOne bool
		for _, rtpth := range opts.RootCAStorePath {
			if caCert, err := ioutil.ReadFile(rtpth); err != nil {
				certFail.Sprintln(err.Error())
				continue
			} else if pool.AppendCertsFromPEM(caCert) {
				atLeastOne = true
			}
		}
		if !atLeastOne {
			certFail.Sprintf("Could not find at least one valid CA for client certificate. Checked following: %v\n", opts.RootCAStorePath)
			return certFail
		}
	}
	if opts.EnableManMiddleAttack {
		//  should only be enabled for debugging with self-signed certificates
		cfg.InsecureSkipVerify = true
	}
	trans.TLSClientConfig = &cfg
	return nil
}
