package restyc

import (
	"crypto/tls"

	"github.com/WhisperingChaos/config"

	resty "gopkg.in/resty.v0"
)

type TLSclientOpts struct {
	Disable               bool     // trust anybody and send packets in plain text - used for debugging
	EnableManMiddleAttack bool     // implicitly trusts the server's certificate - doesn't check its CA
	RootCAStorePath       []string // client provided root Certificate Authority store.  Use to verify the server's certificate`
	X509CertificatePath   string   // client's certificate derived from its public key and when not self signed, one or more intermediate certificates
	X509KeyPath           string   // client's private key
}

type Opts struct {
	RootURL         string
	TimeOutInterval config.Duration
	RetryCount      uint8
	TLSclient       TLSclientOpts
}

func Config(opts Opts) (client *resty.Client) {
	client = resty.New()
	//client.SetDebug(true)
	client.AddRetryCondition(retryStatusList).
		SetRESTMode().
		SetTimeout(opts.TimeOutInterval.Duration).
		SetRetryCount(int(uint(opts.RetryCount)))

	if !opts.TLSclient.Disable {
		tlsOptsLoad(opts.TLSclient, client)
	}
	return
}

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

func tlsOptsLoad(opts TLSclientOpts, client *resty.Client) {
	cert, err := tls.LoadX509KeyPair(opts.X509CertificatePath, opts.X509KeyPath)
	if err != nil {
		panic("Certificate load failed: " + err.Error())
	}
	client.SetCertificates(cert)
	for _, rtpth := range opts.RootCAStorePath {
		client.SetRootCertificate(rtpth)
	}
	if opts.EnableManMiddleAttack {
		//  should only be disabled for debugging with self-signed certificates
		client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	}
}
