package client

import (
	"net/http"

	cttp "github.com/WhisperingChaos/client/http"

	dkr "github.com/moby/moby/client"
)

type Opts struct {
	TmOut      cttp.Opts
	TLS        cttp.TLSclientOpts
	RootURL    string
	APIversion string
}

func Config(opts Opts) (cli *dkr.Client, err error) {
	if opts.RootURL != "" {
		// config file overrides env variables
		hClient := new(http.Client)
		if err = cttp.Config(opts.TmOut, opts.TLS, hClient); err != nil {
			return
		}
		var headers map[string]string
		return dkr.NewClient(opts.RootURL, opts.APIversion, hClient, headers)
	}
	return dkr.NewEnvClient()
}
