package oauth

import (
	"fmt"
	"log"
	"time"

	"github.com/WhisperingChaos/errorf"

	"github.com/WhisperingChaos/terminator"

	enttp "github.com/WhisperingChaos/client/restyc"
	resty "gopkg.in/resty.v0"
)

type Opts struct {
	RootURL string
	enttp.Opts
	ClientId     string
	ClientSecret string
}

/*
	Configure and start an Oauth2 http client.
	This client currently manages tokens produced for the "client credential" Oauth2
	grant type. Management includes acquiring an initial token and predicting its
	future experation.  It is hoped prediction will reduce the network latency of http
	requests to a resource server by eliminating the client's token experation failures.

	Prediction attempts to obtain a new token just before the current one
	expires.  The algorithm calculates the time to initiate a future
	new token request by subtracting the average round trip time necessary
	to obtain a token from the token's lifespan.  A countdown
	timer is initialized with this interval and when spent, triggers a request
	addressed to the authentication server to obtain a new token.

	The ability to access the mechanics mentioned above is encapsulated within the
	function: func(force bool) (OauthToken string) returned by Start.  The value of
	"force" should typically be 'false'.  This setting almost always retrieves a valid
	access token, as long as the prediciton successfully forecasts the need for a new
	one.  However, if a client request to its resource server should fail, due to a poor
	prediction or an event that causes an access token to prematurely expire, the client
	can force (force=true) the function to return a newly obtained access toke from the
	the authorization server.
*/
func Start(
	opts Opts, // oauth http connection configuration
	term terminator.Isync, // a means to terminate the oauth client
	ef errorf.Iwrap, // a means to report on errorsi
	debug *log.Logger, // debugging agent
) func(force bool, // true - force token renewal process to aquire new access token, otherwise, use provided value
) (OAuthToken string, // function providing OAuth token
) {
	needToken := make(chan bool)
	provider := make(chan string)
	term.Add(1)
	errf := ef(nil)
	if debug != nil {
		dbg = debug
	}
	go tokenProvide(opts, needToken, provider, term, errf)
	return tokenBroker(needToken, provider, term)
}

/*
	Provide a default access token retry mechanism for a "resty" inspired http client
	that's attempting to communicate with its resource server.

	Since this package's private implementation depends on the "resty" package,
	it's easy to provide a retry function that can be consumed by a "resty"
	encoded client.  The retry code assumes a resource server will issue
	an http status code of 401.
	(see https://tools.ietf.org/html/rfc6749 5.2. Error Response).
*/
func TokenExpiredRetry(tokenRenewal func(force bool) (OAuthToken string)) resty.RetryConditionFunc {
	return func(resp *resty.Response) (ok bool, err error) {
		if resp.StatusCode() == 401 {
			dbg.Println("retry issued due to token experation")
			tokenRenewal(true)
		}
		return true, nil
	}
}

// private ---------------------------------------------------------------------

func tokenProvide(opts Opts, needToken chan bool, provider chan<- string, term terminator.Isync, errf errorf.I) {
	defer term.Done()
	defer dbg.Println("Token refresh goroutine exited")
	defer close(needToken)
	defer close(provider)
	renew := make(chan string, 1) //two goroutines are interacting one generates an input that results in an output feedback reply.  However, the input and output request cannot be same select, otherwise may spin.  Therefore, make output channel buffered to prohibit blocking behavior in goroutine generating output so the requester can transition to a second select statement that then reads this output.
	defer close(renew)
	renewForce := make(chan bool)
	defer close(renewForce)
	renewToken := tokenRenewConfig(opts, renew, renewForce, errf)
	go renewToken()
	var token string
	for term.IsNot() {
		select {
		case force, ok := <-needToken:
			if !ok {
				return
			}
			dbg.Println("token requested")
			for force {
				dbg.Println("force new token")
				select {
				case renewForce <- true:
				case <-term.Chan():
					return
				}
				dbg.Println("waiting for renew")
				select {
				case token = <-renew:
					force = false
					dbg.Println("obtained token from renew channel")
				case <-term.Chan():
					return
				}
			}
			dbg.Println("renew complete")
			select {
			case <-needToken: // discards token requests issued while aquiring the most recent one.  Don't want to spin.
			default:
			}
			dbg.Printf("pushing token: '%s', back to requester\n", token)
			provider <- token
			dbg.Println("requester received token")

		case token = <-renew: // periodic refresh typically before token expires.  Eliminates network lag for future token request.
			dbg.Println("periodic refreshed token:  " + token)
		case <-term.Chan():

		}
	}
}
func tokenRenewConfig(opts Opts, renew chan<- string, renewForce <-chan bool, errf errorf.I) func() {
	return func() {
		defer dbg.Println("token renewal goroutine exited")
		var countDwn *time.Ticker
		countDwnCleanUp := func() {
			countDwn.Stop()
		}
		predictRenewal := predictConfg()
		dbg.Println("token renewal started")
		countDwn = time.NewTicker(48 * time.Hour) // bogus initial timer.  go routine is idle until renewForce causes first Oauth2 token query.
		defer countDwnCleanUp()
		for {
			var open bool
			select {
			case _, open = <-countDwn.C:
			case _, open = <-renewForce:
			}
			if !open {
				return
			}
			countDwnCleanUp()
			dbg.Println("token renewal contact oauth server")
			respAtTime := time.Now()
			if token, expire, err := tokenRenewal(opts); err == nil {
				predictedInterval := predictRenewal(respAtTime, expire)
				dbg.Printf("token renewal predicted interval: %v\n", predictedInterval)
				countDwn = time.NewTicker(predictedInterval)
				dbg.Println("token renewal token: " + token)
				renew <- token
				dbg.Println("token renewal pushed token")
			} else {
				// unable to retrieve new token. set countDwn interval
				// to maximum timeout duration then retry.
				// this causes token requests to block and any other
				// goroutine that depends on an Oauth token.
				dbg.Println("token renewal failed: " + err.Error())
				errf.Pln("token renewal failed: " + err.Error())
				countDwn = time.NewTicker(opts.TimeOutInterval.Duration)
			}
		}
	}
}
func predictConfg() func(respAtTime time.Time, tokenExpireInterval time.Duration) (predictRenewal time.Duration) {
	var avgRenewalInterval time.Duration
	return func(respAtTime time.Time, tokenExpireInterval time.Duration) (predictRenewal time.Duration) {
		if avgRenewalInterval == 0 {
			avgRenewalInterval = time.Since(respAtTime)
		}
		avgRenewalInterval += time.Since(respAtTime)
		avgRenewalInterval /= 2
		predictRenewal = tokenExpireInterval
		if tokenExpireInterval > avgRenewalInterval {
			predictRenewal = tokenExpireInterval - avgRenewalInterval
		} else {
			// acquiring token taking longer than its experation interval
			// probably network problem.  Attempt to obtain next token after
			// half this new token's lifespan has elapsed
			predictRenewal /= 2
		}
		return
	}
}
func tokenRenewal(opts Opts) (token string, interval time.Duration, err error) {
	dbg.Println("OAuth request begin")
	defer dbg.Println("OAuth requet end")
	client := enttp.Config(opts.Opts)
	const body = "grant_type=client_credentials"
	var respBody interface{}
	req := client.R().
		SetHeader("Content-type", "application/x-www-form-urlencoded").
		SetBody(body).
		SetResult(&respBody).
		SetBasicAuth(opts.ClientId, opts.ClientSecret)

	url := "https://" + opts.RootURL
	if opts.TLSclient.Disable {
		url = "http://" + opts.RootURL
	}
	url += "/token"
	dbg.Println("OAuth request before post url: " + url)
	var resp *resty.Response
	if resp, err = req.Post(url); err != nil {
		err = fmt.Errorf("OAuth Post reply failed: '%s'", err.Error())
		return
	}
	if resp == nil {
		err = fmt.Errorf("No response from server.")
		return
	}
	dbg.Printf("OAuth request after post status code: %d\n", resp.StatusCode())
	if !(resp.StatusCode() > 199 && resp.StatusCode() < 300) {
		err = fmt.Errorf("OAuth Post reply failed: Status: '%s'", resp.Status())
		return
	}
	var ok bool
	var respMap map[string]interface{}
	if respMap, ok = respBody.(map[string]interface{}); !ok {
		err = fmt.Errorf("Response body type not expected map type.")
		return
	}
	if token, ok = respMap["access_token"].(string); !ok {
		err = fmt.Errorf("OAuth 'access_token' absent from response.")
		return
	}
	dbg.Println("OAuth token: " + token)
	var expiresIn float64
	if expiresIn, ok = respMap["expires_in"].(float64); !ok {
		err = fmt.Errorf("OAuth 'expires_in' absent from response.")
		return
	}
	interval = time.Duration(expiresIn) * time.Second
	if interval < 1*time.Second {
		// interval should never be less than 1 second
		interval = 1 * time.Second
	}
	dbg.Printf("OAuth expire interval: %v\n", interval)
	return
}
func tokenBroker(needToken chan<- bool, provider <-chan string, term terminator.I) func(force bool) (token string) {
	var ok bool = true
	return func(force bool) (token string) {
		if term.IsNot() && ok {
			needToken <- force
			token, ok = <-provider
		}
		return
	}
}

var dbg *log.Logger = debugNull()

type nullog struct{}

func (*nullog) Write(p []byte) (int, error) {
	return len(p), nil
}
func debugNull() *log.Logger {
	return log.New(new(nullog), "", 0)
}
