package oauth

import (
	"fmt"
	"sync"
	"time"

	"github.com/WhisperingChaos/terminator"

	enttp "github.com/WhisperingChaos/client/restyc"
	"github.com/WhisperingChaos/msg"
	resty "gopkg.in/resty.v0"
)

/*
TODO

  accept token URL path as input to elmininate hard coding

*/

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
	future expiration.  It is hoped prediction will reduce the network latency of http
	requests to a resource server by eliminating the client's token expiration failures.

	Prediction attempts to obtain a new token just before the current one
	expires.  The algorithm calculates the time to initiate a future
	new token request by subtracting the average round trip time necessary
	to obtain a token from the token's lifespan.  A countdown
	timer is initialized with twice this interval and when spent, triggers a request
	addressed to the authentication server to obtain a new token.

	The ability to access the mechanics mentioned above is encapsulated within the
	function: func(force bool) (OauthToken string, err error) returned by Start.  The value of
	"force" should typically be 'false'.  This setting almost always retrieves a valid
	access token, as long as the prediciton successfully forecasts the need for a new
	one.  However, if a client request to its resource server should fail, due to a poor
	prediction or an event that causes an access token to prematurely expire, the client
	can force (force=true) the function to return a newly obtained access token from the
	the authorization server.
*/
func Start(
	opts Opts, // oauth http connection configuration
	term terminator.Isync, // a means to terminate the oauth client
	debug msg.I, // debugging agent
) func(force bool, // true - force token renewal process to aquire new access token, otherwise, use provided value
) (OAuthToken string, // function providing OAuth token
	err error, // return potential error

) {
	needToken := make(chan bool)
	provider := make(chan string)
	errMsg := make(chan error, 1)
	term.Add(1)
	dbgAssign(&dbg, debug)
	go tokenProvide(opts, needToken, provider, errMsg, term)
	return tokenBroker(needToken, provider, errMsg, term)
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
func TokenExpiredRetry(tokenRenewal func(force bool) (OAuthToken string, err error)) resty.RetryConditionFunc {
	return func(resp *resty.Response) (attemptRetry bool, err error) {
		if resp.StatusCode() != 401 {
			// didn't attempt retry
			return
		}
		attemptRetry = true
		dbg.P("status='retry issued due to token expiration'")
		_, err = tokenRenewal(true)
		return
	}
}

// private ---------------------------------------------------------------------

func tokenProvide(opts Opts, needToken chan bool, provider chan<- string, errMsg chan error, term terminator.Isync) {
	defer term.Done()
	dbg.P("status='started'")
	defer dbg.P("status='ended'")
	defer close(errMsg)
	defer close(needToken)
	defer close(provider)
	renew := make(chan string, 1) //two goroutines are interacting one generates an input that results in an output feedback reply.  However, the input and output request cannot be same select, otherwise may spin.  Therefore, make output channel buffered to prohibit blocking behavior in goroutine generating output so the requester can transition to a second select statement that then reads this output.
	defer close(renew)
	errRenew := make(chan error, 1)
	defer close(errRenew)
	renewForce := make(chan bool)
	defer close(renewForce)
	renewToken := tokenRenewConfig(opts, renew, renewForce, errRenew)
	go renewToken()
	var token string
	for term.IsNot() {
		select {
		case force, ok := <-needToken:
			if !ok {
				return
			}
			dbg.Pf("status='token requested' force=%t", force)
			var err error
			if force {
				// a force requests the immediate aquisition of a token therefore
				// eliminate error messages produced before this request as they
				// refer to errors that occurred before its initiation
				drainErrorMsg(errMsg)
				drainErrorMsg(errRenew)
				dbg.P("status='force new token'")
				select {
				case renewForce <- true:
				case err = <-errRenew: // as frequent as plantery alingment
					drainErrorMsg(errRenew)
					renewForce <- true // if unexpected problem - will block forever
				case <-term.Chan():
					return
				}
				dbg.P("status='waiting for forced renew'")
				select {
				case token = <-renew:
					dbg.Pf("status='obtained token' token='%s'", token)
				case err = <-errRenew:
					drainErrorMsg(errMsg)
					errMsg <- err
				case <-term.Chan():
					return
				}
				drainTokenRequests(needToken) // discards token requests issued while attempting to acquiring another one via long running process.  Don't want to spin.
			}
			dbg.P("status='renew complete'")
			if err == nil {
				dbg.Pf("status='pushing token to requester' token='%s'", token)
				provider <- token
				dbg.Pf("status='requester received token' token='%s'", token)
			}
		case token = <-renew: // periodic refresh typically before token expires.  Eliminates network lag for future token request.
			dbg.Pf("status='successful periodic refresh' token='%s'", token)
		case err := <-errRenew:
			drainErrorMsg(errMsg)
			errMsg <- err
		case <-term.Chan():
			return
		}
	}
}
func tokenRenewConfig(opts Opts, renew chan<- string, renewForce <-chan bool, errMsg chan<- error) func() {
	return func() {
		dbg.P("status='token renewal started'")
		defer dbg.P("status='token renewal goroutine exited'")
		var countDwn *time.Ticker
		countDwnCleanUp := func() {
			countDwn.Stop()
		}
		predictRenewal := predictConfg()
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
			dbg.P("status='token renewal contact oauth server'")
			respAtTime := time.Now()
			if token, expire, err := tokenRenewal(opts); err == nil {
				predictedInterval := predictRenewal(respAtTime, expire)
				dbg.Pf("status='token renewal predicted interval' interval=%v", predictedInterval)
				countDwn = time.NewTicker(predictedInterval)
				dbg.Pf("status='token renewal pushing token' token='%s'", token)
				renew <- token
				dbg.Pf("status='token renewal pushed token' token='%s'", token)
			} else {
				dbg.Pf("status='token renewal failed' error=(%s)", err.Error())
				// send error msg channel to unblock and deliver error message to
				// routines dependent on this one.  Note below works because
				// error channel buffers at least one message, so message isn't forgotten,
				// and if more than one message, it discards next one so it doesn't
				// block.  Of course more recent discarded message may be more insightful
				// but for now not worth the effort.
				select {
				case errMsg <- fmt.Errorf("status='token renewal failed' error=(%s)", err.Error()):
				default:
				}
				// unable to retrieve new token. set countDwn interval
				// to maximum timeout duration then retry.
				countDwn = time.NewTicker(opts.TimeOutInterval)
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
		dbg.Pf("status='token renewal computed network round trip avg' avgRenewalInterval=%v", avgRenewalInterval)
		predictRenewal = tokenExpireInterval
		if tokenExpireInterval > avgRenewalInterval*2 {
			// twice the average to provide a buffer that ensures completion before token expires
			predictRenewal = tokenExpireInterval - avgRenewalInterval*2
		} else if tokenExpireInterval > avgRenewalInterval {
			predictRenewal = tokenExpireInterval - avgRenewalInterval
		} else {
			// acquiring token taking longer than its expiration interval
			// probably network problem.  Attempt to obtain next token after
			// half this new token's lifespan has elapsed
			predictRenewal /= 2
		}
		return
	}
}
func tokenRenewal(opts Opts) (token string, interval time.Duration, err error) {
	dbg.P("status='OAuth request begin'")
	defer dbg.P("status='OAuth request end'")
	client := enttp.Config(opts.Opts)
	const body = "grant_type=client_credentials"
	var respBody interface{}
	req := client.R().
		SetHeader("Content-type", "application/x-www-form-urlencoded").
		SetBody(body).
		SetResult(&respBody).
		SetBasicAuth(opts.ClientId, opts.ClientSecret)

	url := "https://" + opts.RootURL
	/* debug
	if opts.TLSclient.Disable {
		url = "http://" + opts.RootURL
	}
	*/
	url += "/o/token/"
	var resp *resty.Response
	if resp, err = req.Post(url); err != nil {
		err = fmt.Errorf("OAuth Post reply failed: '%s'", err.Error())
		return
	}
	if resp == nil {
		err = fmt.Errorf("No response from server.")
		return
	}
	dbg.Pf("status='OAuth request after post'  StatusCode=%d Status='%s'", resp.StatusCode(), resp.Status())
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
		err = fmt.Errorf("status='OAuth access_token absent from response'")
		return
	}
	dbg.Pf("status='aquire token' token='%s'", token)
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
	dbg.Pf("status='success' tokenExpireInterval=%v", interval)
	return
}
func tokenBroker(needToken chan<- bool, provider <-chan string, errMsg <-chan error, term terminator.I) func(force bool) (token string, err error) {
	mutex := &sync.Mutex{}
	ok := true
	firstTime := true
	return func(force bool) (token string, err error) {
		mutex.Lock()
		defer mutex.Unlock()
		if firstTime {
			force = true
			firstTime = false
		}
		if !term.IsNot() || !ok {
			err = fmt.Errorf("Unable to obtain token - token retrieval process terminated")
			return
		}
		needToken <- force
		select {
		case token, ok = <-provider:
		case err = <-errMsg:
			return
		case <-term.Chan():
			err = fmt.Errorf("Unable to obtain token - token retrieval process terminated")
		}
		return
	}
}
func drainErrorMsg(errMsg <-chan error) {
	for {
		select {
		case _, ok := <-errMsg:
			if !ok {
				return
			}
		default:
			return
		}
	}
}
func drainTokenRequests(token <-chan bool) {
	for {
		select {
		case _, ok := <-token:
			if !ok {
				return
			}
		default:
			return
		}
	}
}

var dbg msg.I = msg.NewDiscard()

func dbgAssign(lhs *msg.I, rhs msg.I) {
	if rhs == nil {
		return
	}
	*lhs = rhs
}
