package lxd

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math"
	mrand "math/rand"
	"net"
	"net/http"
	"time"

	"github.com/pborman/uuid"
	"github.com/zitadel/oidc/v2/pkg/client/rp"
	"github.com/zitadel/oidc/v2/pkg/client/rp/cli"
	httphelper "github.com/zitadel/oidc/v2/pkg/http"
	"github.com/zitadel/oidc/v2/pkg/oidc"

	"github.com/lxc/lxd/shared"
)

var ErrRefreshAccessToken = fmt.Errorf("Failed refreshing access token")
var oidcCallbackPath = "/auth/lxd/callback"
var oidcLoginPath = "/login"

type oidcClient struct {
	httpClient *http.Client
	tokens     *oidc.Tokens[*oidc.IDTokenClaims]
}

func NewOIDCClient(tokens *oidc.Tokens[*oidc.IDTokenClaims]) *oidcClient {
	client := oidcClient{
		tokens: tokens,
	}

	return &client
}

func (o *oidcClient) do(req *http.Request) (*http.Response, error) {
	req.Header.Set("X-LXD-oidc", "true")

	if o.tokens != nil && o.tokens.Token != nil {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", o.tokens.AccessToken))
	}

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (o *oidcClient) Do(req *http.Request) (*http.Response, error) {
	resp, err := o.do(req)
	if err != nil {
		return nil, err
	}

	oidcAuthError := &shared.ErrOIDCAuthentication{}

	// Since the response body can only be read once (io.ReadCloser), we store it, and feed it back
	// to the response before returning it. This way, the caller won't have an empty body after
	// we're done processing it.
	var bodyBytes []byte
	if resp.Body != nil {
		bodyBytes, _ = io.ReadAll(resp.Body)
	}

	resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	_, _, err = lxdParseResponse(resp)
	if err == nil {
		resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		return resp, nil
	}

	if errors.As(err, &oidcAuthError) {
		if oidcAuthError.Err == shared.AuthenticationRequired {
			err = o.authenticate(oidcAuthError.Issuer, oidcAuthError.ClientID, oidcAuthError.URLParameters)
			if err != nil {
				return nil, err
			}
		} else if oidcAuthError.Err == shared.InvalidToken {
			err = o.refresh(oidcAuthError.Issuer, oidcAuthError.ClientID)
			if err != nil {
				if errors.Is(err, ErrRefreshAccessToken) {
					err = o.authenticate(oidcAuthError.Issuer, oidcAuthError.ClientID, oidcAuthError.URLParameters)
					if err != nil {
						return nil, err
					}
				} else {
					return nil, err
				}
			}
		}

		resp, err = o.do(req)
		if err != nil {
			return nil, err
		}
	}

	return resp, nil
}

func (o *oidcClient) getProvider(issuer string, clientID string, port int32) (rp.RelyingParty, error) {
	redirectURI := fmt.Sprintf("http://localhost:%d%v", port, oidcCallbackPath)
	scopes := []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess}
	hashKey := make([]byte, 16)
	encryptKey := make([]byte, 16)

	_, err := rand.Read(hashKey)
	if err != nil {
		return nil, err
	}

	_, err = rand.Read(encryptKey)
	if err != nil {
		return nil, err
	}

	cookieHandler := httphelper.NewCookieHandler(hashKey, encryptKey, httphelper.WithUnsecure())
	options := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
		rp.WithPKCE(cookieHandler),
	}

	provider, err := rp.NewRelyingPartyOIDC(issuer, clientID, "", redirectURI, scopes, options...)
	if err != nil {
		return nil, err
	}

	return provider, nil
}

func (o *oidcClient) refresh(issuer string, clientID string) error {
	// We set the port to 0 because RefreshAccessToken doesn't use or need the redirectURI and the port number therefore doesn't matter.
	provider, err := o.getProvider(issuer, clientID, 0)
	if err != nil {
		return err
	}

	oauthTokens, err := rp.RefreshAccessToken(provider, o.tokens.RefreshToken, "", "")
	if err != nil {
		return ErrRefreshAccessToken
	}

	*o.tokens.Token = *oauthTokens

	return nil
}

func (o *oidcClient) getListenerAndPort() (net.Listener, int32) {
	var listener net.Listener
	var err error
	var port int32

	// Try getting a port to listen on.
	for i := 0; i < 10; i++ {
		// Get random port between 1024 and 65535.
		port = 1024 + mrand.Int31n(math.MaxUint16-1024)

		listener, err = net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err == nil {
			break
		}
	}

	return listener, port
}

func (o *oidcClient) authenticate(issuer string, clientID string, parameters map[string]string) error {
	var err error

	listener, port := o.getListenerAndPort()
	if listener == nil {
		return fmt.Errorf("Failed finding free listen port")
	}

	provider, err := o.getProvider(issuer, clientID, port)
	if err != nil {
		return err
	}

	// Generate some state (representing the state of the user in your application,
	// e.g. the page where they were before sending them to login
	state := func() string {
		return uuid.New()
	}

	codeflowCtx, codeflowCancel := context.WithCancel(context.TODO())
	defer codeflowCancel()

	tokenChan := make(chan *oidc.Tokens[*oidc.IDTokenClaims], 1)

	callback := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], state string, rp rp.RelyingParty) {
		tokenChan <- tokens
		msg := "<p><strong>Success!</strong></p>"
		msg = msg + "<p>You are authenticated and can now return to the CLI.</p>"
		_, _ = w.Write([]byte(msg))
	}

	urlParams := make([]rp.URLParamOpt, len(parameters))

	i := 0
	for k, v := range parameters {
		urlParams[i] = rp.WithURLParam(k, v)
		i++
	}

	mux := http.NewServeMux()
	// When the browser is opened, it will go to the login path which will redirect to the issuer where the user is able to log in.
	mux.Handle(oidcLoginPath, rp.AuthURLHandler(state, provider, urlParams...))
	// Once the user has logged in, they are redirected to the callback path where the tokens are provided.
	mux.Handle(oidcCallbackPath, rp.CodeExchangeHandler(callback, provider))

	server := &http.Server{Addr: fmt.Sprintf(":%d", port), Handler: mux}

	go func() {
		_ = server.Serve(listener)
	}()

	go func() {
		<-codeflowCtx.Done()
		ctxShutdown, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelShutdown()

		_ = server.Shutdown(ctxShutdown)
	}()

	// This opens the browser where the user will be able to log in.
	cli.OpenBrowser(fmt.Sprintf("http://localhost:%d%s", port, oidcLoginPath))

	*o.tokens = *<-tokenChan

	return nil
}
