package twitter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/log"

	"github.com/dghubble/go-twitter/twitter"
	"github.com/dghubble/oauth1"
	twauth "github.com/dghubble/oauth1/twitter"
)

// Config holds configuration options for Twitter logins.
type Config struct {
	TwitterConsumerKey    string `json:"clientID"`
	TwitterConsumerSecret string `json:"clientSecret"`
	CallbackURI           string `json:"callbackURI"`
}

// Open returns a strategy for logging in through Twitter
func (c *Config) Open(id string, logger log.Logger) (connector.Connector, error) {
	return &twitterConnector{
		oauth1Config: &oauth1.Config{
			ConsumerKey:    c.TwitterConsumerKey,
			ConsumerSecret: c.TwitterConsumerSecret,
			CallbackURL:    c.CallbackURI,
			Endpoint:       twauth.AuthorizeEndpoint,
		},
		logger: logger,
	}, nil
}

type twitterConnector struct {
	oauth1Config *oauth1.Config
	logger       log.Logger
}

// Twitter tokens don't expire and have no refresh mechanism, so implementing
// connector.RefreshConnector as a no-op
var (
	_ connector.CallbackConnector = (*twitterConnector)(nil)
	_ connector.RefreshConnector  = (*twitterConnector)(nil)
)

// LoginURL returns an access token request URL
func (c *twitterConnector) LoginURL(scopes connector.Scopes, callbackURL, state string) (string, error) {
	u, err := url.Parse(c.oauth1Config.CallbackURL)
	if err != nil {
		c.logger.Error(err)
		return "", err
	}

	q := u.Query()
	q.Del("state")
	u.RawQuery = q.Encode()

	if u.String() != callbackURL {
		return "", fmt.Errorf("expected callback URL %q did not match the URL in the config %q",
			callbackURL, c.oauth1Config.CallbackURL)
	}

	q.Add("state", state)
	u.RawQuery = q.Encode()
	c.oauth1Config.CallbackURL = u.String()

	requestToken, _, err := c.oauth1Config.RequestToken()
	if err != nil {
		return "", err
	}

	authorizationURL, err := c.oauth1Config.AuthorizationURL(requestToken)
	if err != nil {
		return "", err
	}

	return authorizationURL.String(), nil
}

// HandleCallback handles HTTP redirect from Twitter
func (c *twitterConnector) HandleCallback(s connector.Scopes, r *http.Request) (identity connector.Identity, err error) {
	requestToken, verifier, err := oauth1.ParseAuthorizationCallback(r)
	if err != nil {
		c.logger.Error(err)
		return identity, err
	}

	accessToken, accessSecret, err := c.oauth1Config.AccessToken(requestToken, "secret does not matter", verifier)
	if err != nil {
		c.logger.Error(err)
		return identity, err
	}

	// ctx := r.Context()
	ctx := context.Background()
	httpClient := c.oauth1Config.Client(ctx, oauth1.NewToken(accessToken, accessSecret))
	twitterClient := twitter.NewClient(httpClient)
	accountVerifyParams := &twitter.AccountVerifyParams{
		IncludeEntities: twitter.Bool(true),
		SkipStatus:      twitter.Bool(true),
		IncludeEmail:    twitter.Bool(true),
	}
	user, resp, err := twitterClient.Accounts.VerifyCredentials(accountVerifyParams)
	if err != nil {
		c.logger.Error(err)
		return
	}

	err = validateResponse(user, resp, err)
	if err != nil {
		c.logger.Error(err)
		return
	}

	identity = connector.Identity{
		UserID:        user.IDStr,
		Username:      user.Name,
		Email:         user.Email,
		EmailVerified: true,
	}

	if s.OfflineAccess {
		data := map[string]string{"accessToken": accessToken, "accessSecret": accessSecret}
		connData, err := json.Marshal(data)
		if err != nil {
			return identity, fmt.Errorf("twitter: marshal connector data: %v", err)
		}
		identity.ConnectorData = connData
	}

	return identity, nil
}

func (c *twitterConnector) Refresh(ctx context.Context, s connector.Scopes, ident connector.Identity) (connector.Identity, error) {
	// Twitter doesn't expire access tokens so refreshing is a no-op
	return ident, nil
}

// Twitter login errors
var (
	ErrUnableToGetTwitterUser = fmt.Errorf("twitter: unable to get Twitter User")
)

// validateResponse returns an error if the given Twitter user, raw
// http.Response, or error are unexpected. Returns nil if they are valid.
func validateResponse(user *twitter.User, resp *http.Response, err error) error {
	if err != nil || resp.StatusCode != http.StatusOK {
		return ErrUnableToGetTwitterUser
	}
	if user == nil || user.ID == 0 || user.IDStr == "" {
		return ErrUnableToGetTwitterUser
	}
	return nil
}
