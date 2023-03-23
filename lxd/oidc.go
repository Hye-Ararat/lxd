package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/zitadel/oidc/v2/pkg/client"
	"github.com/zitadel/oidc/v2/pkg/client/rp"
	"github.com/zitadel/oidc/v2/pkg/oidc"
	"github.com/zitadel/oidc/v2/pkg/op"
)

// oidcVerifier holds all information needed to verify an access token offline.
type oidcVerifier struct {
	keySet   oidc.KeySet
	verifier op.AccessTokenVerifier
}

// NewOIDCVerifier returns an oidcVerifier. It calls the OIDC discovery endpoint in order to get the issuer's remote keys which are needed to verify an issued access token.
func NewOIDCVerifier(issuer string) (*oidcVerifier, error) {
	discoveryConfig, err := client.Discover(issuer, http.DefaultClient)
	if err != nil {
		return nil, fmt.Errorf("Failed calling OIDC discovery endpoint: %w", err)
	}

	keySet := rp.NewRemoteKeySet(http.DefaultClient, discoveryConfig.JwksURI)
	verifier := op.NewAccessTokenVerifier(issuer, keySet)

	return &oidcVerifier{keySet: keySet, verifier: verifier}, nil
}

// VerifyAccessToken is a wrapper around op.VerifyAccessToken which avoids having to deal with Go generics elsewhere. It validates the access token (issuer, signature and expiration).
func (o *oidcVerifier) VerifyAccessToken(ctx context.Context, token string) (*oidc.AccessTokenClaims, error) {
	return op.VerifyAccessToken[*oidc.AccessTokenClaims](ctx, token, o.verifier)
}
