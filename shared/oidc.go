package shared

const (
	AuthenticationRequired = "authentication required"
	InvalidToken           = "invalid token"
)

// ErrOIDCAuthentication represents an OIDC error. It is returned if authentication is required,
// i.e. no access token has been provided. It is also returned if the provided access token is
// invalid. In this case the reason for why it is invalid will be set in the Reason field.
type ErrOIDCAuthentication struct {
	Issuer        string            `json:"issuer"`
	ClientID      string            `json:"client_id"`
	Err           string            `json:"error"`
	Reason        string            `json:"reason,omitempty"`
	URLParameters map[string]string `json:"parameters,omitempty"`
}

func (e ErrOIDCAuthentication) Error() string {
	return e.Err
}
