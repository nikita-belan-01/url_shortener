package token

import (
	"errors"
	"fmt"
	"time"
)

var (
	ErrEmptyIssuer            = errors.New("empty issuer")
	ErrEmptyAudience          = errors.New("empty audience")
	ErrInvalidAccessTokenTTL  = errors.New("invalid access token ttl")
	ErrInvalidRefreshTokenTTL = errors.New("invalid refresh token ttl")
)

type Config struct {
	Secret     []byte
	Issuer     string
	Audience   string
	AccessTTL  time.Duration
	RefreshTTL time.Duration
}

type Manager struct {
	conf Config
}

func NewManager(conf Config) (*Manager, error) {
	if len(conf.Secret) < 32 {
		return nil, fmt.Errorf("secret must be at least 32 bytes, got %d", len(conf.Secret))
	}

	if conf.Issuer == "" {
		return nil, ErrEmptyIssuer
	}

	if conf.Audience == "" {
		return nil, ErrEmptyAudience
	}

	if conf.AccessTTL <= 0 {
		return nil, ErrInvalidAccessTokenTTL
	}

	if conf.RefreshTTL <= 0 {
		return nil, ErrInvalidRefreshTokenTTL
	}

	secret := make([]byte, len(conf.Secret))
	copy(secret, conf.Secret)
	conf.Secret = secret

	return &Manager{
		conf: conf,
	}, nil
}
