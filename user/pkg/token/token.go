package token

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidToken     = errors.New("invalid token")
	ErrExpiredToken     = errors.New("token expired")
	ErrUnknownTokenType = errors.New("unknown token type")
)

type Identity struct {
	UserID    string
	SessionID string
}

type tokenType string

const (
	accessTokenType  tokenType = "access"
	refreshTokenType tokenType = "refresh"
)

type claims struct {
	jwt.RegisteredClaims
	SessionID string    `json:"sid"`
	TokenType tokenType `json:"token_type"`
}

type Token struct {
	Raw       string
	ExpiresAt time.Time
}

func (t Token) ExpiresIn() int {
	return int(time.Until(t.ExpiresAt).Seconds())
}

func (m Manager) NewAccess(userID, sessionID string) (*Token, error) {
	return m.newToken(userID, sessionID, accessTokenType)
}

func (m Manager) NewRefresh(userID, sessionID string) (*Token, error) {
	return m.newToken(userID, sessionID, refreshTokenType)
}

func (m Manager) newToken(userID, sessionID string, tokenType tokenType) (*Token, error) {
	now := time.Now()
	var expiresAt time.Time

	switch tokenType {
	case accessTokenType:
		expiresAt = now.Add(m.conf.AccessTTL)
	case refreshTokenType:
		expiresAt = now.Add(m.conf.RefreshTTL)
	default:
		return nil, ErrUnknownTokenType
	}

	c := claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			Issuer:    m.conf.Issuer,
			Audience:  jwt.ClaimStrings{m.conf.Audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
		SessionID: sessionID,
		TokenType: tokenType,
	}

	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString(m.conf.Secret)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	return &Token{
		Raw:       signed,
		ExpiresAt: expiresAt,
	}, nil
}

func (m Manager) ParseAccess(raw string) (*Identity, error) {
	return m.parse(raw, accessTokenType)
}

func (m Manager) ParseRefresh(raw string) (*Identity, error) {
	return m.parse(raw, refreshTokenType)
}

func (m Manager) parse(raw string, want tokenType) (*Identity, error) {
	var c claims

	if _, err := jwt.ParseWithClaims(raw, &c,
		func(*jwt.Token) (any, error) { return m.conf.Secret, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(m.conf.Issuer),
		jwt.WithAudience(m.conf.Audience),
		jwt.WithExpirationRequired(),
	); err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}

		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if c.TokenType != want {
		return nil, fmt.Errorf("%w: expected %s, got %s", ErrInvalidToken, want, c.TokenType)
	}

	return &Identity{
		UserID:    c.Subject,
		SessionID: c.SessionID,
	}, nil
}
