package password

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

var ErrMismatchedHashAndPassword = errors.New("mismatched hash and password")

type Hasher struct {
	cost int
}

func New(cost int) *Hasher {
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}

	return &Hasher{cost: cost}
}

func (h Hasher) Hash(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), h.cost)
	if err != nil {
		return "", ErrMismatchedHashAndPassword
	}

	return string(hash), nil
}

func (h Hasher) Compare(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
