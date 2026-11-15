package validator

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
)

const (
	minPasswordLength = 12
	maxPasswordLength = 72 // bcrypt limit
)

var (
	ErrPasswordTooShort = fmt.Errorf("password must be at least %d characters long", minPasswordLength)
	ErrPasswordTooLong  = fmt.Errorf("password must be at most %d characters long", maxPasswordLength)
	ErrPasswordCharset  = errors.New("password must contain only latin letters, digits and punctuation")
	ErrPasswordNoUpper  = errors.New("password must contain an uppercase letter")
	ErrPasswordNoLower  = errors.New("password must contain a lowercase letter")
	ErrPasswordNoDigit  = errors.New("password must contain a digit")
	ErrPasswordNoSymbol = errors.New("password must contain a special character")
	ErrPasswordContext  = errors.New("password must not contain your email, username or the service name")
)

func Password(password string, context ...string) error {
	var hasUpper, hasLower, hasDigit, hasSymbol bool

	for i := 0; i < len(password); i++ {
		switch c := password[i]; {
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= '0' && c <= '9':
			hasDigit = true
		case c >= '!' && c <= '~':
			hasSymbol = true
		default:
			return ErrPasswordCharset
		}
	}

	var errs []error

	switch {
	case len(password) < minPasswordLength:
		errs = append(errs, ErrPasswordTooShort)
	case len(password) > maxPasswordLength:
		errs = append(errs, ErrPasswordTooLong)
	}

	if !hasUpper {
		errs = append(errs, ErrPasswordNoUpper)
	}

	if !hasLower {
		errs = append(errs, ErrPasswordNoLower)
	}

	if !hasDigit {
		errs = append(errs, ErrPasswordNoDigit)
	}

	if !hasSymbol {
		errs = append(errs, ErrPasswordNoSymbol)
	}

	words := append(contextWords(context...), "urlshortener", "shortener")
	if containsContext(password, words) {
		errs = append(errs, ErrPasswordContext)
	}

	return errors.Join(errs...)
}

func contextWords(values ...string) []string {
	var words []string

	for _, value := range values {
		if local, _, ok := strings.Cut(value, "@"); ok {
			value = local
		}

		isSeparator := func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }

		for _, word := range strings.FieldsFunc(value, isSeparator) {
			if len(word) >= 4 {
				words = append(words, strings.ToLower(word))
			}
		}
	}

	return words
}

func containsContext(password string, words []string) bool {
	lower := strings.ToLower(password)

	for _, word := range words {
		if strings.Contains(lower, word) {
			return true
		}
	}

	return false
}
