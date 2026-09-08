// Package devisecrypto reproduces the password hashing of Devise's
// Devise::Encryptor, so a Go program can authenticate against a Rails
// user table.
//
// Ruby's bcrypt gem and golang.org/x/crypto/bcrypt both emit the $2a$
// variant, so hashes are interchangeable between the two.
//
// Where the two libraries handle an input differently, one rule decides:
// copy Ruby when Ruby has a definite behaviour, refuse when the two would
// silently do different things. peppered applies the first half, and
// ErrStretchesOutOfRange and ErrNullByte the second.
package devisecrypto

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// DefaultStretches is the bcrypt cost Devise 4.9 uses by default.
const DefaultStretches = 12

// MinStretches is the lowest cost Digest accepts. bcrypt's own floor is 4,
// and below it the two libraries disagree without saying so: x/crypto
// substitutes its default of 10, while bcrypt-ruby raises at 0 and clamps
// 1..3 up to 4. The floor here is 10 rather than 4 by policy, because 10 is
// the weakest cost a current Devise app would use.
const MinStretches = 10

// MaxStretches is bcrypt's ceiling. Ruby and Go agree here already.
const MaxStretches = bcrypt.MaxCost

// MaxPasswordBytes is bcrypt's input limit. Bytes past it never reach the
// key schedule, so they add no security.
const MaxPasswordBytes = 72

// ErrStretchesOutOfRange reports a cost Digest will not use. Compare never
// returns it, because verifying an old low-cost hash must keep working.
//
// Digest wraps this error with the received cost (using %w). Callers should
// check for this error using errors.Is(err, ErrStretchesOutOfRange) rather than
// direct equality.
var ErrStretchesOutOfRange = fmt.Errorf("devisecrypto: stretches must be between %d and %d", MinStretches, MaxStretches)

// ErrNullByte reports a password or pepper containing a null byte (0x00).
// Ruby's bcrypt gem refuses null bytes with ArgumentError, so we reject them
// rather than silently produce or verify credentials Devise cannot handle.
var ErrNullByte = errors.New("devisecrypto: password or pepper contains null byte")

// peppered builds the bcrypt input the way Devise::Encryptor.digest does.
//
// Devise guards the pepper with pepper.present?, so a whitespace-only
// pepper is dropped rather than appended. strings.TrimSpace matches the
// Unicode whitespace class that Rails' blank? regexp uses.
//
// The truncation is deliberate: Ruby ignores everything past 72 bytes, so a
// stored Devise hash was built from the cut input and erroring here would
// lock out users who can log in today. A cut may land mid-rune, but Ruby
// cuts on the same byte boundary, so the two still agree.
func peppered(password, pepper string) []byte {
	usePepper := strings.TrimSpace(pepper) != ""
	totalLen := len(password)
	if usePepper {
		totalLen += len(pepper)
	}
	if totalLen > MaxPasswordBytes {
		totalLen = MaxPasswordBytes
	}

	buf := make([]byte, totalLen)
	n := copy(buf, password)
	if usePepper && n < totalLen {
		copy(buf[n:], pepper)
	}
	return buf
}

// Digest hashes password at the given cost, appending pepper when it is not
// blank. Pass "" for pepper when Devise has none configured. Use
// DefaultStretches to match Devise. It never returns
// bcrypt.ErrPasswordTooLong; see peppered.
// A cost outside MinStretches..MaxStretches is refused, not adjusted; see
// MinStretches. A password or pepper containing a null byte is refused with
// ErrNullByte; see ErrNullByte.
func Digest(password string, stretches int, pepper string) (string, error) {
	if strings.IndexByte(password, 0) != -1 || strings.IndexByte(pepper, 0) != -1 {
		return "", ErrNullByte
	}
	if stretches < MinStretches || stretches > MaxStretches {
		return "", fmt.Errorf("%w, got %d", ErrStretchesOutOfRange, stretches)
	}

	// With the cost checked and the input truncated, bcrypt can only fail
	// here if the system entropy source does.
	digested, err := bcrypt.GenerateFromPassword(peppered(password, pepper), stretches)
	if err != nil {
		return "", err
	}

	return string(digested), nil
}

// Compare reports whether password with pepper matches hashedPassword. A
// malformed hash is reported as a non-match; use CompareErr to see why.
//
// Parameter order is (password, pepper, hashedPassword). Note that this differs
// from golang.org/x/crypto/bcrypt (which takes hash first) and Ruby Devise's
// Devise::Encryptor.compare (which takes hashed_password before password).
//
// MinStretches does not apply here. Any hash bcrypt can parse still
// verifies, including one an old Rails app wrote below the floor.
func Compare(password string, pepper string, hashedPassword string) bool {
	match, _ := CompareErr(password, pepper, hashedPassword)

	return match
}

// CompareErr is Compare with the failure reason. A wrong password is
// (false, nil); a hash bcrypt cannot parse or a null-byte input is (false, err).
//
// Parameter order is (password, pepper, hashedPassword).
//
// Timing attack / user enumeration note:
// If hashedPassword is blank (empty or whitespace-only), CompareErr returns
// immediately ((false, nil)) without performing a bcrypt verification, matching
// Devise's behavior. Callers requiring protection against timing-based user
// enumeration when an account or password hash is absent should perform a
// dummy comparison with a placeholder hash.
func CompareErr(password string, pepper string, hashedPassword string) (bool, error) {
	// A blank encrypted_password column is an ordinary Devise state for an
	// account with no password set, not a corrupt hash, so it is not an error.
	if strings.TrimSpace(hashedPassword) == "" {
		return false, nil
	}

	if strings.IndexByte(password, 0) != -1 || strings.IndexByte(pepper, 0) != -1 {
		return false, ErrNullByte
	}

	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), peppered(password, pepper))
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return false, nil
	}

	return err == nil, err
}
