# Proposal: Modernize go-devise-encryptor

Status: implemented on branch `modernize-go-126`, 2026-09-08.
Date proposed: 2026-09-07.

The rest of this document is kept as written, as a record of the
reasoning and the decisions behind the change.

## Decisions made

- **2026-09-08 — minimum Go version: 1.24, not 1.26.** Approved by John
  Bolliger. The original `go 1.26` came from `go mod tidy` picking
  `x/crypto v0.56.0`, which itself requires 1.26. Nothing in this package
  needs more than Go 1.24, whose `b.Loop()` the benchmarks use. A `go`
  directive is a hard minimum for anyone importing the package, so 1.26
  locked out 1.24 and 1.25 users for no gain. Pinned to
  `x/crypto v0.48.0`, the newest release that still targets Go 1.24. The
  CI matrix needed no toolchain pin: `actions/setup-go` already sets
  `GOTOOLCHAIN=local`, so a runner older than the `go` directive fails
  loudly instead of downloading a newer toolchain.

- **2026-09-08 — cost below 10: return an error.** Approved by John
  Bolliger, after a probe found Go and Ruby disagree on every invalid cost.
  Go silently substitutes 10; Ruby raises at 0 and clamps 1..3 up to 4.
  `Digest` now returns `ErrStretchesOutOfRange` outside 10..31. `Compare`
  is deliberately exempt, so hashes an old Rails app stored below cost 10
  still verify. The README documents this under "The cost floor".

- **2026-09-07 — 72-byte overflow: truncate, do not error.** Approved by
  John Bolliger. See "Problem 2" below. The README must state this choice
  and the reason: it matches real-world Devise behaviour, so credentials
  that Rails already accepts keep working.

## Summary

This package hashes passwords the same way Devise does. It lets a Go
application read a Rails user table. The code works, but it is old.

Three things need attention:

1. The repository has no `go.mod` file.
2. Go and Ruby do not agree on passwords longer than 72 bytes.
3. The tests do not check Ruby compatibility at all.

## Current state

Files:

- `devisecrypto.go` — 43 lines, two functions.
- `devisecrypto_test.go` — Go-only tests, 2-space indent, not gofmt clean.
- `.travis.yml` — targets Go 1.3.3 through 1.6.0. Travis CI is dead.
- `README.md` — has a dead build badge.

There is no `go.mod`. The package only builds under `GOPATH`.
Go 1.26 is the local toolchain.

## Problem 1: no module

Without `go.mod`, `go get github.com/consyse/go-devise-encryptor` fails
for modern users. This blocks every new consumer of the package.

Fix: run `go mod init github.com/consyse/go-devise-encryptor`.
Set `go 1.26`. Add `golang.org/x/crypto v0.56.0`.

## Problem 2: the 72-byte disagreement

bcrypt only reads the first 72 bytes of a password.

- Ruby truncates the input and makes a hash.
- Go returns `bcrypt: password length exceeds 72 bytes` and makes nothing.

Verified locally with `golang.org/x/crypto v0.56.0`.

So `Digest` fails where Rails succeeds. A Go service cannot reproduce a
hash that Rails already stored.

There is a second problem. `bcrypt.CompareHashAndPassword` does NOT
return that error. It truncates and compares. Verified locally: an
80-byte password matched a hash built from its first 72 bytes.

So `Digest` and `Compare` disagree with each other.

A pepper makes this worse. Devise appends the pepper to the password.
A 60-byte password plus a 20-byte pepper crosses the limit.

Two options:

- **Option A — truncate.** Cut password + pepper to 72 bytes before
  bcrypt. This matches Ruby exactly. Old logins keep working.
- **Option B — error.** Return an explicit error. This is safer, but it
  breaks logins that Rails accepts.

**Decided: Option A, truncate.** The whole purpose of this package is to
agree with Rails.

The README must carry an explicit note. Required content:

- We truncate password + pepper at 72 bytes.
- We do NOT return an error, even though Go's bcrypt does.
- The reason is real-world behaviour: Ruby truncates, so a stored Rails
  hash was built from truncated bytes. An error would lock out users who
  can log in today.
- Bytes past 72 do not add security. bcrypt never reads them.

## Problem 3: Devise has moved on

Modern Devise 4.9 `Devise::Encryptor` does this:

```ruby
def self.digest(klass, password)
  password = "#{password}#{klass.pepper}" if klass.pepper.present?
  ::BCrypt::Password.create(password, cost: klass.stretches).to_s
end
```

Two differences from our Go code:

- Devise uses `pepper.present?`. A whitespace-only pepper counts as
  blank. Our Go code uses `pepper != ""`, so `" "` counts as real.
- The Devise default for `stretches` is now 12. Our README says 10.

Fix: match `present?` semantics. Add a `DefaultStretches = 12` constant.

## Problem 4: the tests are not real

The current tests only compare Go against Go. They never touch Ruby.
So they cannot detect a Devise compatibility break.

Ruby 3.4.9 with the `bcrypt` gem is available on this machine.

Plan:

- Generate golden fixtures with the Ruby `bcrypt` gem.
- Store them in `testdata/devise_hashes.json`.
- Check Go `Compare` against every real Ruby hash.
- Check Ruby against hashes that Go produced.
- Convert the tests to table-driven subtests.
- Add cases: empty password, unicode, exactly 72 bytes, 100 bytes,
  wrong pepper, whitespace pepper, corrupt hash, `$2b$` prefix.
- Add a fuzz test that round-trips `Digest` then `Compare`.
- Add benchmarks at cost 10 and cost 12.

## Problem 5: dead CI

`.travis.yml` targets Go versions from 2014. Travis CI no longer runs.

Fix: delete it. Add `.github/workflows/ci.yml`.

The workflow runs:

- Go 1.25 and Go 1.26.
- `gofmt -l`, `go vet`, `staticcheck`.
- `go test -race -cover ./...`.
- A Ruby job that verifies the cross-language fixtures.

## Proposed API

Keep the current functions. Add a small amount.

```go
const DefaultStretches = 12

// MaxPasswordBytes is the bcrypt input limit.
const MaxPasswordBytes = 72

func Digest(password string, stretches int, pepper string) (string, error)
func Compare(password, pepper, hashedPassword string) bool
func CompareErr(password, pepper, hashedPassword string) (bool, error)
```

`Compare` stays as it is, so no caller breaks. `CompareErr` returns the
reason a comparison failed, such as a malformed hash.

Internal cleanup:

- Drop `bytes.Buffer`. Use plain string concatenation.
- Add one shared `peppered()` helper. Both functions call it.
- Fix the comment typos, such as the doubled spaces.

## Work order

1. Add `go.mod` and `go.sum`.
2. Rewrite `devisecrypto.go` with truncation and the pepper fix.
3. Write the Ruby fixture generator script.
4. Rewrite the tests.
5. Add the GitHub Actions workflow. Delete `.travis.yml`.
6. Update the README.
7. Run `/simplify`.

## Open questions

None. The 72-byte question is decided above.
