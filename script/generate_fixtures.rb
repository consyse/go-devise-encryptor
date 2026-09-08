#!/usr/bin/env ruby
# Generates testdata/devise_hashes.json with hashes produced by the real
# Ruby bcrypt gem, following Devise::Encryptor.digest exactly. The Go tests
# verify Compare against these, which is the only way to catch a drift from
# Devise that a Go-only round trip would miss.
#
# Usage: gem install bcrypt && ruby script/generate_fixtures.rb

require "bcrypt"
require "json"

# Cost 4 is the bcrypt minimum. The fixtures exercise byte handling, not the
# work factor, so keep the suite fast.
COST = 4

CASES = [
  { name: "simple_with_pepper",   password: "changeme",      pepper: "a bad pepper" },
  { name: "simple_no_pepper",     password: "changeme",      pepper: "" },
  { name: "empty_password",       password: "",              pepper: "a bad pepper" },
  { name: "empty_everything",     password: "",              pepper: "" },
  { name: "unicode",              password: "pässwörd✓🔐",   pepper: "pépper" },
  { name: "whitespace_pepper",    password: "changeme",      pepper: "   " },
  { name: "tab_newline_pepper",   password: "changeme",      pepper: "\t\n" },
  { name: "exactly_72_bytes",     password: "a" * 72,        pepper: "" },
  { name: "73_bytes",             password: "a" * 73,        pepper: "" },
  { name: "long_password",        password: "a" * 100,       pepper: "" },
  { name: "pepper_crosses_limit", password: "b" * 60,        pepper: "c" * 20 },
  { name: "unicode_split_by_cut", password: "d" * 71 + "é",  pepper: "" },
  { name: "spaces_in_password",   password: "  spaced  ",    pepper: "" },
  { name: "high_cost",            password: "changeme",      pepper: "", cost: 10 },
]

# Rails' Object#present? is !blank?, and String#blank? is this regexp. Copied
# rather than required so the script needs no activesupport.
BLANK_RE = /\A[[:space:]]*\z/

# Mirrors Devise::Encryptor.digest, including the pepper.present? guard.
def devise_digest(password, pepper, cost)
  password = "#{password}#{pepper}" unless BLANK_RE.match?(pepper.to_s)
  BCrypt::Password.create(password, cost: cost).to_s
end

fixtures = CASES.map do |c|
  cost = c[:cost] || COST
  {
    "name" => c[:name],
    "password" => c[:password],
    "pepper" => c[:pepper],
    "stretches" => cost,
    "hash" => devise_digest(c[:password], c[:pepper], cost),
  }
end

out = {
  "generated_by" => "ruby #{RUBY_VERSION} / bcrypt #{Gem.loaded_specs['bcrypt']&.version}",
  "fixtures" => fixtures,
}

File.write(
  File.expand_path("../testdata/devise_hashes.json", __dir__),
  JSON.pretty_generate(out) + "\n"
)

puts "wrote #{fixtures.length} fixtures"
