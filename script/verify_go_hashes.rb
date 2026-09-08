#!/usr/bin/env ruby
# Reads {"fixtures":[{name,password,pepper,hash}]} on stdin and checks each
# Go-produced hash with the real Ruby bcrypt gem. Prints one result line per
# fixture and exits non-zero on any mismatch. Driven by TestGoHashesVerifyInRuby,
# which is the only check that Go hashes are readable by Rails.

require "bcrypt"
require "json"

# Rails' String#blank?, mirroring the pepper.present? guard in Devise::Encryptor.
BLANK_RE = /\A[[:space:]]*\z/

input = JSON.parse($stdin.read)
fixtures = input["fixtures"] || []

abort "no fixtures on stdin" if fixtures.empty?

failed = 0

fixtures.each do |f|
  secret = f["password"].to_s
  pepper = f["pepper"].to_s
  secret = "#{secret}#{pepper}" unless BLANK_RE.match?(pepper)

  begin
    ok = BCrypt::Password.new(f["hash"]) == secret
    detail = ok ? "" : " (hash #{f['hash'].inspect} rejects password #{f['password'].inspect})"
  rescue BCrypt::Errors::InvalidHash => e
    ok = false
    detail = " (#{e.class}: #{f['hash'].inspect})"
  end

  failed += 1 unless ok
  puts "#{ok ? 'ok' : 'FAIL'} #{f['name']}#{detail}"
end

puts "#{fixtures.length - failed}/#{fixtures.length} Go hashes verified in Ruby"

exit(failed.zero? ? 0 : 1)
