# Retired cases

Cases for risks that omamori no longer checks with AI. They are kept for reference and are not loaded by `evals/run.rb`.

- `dependency_trojan_package/`: malicious or typosquatted packages cannot be judged reliably from code. Use bundler-audit (run by omamori) for known vulnerable versions, and a malicious-package scanner such as OSV-Scanner or GitHub dependency review.
- `inappropriate_cookie_attributes/vulnerable-embed-cookie-samesite-none-no-secure.yml`: the label was not right. Browsers reject a SameSite=None cookie without Secure, and Rails 8's default production settings (force_ssl) add Secure anyway, so the change breaks the embed rather than weakening security.
