# Audit

Your goal is to identify and address vulnerable or outdated dependencies.

## Prerequisites

1. Check if cargo-audit is installed by running `cargo audit --version`. If not
   installed, install it with `cargo install cargo-audit`
2. Check if cargo-outdated is installed by running `cargo outdated --version`.
   If not installed, install it with `cargo install cargo-outdated`

## Audit Process

1. Run `cargo audit` to find vulnerable dependencies
2. Run `cargo outdated` to identify dependencies with newer versions available
3. **Review findings before taking action:**
   - Not all vulnerabilities require immediate action (e.g., if the vulnerable
     code path isn't used in this project)
   - Check if vulnerabilities are in direct dependencies vs transitive ones
   - Review the advisory details to understand severity and impact
   - Consider whether major version updates might introduce breaking changes

## Remediation

1. For vulnerabilities that need addressing:
   - Run `cargo update` to update to patched versions within semver bounds
   - If a major version update is needed, update Cargo.toml manually
2. Run `cargo test` to verify the updates didn't break anything
3. Run `cargo audit` again to confirm vulnerabilities are resolved

## Severity Guidelines

- **Critical/High**: Address immediately if the vulnerable code path is used
- **Medium**: Plan to address soon, especially for security-sensitive code
- **Low/Informational**: Address when convenient, or accept the risk if the
  code path isn't relevant to this project
