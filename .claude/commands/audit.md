# Audit

Your goal is to update any vulnerable dependencies.

Do the following:

1. Check if cargo-audit is installed by running 'cargo audit --version'. If not
   installed, install it with 'cargo install cargo-audit'
2. Run 'cargo audit' to find vulnerable dependencies in this project
3. Run 'cargo update' to update dependencies to patched versions
4. Run 'cargo test' to verify the updates didn't break anything
