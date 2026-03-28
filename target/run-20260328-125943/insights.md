# What Worked

- Thin Make wrappers over one Rust-owned blocker contract remain the right design.
- Explicit self-test aliases are easier for operators than profile overrides.
- Docs tests caught drift quickly once the remediation wording changed.

# What Failed

- Canonical blocker text lagged behind the newer self-test path.
- Leaving both the old profile override wording and the new self-test aliases in circulation created operator confusion.

# What To Avoid Next Time

- Do not add new operator aliases without updating the live Rust remediation text in the same change.
- Do not auto-fallback from canonical `/srv` to local state.

# Promising Next Directions

- Keep reviewing operator-visible blocker text whenever a manual-lab verb or alias is added.
- Consider a docs or contract test that explicitly asserts the canonical `missing_store_root` remediation advertises the current self-test quick path.
