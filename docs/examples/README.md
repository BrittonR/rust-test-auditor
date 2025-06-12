# Examples

This directory contains example Rust test files that demonstrate various testing patterns.

## Files

### `bad_tests.rs`
Examples of **poor testing practices** that the auditor will detect and flag:
- Tests that always pass (tautologies)
- Empty test bodies
- Tests without assertions
- Non-deterministic test data
- Hardcoded values and magic numbers
- Unsafe unwrap usage
- Misleading test names
- And more...

### `good_tests.rs`
Examples of **good testing practices** that demonstrate:
- Clear, descriptive test names
- Proper error handling with `expect()`
- Deterministic test data
- Testing behavior rather than implementation details
- Meaningful constants instead of magic numbers
- Proper async test patterns
- Comprehensive edge case testing

## Usage

You can run the auditor on these examples to see how it detects issues:

```bash
# This should find many issues
cargo run -- --path examples/bad_tests.rs

# This should find few or no issues
cargo run -- --path examples/good_tests.rs

# Audit all examples
cargo run -- --path examples/
```

## Learning

Compare the patterns in `bad_tests.rs` with their improved versions in `good_tests.rs` to understand:
- What makes a test reliable and maintainable
- How to write clear, self-documenting tests
- Best practices for error handling in tests
- Techniques for avoiding flaky tests
- How to test behavior rather than implementation details

These examples serve as both documentation and validation for the test auditor's detection capabilities.