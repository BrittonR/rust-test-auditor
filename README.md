# Rust Test Auditor

A comprehensive tool for auditing Rust test suites to identify common anti-patterns and bad practices that can lead to unreliable, unclear, or unmaintainable tests.

## Features

The auditor detects **12 different types** of test quality issues:

### 🔴 Critical Issues (Red)
- **Test always passes (tautology)** - Tests with `assert!(true)` or self-comparing assertions
- **Empty test body** - Tests that don't do anything
- **Test has no assertions** - Tests that run code but never verify results
- **Errors improperly ignored** - Using `let _ =` to ignore errors or results
- **Non-deterministic test data** - Time-based or random values that can cause flaky tests

### 🟡 Warning Issues (Yellow)
- **Hardcoded expected values** - Comparing literals directly (e.g., `assert_eq!(42, 42)`)
- **Magic numbers/strings without context** - Unexplained constants in assertions
- **Misleading test name** - Function names that don't match the test behavior
- **Copy-pasted assertions** - Duplicate test bodies that suggest copy-paste errors
- **Unsafe unwrap() without error message** - Using `.unwrap()` instead of `.expect()` with descriptive messages
- **should_panic without specific message** - Vague `#[should_panic]` without expected error details
- **Tests implementation details** - Testing internal details like capacity instead of behavior

## Installation

```bash
git clone <repository-url>
cd rust-test-auditor
cargo build --release
```

## Usage

### Basic Usage

Audit the current directory:
```bash
cargo run
```

Audit a specific directory:
```bash
cargo run -- --path tests/
cargo run -- --path src/
```

### Command Line Options

```bash
cargo run -- --help
```

- `-p, --path <PATH>` - Path to the directory to audit (default: current directory)
- `-v, --verbose` - Enable verbose output

### Example Output

```
=== TEST AUDIT REPORT ===
Total issues found: 8

Test always passes (tautology) (2)
  📁 tests/example_test.rs
  📍 Line 15: Line matches pattern: Test always passes (tautology)
  💻 assert!(true);

  📁 tests/example_test.rs
  📍 Line 23: Tautological assertion - comparing variable to itself
  💻 assert_eq!(value, value);

Test has no assertions (1)
  📁 tests/example_test.rs
  📍 Line 28: Test function has no assertions or expectations
  💻 Test body: 4 lines

Non-deterministic test data (2)
  📁 tests/example_test.rs
  📍 Line 35: Line matches pattern: Non-deterministic test data
  💻 let now = SystemTime::now();

  📁 tests/example_test.rs
  📍 Line 42: Line matches pattern: Non-deterministic test data
  💻 let value = rand::random::<i32>();

❌ Issues found that may need attention.
```

## Examples of Detected Issues

### ❌ Bad Test Patterns

```rust
#[test]
fn test_always_passes() {
    assert!(true); // Always passes - not testing anything
}

#[test]
fn test_hardcoded() {
    assert_eq!(42, 42); // Comparing literals
}

#[test]
fn test_no_assertions() {
    let result = calculate_something();
    // No assertions - test always passes
}

#[test]
fn test_non_deterministic() {
    let now = SystemTime::now();
    let random_val = rand::random::<i32>();
    assert!(now.elapsed().unwrap().as_secs() < random_val); // Flaky!
}

#[should_panic] // Too vague
#[test]
fn test_should_fail() {
    panic!("something");
}

#[test]
fn test_magic_numbers() {
    let result = process_data();
    assert_eq!(result.len(), 42); // What is 42?
}
```

### ✅ Good Test Patterns

```rust
#[test]
fn test_addition() {
    let result = add(2, 3);
    assert_eq!(result, 5); // Clear expectation
}

#[test]
fn test_error_handling() {
    let result = divide(10, 0);
    assert!(result.is_err()); // Testing behavior
}

#[should_panic(expected = "division by zero")]
#[test]
fn test_panic_with_specific_message() {
    divide(5, 0).expect("division by zero");
}

#[test]
fn test_with_meaningful_constants() {
    const EXPECTED_USER_COUNT: usize = 5;
    let users = get_all_users();
    assert_eq!(users.len(), EXPECTED_USER_COUNT);
}
```

## Integration with CI/CD

You can integrate the test auditor into your CI pipeline:

```yaml
# .github/workflows/test-audit.yml
name: Test Quality Audit
on: [push, pull_request]

jobs:
  test-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
      - name: Run Test Auditor
        run: |
          git clone https://github.com/your-username/rust-test-auditor
          cd rust-test-auditor
          cargo run -- --path ../tests/
```

## Development

### Running Tests

```bash
cargo test
```

### Running the Auditor on Itself

```bash
# Audit the source code (should be clean)
cargo run -- --path src/

# Audit the integration tests (intentionally contains bad patterns for testing)
cargo run -- --path tests/
```

### Adding New Detection Patterns

1. Add new `IssueType` variant in `src/main.rs`
2. Add color and description in the `impl IssueType` blocks
3. Add detection pattern to `issue_patterns` in `TestAuditor::new()`
4. Add unit tests for the new pattern
5. Update integration tests to verify detection

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new detection patterns
4. Ensure all tests pass
5. Submit a pull request

## License

[Add your license here]

## Acknowledgments

Inspired by tools like `clippy` for Rust and various test quality analysis tools in other languages.