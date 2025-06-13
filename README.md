# Rust Test Auditor

A comprehensive tool for auditing Rust test suites to identify common anti-patterns and bad practices that can lead to unreliable, unclear, or unmaintainable tests.

## 🚀 Key Features

### **Dual Analysis Engine**
- **🧩 AST-Based Analysis** - Advanced semantic analysis using Abstract Syntax Trees
- **🔍 Regex-Based Detection** - Fast pattern matching for common anti-patterns
- **⚡ Hybrid Processing** - Combines both approaches for comprehensive coverage

### **Sophisticated Detection Capabilities**
The auditor detects **20+ different types** of test quality issues using advanced static analysis:

### 🔴 Critical Issues (Red)
- **Empty test body** - Tests that don't do anything (AST)
- **Test always passes (tautology)** - Tests with `assert!(true)` or self-comparing assertions
- **Test has no assertions** - Tests that run code but never verify results (AST)
- **Unreachable code** - Code after `return` or `panic!` statements (AST)
- **Errors improperly ignored** - Using `let _ =` to ignore errors or results
- **Non-deterministic test data** - Time-based or random values that can cause flaky tests
- **Flaky test patterns** - Tests with timing dependencies or retry logic
- **Async test issues** - Incorrect async/await usage in tests

### 🟡 Warning Issues (Yellow)
- **Unused variables** - Variables declared but never used in tests (AST)
- **Unsafe unwrap calls** - `.unwrap()` and `.expect()` without proper error handling (AST)
- **Hardcoded expected values** - Comparing literals directly (e.g., `assert_eq!(42, 42)`)
- **Magic numbers/strings without context** - Unexplained constants in assertions
- **Misleading test name** - Function names that don't match the test behavior
- **Copy-pasted assertions** - Duplicate test bodies that suggest copy-paste errors
- **Debug output** - `println!`, `dbg!`, etc. left in test code
- **Commented-out code** - Dead code in test files
- **TODO comments** - Incomplete test implementations
- **should_panic without specific message** - Vague `#[should_panic]` without expected error details
- **Tests implementation details** - Testing internal details like capacity instead of behavior

### 🆕 **Advanced AST-Based Detection**
The auditor now includes sophisticated Abstract Syntax Tree analysis that understands Rust code structure:

- **Semantic Analysis** - Understands variable scope, usage, and control flow
- **Code Structure Analysis** - Detects unreachable code patterns
- **Type-Aware Detection** - More accurate identification of test patterns
- **Macro Parsing** - Basic analysis of assertion macros and test attributes

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
cargo run -- --path docs/examples/
```

### Command Line Options

```bash
cargo run -- --help
```

- `-p, --path <PATH>` - Path to the directory to audit (default: current directory)
- `-v, --verbose` - Enable verbose output
- `-j, --json` - Output in JSON format
- `-x, --xml` - Output in XML format
- `--no-color` - Disable colored output
- `-c, --config <CONFIG_FILE>` - Path to configuration file

### Example Output

```
=== TEST AUDIT REPORT ===
Total issues found: 12

Empty test body (1)
  📁 tests/example_test.rs
  📍 Line 5: Test function 'test_empty' has an empty body
  💻 fn test_empty() { }

Variable declared but never used in test (2)
  📁 tests/example_test.rs
  📍 Line 1: Variable 'unused' is declared but never used in test
  💻 let unused = ...

  📁 tests/example_test.rs
  📍 Line 1: Variable 'result' is declared but never used in test
  💻 let result = ...

Unsafe unwrap() without error message (1)
  📁 tests/example_test.rs
  📍 Line 15: Unsafe unwrap call without proper error handling
  💻 receiver.unwrap()

Test always passes (tautology) (2)
  📁 tests/example_test.rs
  📍 Line 20: Line matches pattern: Test always passes (tautology)
  💻 assert!(true);

  📁 tests/example_test.rs
  📍 Line 25: Tautological assertion - comparing variable to itself
  💻 assert_eq!(value, value);

Test has no assertions (1)
  📁 tests/example_test.rs
  📍 Line 30: Test function 'test_no_assertions' has no assertions
  💻 fn test_no_assertions() { ... }

Unreachable code detected in test function (1)
  📁 tests/example_test.rs
  📍 Line 35: Code after return or panic statement is unreachable
  💻 unreachable code

Non-deterministic test data (2)
  📁 tests/example_test.rs
  📍 Line 40: Line matches pattern: Non-deterministic test data
  💻 let now = SystemTime::now();

  📁 tests/example_test.rs
  📍 Line 45: Line matches pattern: Non-deterministic test data
  💻 let value = rand::random::<i32>();

Magic numbers/strings without context (2)
  📁 tests/example_test.rs
  📍 Line 50: Line matches pattern: Magic numbers/strings without context
  💻 assert_eq!(result, 42);

❌ Issues found that may need attention.
```

## Examples of Detected Issues

### ❌ Bad Test Patterns

```rust
#[test]
fn test_empty() {
    // AST detects: Empty test body
}

#[test]
fn test_unused_variables() {
    // AST detects: Unused variable 'unused_var'
    let unused_var = 42;
    let used_var = 100;
    assert_eq!(used_var, 100);
}

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
    // AST detects: Test has no assertions
    let result = calculate_something();
    println!("Result: {}", result);
}

#[test]
fn test_unsafe_unwrap() {
    // AST detects: Unsafe unwrap without error handling
    let result = Some(42);
    let value = result.unwrap();
    assert_eq!(value, 42);
}

#[test]
fn test_unreachable_code() {
    // AST detects: Unreachable code after return
    let x = 42;
    assert_eq!(x, 42);
    return;
    
    // This code is unreachable and will be flagged
    let y = 24;
    assert_eq!(y, 24);
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
fn test_addition_returns_correct_sum() {
    // All variables used, clear assertions
    let input1 = 2;
    let input2 = 3;
    let result = add(input1, input2);
    assert_eq!(result, 5, "Addition should return correct sum");
}

#[test]
fn test_error_handling_with_proper_expect() {
    let result = divide(10, 0);
    assert!(result.is_err(), "Division by zero should return error");
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
    assert_eq!(
        users.len(), 
        EXPECTED_USER_COUNT,
        "Should have exactly {} users", 
        EXPECTED_USER_COUNT
    );
}

#[test]
fn test_proper_error_handling() {
    // Good: Using expect instead of unwrap
    let result = Some(42);
    let value = result.expect("Should have a value");
    assert_eq!(value, 42);
}
```

## Output Formats

The auditor supports multiple output formats:

### Console Output (Default)
Human-readable colored output with issue descriptions and code snippets.

### JSON Output
Machine-readable JSON format for integration with other tools:
```bash
cargo run -- --json
```

### XML Output
XML format for systems that prefer XML over JSON:
```bash
cargo run -- --xml
```

## Examples

See the `docs/examples/` directory for:
- `bad_tests.rs` - Examples of poor testing practices that the auditor detects
- `good_tests.rs` - Examples of good testing practices to follow
- `ast_examples.rs` - Examples showcasing AST-based analysis capabilities
- `README.md` - Detailed explanations of each pattern

### Real-World Performance

When run on its own codebase, the auditor demonstrates its effectiveness:

```bash
# Running on the project's own test files
$ cargo run -- -p tests/
Found 2 test files
Total issues found: 270

# Categories detected:
- Magic numbers/strings: 19 instances
- Unused variables: 152 instances (AST analysis)
- Unsafe unwraps: 99 instances  
- Copy-pasted tests: 10 instances
- Debug output: 4 instances
- And many more...
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

# Audit the example files
cargo run -- --path docs/examples/
```

### Architecture

The auditor uses a **hybrid analysis approach**:

1. **AST Analysis** (`src/ast_analyzer.rs`)
   - Parses Rust code into Abstract Syntax Trees using the `syn` crate
   - Performs semantic analysis with visitor pattern
   - Detects structural issues like unused variables and unreachable code

2. **Regex Analysis** (`src/patterns.rs`)
   - Fast pattern matching for common anti-patterns
   - Detects text-based issues like magic numbers and debug output

3. **Hybrid Integration** (`src/auditor.rs`)
   - Combines both analysis methods
   - Filters results based on configuration
   - Provides unified reporting

### Adding New Detection Patterns

#### For Regex-Based Patterns:
1. Add new `IssueType` variant in `src/issue.rs`
2. Add color and description in the `impl IssueType` blocks
3. Add detection pattern to `ISSUE_PATTERNS` in `src/patterns.rs`
4. Add unit tests for the new pattern

#### For AST-Based Patterns:
1. Add new `IssueType` variant in `src/issue.rs`
2. Add detection logic in `src/ast_analyzer.rs` visitor methods
3. Add rule configuration in `src/config.rs`
4. Add comprehensive unit tests

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new detection patterns
4. Ensure all tests pass
5. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Acknowledgments

Inspired by tools like `clippy` for Rust and various test quality analysis tools in other languages.