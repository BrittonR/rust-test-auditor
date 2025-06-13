// Examples showcasing AST-based analysis capabilities
// These tests demonstrate advanced patterns that AST analysis can detect

#[test]
fn test_empty_function() {
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
fn test_no_assertions() {
    // AST detects: Test has no assertions
    let value = compute_something();
    println!("Computed: {}", value);
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
fn test_unreachable_after_panic() {
    // AST detects: Unreachable code after panic
    let condition = false;
    if !condition {
        panic!("Condition failed");
        // This code is unreachable
        let never_reached = true;
        assert!(never_reached);
    }
}

// Helper function for examples
fn compute_something() -> i32 {
    42
}

#[test]
fn test_good_practices() {
    // This test follows good practices and should not trigger AST warnings
    let input = 42;
    let result = input * 2;
    assert_eq!(result, 84, "Multiplication should work correctly");
}

#[test]
fn test_proper_error_handling() {
    // Good: Using expect instead of unwrap
    let result = Some(42);
    let value = result.expect("Should have a value");
    assert_eq!(value, 42);
}