// Examples of BAD test patterns that the auditor should catch
// This file demonstrates common anti-patterns in test writing

#[cfg(test)]
mod tests {
    use std::time::SystemTime;
    
    // ❌ Test always passes (tautology)
    #[test]
    fn test_always_passes() {
        assert!(true); // This always passes - not testing anything
    }
    
    // ❌ Hardcoded comparison
    #[test]
    fn test_hardcoded_values() {
        assert_eq!(42, 42); // Comparing literals
    }
    
    // ❌ Tautological assertion
    #[test]
    fn test_tautology() {
        let value = 5;
        assert_eq!(value, value); // Comparing variable to itself
    }
    
    // ❌ Empty test body
    #[test]
    fn test_empty() {
        // This test does nothing
    }
    
    // ❌ Test with no assertions
    #[test]
    fn test_no_assertions() {
        let result = calculate_something();
        let _processed = process_result(result);
        // No assertions - test always passes
    }
    
    // ❌ Errors improperly ignored
    #[test]
    fn test_error_ignored() {
        let result = risky_operation();
        let _ = result.unwrap(); // Ignoring the result
    }
    
    // ❌ Non-deterministic test data
    #[test]
    fn test_non_deterministic() {
        let now = SystemTime::now();
        let random_val = rand::random::<i32>();
        assert!(now.elapsed().unwrap().as_secs() < random_val as u64); // Flaky!
    }
    
    // ❌ Vague should_panic
    #[should_panic]
    #[test]
    fn test_should_fail() {
        panic!("something went wrong");
    }
    
    // ❌ Magic numbers without context
    #[test]
    fn test_magic_numbers() {
        let result = process_data();
        assert_eq!(result.len(), 42); // What is 42?
        assert!(result.capacity() > 1337); // Testing implementation details
    }
    
    // ❌ Unsafe unwrap without message
    #[test]
    fn test_unsafe_unwrap() {
        let result = parse_number("123");
        let value = result.unwrap(); // Should use expect() with message
        assert_eq!(value, 123);
    }
    
    // ❌ Misleading test name
    #[test]
    fn test_addition() {
        let result = multiply(2, 3); // Name says addition, code does multiplication
        assert_eq!(result, 6);
    }
    
    // Helper functions for examples
    fn calculate_something() -> i32 { 42 }
    fn process_result(x: i32) -> i32 { x * 2 }
    fn risky_operation() -> Result<i32, &'static str> { Ok(123) }
    fn process_data() -> Vec<i32> { vec![1, 2, 3] }
    fn parse_number(s: &str) -> Result<i32, std::num::ParseIntError> { s.parse() }
    fn multiply(a: i32, b: i32) -> i32 { a * b }
}