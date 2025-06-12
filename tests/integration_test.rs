use std::fs;
use tempfile::tempdir;
use std::io::Write;

#[test]
fn test_audit_real_test_file() {
    let dir = tempdir().unwrap();
    let test_file = dir.path().join("sample_test.rs");
    let mut file = fs::File::create(&test_file).unwrap();
    
    writeln!(file, r#"
#[cfg(test)]
mod tests {{
    use super::*;

    #[test]
    fn test_always_passes() {{
        assert!(true);
    }}

    #[test]
    fn test_hardcoded() {{
        assert_eq!(42, 42);
    }}

    #[test] fn test_empty() {{}}

    #[test]
    fn test_error_ignored() {{
        let result = Some(5);
        let _ = result.unwrap();
    }}

    #[test]
    fn test_no_assertions() {{
        let value = calculate_something();
        // No assertions - test always passes!
    }}

    #[test]
    fn test_non_deterministic() {{
        use std::time::SystemTime;
        let now = SystemTime::now();
        let value = rand::random::<i32>();
        assert!(now.elapsed().unwrap().as_secs() < value);
    }}

    #[should_panic]
    #[test] 
    fn test_vague_panic() {{
        panic!("something went wrong");
    }}

    #[test]
    fn test_magic_numbers() {{
        let result = process_data();
        assert_eq!(result.len(), 42);
        assert!(result.capacity() > 1337);
    }}

    #[test]
    fn test_duplicate_1() {{
        let x = 5;
        assert_eq!(x, 5);
    }}

    #[test]
    fn test_duplicate_2() {{
        let x = 5;
        assert_eq!(x, 5);
    }}
}}"#).unwrap();

    // Run the auditor binary
    let output = std::process::Command::new("cargo")
        .args(&["run", "--", "-p", dir.path().to_str().unwrap()])
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8(output.stdout).unwrap();
    let _stderr = String::from_utf8(output.stderr).unwrap();
    
    // Verify the output contains expected issues
    assert!(stdout.contains("Test always passes"));
    assert!(stdout.contains("Hardcoded expected values"));
    assert!(stdout.contains("Empty test body"));
    assert!(stdout.contains("Errors improperly ignored"));
    assert!(stdout.contains("Copy-pasted assertions"));
    assert!(stdout.contains("Test has no assertions"));
    assert!(stdout.contains("Non-deterministic test data"));
    assert!(stdout.contains("should_panic without specific message"));
    assert!(stdout.contains("Magic numbers/strings without context"));
}

#[test]
fn test_no_issues_found() {
    let dir = tempdir().unwrap();
    let test_file = dir.path().join("good_test.rs");
    let mut file = fs::File::create(&test_file).unwrap();
    
    writeln!(file, r#"
#[cfg(test)]
mod tests {{
    use super::*;

    #[test]
    fn test_addition() {{
        let result = add(2, 3);
        assert_eq!(result, 5);
    }}

    #[test]
    fn test_error_handling() {{
        let result = divide(10, 0);
        assert!(result.is_err());
    }}

    #[test]
    fn test_boundary_condition() {{
        let result = process_value(i32::MAX);
        assert!(result.is_ok());
    }}
}}"#).unwrap();

    // Run the auditor binary
    let output = std::process::Command::new("cargo")
        .args(&["run", "--", "-p", dir.path().to_str().unwrap()])
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8(output.stdout).unwrap();
    
    // Verify no issues found
    assert!(stdout.contains("No issues found"));
}

#[test]
fn test_misleading_names() {
    let dir = tempdir().unwrap();
    let test_file = dir.path().join("misleading_test.rs");
    let mut file = fs::File::create(&test_file).unwrap();
    
    writeln!(file, r#"
#[cfg(test)]
mod tests {{
    #[test]
    fn test_should_fail() {{
        assert!(true);
    }}

    #[test]
    fn test_success_case() {{
        panic!("This should not happen");
    }}
}}"#).unwrap();

    // Run the auditor binary
    let output = std::process::Command::new("cargo")
        .args(&["run", "--", "-p", dir.path().to_str().unwrap()])
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8(output.stdout).unwrap();
    
    // Verify misleading names are detected
    assert!(stdout.contains("Misleading test name"));
}