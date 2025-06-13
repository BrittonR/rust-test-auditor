use rust_test_auditor::{TestAuditor, Config};
use std::fs;
use tempfile::tempdir;

#[test]
fn test_ast_integration_empty_test() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("test.rs");
    
    fs::write(&file_path, r#"
        #[test]
        fn test_empty() {
        }
    "#).unwrap();

    let mut auditor = TestAuditor::with_config(Config::default(), dir.path().to_path_buf()).unwrap();
    auditor.audit_file(&file_path).unwrap();

    // Should detect empty test
    let empty_test_issues: Vec<_> = auditor.issues.iter()
        .filter(|issue| matches!(issue.issue_type, rust_test_auditor::IssueType::EmptyTest))
        .collect();
    
    assert!(!empty_test_issues.is_empty(), "Should detect empty test function");
}

#[test]
fn test_ast_integration_unused_variable() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("test.rs");
    
    fs::write(&file_path, r#"
        #[test]
        fn test_with_unused() {
            let unused = 42;
            assert!(true);
        }
    "#).unwrap();

    let mut auditor = TestAuditor::with_config(Config::default(), dir.path().to_path_buf()).unwrap();
    auditor.audit_file(&file_path).unwrap();

    // Should detect unused variable
    let unused_var_issues: Vec<_> = auditor.issues.iter()
        .filter(|issue| matches!(issue.issue_type, rust_test_auditor::IssueType::UnusedVariable))
        .collect();
    
    assert!(!unused_var_issues.is_empty(), "Should detect unused variable");
}

#[test]
fn test_ast_integration_unwrap_detection() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("test.rs");
    
    fs::write(&file_path, r#"
        #[test]
        fn test_unwrap() {
            let result = Some(42);
            let value = result.unwrap();
            assert_eq!(value, 42);
        }
    "#).unwrap();

    let mut auditor = TestAuditor::with_config(Config::default(), dir.path().to_path_buf()).unwrap();
    auditor.audit_file(&file_path).unwrap();

    // Should detect unsafe unwrap
    let unwrap_issues: Vec<_> = auditor.issues.iter()
        .filter(|issue| matches!(issue.issue_type, rust_test_auditor::IssueType::UnsafeUnwrap))
        .collect();
    
    assert!(!unwrap_issues.is_empty(), "Should detect unsafe unwrap");
}

#[test]
fn test_ast_integration_comprehensive() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("test.rs");
    
    fs::write(&file_path, r#"
        #[test]
        fn test_good() {
            let input = 42;
            let result = input * 2;
            assert_eq!(result, 84);
        }

        #[test]
        fn test_empty() {
        }

        #[test]
        fn test_unused_var() {
            let unused = 99;
            let used = 42;
            assert_eq!(used, 42);
        }

        #[test]
        fn test_no_assertions() {
            let value = 42;
            println!("Value: {}", value);
        }

        #[test]
        fn test_unsafe_unwrap() {
            let opt = Some(42);
            let val = opt.unwrap();
            assert_eq!(val, 42);
        }
    "#).unwrap();

    let mut auditor = TestAuditor::with_config(Config::default(), dir.path().to_path_buf()).unwrap();
    auditor.audit_file(&file_path).unwrap();

    println!("Found {} total issues", auditor.issues.len());
    
    // Print all issues for debugging
    for issue in &auditor.issues {
        println!("Issue: {:?} - {}", issue.issue_type, issue.description);
    }

    // Should detect multiple issue types
    let empty_test_count = auditor.issues.iter()
        .filter(|issue| matches!(issue.issue_type, rust_test_auditor::IssueType::EmptyTest))
        .count();
    
    let unused_var_count = auditor.issues.iter()
        .filter(|issue| matches!(issue.issue_type, rust_test_auditor::IssueType::UnusedVariable))
        .count();
    
    let no_assertions_count = auditor.issues.iter()
        .filter(|issue| matches!(issue.issue_type, rust_test_auditor::IssueType::NoAssertions))
        .count();
    
    let unsafe_unwrap_count = auditor.issues.iter()
        .filter(|issue| matches!(issue.issue_type, rust_test_auditor::IssueType::UnsafeUnwrap))
        .count();

    assert!(empty_test_count >= 1, "Should detect at least 1 empty test");
    assert!(unused_var_count >= 1, "Should detect at least 1 unused variable");
    assert!(no_assertions_count >= 1, "Should detect at least 1 test with no assertions");
    assert!(unsafe_unwrap_count >= 1, "Should detect at least 1 unsafe unwrap");
}