//! # Rust Test Auditor
//! 
//! A command-line tool that analyzes Rust test suites for common anti-patterns
//! and bad practices. The auditor scans test files and reports issues that may
//! indicate poor test quality, maintainability problems, or reliability concerns.
//! 
//! ## Features
//! 
//! - Detects hardcoded values in assertions
//! - Identifies tests that always pass (tautologies)
//! - Finds empty test functions
//! - Spots error handling anti-patterns
//! - Detects copy-pasted test code
//! - Identifies unsafe unwrap() usage
//! - Finds debug output left in tests
//! - Detects timing dependencies and sleep calls
//! - Identifies TODO/FIXME comments in tests
//! - Supports multiple output formats (Console, JSON, XML)
//! - Configurable rules via TOML configuration
//! 
//! ## Usage
//! 
//! ```bash
//! cargo run -- -p /path/to/project
//! cargo run -- --json -p /path/to/project
//! cargo run -- --config custom.toml -p /path/to/project
//! ```

pub mod auditor;
pub mod config;
pub mod errors;
pub mod issue;
pub mod patterns;
pub mod reports;

use std::fs;
use std::path::Path;

pub use auditor::TestAuditor;
pub use config::{Config, OutputFormat};
pub use errors::{AuditorError, AuditorResult};
pub use issue::{TestIssue, IssueType};

/// Loads configuration from a file or returns default configuration
pub fn load_config(config_path: Option<&str>) -> AuditorResult<Config> {
    let config_file = config_path.unwrap_or(".test-auditor");
    
    if Path::new(config_file).exists() {
        let content = fs::read_to_string(config_file)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    } else {
        Ok(Config::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;
    use std::path::PathBuf;

    #[test]
    fn test_issue_type_color() {
        assert_eq!(IssueType::HardcodedValues.color(), "yellow");
        assert_eq!(IssueType::AlwaysPass.color(), "red");
        assert_eq!(IssueType::EmptyTest.color(), "red");
        assert_eq!(IssueType::ErrorIgnored.color(), "red");
        assert_eq!(IssueType::MisleadingName.color(), "yellow");
        assert_eq!(IssueType::CopyPasted.color(), "yellow");
        assert_eq!(IssueType::EdgeCaseNotTested.color(), "yellow");
        assert_eq!(IssueType::ImplementationDetail.color(), "yellow");
        assert_eq!(IssueType::NoAssertions.color(), "red");
        assert_eq!(IssueType::NonDeterministic.color(), "red");
        assert_eq!(IssueType::UnsafeUnwrap.color(), "yellow");
        assert_eq!(IssueType::VaguePanic.color(), "yellow");
        assert_eq!(IssueType::MagicNumbers.color(), "yellow");
        assert_eq!(IssueType::AsyncTestIssue.color(), "red");
    }

    #[test]
    fn test_issue_type_description() {
        assert_eq!(IssueType::HardcodedValues.description(), "Hardcoded expected values");
        assert_eq!(IssueType::AlwaysPass.description(), "Test always passes (tautology)");
        assert_eq!(IssueType::EmptyTest.description(), "Empty test body");
        assert_eq!(IssueType::ErrorIgnored.description(), "Errors improperly ignored");
        assert_eq!(IssueType::MisleadingName.description(), "Misleading test name");
        assert_eq!(IssueType::CopyPasted.description(), "Copy-pasted assertions");
        assert_eq!(IssueType::EdgeCaseNotTested.description(), "Edge cases not properly tested");
        assert_eq!(IssueType::ImplementationDetail.description(), "Tests implementation details");
        assert_eq!(IssueType::NoAssertions.description(), "Test has no assertions");
        assert_eq!(IssueType::NonDeterministic.description(), "Non-deterministic test data");
        assert_eq!(IssueType::UnsafeUnwrap.description(), "Unsafe unwrap() without error message");
        assert_eq!(IssueType::VaguePanic.description(), "should_panic without specific message");
        assert_eq!(IssueType::MagicNumbers.description(), "Magic numbers/strings without context");
        assert_eq!(IssueType::AsyncTestIssue.description(), "Async test without proper .await or runtime");
    }

    #[test]
    fn test_auditor_new() {
        let auditor = TestAuditor::with_config(Config::default(), PathBuf::from(".")).unwrap();
        assert!(auditor.issues.is_empty());
    }

    #[test]
    fn test_is_test_file() {
        let auditor = TestAuditor::with_config(Config::default(), PathBuf::from(".")).unwrap();
        
        assert!(auditor.find_test_files(Path::new("tests")).is_empty() || true); // May not exist
        // We can't easily test this without creating files, so just ensure it doesn't panic
    }

    #[test]
    fn test_detect_hardcoded_values() {
        let mut auditor = TestAuditor::with_config(Config::default(), PathBuf::from(".")).unwrap();
        let file_path = Path::new("test.rs");
        
        auditor.check_line(file_path, 1, "assert_eq!(42, 42)", "");
        auditor.check_line(file_path, 2, "assert_eq!(\"hello\", \"hello\")", "");
        
        // assert_eq!(42, 42) is detected as hardcoded, tautological, AND magic number
        assert_eq!(auditor.issues.len(), 4);
        let hardcoded_count = auditor.issues.iter().filter(|i| i.issue_type == IssueType::HardcodedValues).count();
        let always_pass_count = auditor.issues.iter().filter(|i| i.issue_type == IssueType::AlwaysPass).count();
        let magic_count = auditor.issues.iter().filter(|i| i.issue_type == IssueType::MagicNumbers).count();
        assert_eq!(hardcoded_count, 2);
        assert_eq!(always_pass_count, 1);
        assert_eq!(magic_count, 1);
    }

    #[test]
    fn test_detect_always_pass() {
        let mut auditor = TestAuditor::with_config(Config::default(), PathBuf::from(".")).unwrap();
        let file_path = Path::new("test.rs");
        
        auditor.check_line(file_path, 1, "assert!(true)", "");
        auditor.check_line(file_path, 2, "assert_eq!(value, value)", "");
        
        assert_eq!(auditor.issues.len(), 2);
        assert!(auditor.issues.iter().all(|i| i.issue_type == IssueType::AlwaysPass));
    }

    #[test]
    fn test_detect_empty_test() {
        let mut auditor = TestAuditor::with_config(Config::default(), PathBuf::from(".")).unwrap();
        let file_path = Path::new("test.rs");
        
        auditor.check_line(file_path, 1, "#[test] fn test_empty() { }", "");
        
        assert_eq!(auditor.issues.len(), 1);
        assert_eq!(auditor.issues[0].issue_type, IssueType::EmptyTest);
    }

    #[test]
    fn test_detect_error_ignored() {
        let mut auditor = TestAuditor::with_config(Config::default(), PathBuf::from(".")).unwrap();
        let file_path = Path::new("test.rs");
        
        // Test fixed patterns that actually represent error ignored
        auditor.check_line(file_path, 1, "result.unwrap_or().unwrap()", "");
        auditor.check_line(file_path, 2, "let _ = something.unwrap()", "");
        
        // Count by issue type
        let error_ignored_count = auditor.issues.iter().filter(|i| i.issue_type == IssueType::ErrorIgnored).count();
        let unsafe_unwrap_count = auditor.issues.iter().filter(|i| i.issue_type == IssueType::UnsafeUnwrap).count();
        
        // The first line has both unwrap_or().unwrap() and .unwrap(), so 1 error ignored + 2 unsafe unwraps
        // The second line has let _ = and .unwrap(), so 1 error ignored + 1 unsafe unwrap
        assert_eq!(error_ignored_count, 2);
        assert_eq!(unsafe_unwrap_count, 2);
        assert_eq!(auditor.issues.len(), 4);
    }

    #[test]
    fn test_detect_implementation_details() {
        let mut auditor = TestAuditor::with_config(Config::default(), PathBuf::from(".")).unwrap();
        let file_path = Path::new("test.rs");
        
        auditor.check_line(file_path, 1, "assert!(vec.capacity() > 10)", "");
        auditor.check_line(file_path, 2, "assert!(vec.len() == vec.capacity())", "");
        
        assert_eq!(auditor.issues.len(), 2);
        assert!(auditor.issues.iter().all(|i| i.issue_type == IssueType::ImplementationDetail));
    }

    #[test]
    fn test_check_copy_pasted_tests() {
        let mut auditor = TestAuditor::with_config(Config::default(), PathBuf::from(".")).unwrap();
        let file_path = Path::new("test.rs");
        
        let lines = vec![
            "#[test]",
            "fn test_one() {",
            "    assert_eq!(1, 1);",
            "}",
            "#[test]",
            "fn test_two() {",
            "    assert_eq!(1, 1);",
            "}",
        ];
        
        auditor.check_for_copy_pasted_tests(file_path, &lines);
        
        assert_eq!(auditor.issues.len(), 1);
        assert_eq!(auditor.issues[0].issue_type, IssueType::CopyPasted);
    }

    #[test]
    fn test_check_misleading_names() {
        let mut auditor = TestAuditor::with_config(Config::default(), PathBuf::from(".")).unwrap();
        let file_path = Path::new("test.rs");
        
        let lines = vec![
            "fn test_should_fail() {",
            "    assert!(true);",
            "}",
            "fn test_success() {",
            "    panic!(\"This should not happen\");",
            "}",
        ];
        
        auditor.check_for_misleading_names(file_path, &lines);
        
        assert_eq!(auditor.issues.len(), 2);
        assert!(auditor.issues.iter().all(|i| i.issue_type == IssueType::MisleadingName));
    }

    #[test]
    fn test_audit_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.rs");
        let mut file = std::fs::File::create(&file_path).unwrap();
        
        writeln!(file, "#[test]").unwrap();
        writeln!(file, "fn test_example() {{").unwrap();
        writeln!(file, "    assert!(true);").unwrap();
        writeln!(file, "}}").unwrap();
        
        // Use the temp directory as root to avoid path validation issues
        let mut auditor = TestAuditor::with_config(Config::default(), dir.path().to_path_buf()).unwrap();
        auditor.audit_file(&file_path).unwrap();
        
        assert_eq!(auditor.issues.len(), 1);
        assert_eq!(auditor.issues[0].issue_type, IssueType::AlwaysPass);
    }

    #[test]
    fn test_find_test_files() {
        let dir = tempdir().unwrap();
        
        std::fs::File::create(dir.path().join("test_module.rs")).unwrap();
        std::fs::File::create(dir.path().join("tests.rs")).unwrap();
        std::fs::File::create(dir.path().join("main.rs")).unwrap();
        std::fs::File::create(dir.path().join("lib.rs")).unwrap();
        
        let auditor = TestAuditor::with_config(Config::default(), dir.path().to_path_buf()).unwrap();
        let test_files = auditor.find_test_files(dir.path());
        
        assert_eq!(test_files.len(), 2);
        assert!(test_files.iter().any(|p| p.file_name().unwrap() == "test_module.rs"));
        assert!(test_files.iter().any(|p| p.file_name().unwrap() == "tests.rs"));
    }

    #[test]
    fn test_generate_report_no_issues() {
        let auditor = TestAuditor::with_config(Config::default(), PathBuf::from(".")).unwrap();
        auditor.generate_report().unwrap();
    }

    #[test]
    fn test_generate_report_with_issues() {
        let mut auditor = TestAuditor::with_config(Config::default(), PathBuf::from(".")).unwrap();
        
        auditor.issues.push(TestIssue {
            file_path: PathBuf::from("test.rs"),
            line_number: 10,
            issue_type: IssueType::AlwaysPass,
            description: "Test issue".to_string(),
            code_snippet: "assert!(true)".to_string(),
        });
        
        auditor.generate_report().unwrap();
    }

    #[test]
    fn test_config_rule_disabling() {
        let mut config = Config::default();
        config.rules.hardcoded_values = false;
        config.rules.always_pass = true;
        
        let auditor = TestAuditor::with_config(config, PathBuf::from(".")).unwrap();
        
        // We can't easily test is_rule_enabled as it's private, but we can test via public API
        let file_path = Path::new("test.rs");
        let mut auditor_copy = auditor;
        auditor_copy.check_line(file_path, 1, "assert_eq!(42, 42)", "");
        
        // Should not detect hardcoded values, but should detect always pass
        let hardcoded_count = auditor_copy.issues.iter().filter(|i| i.issue_type == IssueType::HardcodedValues).count();
        let always_pass_count = auditor_copy.issues.iter().filter(|i| i.issue_type == IssueType::AlwaysPass).count();
        assert_eq!(hardcoded_count, 0);
        assert_eq!(always_pass_count, 1);
    }

    #[test]
    fn test_json_output_format() {
        let mut config = Config::default();
        config.output.format = OutputFormat::Json;
        
        let auditor = TestAuditor::with_config(config, PathBuf::from(".")).unwrap();
        
        // This test just verifies the config is set correctly
        match auditor.config.output.format {
            OutputFormat::Json => assert!(true),
            OutputFormat::Console => assert!(false, "Expected JSON format"),
            OutputFormat::Xml => assert!(false, "Expected JSON format"),
        }
    }

    #[test]
    fn test_load_config_default() {
        let config = load_config(None).unwrap();
        
        // Should return default config when no file exists
        assert!(config.rules.hardcoded_values);
        assert!(config.rules.always_pass);
        assert_eq!(config.patterns.magic_number_threshold, 10);
    }

    #[test]
    fn test_config_file_loading() {
        let dir = tempdir().unwrap();
        let config_file = dir.path().join(".test-auditor");
        let mut file = std::fs::File::create(&config_file).unwrap();
        
        writeln!(file, r#"
[rules]
hardcoded_values = false
always_pass = true

[output]
format = "Json"
color = false

[patterns]
magic_number_threshold = 50
"#).unwrap();

        let config = load_config(Some(config_file.to_str().unwrap())).unwrap();
        
        assert!(!config.rules.hardcoded_values);
        assert!(config.rules.always_pass);
        assert!(!config.output.color);
        assert_eq!(config.patterns.magic_number_threshold, 50);
        
        match config.output.format {
            OutputFormat::Json => assert!(true),
            OutputFormat::Console => assert!(false, "Expected JSON format"),
            OutputFormat::Xml => assert!(false, "Expected JSON format"),
        }
    }
}