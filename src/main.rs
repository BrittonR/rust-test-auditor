use clap::{Arg, Command};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use regex::Regex;
use colored::*;

#[derive(Debug, Clone)]
struct TestIssue {
    file_path: PathBuf,
    line_number: usize,
    issue_type: IssueType,
    description: String,
    code_snippet: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum IssueType {
    HardcodedValues,
    AlwaysPass,
    EmptyTest,
    ErrorIgnored,
    MisleadingName,
    CopyPasted,
    EdgeCaseNotTested,
    ImplementationDetail,
    NoAssertions,
    NonDeterministic,
    UnsafeUnwrap,
    VaguePanic,
    MagicNumbers,
}

impl IssueType {
    fn color(&self) -> &'static str {
        match self {
            IssueType::HardcodedValues => "yellow",
            IssueType::AlwaysPass => "red",
            IssueType::EmptyTest => "red",
            IssueType::ErrorIgnored => "red",
            IssueType::MisleadingName => "yellow",
            IssueType::CopyPasted => "yellow",
            IssueType::EdgeCaseNotTested => "yellow",
            IssueType::ImplementationDetail => "yellow",
            IssueType::NoAssertions => "red",
            IssueType::NonDeterministic => "red",
            IssueType::UnsafeUnwrap => "yellow",
            IssueType::VaguePanic => "yellow",
            IssueType::MagicNumbers => "yellow",
        }
    }

    fn description(&self) -> &'static str {
        match self {
            IssueType::HardcodedValues => "Hardcoded expected values",
            IssueType::AlwaysPass => "Test always passes (tautology)",
            IssueType::EmptyTest => "Empty test body",
            IssueType::ErrorIgnored => "Errors improperly ignored",
            IssueType::MisleadingName => "Misleading test name",
            IssueType::CopyPasted => "Copy-pasted assertions",
            IssueType::EdgeCaseNotTested => "Edge cases not properly tested",
            IssueType::ImplementationDetail => "Tests implementation details",
            IssueType::NoAssertions => "Test has no assertions",
            IssueType::NonDeterministic => "Non-deterministic test data",
            IssueType::UnsafeUnwrap => "Unsafe unwrap() without error message",
            IssueType::VaguePanic => "should_panic without specific message",
            IssueType::MagicNumbers => "Magic numbers/strings without context",
        }
    }
}

struct TestAuditor {
    issues: Vec<TestIssue>,
    test_patterns: Vec<Regex>,
    issue_patterns: Vec<(Regex, IssueType)>,
}

impl TestAuditor {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let test_patterns = vec![
            Regex::new(r"#\[test\]")?,
            Regex::new(r"#\[cfg\(test\)\]")?,
            Regex::new(r"fn test_\w+")?,
            Regex::new(r"describe\(")?,
            Regex::new(r"it\(")?,
            Regex::new(r"TEST\(")?,
        ];

        let issue_patterns = vec![
            // Hardcoded values
            (Regex::new(r"assert_eq!\(\s*\d+\s*,\s*\d+\s*\)")?, IssueType::HardcodedValues),
            (Regex::new(r#"assert_eq!\(\s*"[^"]*"\s*,\s*"[^"]*"\s*\)"#)?, IssueType::HardcodedValues),
            
            // Always pass
            (Regex::new(r"assert!\(true\)")?, IssueType::AlwaysPass),
            
            // Empty tests
            (Regex::new(r"#\[test\]\s*fn\s+\w+\(\)\s*\{\s*\}")?, IssueType::EmptyTest),
            
            // Error ignored
            (Regex::new(r"\.unwrap_or\(\)")?, IssueType::ErrorIgnored),
            (Regex::new(r"let\s+_\s*=.*\.unwrap\(\)")?, IssueType::ErrorIgnored),
            (Regex::new(r"catch\s*\{[^}]*\}")?, IssueType::ErrorIgnored),
            
            // Implementation details
            (Regex::new(r"assert!\(\w+\.capacity\(\)")?, IssueType::ImplementationDetail),
            (Regex::new(r"assert!\(\w+\.len\(\)\s*==\s*\w+\.capacity\(\)")?, IssueType::ImplementationDetail),
            
            // Non-deterministic patterns
            (Regex::new(r"SystemTime::now\(\)|Instant::now\(\)")?, IssueType::NonDeterministic),
            (Regex::new(r"rand::|random\(\)|thread_rng\(\)")?, IssueType::NonDeterministic),
            
            // Unsafe unwrap (simple pattern - will refine later)
            (Regex::new(r"\.unwrap\(\)")?, IssueType::UnsafeUnwrap),
            
            // Vague should_panic
            (Regex::new(r"#\[should_panic\]\s*$")?, IssueType::VaguePanic),
            
            // Magic numbers in assertions (numbers > 10 without obvious context)
            (Regex::new(r"assert_eq!\([^,]*,\s*\d{2,}\s*\)")?, IssueType::MagicNumbers),
            (Regex::new(r"assert!\([^)]*>\s*\d{2,}\s*\)")?, IssueType::MagicNumbers),
        ];

        Ok(TestAuditor {
            issues: Vec::new(),
            test_patterns,
            issue_patterns,
        })
    }

    fn is_test_file(&self, path: &Path) -> bool {
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            // Only consider .rs files
            if !name.ends_with(".rs") {
                return false;
            }
            let path_str = path.to_str().unwrap_or("");
            // Exclude target directory, hidden directories, and other build artifacts
            if path_str.contains("target/") || path_str.contains("/.") {
                return false;
            }
            return name.contains("test") || name.ends_with("_test.rs") || name == "tests.rs";
        }
        false
    }

    fn find_test_files(&self, root_path: &Path) -> Vec<PathBuf> {
        let mut test_files = Vec::new();
        
        for entry in WalkDir::new(root_path)
            .follow_links(true)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if path.is_file() && self.is_test_file(path) {
                test_files.push(path.to_path_buf());
            }
        }
        
        test_files
    }

    fn audit_file(&mut self, file_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let content = fs::read_to_string(file_path)?;
        let lines: Vec<&str> = content.lines().collect();

        for (line_number, line) in lines.iter().enumerate() {
            self.check_line(file_path, line_number + 1, line, &content);
        }

        self.check_for_copy_pasted_tests(file_path, &lines);
        self.check_for_misleading_names(file_path, &lines);
        self.check_for_no_assertions(file_path, &lines);

        Ok(())
    }

    fn check_line(&mut self, file_path: &Path, line_number: usize, line: &str, full_content: &str) {
        for (pattern, issue_type) in &self.issue_patterns {
            if pattern.is_match(line) {
                self.issues.push(TestIssue {
                    file_path: file_path.to_path_buf(),
                    line_number,
                    issue_type: issue_type.clone(),
                    description: format!("Line matches pattern: {}", issue_type.description()),
                    code_snippet: line.trim().to_string(),
                });
            }
        }
        
        // Check for edge cases not tested
        if line.contains("todo!") && self.test_patterns.iter().any(|p| p.is_match(full_content)) {
            self.issues.push(TestIssue {
                file_path: file_path.to_path_buf(),
                line_number,
                issue_type: IssueType::EdgeCaseNotTested,
                description: "Test contains todo! indicating incomplete edge case testing".to_string(),
                code_snippet: line.trim().to_string(),
            });
        }
        
        // Check for tautological assert_eq!
        if let Some(captures) = Regex::new(r"assert_eq!\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)").unwrap().captures(line) {
            if captures.get(1).map(|m| m.as_str()) == captures.get(2).map(|m| m.as_str()) {
                self.issues.push(TestIssue {
                    file_path: file_path.to_path_buf(),
                    line_number,
                    issue_type: IssueType::AlwaysPass,
                    description: "Tautological assertion - comparing variable to itself".to_string(),
                    code_snippet: line.trim().to_string(),
                });
            }
        }
    }

    fn check_for_copy_pasted_tests(&mut self, file_path: &Path, lines: &[&str]) {
        let mut test_bodies = HashSet::new();
        let mut current_test_body = String::new();
        let mut in_test = false;
        let mut test_start_line = 0;
        let mut brace_count = 0;
        let mut seen_opening_brace = false;

        for (line_number, line) in lines.iter().enumerate() {
            if line.contains("#[test]") {
                in_test = true;
                test_start_line = line_number + 1;
                current_test_body.clear();
                brace_count = 0;
                seen_opening_brace = false;
            } else if in_test {
                // Count braces
                for ch in line.chars() {
                    if ch == '{' {
                        brace_count += 1;
                        seen_opening_brace = true;
                    } else if ch == '}' {
                        brace_count -= 1;
                    }
                }
                
                // Only add to body if we've seen the opening brace
                if seen_opening_brace && !line.contains("fn ") {
                    current_test_body.push_str(line);
                    current_test_body.push('\n');
                }
                
                // Check if we've closed all braces
                if brace_count == 0 && seen_opening_brace {
                    let body_hash = current_test_body.trim().to_string();
                    if !body_hash.is_empty() && test_bodies.contains(&body_hash) {
                        self.issues.push(TestIssue {
                            file_path: file_path.to_path_buf(),
                            line_number: test_start_line,
                            issue_type: IssueType::CopyPasted,
                            description: "Potentially copy-pasted test body".to_string(),
                            code_snippet: body_hash.clone(),
                        });
                    }
                    test_bodies.insert(body_hash);
                    in_test = false;
                }
            }
        }
    }

    fn check_for_misleading_names(&mut self, file_path: &Path, lines: &[&str]) {
        let misleading_patterns = vec![
            (Regex::new(r"fn test_\w*success\w*").unwrap(), "panic!"),
            (Regex::new(r"fn test_\w*fail\w*").unwrap(), "assert!"),
            (Regex::new(r"fn test_\w*error\w*").unwrap(), "unwrap"),
        ];

        for (line_number, line) in lines.iter().enumerate() {
            for (name_pattern, should_not_contain) in &misleading_patterns {
                if name_pattern.is_match(line) {
                    // Check next few lines for contradictory patterns
                    let check_lines = &lines[line_number..std::cmp::min(line_number + 10, lines.len())];
                    for check_line in check_lines {
                        if check_line.contains(should_not_contain) {
                            self.issues.push(TestIssue {
                                file_path: file_path.to_path_buf(),
                                line_number: line_number + 1,
                                issue_type: IssueType::MisleadingName,
                                description: format!("Test name suggests one behavior but code suggests another"),
                                code_snippet: line.trim().to_string(),
                            });
                            break;
                        }
                    }
                }
            }
        }
    }

    fn check_for_no_assertions(&mut self, file_path: &Path, lines: &[&str]) {
        let assertion_patterns = vec![
            Regex::new(r"assert!").unwrap(),
            Regex::new(r"assert_eq!").unwrap(),
            Regex::new(r"assert_ne!").unwrap(),
            Regex::new(r"debug_assert!").unwrap(),
            Regex::new(r"panic!").unwrap(),
            Regex::new(r"should_panic").unwrap(),
            Regex::new(r"expect\(").unwrap(),
        ];

        let mut in_test = false;
        let mut test_start_line = 0;
        let mut test_body = String::new();
        let mut brace_count = 0;
        let mut seen_opening_brace = false;

        for (line_number, line) in lines.iter().enumerate() {
            if line.contains("#[test]") {
                in_test = true;
                test_start_line = line_number + 1;
                test_body.clear();
                brace_count = 0;
                seen_opening_brace = false;
            } else if in_test {
                // Count braces
                for ch in line.chars() {
                    if ch == '{' {
                        brace_count += 1;
                        seen_opening_brace = true;
                    } else if ch == '}' {
                        brace_count -= 1;
                    }
                }
                
                // Add to test body if we've seen the opening brace
                if seen_opening_brace {
                    test_body.push_str(line);
                    test_body.push('\n');
                }
                
                // Check if we've closed all braces (end of test)
                if brace_count == 0 && seen_opening_brace {
                    // Check if test body contains any assertions
                    let has_assertions = assertion_patterns.iter().any(|pattern| pattern.is_match(&test_body));
                    
                    if !has_assertions && !test_body.trim().is_empty() {
                        self.issues.push(TestIssue {
                            file_path: file_path.to_path_buf(),
                            line_number: test_start_line,
                            issue_type: IssueType::NoAssertions,
                            description: "Test function has no assertions or expectations".to_string(),
                            code_snippet: format!("Test body: {} lines", test_body.lines().count()),
                        });
                    }
                    in_test = false;
                }
            }
        }
    }

    fn audit_directory(&mut self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let test_files = self.find_test_files(path);
        
        println!("Found {} test files", test_files.len());
        
        for file_path in test_files {
            println!("Auditing: {}", file_path.display());
            self.audit_file(&file_path)?;
        }

        Ok(())
    }

    fn generate_report(&self) {
        println!("\n{}", "=== TEST AUDIT REPORT ===".bold().blue());
        println!("Total issues found: {}\n", self.issues.len());

        let mut issues_by_type: std::collections::HashMap<IssueType, Vec<&TestIssue>> = std::collections::HashMap::new();
        
        for issue in &self.issues {
            issues_by_type.entry(issue.issue_type.clone()).or_insert_with(Vec::new).push(issue);
        }

        for (issue_type, issues) in issues_by_type {
            println!("{} ({})", issue_type.description().color(issue_type.color()).bold(), issues.len());
            
            for issue in issues {
                println!("  📁 {}", issue.file_path.display());
                println!("  📍 Line {}: {}", issue.line_number, issue.description);
                println!("  💻 {}", issue.code_snippet.dimmed());
                println!();
            }
        }

        if self.issues.is_empty() {
            println!("{}", "✅ No issues found! Your tests look good.".green().bold());
        } else {
            println!("{}", "❌ Issues found that may need attention.".red().bold());
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("test-auditor")
        .version("1.0")
        .author("Your Name")
        .about("Audits test suites for common anti-patterns and bad practices")
        .arg(
            Arg::new("path")
                .short('p')
                .long("path")
                .value_name("PATH")
                .help("Path to the directory to audit")
                .default_value(".")
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Enable verbose output")
                .action(clap::ArgAction::SetTrue)
        )
        .get_matches();

    let path = matches.get_one::<String>("path").unwrap();
    let _verbose = matches.get_flag("verbose");

    let mut auditor = TestAuditor::new()?;
    auditor.audit_directory(Path::new(path))?;
    auditor.generate_report();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

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
    }

    #[test]
    fn test_auditor_new() {
        let auditor = TestAuditor::new().unwrap();
        assert!(auditor.issues.is_empty());
        assert!(!auditor.test_patterns.is_empty());
        assert!(!auditor.issue_patterns.is_empty());
    }

    #[test]
    fn test_is_test_file() {
        let auditor = TestAuditor::new().unwrap();
        
        assert!(auditor.is_test_file(Path::new("test_module.rs")));
        assert!(auditor.is_test_file(Path::new("module_test.rs")));
        assert!(auditor.is_test_file(Path::new("tests.rs")));
        assert!(auditor.is_test_file(Path::new("integration_tests.rs")));
        assert!(!auditor.is_test_file(Path::new("main.rs")));
        assert!(!auditor.is_test_file(Path::new("lib.rs")));
    }

    #[test]
    fn test_detect_hardcoded_values() {
        let mut auditor = TestAuditor::new().unwrap();
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
        let mut auditor = TestAuditor::new().unwrap();
        let file_path = Path::new("test.rs");
        
        auditor.check_line(file_path, 1, "assert!(true)", "");
        auditor.check_line(file_path, 2, "assert_eq!(value, value)", "");
        
        assert_eq!(auditor.issues.len(), 2);
        assert!(auditor.issues.iter().all(|i| i.issue_type == IssueType::AlwaysPass));
    }

    #[test]
    fn test_detect_empty_test() {
        let mut auditor = TestAuditor::new().unwrap();
        let file_path = Path::new("test.rs");
        
        auditor.check_line(file_path, 1, "#[test] fn test_empty() { }", "");
        
        assert_eq!(auditor.issues.len(), 1);
        assert_eq!(auditor.issues[0].issue_type, IssueType::EmptyTest);
    }

    #[test]
    fn test_detect_error_ignored() {
        let mut auditor = TestAuditor::new().unwrap();
        let file_path = Path::new("test.rs");
        
        auditor.check_line(file_path, 1, "result.unwrap_or()", "");
        auditor.check_line(file_path, 2, "let _ = something.unwrap()", "");
        
        assert_eq!(auditor.issues.len(), 3);
        let error_ignored_count = auditor.issues.iter().filter(|i| i.issue_type == IssueType::ErrorIgnored).count();
        let unsafe_unwrap_count = auditor.issues.iter().filter(|i| i.issue_type == IssueType::UnsafeUnwrap).count();
        assert_eq!(error_ignored_count, 2);
        assert_eq!(unsafe_unwrap_count, 1);
    }

    #[test]
    fn test_detect_implementation_details() {
        let mut auditor = TestAuditor::new().unwrap();
        let file_path = Path::new("test.rs");
        
        auditor.check_line(file_path, 1, "assert!(vec.capacity() > 10)", "");
        auditor.check_line(file_path, 2, "assert!(vec.len() == vec.capacity())", "");
        
        assert_eq!(auditor.issues.len(), 2);
        assert!(auditor.issues.iter().all(|i| i.issue_type == IssueType::ImplementationDetail));
    }

    #[test]
    fn test_check_copy_pasted_tests() {
        let mut auditor = TestAuditor::new().unwrap();
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
        let mut auditor = TestAuditor::new().unwrap();
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
        let mut file = fs::File::create(&file_path).unwrap();
        
        writeln!(file, "#[test]").unwrap();
        writeln!(file, "fn test_example() {{").unwrap();
        writeln!(file, "    assert!(true);").unwrap();
        writeln!(file, "}}").unwrap();
        
        let mut auditor = TestAuditor::new().unwrap();
        auditor.audit_file(&file_path).unwrap();
        
        assert_eq!(auditor.issues.len(), 1);
        assert_eq!(auditor.issues[0].issue_type, IssueType::AlwaysPass);
    }

    #[test]
    fn test_find_test_files() {
        let dir = tempdir().unwrap();
        
        fs::File::create(dir.path().join("test_module.rs")).unwrap();
        fs::File::create(dir.path().join("tests.rs")).unwrap();
        fs::File::create(dir.path().join("main.rs")).unwrap();
        fs::File::create(dir.path().join("lib.rs")).unwrap();
        
        let auditor = TestAuditor::new().unwrap();
        let test_files = auditor.find_test_files(dir.path());
        
        assert_eq!(test_files.len(), 2);
        assert!(test_files.iter().any(|p| p.file_name().unwrap() == "test_module.rs"));
        assert!(test_files.iter().any(|p| p.file_name().unwrap() == "tests.rs"));
    }

    #[test]
    fn test_generate_report_no_issues() {
        let auditor = TestAuditor::new().unwrap();
        auditor.generate_report();
    }

    #[test]
    fn test_generate_report_with_issues() {
        let mut auditor = TestAuditor::new().unwrap();
        
        auditor.issues.push(TestIssue {
            file_path: PathBuf::from("test.rs"),
            line_number: 10,
            issue_type: IssueType::AlwaysPass,
            description: "Test issue".to_string(),
            code_snippet: "assert!(true)".to_string(),
        });
        
        auditor.generate_report();
    }
}