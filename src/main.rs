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

use clap::{Arg, Command};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::hash::{Hash, Hasher, DefaultHasher};
use walkdir::WalkDir;
use regex::Regex;
use colored::*;
use serde::{Deserialize, Serialize};
use quick_xml::se::to_string as to_xml_string;
use once_cell::sync::Lazy;
use rayon::prelude::*;
use std::sync::Mutex;
use thiserror::Error;

/// Custom error types for the test auditor
#[derive(Error, Debug)]
pub enum AuditorError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Path validation failed: {message}")]
    PathValidation { message: String },
    
    #[error("Configuration error: {0}")]
    Config(#[from] toml::de::Error),
    
    #[error("Regex compilation error: {0}")]
    Regex(#[from] regex::Error),
    
    #[error("File too large: {path} ({size} bytes, max {max_size} bytes)")]
    FileTooLarge { path: String, size: u64, max_size: u64 },
    
    #[error("Canonicalization failed for path '{path}': {source}")]
    Canonicalization { path: String, source: std::io::Error },
    
    #[error("Path traversal detected: '{path}' is outside root '{root}'")]
    PathTraversal { path: String, root: String },
    
    #[error("Parallel processing error: {message}")]
    ParallelProcessing { message: String },
    
    #[error("JSON serialization error: {0}")]
    JsonSerialization(#[from] serde_json::Error),
    
    #[error("XML serialization error: {0}")]
    XmlSerialization(#[from] quick_xml::DeError),
    
    #[error("Invalid configuration: {message}")]
    InvalidConfig { message: String },
}

/// Result type alias for auditor operations
pub type AuditorResult<T> = Result<T, AuditorError>;

/// Represents a single issue found during test auditing
#[derive(Debug, Clone, Serialize)]
struct TestIssue {
    /// Path to the file containing the issue
    file_path: PathBuf,
    /// Line number where the issue was found
    line_number: usize,
    /// Type of issue detected
    issue_type: IssueType,
    /// Human-readable description of the issue
    description: String,
    /// Code snippet that triggered the issue
    code_snippet: String,
}

/// Configuration structure for the test auditor
#[derive(Debug, Deserialize, Clone)]
struct Config {
    /// Configuration for which rules to enable/disable
    #[serde(default)]
    rules: RuleConfig,
    /// Configuration for output formatting
    #[serde(default)]
    output: OutputConfig,
    /// Configuration for pattern matching and file exclusions
    #[serde(default)]
    patterns: PatternConfig,
}

#[derive(Debug, Deserialize, Clone)]
struct RuleConfig {
    #[serde(default = "default_true")]
    hardcoded_values: bool,
    #[serde(default = "default_true")]
    always_pass: bool,
    #[serde(default = "default_true")]
    empty_test: bool,
    #[serde(default = "default_true")]
    error_ignored: bool,
    #[serde(default = "default_true")]
    misleading_name: bool,
    #[serde(default = "default_true")]
    copy_pasted: bool,
    #[serde(default = "default_true")]
    edge_case_not_tested: bool,
    #[serde(default = "default_true")]
    implementation_detail: bool,
    #[serde(default = "default_true")]
    no_assertions: bool,
    #[serde(default = "default_true")]
    non_deterministic: bool,
    #[serde(default = "default_true")]
    unsafe_unwrap: bool,
    #[serde(default = "default_true")]
    vague_panic: bool,
    #[serde(default = "default_true")]
    magic_numbers: bool,
    #[serde(default = "default_true")]
    async_test_issue: bool,
    #[serde(default = "default_true")]
    debug_output: bool,
    #[serde(default = "default_true")]
    commented_out_code: bool,
    #[serde(default = "default_true")]
    sleep_in_test: bool,
    #[serde(default = "default_true")]
    todo_in_test: bool,
    #[serde(default = "default_true")]
    test_timeout: bool,
    #[serde(default = "default_true")]
    flaky_test: bool,
}

#[derive(Debug, Deserialize, Clone)]
struct OutputConfig {
    #[serde(default)]
    format: OutputFormat,
    #[serde(default = "default_true")]
    color: bool,
}

#[derive(Debug, Deserialize, Default, Clone)]
enum OutputFormat {
    #[default]
    Console,
    Json,
    Xml,
}

#[derive(Debug, Deserialize, Clone)]
struct PatternConfig {
    #[serde(default = "default_magic_number_threshold")]
    magic_number_threshold: u32,
    #[serde(default)]
    ignore_patterns: Vec<String>,
    #[serde(default)]
    exclude_dirs: Vec<String>,
    #[serde(default)]
    exclude_files: Vec<String>,
}

fn default_true() -> bool { true }
fn default_magic_number_threshold() -> u32 { 10 }

impl Default for RuleConfig {
    fn default() -> Self {
        Self {
            hardcoded_values: true,
            always_pass: true,
            empty_test: true,
            error_ignored: true,
            misleading_name: true,
            copy_pasted: true,
            edge_case_not_tested: true,
            implementation_detail: true,
            no_assertions: true,
            non_deterministic: true,
            unsafe_unwrap: true,
            vague_panic: true,
            magic_numbers: true,
            async_test_issue: true,
            debug_output: true,
            commented_out_code: true,
            sleep_in_test: true,
            todo_in_test: true,
            test_timeout: true,
            flaky_test: true,
        }
    }
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: OutputFormat::Console,
            color: true,
        }
    }
}

impl Default for PatternConfig {
    fn default() -> Self {
        Self {
            magic_number_threshold: 10,
            ignore_patterns: Vec::new(),
            exclude_dirs: vec![
                "target".to_string(),
                "node_modules".to_string(),
                ".git".to_string(),
                "vendor".to_string(),
            ],
            exclude_files: vec![
                "*_generated.rs".to_string(),
                "*.pb.rs".to_string(),
            ],
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            rules: RuleConfig::default(),
            output: OutputConfig::default(),
            patterns: PatternConfig::default(),
        }
    }
}

/// Types of issues that can be detected in test code
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
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
    AsyncTestIssue,
    DebugOutput,
    CommentedOutCode,
    SleepInTest,
    TodoInTest,
    TestTimeout,
    FlakyTest,
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
            IssueType::AsyncTestIssue => "red",
            IssueType::DebugOutput => "yellow",
            IssueType::CommentedOutCode => "yellow",
            IssueType::SleepInTest => "red",
            IssueType::TodoInTest => "yellow",
            IssueType::TestTimeout => "red",
            IssueType::FlakyTest => "red",
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
            IssueType::AsyncTestIssue => "Async test without proper .await or runtime",
            IssueType::DebugOutput => "Debug output left in test (println!, dbg!, etc)",
            IssueType::CommentedOutCode => "Commented-out test code",
            IssueType::SleepInTest => "Sleep/timing dependency in test",
            IssueType::TodoInTest => "TODO comments in test indicating incomplete work",
            IssueType::TestTimeout => "Test may hang or timeout (infinite loops, blocking calls)",
            IssueType::FlakyTest => "Test may be flaky or non-deterministic",
        }
    }
}

// Cached regex patterns for performance
static TEST_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"#\[test\]").unwrap(),
        Regex::new(r"#\[cfg\(test\)\]").unwrap(),
        Regex::new(r"fn test_\w+").unwrap(),
        Regex::new(r"describe\(").unwrap(),
        Regex::new(r"it\(").unwrap(),
        Regex::new(r"TEST\(").unwrap(),
    ]
});

static ISSUE_PATTERNS: Lazy<Vec<(Regex, IssueType)>> = Lazy::new(|| {
    vec![
        // Hardcoded values
        (Regex::new(r"assert_eq!\(\s*\d+\s*,\s*\d+\s*\)").unwrap(), IssueType::HardcodedValues),
        (Regex::new(r#"assert_eq!\(\s*"[^"]*"\s*,\s*"[^"]*"\s*\)"#).unwrap(), IssueType::HardcodedValues),
        
        // Always pass
        (Regex::new(r"assert!\(true\)").unwrap(), IssueType::AlwaysPass),
        
        // Empty tests
        (Regex::new(r"#\[test\]\s*fn\s+\w+\(\)\s*\{\s*\}").unwrap(), IssueType::EmptyTest),
        
        // Error ignored - more specific patterns (fixed false positive)
        (Regex::new(r"\.unwrap_or\(\s*\)\.unwrap\(\)").unwrap(), IssueType::ErrorIgnored),
        (Regex::new(r"let\s+_\s*=.*\.unwrap\(\)").unwrap(), IssueType::ErrorIgnored),
        (Regex::new(r"\.unwrap_or_default\(\)\s*;").unwrap(), IssueType::ErrorIgnored),
        
        // Implementation details
        (Regex::new(r"assert!\(\w+\.capacity\(\)").unwrap(), IssueType::ImplementationDetail),
        (Regex::new(r"assert!\(\w+\.len\(\)\s*==\s*\w+\.capacity\(\)").unwrap(), IssueType::ImplementationDetail),
        
        // Non-deterministic patterns
        (Regex::new(r"SystemTime::now\(\)|Instant::now\(\)").unwrap(), IssueType::NonDeterministic),
        (Regex::new(r"rand::|random\(\)|thread_rng\(\)").unwrap(), IssueType::NonDeterministic),
        
        // Unsafe unwrap - simple pattern, context checking done separately
        (Regex::new(r"\.unwrap\(\)").unwrap(), IssueType::UnsafeUnwrap),
        
        // Vague should_panic
        (Regex::new(r"#\[should_panic\]\s*$").unwrap(), IssueType::VaguePanic),
        
        // Magic numbers in assertions (numbers > 10 without obvious context)
        (Regex::new(r"assert_eq!\([^,]*,\s*\d{2,}\s*\)").unwrap(), IssueType::MagicNumbers),
        (Regex::new(r"assert!\([^)]*>\s*\d{2,}\s*\)").unwrap(), IssueType::MagicNumbers),
        
        // Async test issues - detect improper async test patterns
        (Regex::new(r"#\[test\]\s*\n\s*async\s+fn").unwrap(), IssueType::AsyncTestIssue),
        (Regex::new(r"#\[tokio::test\]\s*\n\s*fn\s+\w+").unwrap(), IssueType::AsyncTestIssue),
        (Regex::new(r"#\[async_std::test\]\s*\n\s*fn\s+\w+").unwrap(), IssueType::AsyncTestIssue),
        
        // Debug output left in tests
        (Regex::new(r"println!\(").unwrap(), IssueType::DebugOutput),
        (Regex::new(r"eprintln!\(").unwrap(), IssueType::DebugOutput),
        (Regex::new(r"dbg!\(").unwrap(), IssueType::DebugOutput),
        (Regex::new(r"print!\(").unwrap(), IssueType::DebugOutput),
        
        // Commented-out test code
        (Regex::new(r"//\s*(assert_|assert!|expect\()").unwrap(), IssueType::CommentedOutCode),
        (Regex::new(r"//\s*#\[test\]").unwrap(), IssueType::CommentedOutCode),
        
        // Sleep/timing dependencies in tests (more specific patterns)
        (Regex::new(r"thread::sleep\(").unwrap(), IssueType::SleepInTest),
        (Regex::new(r"std::thread::sleep\(").unwrap(), IssueType::SleepInTest),
        
        // TODO comments in tests
        (Regex::new(r"//\s*TODO").unwrap(), IssueType::TodoInTest),
        (Regex::new(r"//\s*FIXME").unwrap(), IssueType::TodoInTest),
        (Regex::new(r"//\s*XXX").unwrap(), IssueType::TodoInTest),
        
        // Test timeout patterns (potential hanging tests)
        (Regex::new(r"loop\s*\{").unwrap(), IssueType::TestTimeout),
        (Regex::new(r"while\s+true").unwrap(), IssueType::TestTimeout),
        (Regex::new(r"std::io::stdin\(\)").unwrap(), IssueType::TestTimeout),
        (Regex::new(r"stdin\(\)\.read_line").unwrap(), IssueType::TestTimeout),
        (Regex::new(r"Channel::recv\(\)").unwrap(), IssueType::TestTimeout),
        (Regex::new(r"\.recv\(\)").unwrap(), IssueType::TestTimeout),
        
        // Flaky test patterns
        (Regex::new(r"retry").unwrap(), IssueType::FlakyTest),
        (Regex::new(r"eventually").unwrap(), IssueType::FlakyTest),
        (Regex::new(r"attempt").unwrap(), IssueType::FlakyTest),
        (Regex::new(r"#\[ignore\]").unwrap(), IssueType::FlakyTest),
        (Regex::new(r"// flaky").unwrap(), IssueType::FlakyTest),
        (Regex::new(r"// unstable").unwrap(), IssueType::FlakyTest),
    ]
});

/// Main auditor structure that analyzes test files for anti-patterns
struct TestAuditor {
    issues: Vec<TestIssue>,
    config: Config,
    root_path: PathBuf,
}

impl TestAuditor {
    /// Creates a new TestAuditor with default configuration
    fn new() -> AuditorResult<Self> {
        Self::with_config(Config::default(), PathBuf::from("."))
    }

    /// Creates a new TestAuditor with the specified configuration and root path
    /// 
    /// # Arguments
    /// * `config` - Configuration settings for the auditor
    /// * `root_path` - Root directory for path validation (prevents path traversal)
    fn with_config(config: Config, root_path: PathBuf) -> AuditorResult<Self> {
        let canonical_root = root_path.canonicalize()
            .map_err(|e| AuditorError::Canonicalization {
                path: root_path.display().to_string(),
                source: e,
            })?;

        Ok(TestAuditor {
            issues: Vec::new(),
            config,
            root_path: canonical_root,
        })
    }

    fn is_rule_enabled(&self, issue_type: &IssueType) -> bool {
        match issue_type {
            IssueType::HardcodedValues => self.config.rules.hardcoded_values,
            IssueType::AlwaysPass => self.config.rules.always_pass,
            IssueType::EmptyTest => self.config.rules.empty_test,
            IssueType::ErrorIgnored => self.config.rules.error_ignored,
            IssueType::MisleadingName => self.config.rules.misleading_name,
            IssueType::CopyPasted => self.config.rules.copy_pasted,
            IssueType::EdgeCaseNotTested => self.config.rules.edge_case_not_tested,
            IssueType::ImplementationDetail => self.config.rules.implementation_detail,
            IssueType::NoAssertions => self.config.rules.no_assertions,
            IssueType::NonDeterministic => self.config.rules.non_deterministic,
            IssueType::UnsafeUnwrap => self.config.rules.unsafe_unwrap,
            IssueType::VaguePanic => self.config.rules.vague_panic,
            IssueType::MagicNumbers => self.config.rules.magic_numbers,
            IssueType::AsyncTestIssue => self.config.rules.async_test_issue,
            IssueType::DebugOutput => self.config.rules.debug_output,
            IssueType::CommentedOutCode => self.config.rules.commented_out_code,
            IssueType::SleepInTest => self.config.rules.sleep_in_test,
            IssueType::TodoInTest => self.config.rules.todo_in_test,
            IssueType::TestTimeout => self.config.rules.test_timeout,
            IssueType::FlakyTest => self.config.rules.flaky_test,
        }
    }

    fn is_safe_unwrap_context(&self, line: &str) -> bool {
        // Known safe unwrap patterns in tests
        let safe_patterns = [
            r"tempdir\(\)\.unwrap\(\)",           // tempfile crate
            r"File::create\([^)]*\)\.unwrap\(\)", // file creation in tests
            r"write!\([^)]*\)\.unwrap\(\)",       // writing in tests
            r"writeln!\([^)]*\)\.unwrap\(\)",     // writing lines in tests
            r"dir\.path\(\)\.join\([^)]*\)",      // path joining
            r"Command::new\([^)]*\)\..*\.unwrap\(\)", // test commands
            r"Vec::new\(\)\..*\.unwrap\(\)",      // vec operations that can't fail
            r"String::from_utf8\([^)]*\)\.unwrap\(\)", // known valid UTF-8 in tests
        ];

        for pattern in &safe_patterns {
            if Regex::new(pattern).map_or(false, |re| re.is_match(line)) {
                return true;
            }
        }

        // Also safe if there's a comment explaining why it's safe
        line.contains("// safe:") || line.contains("// SAFETY:") || line.contains("// OK to unwrap")
    }

    /// Determines if a file should be considered a test file based on naming conventions
    /// 
    /// # Arguments
    /// * `path` - Path to the file to check
    /// 
    /// # Returns
    /// True if the file appears to be a test file
    fn is_test_file(&self, path: &Path) -> bool {
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            // Only consider .rs files
            if !name.ends_with(".rs") {
                return false;
            }
            
            let path_str = path.to_str().unwrap_or("");
            
            // Check exclude directories from config
            for exclude_dir in &self.config.patterns.exclude_dirs {
                if path_str.contains(&format!("/{}/", exclude_dir)) || 
                   path_str.contains(&format!("{}/", exclude_dir)) {
                    return false;
                }
            }
            
            // Check exclude files from config
            for exclude_file in &self.config.patterns.exclude_files {
                if exclude_file.contains('*') {
                    // Simple glob matching for patterns like *.pb.rs
                    let pattern = exclude_file.replace('*', "");
                    if name.contains(&pattern) {
                        return false;
                    }
                } else if name == exclude_file {
                    return false;
                }
            }
            
            // Check general ignore patterns from config
            for pattern in &self.config.patterns.ignore_patterns {
                if path_str.contains(pattern) || name.contains(pattern) {
                    return false;
                }
            }
            
            // Exclude hidden directories (but not temp directories)
            if path_str.contains("/.") && !path_str.contains("/tmp") {
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
            .filter(|e| {
                // Pre-filter directories to avoid walking into excluded dirs
                if e.path().is_dir() {
                    let dir_name = e.path().file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("");
                    
                    for exclude_dir in &self.config.patterns.exclude_dirs {
                        if dir_name == exclude_dir {
                            return false;
                        }
                    }
                }
                true
            })
        {
            let path = entry.path();
            if path.is_file() && self.is_test_file(path) {
                test_files.push(path.to_path_buf());
            }
        }
        
        test_files
    }

    /// Validates that a file path is within the allowed root directory
    /// 
    /// This prevents path traversal attacks by ensuring files are only read
    /// from within the specified root directory.
    fn validate_path(&self, path: &Path) -> AuditorResult<()> {
        let canonical_path = path.canonicalize()
            .map_err(|e| AuditorError::Canonicalization {
                path: path.display().to_string(),
                source: e,
            })?;
        
        if !canonical_path.starts_with(&self.root_path) {
            return Err(AuditorError::PathTraversal {
                path: canonical_path.display().to_string(),
                root: self.root_path.display().to_string(),
            });
        }
        
        Ok(())
    }

    /// Audits a single file for test anti-patterns
    /// 
    /// # Arguments
    /// * `file_path` - Path to the file to audit
    /// 
    /// # Returns
    /// Result indicating success or failure of the audit operation
    fn audit_file(&mut self, file_path: &Path) -> AuditorResult<()> {
        // Validate path to prevent traversal attacks
        self.validate_path(file_path)?;
        
        // Check file size to prevent memory issues
        let metadata = fs::metadata(file_path)?;
        const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024; // 10MB limit
        if metadata.len() > MAX_FILE_SIZE {
            return Err(AuditorError::FileTooLarge {
                path: file_path.display().to_string(),
                size: metadata.len(),
                max_size: MAX_FILE_SIZE,
            });
        }
        
        let content = fs::read_to_string(file_path)?;
        let lines: Vec<&str> = content.lines().collect();

        for (line_number, line) in lines.iter().enumerate() {
            self.check_line(file_path, line_number + 1, line, &content);
        }

        self.check_for_copy_pasted_tests(file_path, &lines);
        self.check_for_misleading_names(file_path, &lines);
        self.check_for_no_assertions(file_path, &lines);
        self.check_async_tests(file_path, &lines);
        self.check_flaky_test_patterns(file_path, &lines);

        Ok(())
    }

    fn check_line(&mut self, file_path: &Path, line_number: usize, line: &str, full_content: &str) {
        // Check for ignore comments
        if line.contains("// auditor:ignore") || line.contains("// test-auditor:ignore") {
            return;
        }

        for (pattern, issue_type) in ISSUE_PATTERNS.iter() {
            if pattern.is_match(line) && self.is_rule_enabled(issue_type) {
                // Skip unwrap checks for well-known safe patterns in tests or with comments
                if *issue_type == IssueType::UnsafeUnwrap && (self.is_safe_unwrap_context(line) || line.contains("//")) {
                    continue;
                }
                
                self.issues.push(TestIssue {
                    file_path: file_path.to_path_buf(),
                    line_number,
                    issue_type: issue_type.clone(),
                    description: format!("Line matches pattern: {}", issue_type.description()),
                    code_snippet: line.trim().to_string(),
                });
            }
        }
        
        // Check for todo! macro in tests
        if line.contains("todo!") && TEST_PATTERNS.iter().any(|p| p.is_match(full_content)) && self.is_rule_enabled(&IssueType::TodoInTest) {
            self.issues.push(TestIssue {
                file_path: file_path.to_path_buf(),
                line_number,
                issue_type: IssueType::TodoInTest,
                description: "Test contains todo! macro indicating incomplete implementation".to_string(),
                code_snippet: line.trim().to_string(),
            });
        }
        
        // Check for tautological assert_eq!
        if let Some(captures) = Regex::new(r"assert_eq!\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)").unwrap().captures(line) {
            if captures.get(1).map(|m| m.as_str()) == captures.get(2).map(|m| m.as_str()) && self.is_rule_enabled(&IssueType::AlwaysPass) {
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
        if !self.is_rule_enabled(&IssueType::CopyPasted) {
            return;
        }
        let mut test_body_hashes = HashMap::new();
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
                    current_test_body.push_str(line.trim());
                    current_test_body.push('\n');
                }
                
                // Check if we've closed all braces
                if brace_count == 0 && seen_opening_brace {
                    let body_content = current_test_body.trim();
                    if !body_content.is_empty() {
                        // Use hash for memory efficiency
                        let mut hasher = DefaultHasher::new();
                        body_content.hash(&mut hasher);
                        let body_hash = hasher.finish();
                        
                        if let Some(first_occurrence) = test_body_hashes.get(&body_hash) {
                            self.issues.push(TestIssue {
                                file_path: file_path.to_path_buf(),
                                line_number: test_start_line,
                                issue_type: IssueType::CopyPasted,
                                description: format!("Copy-pasted test body (first occurrence at line {})", first_occurrence),
                                code_snippet: format!("Test body hash: {}", body_hash),
                            });
                        } else {
                            test_body_hashes.insert(body_hash, test_start_line);
                        }
                    }
                    in_test = false;
                }
            }
        }
    }

    fn check_for_misleading_names(&mut self, file_path: &Path, lines: &[&str]) {
        if !self.is_rule_enabled(&IssueType::MisleadingName) {
            return;
        }
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
        if !self.is_rule_enabled(&IssueType::NoAssertions) {
            return;
        }
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

    fn check_async_tests(&mut self, file_path: &Path, lines: &[&str]) {
        if !self.is_rule_enabled(&IssueType::AsyncTestIssue) {
            return;
        }

        for (line_number, line) in lines.iter().enumerate() {
            // Check for #[test] followed by async fn (incorrect pattern)
            if line.contains("#[test]") {
                if let Some(next_line) = lines.get(line_number + 1) {
                    if next_line.contains("async fn") {
                        self.issues.push(TestIssue {
                            file_path: file_path.to_path_buf(),
                            line_number: line_number + 1,
                            issue_type: IssueType::AsyncTestIssue,
                            description: "Invalid async test: use #[tokio::test] or #[async_std::test] instead of #[test] for async functions".to_string(),
                            code_snippet: format!("{} {}", line.trim(), next_line.trim()),
                        });
                    }
                }
            }
            
            // Check for #[tokio::test] followed by non-async fn (warning)
            if line.contains("#[tokio::test]") || line.contains("#[async_std::test]") {
                if let Some(next_line) = lines.get(line_number + 1) {
                    if next_line.contains("fn ") && !next_line.contains("async fn") {
                        self.issues.push(TestIssue {
                            file_path: file_path.to_path_buf(),
                            line_number: line_number + 1,
                            issue_type: IssueType::AsyncTestIssue,
                            description: "Async test attribute on non-async function".to_string(),
                            code_snippet: format!("{} {}", line.trim(), next_line.trim()),
                        });
                    }
                }
            }
            
            // Check for async functions with missing async test attributes
            if line.contains("async fn test_") || (line.contains("async fn") && line.contains("test")) {
                // Look for test attributes in the previous lines
                let mut has_async_attr = false;
                let mut has_regular_test = false;
                
                for i in 1..=3 {
                    if let Some(prev_line) = lines.get(line_number.saturating_sub(i)) {
                        if prev_line.contains("#[tokio::test]") || prev_line.contains("#[async_std::test]") {
                            has_async_attr = true;
                            break;
                        }
                        if prev_line.contains("#[test]") {
                            has_regular_test = true;
                            break;
                        }
                    }
                }
                
                if !has_async_attr && !has_regular_test {
                    self.issues.push(TestIssue {
                        file_path: file_path.to_path_buf(),
                        line_number: line_number + 1,
                        issue_type: IssueType::AsyncTestIssue,
                        description: "Async test function missing test attribute".to_string(),
                        code_snippet: line.trim().to_string(),
                    });
                }
            }
        }
    }

    fn audit_directory(&mut self, path: &Path) -> AuditorResult<()> {
        let test_files = self.find_test_files(path);
        
        println!("Found {} test files", test_files.len());
        
        if test_files.len() > 5 {
            // Use parallel processing for larger codebases
            self.audit_files_parallel(test_files)
        } else {
            // Use sequential processing for small codebases to avoid overhead
            self.audit_files_sequential(test_files)
        }
    }
    
    fn check_flaky_test_patterns(&mut self, file_path: &Path, lines: &[&str]) {
        if !self.is_rule_enabled(&IssueType::FlakyTest) {
            return;
        }
        
        // Look for patterns that suggest flaky tests
        for (line_number, line) in lines.iter().enumerate() {
            let line_lower = line.to_lowercase();
            
            // Check for retry/timing patterns
            if line_lower.contains("retry") && line_lower.contains("test") {
                self.issues.push(TestIssue {
                    file_path: file_path.to_path_buf(),
                    line_number: line_number + 1,
                    issue_type: IssueType::FlakyTest,
                    description: "Test appears to use retry logic which may indicate flakiness".to_string(),
                    code_snippet: line.trim().to_string(),
                });
            }
            
            // Check for multiple attempts or polling
            if (line_lower.contains("for") && line_lower.contains("attempt")) ||
               (line_lower.contains("while") && line_lower.contains("!ready")) {
                self.issues.push(TestIssue {
                    file_path: file_path.to_path_buf(),
                    line_number: line_number + 1,
                    issue_type: IssueType::FlakyTest,
                    description: "Test uses polling or multiple attempts which may be flaky".to_string(),
                    code_snippet: line.trim().to_string(),
                });
            }
            
            // Check for timing-dependent assertions
            if line_lower.contains("assert") && 
               (line_lower.contains("duration") || line_lower.contains("elapsed")) {
                self.issues.push(TestIssue {
                    file_path: file_path.to_path_buf(),
                    line_number: line_number + 1,
                    issue_type: IssueType::FlakyTest,
                    description: "Test assertions depend on timing which may be unreliable".to_string(),
                    code_snippet: line.trim().to_string(),
                });
            }
        }
    }
    
    fn audit_files_sequential(&mut self, test_files: Vec<PathBuf>) -> AuditorResult<()> {
        for file_path in test_files {
            println!("Auditing: {}", file_path.display());
            self.audit_file(&file_path)?;
        }
        Ok(())
    }
    
    fn audit_files_parallel(&mut self, test_files: Vec<PathBuf>) -> AuditorResult<()> {
        let shared_issues = Mutex::new(Vec::new());
        let shared_errors = Mutex::new(Vec::new());
        let config = self.config.clone();
        let root_path = self.root_path.clone();
        
        // Process files in parallel
        test_files
            .par_iter()
            .for_each(|file_path| {
                println!("Auditing: {}", file_path.display());
                
                // Create a temporary auditor for this thread
                let temp_auditor_result = TestAuditor::with_config(
                    config.clone(),
                    root_path.clone()
                );
                
                let mut temp_auditor = match temp_auditor_result {
                    Ok(auditor) => auditor,
                    Err(e) => {
                        let mut errors = shared_errors.lock().unwrap();
                        errors.push(format!("Failed to create auditor: {}", e));
                        return;
                    }
                };
                
                // Audit the file
                if let Err(e) = temp_auditor.audit_file(file_path) {
                    let mut errors = shared_errors.lock().unwrap();
                    errors.push(format!("Failed to audit {}: {}", file_path.display(), e));
                    return;
                }
                
                // Merge results back
                {
                    let mut shared = shared_issues.lock().unwrap();
                    shared.extend(temp_auditor.issues);
                }
            });
        
        // Check for errors
        let errors = shared_errors.into_inner().unwrap();
        if !errors.is_empty() {
            return Err(AuditorError::ParallelProcessing {
                message: errors.join(", "),
            });
        }
        
        // Collect all issues
        let all_issues = shared_issues.into_inner().unwrap();
        self.issues.extend(all_issues);
        
        Ok(())
    }

    fn generate_report(&self) -> AuditorResult<()> {
        match self.config.output.format {
            OutputFormat::Console => {
                self.generate_console_report();
                Ok(())
            },
            OutputFormat::Json => self.generate_json_report(),
            OutputFormat::Xml => self.generate_xml_report(),
        }
    }

    fn generate_console_report(&self) {
        let title = if self.config.output.color {
            "=== TEST AUDIT REPORT ===".bold().blue().to_string()
        } else {
            "=== TEST AUDIT REPORT ===".to_string()
        };
        println!("\n{}", title);
        println!("Total issues found: {}\n", self.issues.len());

        let mut issues_by_type: std::collections::HashMap<IssueType, Vec<&TestIssue>> = std::collections::HashMap::new();
        
        for issue in &self.issues {
            issues_by_type.entry(issue.issue_type.clone()).or_insert_with(Vec::new).push(issue);
        }

        for (issue_type, issues) in issues_by_type {
            let type_header = if self.config.output.color {
                format!("{} ({})", issue_type.description().color(issue_type.color()).bold(), issues.len())
            } else {
                format!("{} ({})", issue_type.description(), issues.len())
            };
            println!("{}", type_header);
            
            for issue in issues {
                println!("  📁 {}", issue.file_path.display());
                println!("  📍 Line {}: {}", issue.line_number, issue.description);
                let snippet = if self.config.output.color {
                    issue.code_snippet.dimmed().to_string()
                } else {
                    issue.code_snippet.clone()
                };
                println!("  💻 {}", snippet);
                println!();
            }
        }

        let status_message = if self.issues.is_empty() {
            if self.config.output.color {
                "✅ No issues found! Your tests look good.".green().bold().to_string()
            } else {
                "✅ No issues found! Your tests look good.".to_string()
            }
        } else {
            if self.config.output.color {
                "❌ Issues found that may need attention.".red().bold().to_string()
            } else {
                "❌ Issues found that may need attention.".to_string()
            }
        };
        println!("{}", status_message);
    }

    fn generate_json_report(&self) -> AuditorResult<()> {
        #[derive(Serialize)]
        struct JsonReport {
            total_issues: usize,
            issues: Vec<TestIssue>,
        }

        let report = JsonReport {
            total_issues: self.issues.len(),
            issues: self.issues.clone(),
        };

        let json = serde_json::to_string_pretty(&report)?;
        println!("{}", json);
        Ok(())
    }

    fn generate_xml_report(&self) -> AuditorResult<()> {
        #[derive(Serialize)]
        #[serde(rename = "test_audit_report")]
        struct XmlReport {
            total_issues: usize,
            issues: Vec<TestIssue>,
        }

        let report = XmlReport {
            total_issues: self.issues.len(),
            issues: self.issues.clone(),
        };

        let xml = to_xml_string(&report)
            .map_err(|e| AuditorError::XmlSerialization(e))?;
        println!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}", xml);
        Ok(())
    }
}

fn load_config(config_path: Option<&str>) -> AuditorResult<Config> {
    let config_file = config_path.unwrap_or(".test-auditor");
    
    if Path::new(config_file).exists() {
        let content = fs::read_to_string(config_file)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    } else {
        Ok(Config::default())
    }
}

fn main() -> AuditorResult<()> {
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
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("CONFIG_FILE")
                .help("Path to configuration file")
        )
        .arg(
            Arg::new("json")
                .short('j')
                .long("json")
                .help("Output in JSON format")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("xml")
                .short('x')
                .long("xml")
                .help("Output in XML format")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("no-color")
                .long("no-color")
                .help("Disable colored output")
                .action(clap::ArgAction::SetTrue)
        )
        .get_matches();

    let path = matches.get_one::<String>("path").unwrap();
    let _verbose = matches.get_flag("verbose");
    let config_path = matches.get_one::<String>("config").map(|s| s.as_str());
    let json_output = matches.get_flag("json");
    let xml_output = matches.get_flag("xml");
    let no_color = matches.get_flag("no-color");

    let mut config = load_config(config_path)?;
    
    // Override config with CLI arguments
    if json_output {
        config.output.format = OutputFormat::Json;
    }
    if xml_output {
        config.output.format = OutputFormat::Xml;
    }
    if no_color {
        config.output.color = false;
    }

    let mut auditor = TestAuditor::with_config(config, PathBuf::from(path))?;
    auditor.audit_directory(Path::new(path))?;
    auditor.generate_report()?;

    // Return proper exit code for CI without using std::process::exit
    if !auditor.issues.is_empty() {
        std::process::exit(1);
    }
    
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
        assert!(!TEST_PATTERNS.is_empty());
        assert!(!ISSUE_PATTERNS.is_empty());
    }

    #[test]
    fn test_is_test_file() {
        let auditor = TestAuditor::with_config(Config::default(), PathBuf::from(".")).unwrap();
        
        assert!(auditor.is_test_file(Path::new("test_module.rs")));
        assert!(auditor.is_test_file(Path::new("module_test.rs")));
        assert!(auditor.is_test_file(Path::new("tests.rs")));
        assert!(auditor.is_test_file(Path::new("integration_tests.rs")));
        assert!(!auditor.is_test_file(Path::new("main.rs")));
        assert!(!auditor.is_test_file(Path::new("lib.rs")));
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
        let mut file = fs::File::create(&file_path).unwrap();
        
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
        
        fs::File::create(dir.path().join("test_module.rs")).unwrap();
        fs::File::create(dir.path().join("tests.rs")).unwrap();
        fs::File::create(dir.path().join("main.rs")).unwrap();
        fs::File::create(dir.path().join("lib.rs")).unwrap();
        
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
        
        assert!(!auditor.is_rule_enabled(&IssueType::HardcodedValues));
        assert!(auditor.is_rule_enabled(&IssueType::AlwaysPass));
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
    fn test_safe_unwrap_detection() {
        let auditor = TestAuditor::with_config(Config::default(), PathBuf::from(".")).unwrap();
        
        // Test safe unwrap patterns
        assert!(auditor.is_safe_unwrap_context("let dir = tempdir().unwrap();"));
        assert!(auditor.is_safe_unwrap_context("let file = File::create(path).unwrap();"));
        assert!(auditor.is_safe_unwrap_context("writeln!(file, \"test\").unwrap();"));
        assert!(auditor.is_safe_unwrap_context("result.unwrap(); // safe: this is guaranteed to work"));
        
        // Test unsafe unwrap patterns
        assert!(!auditor.is_safe_unwrap_context("let value = some_result.unwrap();"));
        assert!(!auditor.is_safe_unwrap_context("process_data().unwrap();"));
    }
    
    #[test]
    fn test_custom_error_types() {
        // Test path traversal error
        let auditor = TestAuditor::with_config(Config::default(), PathBuf::from("/tmp")).unwrap();
        let result = auditor.validate_path(Path::new("/etc/passwd"));
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        match error {
            AuditorError::PathTraversal { path, root } => {
                assert!(path.contains("/etc/passwd"));
                assert!(root.contains("/tmp"));
            }
            _ => panic!("Expected PathTraversal error, got: {:?}", error),
        }
        
        // Test config error
        let invalid_toml = "[invalid toml content";
        let config_result: Result<Config, _> = toml::from_str(invalid_toml);
        assert!(config_result.is_err());
        
        // Test file too large error (simulated)
        let large_file_error = AuditorError::FileTooLarge {
            path: "large_file.rs".to_string(),
            size: 20_000_000,
            max_size: 10_000_000,
        };
        
        let error_message = large_file_error.to_string();
        assert!(error_message.contains("File too large"));
        assert!(error_message.contains("large_file.rs"));
        assert!(error_message.contains("20000000 bytes"));
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
        let mut file = fs::File::create(&config_file).unwrap();
        
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