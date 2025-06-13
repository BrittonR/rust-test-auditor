use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::hash::{Hash, Hasher, DefaultHasher};
use walkdir::WalkDir;
use regex::Regex;
use rayon::prelude::*;
use std::sync::Mutex;

use crate::ast_analyzer::AstAnalyzer;
use crate::config::Config;
use crate::errors::{AuditorError, AuditorResult};
use crate::issue::{TestIssue, IssueType};
use crate::patterns::{TEST_PATTERNS, ISSUE_PATTERNS};

/// Main auditor structure that analyzes test files for anti-patterns
pub struct TestAuditor {
    pub issues: Vec<TestIssue>,
    pub config: Config,
    root_path: PathBuf,
}

impl TestAuditor {
    /// Creates a new TestAuditor with default configuration
    pub fn new() -> AuditorResult<Self> {
        Self::with_config(Config::default(), PathBuf::from("."))
    }

    /// Creates a new TestAuditor with the specified configuration and root path
    /// 
    /// # Arguments
    /// * `config` - Configuration settings for the auditor
    /// * `root_path` - Root directory for path validation (prevents path traversal)
    pub fn with_config(config: Config, root_path: PathBuf) -> AuditorResult<Self> {
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
            IssueType::UnusedVariable => self.config.rules.unused_variable,
            IssueType::UnreachableCode => self.config.rules.unreachable_code,
            IssueType::TautologicalAssertion => self.config.rules.tautological_assertion,
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

    pub fn find_test_files(&self, root_path: &Path) -> Vec<PathBuf> {
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
    pub fn audit_file(&mut self, file_path: &Path) -> AuditorResult<()> {
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

        // Run regex-based analysis
        for (line_number, line) in lines.iter().enumerate() {
            self.check_line(file_path, line_number + 1, line, &content);
        }

        self.check_for_copy_pasted_tests(file_path, &lines);
        self.check_for_misleading_names(file_path, &lines);
        self.check_for_no_assertions(file_path, &lines);
        self.check_async_tests(file_path, &lines);
        self.check_flaky_test_patterns(file_path, &lines);

        // Run AST-based analysis
        self.run_ast_analysis(file_path, &content)?;

        Ok(())
    }

    /// Runs AST-based analysis on the file content
    /// 
    /// # Arguments
    /// * `file_path` - Path to the file being analyzed
    /// * `content` - The file content as a string
    /// 
    /// # Returns
    /// Result indicating success or failure of the AST analysis
    fn run_ast_analysis(&mut self, file_path: &Path, content: &str) -> AuditorResult<()> {
        let mut ast_analyzer = AstAnalyzer::new();
        
        match ast_analyzer.analyze_file(file_path, content) {
            Ok(()) => {
                // Filter AST issues based on enabled rules before adding them
                for issue in ast_analyzer.issues {
                    if self.is_rule_enabled(&issue.issue_type) {
                        self.issues.push(issue);
                    }
                }
            }
            Err(syn_error) => {
                // If AST parsing fails, log a warning but don't fail the entire audit
                // This allows the regex-based analysis to still work on malformed code
                eprintln!("Warning: AST analysis failed for {}: {}", file_path.display(), syn_error);
            }
        }
        
        Ok(())
    }

    pub fn check_line(&mut self, file_path: &Path, line_number: usize, line: &str, full_content: &str) {
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

    pub fn check_for_copy_pasted_tests(&mut self, file_path: &Path, lines: &[&str]) {
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

    pub fn check_for_misleading_names(&mut self, file_path: &Path, lines: &[&str]) {
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

    pub fn check_for_no_assertions(&mut self, file_path: &Path, lines: &[&str]) {
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

    pub fn check_async_tests(&mut self, file_path: &Path, lines: &[&str]) {
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

    pub fn audit_directory(&mut self, path: &Path) -> AuditorResult<()> {
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
    
    pub fn check_flaky_test_patterns(&mut self, file_path: &Path, lines: &[&str]) {
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
}