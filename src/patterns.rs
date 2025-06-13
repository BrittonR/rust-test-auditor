use regex::Regex;
use once_cell::sync::Lazy;
use crate::issue::IssueType;

// Cached regex patterns for performance
pub static TEST_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"#\[test\]").unwrap(),
        Regex::new(r"#\[cfg\(test\)\]").unwrap(),
        Regex::new(r"fn test_\w+").unwrap(),
        Regex::new(r"describe\(").unwrap(),
        Regex::new(r"it\(").unwrap(),
        Regex::new(r"TEST\(").unwrap(),
    ]
});

pub static ISSUE_PATTERNS: Lazy<Vec<(Regex, IssueType)>> = Lazy::new(|| {
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