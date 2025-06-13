use serde::Serialize;
use std::path::PathBuf;

/// Represents a single issue found during test auditing
#[derive(Debug, Clone, Serialize)]
pub struct TestIssue {
    /// Path to the file containing the issue
    pub file_path: PathBuf,
    /// Line number where the issue was found
    pub line_number: usize,
    /// Type of issue detected
    pub issue_type: IssueType,
    /// Human-readable description of the issue
    pub description: String,
    /// Code snippet that triggered the issue
    pub code_snippet: String,
}

/// Types of issues that can be detected in test code
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub enum IssueType {
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
    pub fn color(&self) -> &'static str {
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

    pub fn description(&self) -> &'static str {
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