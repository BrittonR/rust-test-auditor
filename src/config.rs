use serde::Deserialize;

/// Configuration structure for the test auditor
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    /// Configuration for which rules to enable/disable
    #[serde(default)]
    pub rules: RuleConfig,
    /// Configuration for output formatting
    #[serde(default)]
    pub output: OutputConfig,
    /// Configuration for pattern matching and file exclusions
    #[serde(default)]
    pub patterns: PatternConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RuleConfig {
    #[serde(default = "default_true")]
    pub hardcoded_values: bool,
    #[serde(default = "default_true")]
    pub always_pass: bool,
    #[serde(default = "default_true")]
    pub empty_test: bool,
    #[serde(default = "default_true")]
    pub error_ignored: bool,
    #[serde(default = "default_true")]
    pub misleading_name: bool,
    #[serde(default = "default_true")]
    pub copy_pasted: bool,
    #[serde(default = "default_true")]
    pub edge_case_not_tested: bool,
    #[serde(default = "default_true")]
    pub implementation_detail: bool,
    #[serde(default = "default_true")]
    pub no_assertions: bool,
    #[serde(default = "default_true")]
    pub non_deterministic: bool,
    #[serde(default = "default_true")]
    pub unsafe_unwrap: bool,
    #[serde(default = "default_true")]
    pub vague_panic: bool,
    #[serde(default = "default_true")]
    pub magic_numbers: bool,
    #[serde(default = "default_true")]
    pub async_test_issue: bool,
    #[serde(default = "default_true")]
    pub debug_output: bool,
    #[serde(default = "default_true")]
    pub commented_out_code: bool,
    #[serde(default = "default_true")]
    pub sleep_in_test: bool,
    #[serde(default = "default_true")]
    pub todo_in_test: bool,
    #[serde(default = "default_true")]
    pub test_timeout: bool,
    #[serde(default = "default_true")]
    pub flaky_test: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct OutputConfig {
    #[serde(default)]
    pub format: OutputFormat,
    #[serde(default = "default_true")]
    pub color: bool,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub enum OutputFormat {
    #[default]
    Console,
    Json,
    Xml,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PatternConfig {
    #[serde(default = "default_magic_number_threshold")]
    pub magic_number_threshold: u32,
    #[serde(default)]
    pub ignore_patterns: Vec<String>,
    #[serde(default)]
    pub exclude_dirs: Vec<String>,
    #[serde(default)]
    pub exclude_files: Vec<String>,
}

fn default_true() -> bool { 
    true 
}

fn default_magic_number_threshold() -> u32 { 
    10 
}

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