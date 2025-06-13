use std::collections::HashMap;
use colored::*;
use serde::Serialize;
use quick_xml::se::to_string as to_xml_string;

use crate::auditor::TestAuditor;
use crate::config::OutputFormat;
use crate::errors::{AuditorError, AuditorResult};
use crate::issue::{TestIssue, IssueType};

impl TestAuditor {
    pub fn generate_report(&self) -> AuditorResult<()> {
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

        let mut issues_by_type: HashMap<IssueType, Vec<&TestIssue>> = HashMap::new();
        
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