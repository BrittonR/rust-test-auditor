use clap::{Arg, Command};
use std::path::{Path, PathBuf};
use rust_test_auditor::{load_config, TestAuditor, OutputFormat, AuditorResult};

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