use anyhow::Context;
use clap::Parser;
use nix::sys::resource::{getrlimit, setrlimit, Resource};
use std::env;
use std::fs::{self, File};
use std::panic::catch_unwind;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tempdir::TempDir;
use test_cases::{test_cases, Test, TestCase, TestSetup};

fn get_test(name: &str) -> anyhow::Result<Box<dyn Test>> {
    let tests = test_cases();
    tests
        .into_iter()
        .find(|t| t.name() == name)
        .with_context(|| format!("No such test: {name}"))
        .map(|t| t.test)
}

fn start_vm(test_setup: TestSetup) -> anyhow::Result<()> {
    // Raise soft fd limit up to the hard limit
    let (_soft_limit, hard_limit) =
        getrlimit(Resource::RLIMIT_NOFILE).context("getrlimit RLIMIT_NOFILE")?;
    setrlimit(Resource::RLIMIT_NOFILE, hard_limit, hard_limit)
        .context("setrlimit RLIMIT_NOFILE")?;

    let test = get_test(&test_setup.test_case)?;
    test.start_vm(test_setup.clone())
        .with_context(|| format!("testcase: {test_setup:?}"))?;
    Ok(())
}

fn run_single_test(
    test_case: &str,
    base_dir: &Path,
    keep_all: bool,
    max_name_len: usize,
) -> anyhow::Result<bool> {
    let executable = env::current_exe().context("Failed to detect current executable")?;
    let test_dir = base_dir.join(test_case);
    fs::create_dir(&test_dir).context("Failed to create test directory")?;

    let log_path = test_dir.join("log.txt");
    let log_file = File::create(&log_path).context("Failed to create log file")?;

    eprint!(
        "[{test_case}] {:.<width$} ",
        "",
        width = max_name_len - test_case.len() + 3
    );

    let child = Command::new(&executable)
        .arg("start-vm")
        .arg("--test-case")
        .arg(test_case)
        .arg("--tmp-dir")
        .arg(&test_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(log_file)
        .spawn()
        .context("Failed to start subprocess for test")?;

    let _ = get_test(test_case)?;
    let result = catch_unwind(|| {
        let test = get_test(test_case).unwrap();
        test.check(child);
    });

    match result {
        Ok(()) => {
            eprintln!("OK");
            if !keep_all {
                let _ = fs::remove_dir_all(&test_dir);
            }
            Ok(true)
        }
        Err(_e) => {
            eprintln!("FAIL");
            Ok(false)
        }
    }
}

fn run_tests(test_case: &str, base_dir: Option<PathBuf>, keep_all: bool) -> anyhow::Result<()> {
    // Create the base directory - either use provided path or create a temp one
    let base_dir = match base_dir {
        Some(path) => {
            fs::create_dir_all(&path).context("Failed to create base directory")?;
            path
        }
        None => TempDir::new("libkrun-tests")
            .context("Failed to create temp base directory")?
            .into_path(),
    };

    let mut num_tests = 1;
    let mut num_ok: usize = 0;

    if test_case == "all" {
        let all_tests = test_cases();
        num_tests = all_tests.len();
        let max_name_len = all_tests.iter().map(|t| t.name.len()).max().unwrap_or(0);

        for TestCase { name, test: _ } in all_tests {
            num_ok +=
                run_single_test(name, &base_dir, keep_all, max_name_len).context(name)? as usize;
        }
    } else {
        let max_name_len = test_case.len();
        num_ok += run_single_test(test_case, &base_dir, keep_all, max_name_len)
            .context(test_case.to_string())? as usize;
    }

    let num_failures = num_tests - num_ok;
    if num_failures > 0 {
        eprintln!("(See test artifacts at: {})", base_dir.display());
        println!("\nFAIL (PASSED {num_ok}/{num_tests})");
        anyhow::bail!("")
    } else {
        if keep_all {
            eprintln!("(See test artifacts at: {})", base_dir.display());
        }
        eprintln!("\nOK ({num_ok}/{num_tests} passed)");
    }

    Ok(())
}

#[derive(clap::Subcommand, Clone, Debug)]
enum CliCommand {
    Test {
        /// Specify which test to run or "all"
        #[arg(long, default_value = "all")]
        test_case: String,
        /// Base directory for test artifacts
        #[arg(long)]
        base_dir: Option<PathBuf>,
        /// Keep all test artifacts even on success
        #[arg(long)]
        keep_all: bool,
    },
    StartVm {
        #[arg(long)]
        test_case: String,
        #[arg(long)]
        tmp_dir: PathBuf,
    },
}

impl Default for CliCommand {
    fn default() -> Self {
        Self::Test {
            test_case: "all".to_string(),
            base_dir: None,
            keep_all: false,
        }
    }
}

#[derive(clap::Parser)]
struct Cli {
    #[command(subcommand)]
    command: Option<CliCommand>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let command = cli.command.unwrap_or_default();

    match command {
        CliCommand::StartVm { test_case, tmp_dir } => start_vm(TestSetup { test_case, tmp_dir }),
        CliCommand::Test {
            test_case,
            base_dir,
            keep_all,
        } => run_tests(&test_case, base_dir, keep_all),
    }
}
