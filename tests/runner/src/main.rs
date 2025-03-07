use anyhow::Context;
use clap::Parser;
use nix::sys::resource::{getrlimit, setrlimit, Resource};
use std::panic::catch_unwind;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::{env, mem};
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

fn run_single_test(test_case: &str) -> anyhow::Result<bool> {
    let executable = env::current_exe().context("Failed to detect current executable")?;
    let tmp_dir =
        TempDir::new(&format!("krun-test-{test_case}")).context("Failed to create tmp dir")?;

    let child = Command::new(&executable)
        .arg("start-vm")
        .arg("--test-case")
        .arg(test_case)
        .arg("--tmp-dir")
        .arg(tmp_dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to start subprocess for test")?;

    let _ = get_test(test_case)?;
    let result = catch_unwind(|| {
        let test = get_test(test_case).unwrap();
        test.check(child);
    });

    match result {
        Ok(()) => {
            println!("[{test_case}]: OK");
            Ok(true)
        }
        Err(_e) => {
            println!("[{test_case}]: FAIL (dir {:?} kept)", tmp_dir.path());
            mem::forget(tmp_dir);
            Ok(false)
        }
    }
}

fn run_tests(test_case: &str) -> anyhow::Result<()> {
    let mut num_tests = 1;
    let mut num_ok: usize = 0;

    if test_case == "all" {
        let test_cases = test_cases();
        num_tests = test_cases.len();

        for TestCase { name, test: _ } in test_cases {
            num_ok += run_single_test(name).context(name)? as usize;
        }
    } else {
        num_ok += run_single_test(test_case).context(test_case.to_string())? as usize;
    }

    let num_failures = num_tests - num_ok;
    if num_failures > 0 {
        println!("\nFAIL (PASSED {num_ok}/{num_tests})");
        anyhow::bail!("")
    } else {
        println!("\nOK (PASSED {num_ok}/{num_tests})");
    }

    Ok(())
}

#[derive(clap::Subcommand, Clone, Debug)]
enum CliCommand {
    Test {
        /// Specify which test to run or "all"
        #[arg(long, default_value = "all")]
        test_case: String,
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
        CliCommand::Test { test_case } => run_tests(&test_case),
    }
}
