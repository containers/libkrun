use anyhow::Context;
use std::env::args;
use test_cases::{test_cases, TestCase};

fn run_guest_agent(test_name: &str) -> anyhow::Result<()> {
    let tests = test_cases();
    let test_case = tests
        .into_iter()
        .find(|t| t.name() == test_name)
        .context("No such test!")?;
    let TestCase { test, name: _ } = test_case;
    test.in_guest();
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let mut cli_args = args();
    let _exec_name = cli_args.next();
    let test_name = cli_args.next().context("Missing test name argument")?;
    run_guest_agent(&test_name)?;
    Ok(())
}
