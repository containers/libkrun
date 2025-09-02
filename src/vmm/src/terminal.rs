use libc::{STDERR_FILENO, STDIN_FILENO, STDOUT_FILENO};
use nix::sys::termios::{tcgetattr, tcsetattr, LocalFlags, SetArg};
use nix::unistd::isatty;
use std::os::fd::BorrowedFd;

pub fn term_set_raw_mode(handle_signals_by_terminal: bool) -> Result<(), nix::Error> {
    if let Some(fd) = get_connected_term_fd() {
        term_fd_set_raw_mode(fd, handle_signals_by_terminal)
    } else {
        Ok(())
    }
}

pub fn term_set_canonical_mode() -> Result<(), nix::Error> {
    if let Some(fd) = get_connected_term_fd() {
        term_fd_set_canonical_mode(fd)
    } else {
        Ok(())
    }
}

pub fn term_fd_set_raw_mode(
    term: BorrowedFd,
    handle_signals_by_terminal: bool,
) -> Result<(), nix::Error> {
    let mut termios = tcgetattr(term)?;

    let mut mask = LocalFlags::ECHO | LocalFlags::ICANON;
    if !handle_signals_by_terminal {
        mask |= LocalFlags::ISIG
    }

    termios.local_flags &= !mask;
    tcsetattr(term, SetArg::TCSANOW, &termios)?;
    Ok(())
}

pub fn term_fd_set_canonical_mode(term: BorrowedFd) -> Result<(), nix::Error> {
    let mut termios = tcgetattr(term)?;
    termios.local_flags |= LocalFlags::ECHO | LocalFlags::ICANON | LocalFlags::ISIG;
    tcsetattr(term, SetArg::TCSANOW, &termios)?;
    Ok(())
}

pub fn get_connected_term_fd() -> Option<BorrowedFd<'static>> {
    let (stdin, stdout, stderr) = unsafe {
        (
            BorrowedFd::borrow_raw(STDIN_FILENO),
            BorrowedFd::borrow_raw(STDOUT_FILENO),
            BorrowedFd::borrow_raw(STDERR_FILENO),
        )
    };

    if isatty(stdin).unwrap_or(false) {
        Some(stdin)
    } else if isatty(stdout).unwrap_or(false) {
        Some(stdout)
    } else if isatty(stderr).unwrap_or(false) {
        Some(stderr)
    } else {
        None
    }
}
