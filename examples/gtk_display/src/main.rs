use crate::display_backend::GtkDisplayBackend;
use crate::display_loop::display_loop;
use crate::event::DisplayEvent;
use ::utils::pollable_channel::{PollableChannelSender, pollable_channel};
use clap::Parser;
use clap_derive::Parser;
use krun_display::{DisplayBackend, IntoDisplayBackend};
use krun_sys::{
    KRUN_DISPLAY_FEATURE_BASIC_FRAMEBUFFER, VIRGLRENDERER_THREAD_SYNC,
    VIRGLRENDERER_USE_ASYNC_FENCE_CB, VIRGLRENDERER_USE_EGL, krun_create_ctx, krun_set_display,
    krun_set_display_backend, krun_set_exec, krun_set_gpu_options, krun_set_log_level,
    krun_set_root, krun_start_enter,
};
use std::ffi::{CString, c_char, c_void};
use std::process::exit;
use std::ptr::null;
use std::thread;

mod display_backend;
mod display_loop;
mod event;
mod utils;

#[derive(Debug, Clone, Copy)]
struct DisplayArg {
    id: u32,
    width: u32,
    height: u32,
}

fn parse_display(s: &str) -> Result<DisplayArg, String> {
    let parts: Vec<&str> = s.split(',').collect();
    if parts.len() != 3 {
        return Err("Expected format: id,width,height".to_string());
    }
    let id = parts[0].parse().map_err(|_| "Invalid id")?;
    let width = parts[1].parse().map_err(|_| "Invalid width")?;
    let height = parts[2].parse().map_err(|_| "Invalid height")?;
    Ok(DisplayArg { id, width, height })
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    root_dir: CString,
    #[clap(long, value_parser = parse_display)]
    display: Vec<DisplayArg>,
    argv: Vec<CString>,
}

fn krun_thread(args: &Args, tx: &PollableChannelSender<DisplayEvent>) -> anyhow::Result<()> {
    unsafe {
        krun_call!(krun_set_log_level(3))?;
        let ctx = krun_call_u32!(krun_create_ctx())?;

        krun_call!(krun_set_gpu_options(
            ctx,
            VIRGLRENDERER_USE_EGL
                | VIRGLRENDERER_USE_EGL
                | VIRGLRENDERER_THREAD_SYNC
                | VIRGLRENDERER_USE_ASYNC_FENCE_CB
        ))?;

        krun_call!(krun_set_root(ctx, args.root_dir.as_ptr()))?;

        for display in &args.display {
            krun_call!(krun_set_display(
                ctx,
                display.id,
                display.width,
                display.height
            ))?;
        }

        let display_backend = GtkDisplayBackend::into_display_backend(Some(tx));

        krun_call!(krun_set_display_backend(
            ctx,
            1,
            &raw const display_backend as *const c_void,
            size_of::<DisplayBackend>()
        ))?;

        let envp = [c"TEST=works".as_ptr(), null()];
        let argv_ptrs: Vec<*const c_char> = args.argv.iter().map(|x| x.as_ptr()).collect();
        krun_call!(krun_set_exec(
            ctx,
            argv_ptrs[0],
            argv_ptrs[1..].as_ptr(),
            envp.as_ptr()
        ))?;
        krun_call!(krun_start_enter(ctx))?;
    };
    Ok(())
}

fn main() -> anyhow::Result<()> {
    // Note that we have a different instance of env_logger than libkrun
    // env_logger::init();

    thread::scope(|s| {
        let args = Args::parse();
        let (tx, rx) = pollable_channel().unwrap();
        s.spawn(move || {
            if let Err(e) = krun_thread(&args, &tx) {
                eprintln!("{e}");
                exit(1);
            }
        });
        display_loop(rx);
    });
    unreachable!()
}
