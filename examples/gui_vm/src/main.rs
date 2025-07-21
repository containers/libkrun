use clap::Parser;
use clap_derive::Parser;
use gtk_display::DisplayBackendHandle;
use krun_sys::{
    VIRGLRENDERER_RENDER_SERVER, VIRGLRENDERER_THREAD_SYNC, VIRGLRENDERER_USE_ASYNC_FENCE_CB,
    VIRGLRENDERER_USE_EGL, VIRGLRENDERER_VENUS, krun_add_display, krun_create_ctx,
    krun_set_display_backend, krun_set_exec, krun_set_gpu_options, krun_set_log_level,
    krun_set_root, krun_start_enter,
};
use log::LevelFilter;
use std::ffi::{CString, c_void};
use std::process::exit;
use std::ptr::null;
use std::thread;

mod krun_utils;

#[derive(Debug, Clone, Copy)]
struct DisplayArg {
    width: u32,
    height: u32,
}

fn parse_display(s: &str) -> Result<DisplayArg, String> {
    let parts: Vec<&str> = s.split('x').collect();
    if parts.len() != 2 {
        return Err("Expected format: [width]x[height]".to_string());
    }
    let width = parts[0].parse().map_err(|_| "Invalid width")?;
    let height = parts[1].parse().map_err(|_| "Invalid height")?;
    Ok(DisplayArg { width, height })
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    root_dir: Option<CString>,

    executable: Option<CString>,
    argv: Vec<CString>,
    #[clap(long, value_parser = parse_display)]
    display: Vec<DisplayArg>,
}

fn krun_thread(args: &Args, display_backend_handle: DisplayBackendHandle) -> anyhow::Result<()> {
    unsafe {
        krun_call!(krun_set_log_level(3))?;
        let ctx = krun_call_u32!(krun_create_ctx())?;

        krun_call!(krun_set_gpu_options(
            ctx,
            VIRGLRENDERER_USE_EGL
                | VIRGLRENDERER_VENUS
                | VIRGLRENDERER_RENDER_SERVER
                | VIRGLRENDERER_THREAD_SYNC
                | VIRGLRENDERER_USE_ASYNC_FENCE_CB
        ))?;

        if let Some(root_dir) = &args.root_dir {
            krun_call!(krun_set_root(ctx, root_dir.as_ptr()))?;
            // Executable variable should be set if we have root_dir, this is verified by clap
            let executable = args.executable.as_ref().unwrap().as_ptr();
            let argv: Vec<_> = args.argv.iter().map(|a| a.as_ptr()).collect();
            let argv_ptr = if argv.is_empty() {
                null()
            } else {
                argv.as_ptr()
            };
            let envp = [null()];
            krun_call!(krun_set_exec(ctx, executable, argv_ptr, envp.as_ptr()))?;
        }

        for display in &args.display {
            krun_call!(krun_add_display(ctx, display.width, display.height))?;
        }
        let display_backend = display_backend_handle.get();
        krun_call!(krun_set_display_backend(
            ctx,
            &raw const display_backend as *const c_void,
            size_of_val(&display_backend),
        ))?;
        krun_call!(krun_start_enter(ctx))?;
    };
    Ok(())
}

fn main() -> anyhow::Result<()> {
    env_logger::builder().filter_level(LevelFilter::Info).init();
    let args = Args::parse();

    let (display_backend, display_worker) =
        gtk_display::crate_display("libkrun examples/gui_vm".to_string());

    thread::scope(|s| {
        s.spawn(|| {
            if let Err(e) = krun_thread(&args, display_backend) {
                eprintln!("{e}");
                exit(1);
            }
        });
        display_worker.run()
    });
    unreachable!("Expected libkrun (or error handling) to exit the process");
}
