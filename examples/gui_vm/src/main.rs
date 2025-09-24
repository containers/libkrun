use clap::Parser;
use clap_derive::Parser;
use gtk_display::DisplayBackendHandle;
use krun_sys::{
    VIRGLRENDERER_RENDER_SERVER, VIRGLRENDERER_THREAD_SYNC, VIRGLRENDERER_USE_ASYNC_FENCE_CB,
    VIRGLRENDERER_USE_EGL, VIRGLRENDERER_VENUS, krun_add_display, krun_create_ctx,
    krun_display_set_dpi, krun_display_set_physical_size, krun_display_set_refresh_rate,
    krun_set_display_backend, krun_set_exec, krun_set_gpu_options, krun_set_log_level,
    krun_set_root, krun_start_enter,
};
use log::LevelFilter;
use regex::{Captures, Regex};
use std::ffi::{CString, c_void};
use std::fmt::Display;
use std::process::exit;
use std::ptr::null;
use std::str::FromStr;
use std::sync::LazyLock;
use std::thread;

mod krun_utils;

#[derive(Debug, Copy, Clone)]
pub enum PhysicalSize {
    Dpi(u32),
    DimensionsMillimeters(u16, u16),
}

#[derive(Debug, Clone, Copy)]
struct DisplayArg {
    width: u32,
    height: u32,
    refresh_rate: Option<u32>,
    physical_size: Option<PhysicalSize>,
}

/// Parses a display settings string.
/// The expected format is "WIDTHxHEIGHT[@FPS][:DPIdpi|:PHYSICAL_WIDTHxPHYSICAL_HEIGHTmm]".
fn parse_display(display_string: &str) -> Result<DisplayArg, String> {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"^(?P<width>\d+)x(?P<height>\d+)(?:@(?P<refresh_rate>\d+))?(?::(?P<dpi>\d+)dpi|:(?P<width_mm>\d+)x(?P<height_mm>\d+)mm)?$",
        ).unwrap()
    });

    let captures = RE.captures(display_string).ok_or_else(|| {
        format!("Invalid display string '{display_string}' format. Examples of valid values:\n '1920x1080', '1920x1080@60', '1920x1080:162x91mm', '1920x1080:300dpi', '1920x1080@90:300dpi'")
    })?;

    fn parse_group<T: FromStr>(captures: &Captures, name: &str) -> Result<Option<T>, String>
    where
        T::Err: Display,
    {
        captures
            .name(name)
            .map(|match_| {
                match_
                    .as_str()
                    .parse::<T>()
                    .map_err(|e| format!("Failed to parse {name}: {e}"))
            })
            .transpose()
    }

    Ok(DisplayArg {
        width: parse_group(&captures, "width")?.expect("regex bug"),
        height: parse_group(&captures, "height")?.expect("regex bug"),
        refresh_rate: parse_group(&captures, "refresh_rate")?,
        physical_size: match (
            parse_group(&captures, "dpi")?,
            parse_group(&captures, "width_mm")?,
            parse_group(&captures, "height_mm")?,
        ) {
            (Some(dpi), None, None) => Some(PhysicalSize::Dpi(dpi)),
            (None, Some(width_mm), Some(height_mm)) => {
                Some(PhysicalSize::DimensionsMillimeters(width_mm, height_mm))
            }
            (None, None, None) => None,
            _ => unreachable!("regex bug"),
        },
    })
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    root_dir: Option<CString>,

    executable: Option<CString>,
    argv: Vec<CString>,
    // Display specifications in the format WIDTHxHEIGHT[@FPS][:DPIdpi|:PHYSICAL_WIDTHxPHYSICAL_HEIGHTmm]
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
            let display_id = krun_call_u32!(krun_add_display(ctx, display.width, display.height))?;
            if let Some(refresh_rate) = display.refresh_rate {
                krun_call!(krun_display_set_refresh_rate(ctx, display_id, refresh_rate))?;
            }
            match display.physical_size {
                None => (),
                Some(PhysicalSize::Dpi(dpi)) => {
                    krun_call!(krun_display_set_dpi(ctx, display_id, dpi))?;
                }
                Some(PhysicalSize::DimensionsMillimeters(width_mm, height_mm)) => {
                    krun_call!(krun_display_set_physical_size(
                        ctx, display_id, width_mm, height_mm
                    ))?;
                }
            };
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
