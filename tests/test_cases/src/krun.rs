#[macro_export]
macro_rules! krun_call {
    ($func_call:expr) => {{
        let result = $func_call;
        if result < 0 {
            let err = std::io::Error::from_raw_os_error(-result);
            anyhow::bail!("`{}`: {}", stringify!($func_call), err);
        }
        Ok::<(), anyhow::Error>(())
    }};
}

#[macro_export]
macro_rules! krun_call_u32 {
    ($func_call:expr) => {{
        let result = $func_call;
        if result < 0 {
            let err = std::io::Error::from_raw_os_error(-result);
            anyhow::bail!("`{}`: {}", stringify!($func_call), err);
        }
        Ok::<u32, anyhow::Error>(result as u32)
    }};
}
