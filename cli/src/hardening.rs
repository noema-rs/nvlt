#[cfg(unix)]
pub fn disable_core_dumps() -> Result<(), std::io::Error> {
    use nix::libc::rlim_t;
    use nix::sys::resource::{setrlimit, Resource};
    setrlimit(Resource::RLIMIT_CORE, 0 as rlim_t, 0 as rlim_t)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(())
}

#[cfg(not(unix))]
pub fn disable_core_dumps() -> Result<(), std::io::Error> {
    Ok(())
}
