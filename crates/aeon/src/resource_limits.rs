const DEFAULT_MAX_RAM_GIB: u64 = 20;
const BYTES_PER_GIB: u64 = 1024 * 1024 * 1024;

pub fn install_process_memory_limit() -> Result<Option<u64>, String> {
    let Some(limit_bytes) = desired_limit_bytes()? else {
        return Ok(None);
    };

    #[cfg(unix)]
    {
        install_unix_address_space_limit(limit_bytes)?;
        return Ok(Some(limit_bytes));
    }

    #[cfg(not(unix))]
    {
        Ok(Some(limit_bytes))
    }
}

fn desired_limit_bytes() -> Result<Option<u64>, String> {
    if let Some(value) = std::env::var_os("AEON_MAX_RAM_BYTES") {
        return parse_optional_u64("AEON_MAX_RAM_BYTES", &value.to_string_lossy());
    }

    if let Some(value) = std::env::var_os("AEON_MAX_RAM_GB") {
        let parsed = parse_optional_u64("AEON_MAX_RAM_GB", &value.to_string_lossy())?;
        return Ok(parsed.map(|gigabytes| gigabytes.saturating_mul(BYTES_PER_GIB)));
    }

    Ok(Some(DEFAULT_MAX_RAM_GIB * BYTES_PER_GIB))
}

fn parse_optional_u64(name: &str, raw: &str) -> Result<Option<u64>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("off") || trimmed == "0" {
        return Ok(None);
    }

    trimmed
        .parse::<u64>()
        .map(Some)
        .map_err(|_| format!("Invalid {} value: {}", name, raw))
}

#[cfg(unix)]
fn install_unix_address_space_limit(limit_bytes: u64) -> Result<(), String> {
    let mut current = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };

    let rc = unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut current) };
    if rc != 0 {
        return Err(format!(
            "getrlimit(RLIMIT_AS) failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let desired = limit_bytes as libc::rlim_t;
    let new_soft = if current.rlim_max == libc::RLIM_INFINITY {
        desired
    } else {
        current.rlim_max.min(desired)
    };

    let updated = libc::rlimit {
        rlim_cur: new_soft,
        rlim_max: current.rlim_max,
    };

    let rc = unsafe { libc::setrlimit(libc::RLIMIT_AS, &updated) };
    if rc != 0 {
        return Err(format!(
            "setrlimit(RLIMIT_AS) failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(())
}
