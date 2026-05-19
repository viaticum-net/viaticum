// Path safety validation for restore pipeline.
//
// Pure function, no I/O, no async. Belongs in viaticum-core so it can be
// exhaustively unit-tested without any daemon setup.

#[cfg(test)]
mod tests;

// ─── Types ────────────────────────────────────────────────────────────────────

/// A record path that has passed all safety checks.
/// Holds the individual path components (no leading slash, no separators).
/// The components are guaranteed safe for use with cap_std relative operations.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedPath {
    /// Non-empty list of path components, each individually validated.
    pub components: Vec<String>,
}

impl ValidatedPath {
    /// Join components with the platform path separator.
    /// Useful for display and for passing to cap_std relative ops.
    pub fn to_relative_path(&self) -> std::path::PathBuf {
        self.components.iter().collect()
    }
}

/// Errors from path safety validation.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum PathSafetyError {
    #[error("empty path")]
    EmptyPath,

    #[error("empty component in path")]
    EmptyComponent,

    #[error("'..' component in path")]
    DotDot,

    #[error("'.' component in path")]
    DotComponent,

    #[error("drive letter in path component: {0:?}")]
    DriveLetter(String),

    #[error("UNC path detected")]
    UncPath,

    #[error("control character in component: {0:?}")]
    ControlChar(String),

    #[error("colon in component (Windows ADS or classic Mac sep): {0:?}")]
    ColonInComponent(String),

    #[error("Windows reserved name: {0:?}")]
    WindowsReserved(String),

    #[error("trailing space or dot in component: {0:?}")]
    TrailingSpaceOrDot(String),

    #[error("component too long ({len} bytes, max {max}): {component:?}")]
    ComponentTooLong {
        component: String,
        len: usize,
        max: usize,
    },
}

/// Maximum allowed length for a single path component (bytes).
pub const MAX_COMPONENT_LEN: usize = 255;

/// Windows reserved device names (case-insensitive stem match).
static WINDOWS_RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

// ─── Validation pipeline ──────────────────────────────────────────────────────

/// Validate a raw record path string.
///
/// Accepts POSIX-style absolute paths (leading '/' stripped) and relative paths.
/// Rejects any form that could escape a sandboxed staging directory on any
/// platform that Viaticum supports now or in the future.
///
/// The result is a `ValidatedPath` whose `components` are safe to join with
/// cap_std relative filesystem operations.
pub fn validate_record_path(raw: &str) -> Result<ValidatedPath, PathSafetyError> {
    // Step 1: Empty check.
    if raw.is_empty() {
        return Err(PathSafetyError::EmptyPath);
    }

    // Step 2: UNC prefix check — reject //server/share or \\server\share.
    if raw.starts_with("\\\\") || raw.starts_with("//") {
        return Err(PathSafetyError::UncPath);
    }

    // Step 3: Strip one leading separator (/ or \).
    let stripped = if raw.starts_with('/') || raw.starts_with('\\') {
        &raw[1..]
    } else {
        raw
    };

    // Step 4: Split on both / and \ to handle cross-platform paths.
    let raw_components: Vec<&str> = stripped.split(['/', '\\']).collect();

    let mut components: Vec<String> = Vec::with_capacity(raw_components.len());

    // Step 5: Per-component validation.
    for component in raw_components {
        // 5a: Empty component (catches // or /./ after stripping leading /).
        if component.is_empty() {
            return Err(PathSafetyError::EmptyComponent);
        }

        // 5b: Control characters (\x00..\x1f).
        if component.bytes().any(|b| b <= 0x1f) {
            return Err(PathSafetyError::ControlChar(component.to_string()));
        }

        // 5c: Dot component.
        if component == "." {
            return Err(PathSafetyError::DotComponent);
        }

        // 5d: DotDot component.
        if component == ".." {
            return Err(PathSafetyError::DotDot);
        }

        // 5e: Drive letter (starts with letter followed by ':').
        let component_bytes = component.as_bytes();
        if component_bytes.len() >= 2
            && component_bytes[0].is_ascii_alphabetic()
            && component_bytes[1] == b':'
        {
            return Err(PathSafetyError::DriveLetter(component.to_string()));
        }

        // 5f: Colon anywhere else (Windows ADS or classic Mac separator).
        if component.contains(':') {
            return Err(PathSafetyError::ColonInComponent(component.to_string()));
        }

        // 5g: Trailing dot or space (silently truncated on Windows NTFS).
        if component.ends_with('.') || component.ends_with(' ') {
            return Err(PathSafetyError::TrailingSpaceOrDot(component.to_string()));
        }

        // 5h: Windows reserved names (case-insensitive, strip extension first).
        {
            let stem = component.split('.').next().unwrap_or(component);
            let upper = stem.to_uppercase();
            if WINDOWS_RESERVED.contains(&upper.as_str()) {
                return Err(PathSafetyError::WindowsReserved(component.to_string()));
            }
        }

        // 5i: Length check.
        if component.len() > MAX_COMPONENT_LEN {
            return Err(PathSafetyError::ComponentTooLong {
                component: component.to_string(),
                len: component.len(),
                max: MAX_COMPONENT_LEN,
            });
        }

        components.push(component.to_string());
    }

    // Step 6: At least one component required.
    if components.is_empty() {
        return Err(PathSafetyError::EmptyPath);
    }

    // Step 7: Return validated path.
    Ok(ValidatedPath { components })
}
