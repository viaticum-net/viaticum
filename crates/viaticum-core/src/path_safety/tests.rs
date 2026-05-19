// Tests for PathValidator.
// Pattern: what_when_then.
// All tests are unit tests, no I/O. Cover acceptance criteria A1-A8 plus edge cases.

use super::{MAX_COMPONENT_LEN, PathSafetyError, validate_record_path};

// ─── Group A: Path Traversal ──────────────────────────────────────────────────

#[test]
fn dotdot_in_prefix_is_rejected() {
    // A1: "../../etc/passwd" → Err(DotDot)
    let result = validate_record_path("../../etc/passwd");
    assert_eq!(result, Err(PathSafetyError::DotDot));
}

#[test]
fn dotdot_backslash_path_is_rejected() {
    // A2: "..\\Windows\\System32\\evil.dll" → Err(DotDot) after backslash split
    let result = validate_record_path("..\\Windows\\System32\\evil.dll");
    assert_eq!(result, Err(PathSafetyError::DotDot));
}

#[test]
fn drive_letter_is_rejected() {
    // A3: "C:\\Windows\\evil" → Err(DriveLetter)
    let result = validate_record_path("C:\\Windows\\evil");
    assert_eq!(result, Err(PathSafetyError::DriveLetter("C:".to_string())));
}

#[test]
fn unc_path_is_rejected() {
    // A4: "\\\\server\\share\\evil" → Err(UncPath)
    let result = validate_record_path("\\\\server\\share\\evil");
    assert_eq!(result, Err(PathSafetyError::UncPath));
}

#[test]
fn unc_path_double_slash_is_rejected() {
    // A4 variant: "//server/share/evil" → Err(UncPath)
    let result = validate_record_path("//server/share/evil");
    assert_eq!(result, Err(PathSafetyError::UncPath));
}

#[test]
fn windows_reserved_name_is_rejected() {
    // A5: "docs/CON.txt" → Err(WindowsReserved)
    let result = validate_record_path("docs/CON.txt");
    assert_eq!(
        result,
        Err(PathSafetyError::WindowsReserved("CON.txt".to_string()))
    );
}

#[test]
fn colon_in_component_is_rejected() {
    // A6: "docs/file:stream" → Err(ColonInComponent)
    let result = validate_record_path("docs/file:stream");
    assert_eq!(
        result,
        Err(PathSafetyError::ColonInComponent("file:stream".to_string()))
    );
}

#[test]
fn null_byte_in_component_is_rejected() {
    // A7: "docs/fi\x00le" → Err(ControlChar)
    let result = validate_record_path("docs/fi\x00le");
    assert_eq!(
        result,
        Err(PathSafetyError::ControlChar("fi\x00le".to_string()))
    );
}

#[test]
fn dot_dot_component_is_rejected() {
    // A8: "docs/.." → Err(DotDot)
    let result = validate_record_path("docs/..");
    assert_eq!(result, Err(PathSafetyError::DotDot));
}

#[test]
fn empty_path_is_rejected() {
    // A8: "" → Err(EmptyPath)
    let result = validate_record_path("");
    assert_eq!(result, Err(PathSafetyError::EmptyPath));
}

#[test]
fn empty_component_is_rejected() {
    // A8: "docs//file" → Err(EmptyComponent)
    let result = validate_record_path("docs//file");
    assert_eq!(result, Err(PathSafetyError::EmptyComponent));
}

// ─── Additional edge cases ────────────────────────────────────────────────────

#[test]
fn dot_component_is_rejected() {
    // "." as a component → Err(DotComponent)
    let result = validate_record_path("docs/./file.txt");
    assert_eq!(result, Err(PathSafetyError::DotComponent));
}

#[test]
fn trailing_space_in_component_is_rejected() {
    // "docs/file " (trailing space) → Err(TrailingSpaceOrDot)
    let result = validate_record_path("docs/file ");
    assert_eq!(
        result,
        Err(PathSafetyError::TrailingSpaceOrDot("file ".to_string()))
    );
}

#[test]
fn trailing_dot_in_component_is_rejected() {
    // "docs/file." (trailing dot) → Err(TrailingSpaceOrDot)
    let result = validate_record_path("docs/file.");
    assert_eq!(
        result,
        Err(PathSafetyError::TrailingSpaceOrDot("file.".to_string()))
    );
}

#[test]
fn component_too_long_is_rejected() {
    // Component of 256 chars → Err(ComponentTooLong)
    let long_name = "a".repeat(MAX_COMPONENT_LEN + 1);
    let path = format!("docs/{long_name}");
    let result = validate_record_path(&path);
    assert!(
        matches!(result, Err(PathSafetyError::ComponentTooLong { len, max, .. }) if len == MAX_COMPONENT_LEN + 1 && max == MAX_COMPONENT_LEN),
        "expected ComponentTooLong, got {result:?}"
    );
}

#[test]
fn windows_reserved_name_nul_is_rejected() {
    let result = validate_record_path("docs/NUL");
    assert_eq!(
        result,
        Err(PathSafetyError::WindowsReserved("NUL".to_string()))
    );
}

#[test]
fn windows_reserved_name_com1_is_rejected() {
    let result = validate_record_path("docs/COM1");
    assert_eq!(
        result,
        Err(PathSafetyError::WindowsReserved("COM1".to_string()))
    );
}

#[test]
fn windows_reserved_name_lpt9_is_rejected() {
    let result = validate_record_path("docs/LPT9");
    assert_eq!(
        result,
        Err(PathSafetyError::WindowsReserved("LPT9".to_string()))
    );
}

#[test]
fn windows_reserved_name_with_extension_is_rejected() {
    // "CON.txt" → stem is "CON" → Err(WindowsReserved)
    let result = validate_record_path("docs/CON.txt");
    assert_eq!(
        result,
        Err(PathSafetyError::WindowsReserved("CON.txt".to_string()))
    );
}

#[test]
fn windows_reserved_name_case_insensitive() {
    // "con" → lowercase → still rejected
    let result = validate_record_path("docs/con");
    assert_eq!(
        result,
        Err(PathSafetyError::WindowsReserved("con".to_string()))
    );

    // "Con" → mixed case → still rejected
    let result2 = validate_record_path("docs/Con");
    assert_eq!(
        result2,
        Err(PathSafetyError::WindowsReserved("Con".to_string()))
    );
}

#[test]
fn absolute_posix_path_leading_slash_stripped() {
    // "/home/alice/docs/report.docx" (leading slash stripped) → Ok(["home","alice","docs","report.docx"])
    let result = validate_record_path("/home/alice/docs/report.docx");
    assert!(result.is_ok(), "expected Ok, got {result:?}");
    let validated = result.unwrap();
    assert_eq!(
        validated.components,
        vec!["home", "alice", "docs", "report.docx"]
    );
}

#[test]
fn relative_path_is_valid() {
    // "relative/path/file.txt" → Ok(["relative","path","file.txt"])
    let result = validate_record_path("relative/path/file.txt");
    assert!(result.is_ok(), "expected Ok, got {result:?}");
    let validated = result.unwrap();
    assert_eq!(validated.components, vec!["relative", "path", "file.txt"]);
}

#[test]
fn unicode_filename_is_valid() {
    // "документы/файл.txt" → Ok([...])
    let result = validate_record_path("документы/файл.txt");
    assert!(
        result.is_ok(),
        "expected Ok for unicode path, got {result:?}"
    );
    let validated = result.unwrap();
    assert_eq!(validated.components, vec!["документы", "файл.txt"]);
}

#[test]
fn path_with_backslash_separator_is_split() {
    // "docs\\file.txt" → Ok(["docs","file.txt"])
    let result = validate_record_path("docs\\file.txt");
    assert!(result.is_ok(), "expected Ok, got {result:?}");
    let validated = result.unwrap();
    assert_eq!(validated.components, vec!["docs", "file.txt"]);
}

#[test]
fn mixed_separator_path_is_split() {
    // "docs/sub\\file.txt" → Ok(["docs","sub","file.txt"])
    let result = validate_record_path("docs/sub\\file.txt");
    assert!(result.is_ok(), "expected Ok, got {result:?}");
    let validated = result.unwrap();
    assert_eq!(validated.components, vec!["docs", "sub", "file.txt"]);
}

#[test]
fn single_component_path_is_valid() {
    // "file.txt" → Ok(["file.txt"])
    let result = validate_record_path("file.txt");
    assert!(result.is_ok(), "expected Ok, got {result:?}");
    let validated = result.unwrap();
    assert_eq!(validated.components, vec!["file.txt"]);
}

#[test]
fn control_char_x01_in_component_is_rejected() {
    let result = validate_record_path("docs/fi\x01le");
    assert_eq!(
        result,
        Err(PathSafetyError::ControlChar("fi\x01le".to_string()))
    );
}

#[test]
fn control_char_x1f_in_component_is_rejected() {
    let result = validate_record_path("docs/fi\x1fle");
    assert_eq!(
        result,
        Err(PathSafetyError::ControlChar("fi\x1fle".to_string()))
    );
}

#[test]
fn to_relative_path_joins_correctly() {
    let result = validate_record_path("/home/alice/docs/report.docx").unwrap();
    let rel = result.to_relative_path();
    // On any platform the PathBuf should have the right segments.
    let components: Vec<_> = rel.components().collect();
    assert_eq!(components.len(), 4);
}

#[test]
fn prn_reserved_is_rejected() {
    let result = validate_record_path("docs/PRN");
    assert_eq!(
        result,
        Err(PathSafetyError::WindowsReserved("PRN".to_string()))
    );
}

#[test]
fn aux_reserved_is_rejected() {
    let result = validate_record_path("docs/AUX");
    assert_eq!(
        result,
        Err(PathSafetyError::WindowsReserved("AUX".to_string()))
    );
}

#[test]
fn com9_reserved_with_extension_is_rejected() {
    let result = validate_record_path("docs/com9.log");
    assert_eq!(
        result,
        Err(PathSafetyError::WindowsReserved("com9.log".to_string()))
    );
}

#[test]
fn lpt1_reserved_with_extension_is_rejected() {
    let result = validate_record_path("docs/lpt1.log");
    assert_eq!(
        result,
        Err(PathSafetyError::WindowsReserved("lpt1.log".to_string()))
    );
}

#[test]
fn leading_backslash_stripped_then_validated() {
    // "\docs\file.txt" — leading backslash stripped, then split on backslash
    let result = validate_record_path("\\docs\\file.txt");
    assert!(result.is_ok(), "expected Ok, got {result:?}");
    let validated = result.unwrap();
    assert_eq!(validated.components, vec!["docs", "file.txt"]);
}

#[test]
fn drive_letter_lowercase_is_rejected() {
    let result = validate_record_path("c:\\Windows\\evil");
    assert_eq!(result, Err(PathSafetyError::DriveLetter("c:".to_string())));
}
