// Extension sets for importance classification.
// All values are lowercase — callers must ASCII-lowercase the extension before lookup.

/// Plain text, source code, config, and data file extensions.
///
/// Does NOT include binary document formats (pdf, doc, xls, ppt) — those are Unknown.
/// See D6 in the wave 5 spec for rationale.
pub(crate) const TEXT_OR_CODE_EXTENSIONS: &[&str] = &[
    // Plain text and documents
    "txt",
    "md",
    "rst",
    "tex",
    "org",
    "adoc",
    // Source code — systems
    "rs",
    "c",
    "h",
    "cpp",
    "hpp",
    "cc",
    "cxx",
    "hh",
    // Source code — general purpose
    "py",
    "js",
    "ts",
    "go",
    "java",
    "cs",
    "rb",
    "php",
    "swift",
    "kt",
    "scala",
    // Shell
    "sh",
    "bash",
    "zsh",
    "fish",
    "ps1",
    // Scripting
    "lua",
    "pl",
    "r",
    "julia",
    "elm",
    "ex",
    "exs",
    // Functional
    "hs",
    "ml",
    "mli",
    "clj",
    "cljs",
    "lisp",
    "scm",
    // Web
    "html",
    "htm",
    "css",
    "scss",
    "less",
    "sass",
    "vue",
    "svelte",
    "jsx",
    "tsx",
    // Config and data
    "json",
    "yaml",
    "yml",
    "toml",
    "xml",
    "ini",
    "conf",
    "cfg",
    "env",
    "properties",
    // Tabular data
    "sql",
    "csv",
    "tsv",
    // Notebooks and literate documents
    "ipynb",
    "rmd",
    "rd",
    "qmd",
];

/// Image, video, and audio file extensions.
///
/// Used to detect media folders and to hash-bucket files within them.
pub(crate) const MEDIA_EXTENSIONS: &[&str] = &[
    // Images — common
    "jpg", "jpeg", "png", "gif", "webp", "bmp", // Images — Apple formats
    "heic", "heif", // Images — raw camera
    "raw", "cr2", "cr3", "nef", "arw", "dng", "orf", "rw2", // Images — TIFF
    "tiff", "tif", // Video
    "mp4", "mov", "avi", "mkv", "webm", "m4v", "3gp", "flv", "wmv", "ts", "mts", "m2ts",
    // Audio
    "mp3", "wav", "flac", "ogg", "opus", "m4a", "aac", "wma", "aiff", "alac",
];
