use {
    std::{fmt, str::FromStr},
    strum::Display,
};

// SUPPORTED_ARCHIVE_COMPRESSION lists the compression types that can be
// specified on the command line. "zstd" and "lz4" are valid whereas "gzip",
// "bz2", "tar" and "none" have been deprecated. Thus, all newly created
// snapshots will either use "zstd" or "lz4". By keeping the deprecated types
// in the ArchiveFormat enum, pre-existing snapshot archives with the
// deprecated compression types can still be read.
pub const SUPPORTED_ARCHIVE_COMPRESSION: &[&str] = &["zstd", "lz4"];
pub const DEFAULT_ARCHIVE_COMPRESSION: &str = "zstd";

pub const TAR_BZIP2_EXTENSION: &str = "tar.bz2";
pub const TAR_GZIP_EXTENSION: &str = "tar.gz";
pub const TAR_ZSTD_EXTENSION: &str = "tar.zst";
pub const TAR_LZ4_EXTENSION: &str = "tar.lz4";
pub const TAR_EXTENSION: &str = "tar";

/// The different archive formats used for snapshots
#[derive(Copy, Clone, Debug, Eq, PartialEq, Display)]
pub enum ArchiveFormat {
    TarBzip2,
    TarGzip,
    TarZstd,
    TarLz4,
    Tar,
}

impl ArchiveFormat {
    /// Get the file extension for the ArchiveFormat
    pub fn extension(&self) -> &str {
        match self {
            ArchiveFormat::TarBzip2 => TAR_BZIP2_EXTENSION,
            ArchiveFormat::TarGzip => TAR_GZIP_EXTENSION,
            ArchiveFormat::TarZstd => TAR_ZSTD_EXTENSION,
            ArchiveFormat::TarLz4 => TAR_LZ4_EXTENSION,
            ArchiveFormat::Tar => TAR_EXTENSION,
        }
    }

    pub fn from_cli_arg(archive_format_str: &str) -> Option<ArchiveFormat> {
        match archive_format_str {
            "zstd" => Some(ArchiveFormat::TarZstd),
            "lz4" => Some(ArchiveFormat::TarLz4),
            _ => None,
        }
    }
}

// Change this to `impl<S: AsRef<str>> TryFrom<S> for ArchiveFormat [...]`
// once this Rust bug is fixed: https://github.com/rust-lang/rust/issues/50133
impl TryFrom<&str> for ArchiveFormat {
    type Error = ParseError;

    fn try_from(extension: &str) -> Result<Self, Self::Error> {
        match extension {
            TAR_BZIP2_EXTENSION => Ok(ArchiveFormat::TarBzip2),
            TAR_GZIP_EXTENSION => Ok(ArchiveFormat::TarGzip),
            TAR_ZSTD_EXTENSION => Ok(ArchiveFormat::TarZstd),
            TAR_LZ4_EXTENSION => Ok(ArchiveFormat::TarLz4),
            TAR_EXTENSION => Ok(ArchiveFormat::Tar),
            _ => Err(ParseError::InvalidExtension(extension.to_string())),
        }
    }
}

impl FromStr for ArchiveFormat {
    type Err = ParseError;

    fn from_str(extension: &str) -> Result<Self, Self::Err> {
        Self::try_from(extension)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ParseError {
    InvalidExtension(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ParseError::InvalidExtension(extension) => {
                write!(f, "Invalid archive extension: {extension}")
            }
        }
    }
}
