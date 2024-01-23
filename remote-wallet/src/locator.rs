use {
    solana_sdk::pubkey::{ParsePubkeyError, Pubkey},
    std::{
        convert::{Infallible, TryFrom, TryInto},
        str::FromStr,
    },
    thiserror::Error,
    uriparse::{URIReference, URIReferenceBuilder, URIReferenceError},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Manufacturer {
    Unknown,
    Ledger,
}

impl Default for Manufacturer {
    fn default() -> Self {
        Self::Unknown
    }
}

const MANUFACTURER_UNKNOWN: &str = "unknown";
const MANUFACTURER_LEDGER: &str = "ledger";

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("not a manufacturer")]
pub struct ManufacturerError;

impl From<Infallible> for ManufacturerError {
    fn from(_: Infallible) -> Self {
        ManufacturerError
    }
}

impl FromStr for Manufacturer {
    type Err = ManufacturerError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.to_ascii_lowercase();
        match s.as_str() {
            MANUFACTURER_LEDGER => Ok(Self::Ledger),
            _ => Err(ManufacturerError),
        }
    }
}

impl TryFrom<&str> for Manufacturer {
    type Error = ManufacturerError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Manufacturer::from_str(s)
    }
}

impl AsRef<str> for Manufacturer {
    fn as_ref(&self) -> &str {
        match self {
            Self::Unknown => MANUFACTURER_UNKNOWN,
            Self::Ledger => MANUFACTURER_LEDGER,
        }
    }
}

impl std::fmt::Display for Manufacturer {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let s: &str = self.as_ref();
        write!(f, "{s}")
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum LocatorError {
    #[error(transparent)]
    ManufacturerError(#[from] ManufacturerError),
    #[error(transparent)]
    PubkeyError(#[from] ParsePubkeyError),
    #[error(transparent)]
    UriReferenceError(#[from] URIReferenceError),
    #[error("unimplemented scheme")]
    UnimplementedScheme,
    #[error("infallible")]
    Infallible,
}

impl From<Infallible> for LocatorError {
    fn from(_: Infallible) -> Self {
        Self::Infallible
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Locator {
    pub manufacturer: Manufacturer,
    pub pubkey: Option<Pubkey>,
}

impl std::fmt::Display for Locator {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let maybe_path = self.pubkey.map(|p| p.to_string());
        let path = maybe_path.as_deref().unwrap_or("/");

        let mut builder = URIReferenceBuilder::new();
        builder
            .try_scheme(Some("usb"))
            .unwrap()
            .try_authority(Some(self.manufacturer.as_ref()))
            .unwrap()
            .try_path(path)
            .unwrap();

        let uri = builder.build().unwrap();
        write!(f, "{uri}")
    }
}

impl Locator {
    pub fn new_from_path<P: AsRef<str>>(path: P) -> Result<Self, LocatorError> {
        let path = path.as_ref();
        let uri = URIReference::try_from(path)?;
        Self::new_from_uri(&uri)
    }

    pub fn new_from_uri(uri: &URIReference<'_>) -> Result<Self, LocatorError> {
        let scheme = uri.scheme().map(|s| s.as_str().to_ascii_lowercase());
        let host = uri.host().map(|h| h.to_string());
        match (scheme, host) {
            (Some(scheme), Some(host)) if scheme == "usb" => {
                let path = uri.path().segments().first().and_then(|s| {
                    if !s.is_empty() {
                        Some(s.as_str())
                    } else {
                        None
                    }
                });
                Self::new_from_parts(host.as_str(), path)
            }
            (Some(_scheme), Some(_host)) => Err(LocatorError::UnimplementedScheme),
            (None, Some(_host)) => Err(LocatorError::UnimplementedScheme),
            (_, None) => Err(LocatorError::ManufacturerError(ManufacturerError)),
        }
    }

    pub fn new_from_parts<V, VE, P, PE>(
        manufacturer: V,
        pubkey: Option<P>,
    ) -> Result<Self, LocatorError>
    where
        VE: Into<LocatorError>,
        V: TryInto<Manufacturer, Error = VE>,
        PE: Into<LocatorError>,
        P: TryInto<Pubkey, Error = PE>,
    {
        let manufacturer = manufacturer.try_into().map_err(|e| e.into())?;
        let pubkey = if let Some(pubkey) = pubkey {
            Some(pubkey.try_into().map_err(|e| e.into())?)
        } else {
            None
        };
        Ok(Self {
            manufacturer,
            pubkey,
        })
    }
}
