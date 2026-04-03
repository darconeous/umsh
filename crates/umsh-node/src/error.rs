use crate::mac::{NodeMac, NodeMacError};

/// Errors produced by the endpoint layer.
pub enum EndpointError<M: NodeMac> {
    AppParse(umsh_app::ParseError),
    AppEncode(umsh_app::EncodeError),
    Mac(NodeMacError<M::SendError, M::CapacityError>),
    MissingAdvertisedIdentity,
    PfsSessionMissing,
    PfsSessionTableFull,
    UnsupportedPayload,
    #[cfg(feature = "software-crypto")]
    Crypto(umsh_crypto::CryptoError),
}

impl<M: NodeMac> From<umsh_app::ParseError> for EndpointError<M> {
    fn from(value: umsh_app::ParseError) -> Self {
        Self::AppParse(value)
    }
}

impl<M: NodeMac> From<umsh_app::EncodeError> for EndpointError<M> {
    fn from(value: umsh_app::EncodeError) -> Self {
        Self::AppEncode(value)
    }
}

impl<M: NodeMac> From<NodeMacError<M::SendError, M::CapacityError>> for EndpointError<M> {
    fn from(value: NodeMacError<M::SendError, M::CapacityError>) -> Self {
        Self::Mac(value)
    }
}

#[cfg(feature = "software-crypto")]
impl<M: NodeMac> From<umsh_crypto::CryptoError> for EndpointError<M> {
    fn from(value: umsh_crypto::CryptoError) -> Self {
        Self::Crypto(value)
    }
}

impl<M> core::fmt::Debug for EndpointError<M>
where
    M: NodeMac,
    M::SendError: core::fmt::Debug,
    M::CapacityError: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AppParse(error) => f.debug_tuple("AppParse").field(error).finish(),
            Self::AppEncode(error) => f.debug_tuple("AppEncode").field(error).finish(),
            Self::Mac(error) => f.debug_tuple("Mac").field(error).finish(),
            Self::MissingAdvertisedIdentity => f.write_str("MissingAdvertisedIdentity"),
            Self::PfsSessionMissing => f.write_str("PfsSessionMissing"),
            Self::PfsSessionTableFull => f.write_str("PfsSessionTableFull"),
            Self::UnsupportedPayload => f.write_str("UnsupportedPayload"),
            #[cfg(feature = "software-crypto")]
            Self::Crypto(error) => f.debug_tuple("Crypto").field(error).finish(),
        }
    }
}