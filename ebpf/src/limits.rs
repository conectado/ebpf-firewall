#[cfg(feature = "rules512")]
pub(crate) const MAX_NUMBER_OF_RULES: u32 = 512;

#[cfg(all(feature = "rules256", not(feature = "rules512")))]
pub(crate) const MAX_NUMBER_OF_RULES: u32 = 256;

#[cfg(all(
    feature = "rules128",
    not(any(feature = "rules256", feature = "rules512"))
))]
pub(crate) const MAX_NUMBER_OF_RULES: u32 = 128;

#[cfg(all(
    feature = "rules64",
    not(any(feature = "rules128", feature = "rules256", feature = "rules512"))
))]
pub(crate) const MAX_NUMBER_OF_RULES: u32 = 64;

#[cfg(all(
    feature = "rules32",
    not(any(
        feature = "rules64",
        feature = "rules128",
        feature = "rules256",
        feature = "rules512"
    ))
))]
pub(crate) const MAX_NUMBER_OF_RULES: u32 = 32;

#[cfg(not(any(
    feature = "rules32",
    feature = "rules64",
    feature = "rules128",
    feature = "rules256",
    feature = "rules512"
)))]
pub(crate) const MAX_NUMBER_OF_RULES: u32 = 1024;
