use syn::{Attribute, Expr, ExprLit, Lit, Meta};

#[derive(Debug, thiserror::Error)]
pub(crate) enum ExtractStorageTagError {
    #[error("storage tag not provided")]
    TagNotProvided,
    #[error("invalid storage tag")]
    InvalidTag,
}

/// A helper function to extract a valid `storage_tag` attribute
/// from a list of attributes
pub(crate) fn extract_storage_tag<'a>(
    mut attrs: impl Iterator<Item = &'a Attribute>,
) -> Result<u32, ExtractStorageTagError> {
    let storage_tag_value = attrs
        .find_map(|attr| {
            let Meta::NameValue(nv) = &attr.meta else {
                return None;
            };

            if !nv.path.is_ident("storage_tag") {
                return None;
            }

            Some(nv.value.clone())
        })
        .ok_or(ExtractStorageTagError::TagNotProvided)?;

    let Expr::Lit(ExprLit {
        lit: Lit::Int(int), ..
    }) = &storage_tag_value
    else {
        return Err(ExtractStorageTagError::InvalidTag);
    };

    int.base10_parse()
        .map_err(|_| ExtractStorageTagError::InvalidTag)
}
