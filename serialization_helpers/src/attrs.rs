use syn::{Attribute, Expr, ExprLit, Lit, Meta};

/// A helper function to extract a valid `storage_tag` attribute
/// from a list of attributes
pub(crate) fn extract_storage_tag<'a>(
    mut attrs: impl Iterator<Item = &'a Attribute>,
) -> Option<u32> {
    attrs.find_map(|attr| {
        let Meta::NameValue(nv) = &attr.meta else {
            return None;
        };

        if !nv.path.is_ident("storage_tag") {
            return None;
        }

        let Expr::Lit(ExprLit {
            lit: Lit::Int(int), ..
        }) = &nv.value
        else {
            return None;
        };
        int.base10_parse().ok()
    })
}
