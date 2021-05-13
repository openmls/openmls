use super::*;

pub trait GroupInfoExtension: Codec {
    fn extension_type(&self) -> ExtensionType
    where
        Self: Sized;

    fn to_extension_struct(&self) -> Result<ExtensionStruct, CodecError>
    where
        Self: Sized,
    {
        Ok(ExtensionStruct::new(
            self.extension_type(),
            self.encode_detached()?,
        ))
    }

    fn from_extension_struct(extension_struct: ExtensionStruct) -> Result<Self, CodecError>
    where
        Self: Sized,
    {
        Self::decode_detached(extension_struct.extension_data())
    }
}
