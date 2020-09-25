use crate::codec::Codec;
use crate::codec::Cursor;
use crate::extensions::Extension;
use crate::extensions::ExtensionType;

/// An enum that describes the possible types capabilities of a given device,
/// each encoded as u32.
#[repr(u32)]
pub enum DeviceCapabilityType {
    AddCap = 0b0001u32,
    RemoveCap = 0b0010u32,
    NonRemovableCap = 0b0100u32,
    SelfUpdateCap = 0b1000u32,
}

/// An enum describing the different types of devices, encoded as a u32
/// describing the capabilities associated with the type of device.
#[repr(u32)]
pub enum DeviceType {
    TemporaryDevice = 0u32,
    PermanentDevice = DeviceCapabilityType::AddCap as u32
        | DeviceCapabilityType::RemoveCap as u32
        | DeviceCapabilityType::SelfUpdateCap as u32,
}

/// The capabilities of a given device encoded as a u32.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DeviceCapabilities(pub u32);

impl DeviceCapabilities {
    //fn match_capability(&self) -> bool {
    //    match self.0 {
    //        x if x & DeviceType::PermanentDevice as u32 == DeviceType::PermanentDevice as u32 => {
    //            true
    //        }
    //        x if x = DeviceType::TemporaryDevice as u32 =>
    //    }
    //}
    /// Checks if the device is of DeviceType PermanentDevice.
    pub fn is_permanent(&self) -> bool {
        self.0 & DeviceType::PermanentDevice as u32 == DeviceType::PermanentDevice as u32
    }

    /// Checks if the device is of DeviceType TemporaryDevice.
    pub fn is_temporary(&self) -> bool {
        self.0 == DeviceType::TemporaryDevice as u32
    }

    /// Checks if the device has the capability to add other devices.
    pub fn can_add(&self) -> bool {
        (self.0 & DeviceCapabilityType::AddCap as u32) > 0
    }

    /// Checks if the device has the capability to remove other devices.
    pub fn can_remove(&self) -> bool {
        (self.0 & DeviceCapabilityType::RemoveCap as u32) > 0
    }

    /// Checks if the device can be removed by other devices.
    pub fn cannot_be_removed(&self) -> bool {
        (self.0 & DeviceCapabilityType::NonRemovableCap as u32) > 0
    }

    /// Checks if the device can replace itself with another device.
    pub fn can_self_update(&self) -> bool {
        (self.0 & DeviceCapabilityType::SelfUpdateCap as u32) > 0
    }
}

/// Converts a DeviceType into DeviceCapabilities.
impl From<DeviceType> for DeviceCapabilities {
    fn from(n: DeviceType) -> DeviceCapabilities {
        DeviceCapabilities(n as u32)
    }
}

/// An extension that can be used in Credentials to specify the associated
/// device's capabilities.
#[derive(PartialEq, Clone, Debug)]
pub struct DeviceCapabilityExtension {
    pub capabilities: DeviceCapabilities,
}

impl DeviceCapabilityExtension {
    /// Create a new DeviceCapabilityExtension from DeviceCapabilities.
    pub fn new(capabilities: DeviceCapabilities) -> Self {
        DeviceCapabilityExtension { capabilities }
    }
    /// Create a new DeviceCapabilityExtension from a byte-encoded DeviceCapabilities.
    pub fn new_from_bytes(bytes: &[u8]) -> Self {
        let cursor = &mut Cursor::new(bytes);
        let capabilities = DeviceCapabilities(Codec::decode(cursor).unwrap());
        Self { capabilities }
    }
    /// Creates a generic Extension from a DeviceCapabilityExtension.
    pub fn to_extension(&self) -> Extension {
        let mut extension_data: Vec<u8> = vec![];
        self.capabilities.0.encode(&mut extension_data).unwrap();
        let extension_type = ExtensionType::DeviceCapabilities;
        Extension {
            extension_type,
            extension_data,
        }
    }
}
