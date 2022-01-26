use num_derive::{FromPrimitive, ToPrimitive};

#[derive(Debug, FromPrimitive, ToPrimitive)]
pub enum TargetType {
    /// Any file
    Any = 0,
    /// Portable Executable, both 32- and 64-bit
    PE = 1,
    /// OLE2 containers, including specific macros. Primarily used by MS Office and MSI installation files
    OLE2 = 2,
    /// HTML (normalized)
    HTML = 3,
    /// Mail file
    Mail = 4,
    /// Graphics
    Graphics = 5,
    /// ELF
    ELF = 6,
    /// ASCII text file (normalized)
    Text = 7,
    /// Unused
    Unused = 8,
    /// Mach-O files
    MachO = 9,
    /// PDF files
    PDF = 10,
    /// Flash files
    Flash = 11,
    /// Java class files
    Java = 12,
}
