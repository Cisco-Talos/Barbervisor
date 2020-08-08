use crate::memreader::{MemReader, Address};
use std::convert::TryInto;

macro_rules! impl_from_memreader {
    ($name:ident) => (
        impl $name {
            pub fn from_memreader<R: MemReader>(addr: Address, memreader: &mut R) -> $name {
                let mut data = [0u8; std::mem::size_of::<$name>()];
                memreader.read_mem(addr, &mut data)
                        .expect(&format!("Unable to make {} from_memreader", 
                                        stringify!($name)));
                unsafe { *(data.as_ptr() as *const _) }
            }
        }
    )
}

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct NtTib {
    /* Offset: 0x00 */ res0: u64,
    /* Offset: 0x08 */ res1: u64,
    /* Offset: 0x10 */ res2: u64,
    /* Offset: 0x18 */ res3: u64,
    /* Offset: 0x20 */ res4: u64,
    /* Offset: 0x28 */ res5: u64,
    /* Offset: 0x30 */ res6: u64,
}

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct ClientId(u64, u64);

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct TEB {
    /* Offset: 0x0000 */ pub tib: NtTib,
    /* Offset: 0x0038 */ pub environment_ptr: u64,
    /* Offset: 0x0040 */ pub client_id: ClientId,
    /* Offset: 0x0050 */ pub active_rpc_handle: u64,
    /* Offset: 0x0058 */ pub thread_local_storage_ptr: u64,
    /* Offset: 0x0060 */ pub process_environment_block: u64
}
impl_from_memreader!(TEB);

bitflags! {
    pub struct PEBBitField: u8 {
        const IMAGE_USED_LARGE_PAGES = 0x1;
        const IS_PROTECTED_PROCESS = 0x2;
        const IS_LEGACY_PROCESS = 0x4;
        const IS_IMAGE_DYNAMICALLY_RELOCATED = 0x8;
        const SKIP_PATCHING_USER32_FORWARDERS = 0x10;
        const IS_PACKAGED_PROCESS = 0x20;
        const IS_PROTECTED_PROCESS_LIGHT = 0x40;
        const IS_LONG_PATH_AWARE_PROCESS = 0x80;
    }
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct PEB {
    /* Offset: 0x00 */ pub inherited_address_space: bool,
    /* Offset: 0x01 */ pub read_image_file_exec_options: bool,
    /* Offset: 0x02 */ pub being_debugged: bool,
    /* Offset: 0x03 */ pub bit_field: PEBBitField,
    /* Offset: 0x04 */ pub padding: u32,
    /* Offset: 0x08 */ pub mutant: u64,
    /* Offset: 0x10 */ pub image_base_address: u64,
    /* Offset: 0x18 */ pub ldr: u64,
}
impl_from_memreader!(PEB);

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct ListEntry  {
    /* Offset: 0x00 */ pub flink: u64,
    /* Offset: 0x08 */ pub blink: u64,
}
impl_from_memreader!(ListEntry);

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct LdrData {
    /* Offset: 0x00 */ pub length: u32,
    /* Offset: 0x04 */ pub initialized: u32,
    /* Offset: 0x08 */ pub ss_handle: u64,
    /* Offset: 0x10 */ pub in_load_order_module_list: ListEntry,
    /* Offset: 0x20 */ pub in_memory_order_module_list: ListEntry,
    /* Offset: 0x30 */ pub in_initialization_order_module_list: ListEntry,
    /* Offset: 0x40 */ pub entry_in_progress: u64,
    /* Offset: 0x48 */ pub shutdown_in_progress: u64,
    /* Offset: 0x50 */ pub shutdown_thread_id: u64,
}
impl_from_memreader!(LdrData);

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct LdrDataTableEntry {
    /* Offset: 0x000 */ pub in_load_order_module_list: ListEntry,
    /* Offset: 0x010 */ pub in_memory_order_module_list: ListEntry,
    /* Offset: 0x020 */ pub in_initialization_order_module_list: ListEntry,
    /* Offset: 0x030 */ pub dll_base: u64,
    /* Offset: 0x038 */ pub entry_point: u64,
    /* Offset: 0x040 */ pub size_of_image: u64,
    /* Offset: 0x048 */ pub full_dll_name: UnicodeString,
    /* Offset: 0x058 */ pub base_dll_name: UnicodeString,
    /* Offset: 0x068 */ pub flags: LdrDataFlags,
    /* Offset: 0x06c */ pub obsolete_load_count: u16,
    /* Offset: 0x06e */ pub tls_index: u16,
    /* Offset: 0x070 */ pub hash_links: ListEntry,
    /* Offset: 0x080 */ pub time_date_stamp: u64,
    /* Offset: 0x088 */ pub entry_point_activation_context: u64,
    /* Offset: 0x090 */ pub lock: u64,
    /* Offset: 0x098 */ pub ddag_node: u64,
    /* Offset: 0x0a0 */ pub node_module_link: ListEntry,
    /* Offset: 0x0b0 */ pub load_context: u64,
    /* Offset: 0x0b8 */ pub parent_dll_base: u64,
    /* Offset: 0x0c0 */ pub switchback_context: u64,
    /* Offset: 0x0c8 */ pub base_address_index_node: RtlBalancedNode,
    /* Offset: 0x0e0 */ pub mapping_info_index_node: RtlBalancedNode,
    /* Offset: 0x0f8 */ pub original_base: u64,
    /* Offset: 0x100 */ pub load_time: u64,
    /* Offset: 0x108 */ pub base_name_hash_value: u32,
    /* Offset: 0x10c */ pub load_reason: i32,
    /* Offset: 0x110 */ pub implicit_path_options: u32,
    /* Offset: 0x114 */ pub reference_count: u32,
    /* Offset: 0x118 */ pub dependent_load_flags: u32,
    /* Offset: 0x11c */ pub signing_level: u32,
}
impl_from_memreader!(LdrDataTableEntry);

// Additional methods for KldrDataTableEntry
impl LdrDataTableEntry {
    /// Read the full DLL name from the data entry. Returns None if a name is not found.
    pub fn full_dll<R: MemReader>(&self, cr3: u64, reader: &mut R) -> Option<String> {
        // Length must be an even number to be converted to UTF16
        if self.base_dll_name.length % 2 == 1 || self.base_dll_name.length > 4096 { 
            return None; 
        }

        // Create a buffer for the individual u8 bytes from the buffer
        let mut utf8_buffer = Vec::with_capacity(self.full_dll_name.length as usize);
        unsafe { utf8_buffer.set_len(self.full_dll_name.length as usize) }

        // Attempt to read the base dll name from the buffer
        let res = reader.read_mem(Address::Virtual(self.full_dll_name.buffer, cr3), 
                                  &mut utf8_buffer);

        // Buffer not found
        if res.is_err() { return None; }

        // Convert the utf8 buffer into a utf16 vec
        let utf16_buffer: Vec<u16> = utf8_buffer.chunks(2)
            .map(|x| u16::from_le_bytes(x.try_into().unwrap()))
            .collect();

        // Attempt to create a String from the utf16 vec and return None is one cannot
        // be made
        match String::from_utf16(&utf16_buffer) {
            Ok(x) => Some(x),
            Err(_) => None
        }
    }

    /// Read the base DLL name from the data entry. Returns None if a name is not found.
    pub fn base_dll<R: MemReader>(&self, cr3: u64, reader: &mut R) -> Option<String> {
        // length must be an even number to be converted to utf16
        if self.base_dll_name.length % 2 == 1 || self.base_dll_name.length > 4096 { 
            return None; 
        }

        // create a buffer for the individual u8 bytes from the buffer
        let mut utf8_buffer = Vec::with_capacity(self.base_dll_name.length as usize);
        unsafe { utf8_buffer.set_len(self.base_dll_name.length as usize) }

        // attempt to read the base dll name from the buffer
        let res = reader.read_mem(Address::Virtual(self.base_dll_name.buffer, cr3), 
                                  &mut utf8_buffer);
        // buffer not found
        if res.is_err() { return None; }

        // convert the utf8 buffer into a utf16 vec
        let utf16_buffer: Vec<u16> = utf8_buffer.chunks(2)
            .map(|x| u16::from_le_bytes(x
                        .try_into().expect(&format!("unable to make u16: {:?}", x))))
            .collect();

        // attempt to create a string from the utf16 vec and return none is one cannot
        // be made
        match String::from_utf16(&utf16_buffer) {
            Ok(x) => Some(x),
            Err(_) => None
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct RtlBalancedNode {
    left: u64,
    right: u64,
    parent: u64,
}
impl_from_memreader!(RtlBalancedNode);

#[derive(Debug, Copy, Clone)]
enum LdrLoadReason {
    LoadReasonStaticDependency = 0,
    LoadReasonStaticForwarderDependency = 1,
    LoadReasonDynamicForwarderDependency = 2,
    LoadReasonDelayloadDependency = 3,
    LoadReasonDynamicLoad = 4,
    LoadReasonAsImageLoad = 5,
    LoadReasonAsDataLoad = 6,
    LoadReasonEnclavePrimary = 7,
    LoadReasonEnclaveDependency = 8,
    LoadReasonUnknown = -1,
}

bitflags! {
    pub struct LdrDataFlags: u32 {
        const PACKED_BINARY             = 0x00000001;
        const MARKED_FOR_REMOVAL        = 0x00000002;
        const IMAGE_DLL                 = 0x00000004;
        const LOAD_NOTIFICATION_SENT    = 0x00000008;
        const TELEMETRY_ENTRY_PROCESSED = 0x00000010;
        const PROCESS_STATIC_IMPORT     = 0x00000020;
        const IN_LEGACY_LISTS           = 0x00000040;
        const IN_INDEXES                = 0x00000080;
        const SHIM_DLL                  = 0x00000100;
        const IN_EXCEPTION_TABLE        = 0x00000200;
        const LOAD_IN_PROGRESS          = 0x00001000;
        const LOAD_CONFIG_PROCESSED     = 0x00002000;
        const ENTRY_PROCESSED           = 0x00004000;
        const PROTECT_DELAY_LOAD        = 0x00008000;
        const DONT_CALL_FOR_THREADS     = 0x00040000;
        const PROCESS_ATTACH_CALLED     = 0x00080000;
        const PROCESS_ATTACH_FAILED     = 0x00100000;
        const COR_DEFERRED_VALIDATE     = 0x00200000;
        const COR_IMAGE                 = 0x00400000;
        const DONT_RELOCATE             = 0x00800000;
        const COR_IL_ONLY               = 0x01000000;
        const CHPE_IMAGE                = 0x02000000;
        const REDIRECTED                = 0x10000000;
        const COMPAT_DATABASE_PROCESSED = 0x80000000;
    }
}

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct UnicodeString {
    length: u16,
    max_length: u16,
    reserved: u32,
    buffer: u64
}
impl_from_memreader!(UnicodeString);

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct KldrDataTableEntry {
    pub flink: u64,
    pub blink: u64,
    pub exception_table: u64,
    pub exception_table_size: u64,
    pub gp_value: u64,
    pub non_paged_debug_info: u64,
    pub dll_base: u64,
    pub entry_point: u64,
    pub size_of_image: u64,
    full_dll_name: UnicodeString,
    base_dll_name: UnicodeString,
    pub flags: u32,
    pub load_count: u16,
    pub u1: u16,
    pub section_pointer: u64,
    pub checksum: u32,
    pub coverage_section_size: u16,
    pub coverage_section: u64,
    pub loaded_imports: u64,
    pub spare: u64,
    pub size_of_image_not_rounded: u32,
    pub time_date_stamp: u32
}
impl_from_memreader!(KldrDataTableEntry);

// Additional methods for KldrDataTableEntry
impl KldrDataTableEntry {
    /// Read the full DLL name from the data entry. Returns None if a name is not found.
    pub fn full_dll<R: MemReader>(&self, cr3: u64, reader: &mut R) -> Option<String> {
        // Length must be an even number to be converted to UTF16
        if self.base_dll_name.length % 2 == 1 || self.base_dll_name.length > 4096 { 
            return None; 
        }

        // Create a buffer for the individual u8 bytes from the buffer
        let mut utf8_buffer = Vec::with_capacity(self.full_dll_name.length as usize);
        unsafe { utf8_buffer.set_len(self.full_dll_name.length as usize) }

        // Attempt to read the base dll name from the buffer
        let res = reader.read_mem(Address::Virtual(self.full_dll_name.buffer, cr3), 
                                  &mut utf8_buffer);

        // Buffer not found
        if res.is_err() { return None; }

        // Convert the utf8 buffer into a utf16 vec
        let utf16_buffer: Vec<u16> = utf8_buffer.chunks(2)
            .map(|x| u16::from_le_bytes(x.try_into().unwrap()))
            .collect();

        // Attempt to create a String from the utf16 vec and return None is one cannot
        // be made
        match String::from_utf16(&utf16_buffer) {
            Ok(x) => Some(x),
            Err(_) => None
        }
    }

    /// Read the base DLL name from the data entry. Returns None if a name is not found.
    pub fn base_dll<R: MemReader>(&self, cr3: u64, reader: &mut R) -> Option<String> {
        // length must be an even number to be converted to utf16
        if self.base_dll_name.length % 2 == 1 || self.base_dll_name.length > 4096 { 
            return None; 
        }

        // create a buffer for the individual u8 bytes from the buffer
        let mut utf8_buffer = Vec::with_capacity(self.base_dll_name.length as usize);
        unsafe { utf8_buffer.set_len(self.base_dll_name.length as usize) }

        // attempt to read the base dll name from the buffer
        let res = reader.read_mem(Address::Virtual(self.base_dll_name.buffer, cr3), 
                                  &mut utf8_buffer);
        // buffer not found
        if res.is_err() { return None; }

        // convert the utf8 buffer into a utf16 vec
        let utf16_buffer: Vec<u16> = utf8_buffer.chunks(2)
            .map(|x| u16::from_le_bytes(x
                        .try_into().expect(&format!("unable to make u16: {:?}", x))))
            .collect();

        // attempt to create a string from the utf16 vec and return none is one cannot
        // be made
        match String::from_utf16(&utf16_buffer) {
            Ok(x) => Some(x),
            Err(_) => None
        }
    }
}
