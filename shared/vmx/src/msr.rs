pub const IA32_FEATURE_CONTROL: u32 = 0x3A;
pub const IA32_VMX_BASIC: u32 = 0x480;
pub const IA32_VMX_PINBASED_CTLS: u32 = 0x481;
pub const IA32_VMX_PROCBASED_CTLS: u32 = 0x482;
pub const IA32_VMX_EXIT_CTLS: u32 = 0x483;
pub const IA32_VMX_ENTRY_CTLS: u32 = 0x484;
pub const IA32_VMX_PROCBASED_CTLS2: u32 = 0x48B;

pub const IA32_VMX_CR0_FIXED0: u32 = 0x486;
pub const IA32_VMX_CR0_FIXED1: u32 = 0x487;
pub const IA32_VMX_CR4_FIXED0: u32 = 0x488;
pub const IA32_VMX_CR4_FIXED1: u32 = 0x489;

pub const VMCS_ADDR_IO_BITMAP_A: u32 = 0x2000;
pub const VMCS_ADDR_IO_BITMAP_A_HIGH: u32 = 0x2001;
pub const VMCS_ADDR_IO_BITMAP_B: u32 = 0x2002;
pub const VMCS_ADDR_IO_BITMAP_B_HIGH: u32 = 0x2003;

pub const VMCS_VMEXIT_MSR_STORE_ADDR: u32 = 0x2006;
pub const VMCS_VMEXIT_MSR_STORE_ADDR_HIGH: u32 = 0x2007;
pub const VMCS_VMEXIT_MSR_LOAD_ADDR: u32 = 0x2008;
pub const VMCS_VMEXIT_MSR_LOAD_ADDR_HIGH: u32 = 0x2009;
pub const VMCS_VMENTRY_MSR_LOAD_ADDR: u32 = 0x200a;
pub const VMCS_VMENTRY_MSR_LOAD_ADDR_HIGH: u32 = 0x200b;
pub const VMCS_EXEC_VMCS_PTR: u32 = 0x200c;
pub const VMCS_EXEC_VMCS_PTR_HIGH: u32 = 0x200d;
pub const VMCS_TSC_OFFSET: u32 = 0x2010;
pub const VMCS_TSC_OFFSET_HIGH: u32 = 0x2011;
pub const VMCS_EPT_PTR: u32 = 0x201a;
pub const VMCS_EPT_PTR_HIGH: u32 = 0x201b;

pub const VMCS_PIN_BASED_VMEXEC_CTL: u32 = 0x4000;
pub const VMCS_PROC_BASED_VMEXEC_CTL: u32 = 0x4002;
pub const VMCS_SECONDARY_VMEXEC_CTL: u32 = 0x401e;
pub const VMCS_EXCEPTION_BITMAP: u32 = 0x4004;
pub const VMCS_PAGEFAULT_ERRCODE_MASK: u32 = 0x4006;
pub const VMCS_PAGEFAULT_ERRCODE_MATCH: u32 = 0x4008;
pub const VMCS_CR3_TARGET_COUNT: u32 = 0x400a;

pub const VMCS_VMEXIT_CTL: u32 = 0x400c;
pub const VMCS_VMEXIT_MSR_STORE_COUNT: u32 = 0x400e;
pub const VMCS_VMEXIT_MSR_LOAD_COUNT: u32 = 0x4010;

pub const VMCS_VMENTRY_CTL: u32 = 0x4012;
pub const VMCS_VMENTRY_MSR_LOAD_COUNT: u32 = 0x4014;
pub const VMCS_VMENTRY_INTR_INFO_FIELD: u32 = 0x4016;
pub const VMCS_VMENTRY_EXCEPTION_ERRCODE: u32 = 0x4018;
pub const VMCS_VMENTRY_INSTRUCTION_LEN: u32 = 0x401a;

pub const VMCS_TPR_THRESHOLD: u32 = 0x401c;

pub const VMCS_CR0_GUESTHOST_MASK: u32 = 0x6000;
pub const VMCS_CR4_GUESTHOST_MASK: u32 = 0x6002;
pub const VMCS_CR0_READ_SHADOW: u32 = 0x6004;
pub const VMCS_CR4_READ_SHADOW: u32 = 0x6006;
pub const VMCS_CR3_TARGET_VALUE_0: u32 = 0x6008;
pub const VMCS_CR3_TARGET_VALUE_1: u32 = 0x600a;
pub const VMCS_CR3_TARGET_VALUE_2: u32 = 0x600c;
pub const VMCS_CR3_TARGET_VALUE_3: u32 = 0x600e;

pub const VMCS_HOST_ES_SEL: u32 = 0xc00;
pub const VMCS_HOST_CS_SEL: u32 = 0xc02;
pub const VMCS_HOST_SS_SEL: u32 = 0xc04;
pub const VMCS_HOST_DS_SEL: u32 = 0xc06;
pub const VMCS_HOST_FS_SEL: u32 = 0xc08;
pub const VMCS_HOST_GS_SEL: u32 = 0xc0a;
pub const VMCS_HOST_TR_SEL: u32 = 0xc0c;

pub const VMCS_HOST_CR0: u32 = 0x6c00;
pub const VMCS_HOST_CR3: u32 = 0x6c02;
pub const VMCS_HOST_CR4: u32 = 0x6c04;
pub const VMCS_HOST_FS_BASE: u32 = 0x6c06;
pub const VMCS_HOST_GS_BASE: u32 = 0x6c08;
pub const VMCS_HOST_TR_BASE: u32 = 0x6c0a;
pub const VMCS_HOST_GDTR_BASE: u32 = 0x6c0c;
pub const VMCS_HOST_IDTR_BASE: u32 = 0x6c0e;
pub const VMCS_HOST_RSP: u32 = 0x6c14;
pub const VMCS_HOST_RIP: u32 = 0x6c16;

pub const VMCS_HOST_SYSENTER_ESP: u32 = 0x6c10;
pub const VMCS_HOST_SYSENTER_EIP: u32 = 0x6c12;

pub const VMCS_GUEST_ES_SEL: u32 = 0x800;
pub const VMCS_GUEST_CS_SEL: u32 = 0x802;
pub const VMCS_GUEST_SS_SEL: u32 = 0x804;
pub const VMCS_GUEST_DS_SEL: u32 = 0x806;
pub const VMCS_GUEST_FS_SEL: u32 = 0x808;
pub const VMCS_GUEST_GS_SEL: u32 = 0x80a;
pub const VMCS_GUEST_LDTR_SEL: u32 = 0x80c;
pub const VMCS_GUEST_TR_SEL: u32 = 0x80e;

pub const VMCS_VMCS_LINK_PTR: u32 = 0x2800;
pub const VMCS_VMCS_LINK_PTR_HIGH: u32 = 0x2801;
pub const VMCS_GUEST_IA32_DEBUGCTL: u32 = 0x2802;
pub const VMCS_GUEST_IA32_DEBUGCTL_HIGH: u32 = 0x2803;

pub const VMCS_GUEST_ES_LIMIT: u32 = 0x4800;
pub const VMCS_GUEST_CS_LIMIT: u32 = 0x4802;
pub const VMCS_GUEST_SS_LIMIT: u32 = 0x4804;
pub const VMCS_GUEST_DS_LIMIT: u32 = 0x4806;
pub const VMCS_GUEST_FS_LIMIT: u32 = 0x4808;
pub const VMCS_GUEST_GS_LIMIT: u32 = 0x480a;
pub const VMCS_GUEST_LDTR_LIMIT: u32 = 0x480c;
pub const VMCS_GUEST_TR_LIMIT: u32 = 0x480e;
pub const VMCS_GUEST_GDTR_LIMIT: u32 = 0x4810;
pub const VMCS_GUEST_IDTR_LIMIT: u32 = 0x4812;
pub const VMCS_GUEST_ES_ACCESS_RIGHTS: u32 = 0x4814;
pub const VMCS_GUEST_CS_ACCESS_RIGHTS: u32 = 0x4816;
pub const VMCS_GUEST_SS_ACCESS_RIGHTS: u32 = 0x4818;
pub const VMCS_GUEST_DS_ACCESS_RIGHTS: u32 = 0x481a;
pub const VMCS_GUEST_FS_ACCESS_RIGHTS: u32 = 0x481c;
pub const VMCS_GUEST_GS_ACCESS_RIGHTS: u32 = 0x481e;
pub const VMCS_GUEST_LDTR_ACCESS_RIGHTS: u32 = 0x4820;
pub const VMCS_GUEST_TR_ACCESS_RIGHTS: u32 = 0x4822;
pub const VMCS_GUEST_INTERRUPTIBILITY_STATE: u32 = 0x4824;
pub const VMCS_GUEST_ACTIVITY_STATE: u32 = 0x4826;

pub const VMCS_GUEST_CR0: u32 = 0x6800;
pub const VMCS_GUEST_CR3: u32 = 0x6802;
pub const VMCS_GUEST_CR4: u32 = 0x6804;
pub const VMCS_GUEST_ES_BASE: u32 = 0x6806;
pub const VMCS_GUEST_CS_BASE: u32 = 0x6808;
pub const VMCS_GUEST_SS_BASE: u32 = 0x680a;
pub const VMCS_GUEST_DS_BASE: u32 = 0x680c;
pub const VMCS_GUEST_FS_BASE: u32 = 0x680e;
pub const VMCS_GUEST_GS_BASE: u32 = 0x6810;
pub const VMCS_GUEST_LDTR_BASE: u32 = 0x6812;
pub const VMCS_GUEST_TR_BASE: u32 = 0x6814;
pub const VMCS_GUEST_GDTR_BASE: u32 = 0x6816;
pub const VMCS_GUEST_IDTR_BASE: u32 = 0x6818;
pub const VMCS_GUEST_DR7: u32 = 0x681a;
pub const VMCS_GUEST_RSP: u32 = 0x681c;
pub const VMCS_GUEST_RIP: u32 = 0x681e;
pub const VMCS_GUEST_RFLAGS: u32 = 0x6820;
pub const VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS: u32 = 0x6822;

pub const VMCS_GUEST_SYSENTER_ESP: u32 = 0x6824;
pub const VMCS_GUEST_SYSENTER_EIP: u32 = 0x6826;

pub const VMCS_VM_INSTRUCTION_ERROR: u32 = 0x4400;
pub const VMCS_VMEXIT_REASON: u32 = 0x4402;
pub const VMCS_VMEXIT_INTERRUPTION_INFO: u32 = 0x4404;
pub const VMCS_VMEXIT_INTERRUPTION_ERROR_CODE: u32 = 0x4406;
pub const VMCS_VMEXIT_INSTR_LENGTH: u32 = 0x440c;
pub const VMCS_VMEXIT_INSTR_INFO: u32 = 0x440e;

pub const VMCS_EXIT_QUALIFICATION: u32 = 0x6400;
pub const VMCS_IO_RCX: u32 = 0x6402;
pub const VMCS_IO_RSI: u32 = 0x6404;
pub const VMCS_IO_RDI: u32 = 0x6406;
pub const VMCS_IO_RIP: u32 = 0x6408;
pub const VMCS_GUEST_LINEAR_ADDR: u32 = 0x640a;

pub const VMCS_IDT_INFORMATION: u32 = 0x4408;
pub const VMCS_IDT_ERROR_CODE: u32 = 0x440a;

pub const VMCS_GUEST_PHYSICAL_ADDRESS: u32 = 0x2400;

bitflags! {
    pub struct CTLS: u32 {
        const CR3_LOAD_EXIT =  1 << 15;
        const CR3_STORE_EXIT = 1 << 16;
        const SECONDARY =      1 << 31;
    }
}

bitflags! {
    pub struct CTLS2: u32 {
        const VIRTUALIZE_APIC =    1 << 0;
        const ENABLE_EPT      =    1 << 1;
        const NA2     =            1 << 2;
        const NA3     =            1 << 3;
        const NA4     =            1 << 4;
        const NA5     =            1 << 5;
        const NA6     =            1 << 6;
        const UNRESTRICTED_GUEST = 1 << 7;
        const NA8     =            1 << 8;
        const NA9     =            1 << 9;
        const NA10    =            1 << 10;
        const NA11    =            1 << 11;
        const NA12    =            1 << 12;
        const NA13    =            1 << 13;
        const NA14    =            1 << 14;
        const NA15    =            1 << 15;
        const NA16    =            1 << 16;
        const NA17    =            1 << 17;
        const NA18    =            1 << 18;
        const NA19    =            1 << 19;
        const NA20    =            1 << 20;
        const RESERVED21 =         1 << 21;
        const NA22      =          1 << 22;
        const RESERVED22      =    1 << 23;
        const RESERVED23      =    1 << 24;
        const NA25            =    1 << 25;
        const RESERVED26      =    1 << 26;
        const RESERVED27      =    1 << 27;
        const RESERVED28      =    1 << 28;
        const RESERVED29      =    1 << 29;
        const RESERVED30      =    1 << 30;
        const RESERVED31      =    1 << 31;
    }
}

bitflags! {
    pub struct FeatureControl: u32 {
        const LOCK =      1 << 0;
        const VMXON =     1 << 2;
    }
}
