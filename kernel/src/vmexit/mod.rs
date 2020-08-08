//! Module housing many of the decodings of the information values from VMExits
use crate::msr::*;
use crate::vmx::vmread;
use crate::vmregs::VmRegs;

use crate::num::FromPrimitive;

pub mod descriptor_table;
pub use descriptor_table::*;

#[derive(Debug, Eq, PartialEq, Hash, Copy, Clone)]
#[repr(u8)]
pub enum VmExitReason {
    Exception(ExceptionVector) = 0,
    ExternalInterrupt = 1,
    TripleFault = 2,
    InitSignal = 3,
    StartUpIPI = 4,
    IOSystemManagementInterrupt = 5,
    OtherSMI = 6,
    InterruptWindow = 7,
    NMIWindow = 8,
    TaskSwitch = 9,
    CPUID = 10,
    GETSEC = 11,
    HLT = 12,
    INVD = 13,
    INVLPG = 14,
    RDPMC = 15,
    RDTSC = 16,
    RSM = 17,
    VMCALL = 18,
    VMCLEAR = 19,
    VMLAUNCH = 20,
    VMPTRLD = 21,
    VMPTRST = 22,
    VMREAD = 23,
    VMRESUME = 24,
    VMWRITE = 25,
    VMXOFF = 26,
    VMXON = 27,
    ControlRegisterAccess(u64, u64, u64) = 28,
    MovDR = 29,
    IOInstruction = 30,
    RDMSR(u64) = 31,
    WRMSR = 32,
    VmEntryFailureInvalidGuestState = 33,
    VmEntryFailureMSRLoading = 34,
    MWAIT = 36,
    MonitorTrapFlag = 37,
    MONITOR = 39,
    PAUSE = 40,
    VmEntryFailureMachineCheckEvent = 41,
    TPRBelowThreshold = 43,
    APICAccess = 44,
    VirtualizedEOI = 45,
    GDTRorIDTRAccess = 46,
    LDTRorTRAccess = 47,
    EPTViolation = 48,
    EPTMisconfiguration = 49,
    INVEPT = 50,
    RDTSCP = 51,
    VMXPreemptionTimerExpired = 52,
    INVVPID = 53,
    WBINVD = 54,
    XSETBV = 55,
    APICWrite = 56,
    RDRAND = 57,
    INVPCPID = 58,
    VMFUNC = 59,
    ENCLS = 60,
    RDSEED = 61,
    PageModificationLogFull = 62,
    XSAVES = 63,
    XRSTORS = 64,
}

impl VmExitReason {
    pub fn from_u64(value: u64, regs: &VmRegs) -> VmExitReason {
        let value = value & 0xff;
        match value {
            0 => {
                let exit_info = vmread(VMCS_VMEXIT_INTERRUPTION_INFO);
                let interrupt_info = InterruptionInfo::from(exit_info);
                VmExitReason::Exception(interrupt_info.vector())
            }
            1 => VmExitReason::ExternalInterrupt,
            2 => VmExitReason::TripleFault,
            3 => VmExitReason::InitSignal,
            4 => VmExitReason::StartUpIPI,
            5 => VmExitReason::IOSystemManagementInterrupt,
            6 => VmExitReason::OtherSMI,
            7 => VmExitReason::InterruptWindow,
            8 => VmExitReason::NMIWindow,
            9 => VmExitReason::TaskSwitch,
            10 => VmExitReason::CPUID,
            11 => VmExitReason::GETSEC,
            12 => VmExitReason::HLT,
            13 => VmExitReason::INVD,
            14 => VmExitReason::INVLPG,
            15 => VmExitReason::RDPMC,
            16 => VmExitReason::RDTSC,
            17 => VmExitReason::RSM,
            18 => VmExitReason::VMCALL,
            19 => VmExitReason::VMCLEAR,
            20 => VmExitReason::VMLAUNCH,
            21 => VmExitReason::VMPTRLD,
            22 => VmExitReason::VMPTRST,
            23 => VmExitReason::VMREAD,
            24 => VmExitReason::VMRESUME,
            25 => VmExitReason::VMWRITE,
            26 => VmExitReason::VMXOFF,
            27 => VmExitReason::VMXON,
            28 => {
                let exit_qual = vmread(VMCS_EXIT_QUALIFICATION);

                let register = exit_qual & 0xf;
                let instr_type = exit_qual >> 4 & 0x3;

                let new_value = match (instr_type, register) {
                    /* mov to cr3 */
                    (0,3) => match (exit_qual >> 8) & 0xf {
                            0 => regs.rax,
                            1 => regs.rcx,
                            2 => regs.rdx,
                            3 => regs.rbx,
                            4 => regs.rsp,
                            5 => regs.rbp,
                            6 => regs.rsi,
                            7 => regs.rdi,
                            8 => regs.r8,
                            9 => regs.r9,
                            10 => regs.r10,
                            11 => regs.r11,
                            12 => regs.r12,
                            13 => regs.r13,
                            14 => regs.r14,
                            15 => regs.r15,
                            _ => panic!("Unknown register in handling control regs"),
                    }
                    _ => 0xdeadbeef
                };

                VmExitReason::ControlRegisterAccess(register, instr_type, new_value)
            }
            29 => VmExitReason::MovDR,
            30 => VmExitReason::IOInstruction,
            31 => VmExitReason::RDMSR(regs.rcx),
            32 => VmExitReason::WRMSR,
            33 => VmExitReason::VmEntryFailureInvalidGuestState,
            34 => VmExitReason::VmEntryFailureMSRLoading,
            36 => VmExitReason::MWAIT,
            37 => VmExitReason::MonitorTrapFlag,
            39 => VmExitReason::MONITOR,
            40 => VmExitReason::PAUSE,
            41 => VmExitReason::VmEntryFailureMachineCheckEvent,
            43 => VmExitReason::TPRBelowThreshold,
            44 => VmExitReason::APICAccess,
            45 => VmExitReason::VirtualizedEOI,
            46 => VmExitReason::GDTRorIDTRAccess,
            47 => VmExitReason::LDTRorTRAccess,
            48 => VmExitReason::EPTViolation,
            49 => VmExitReason::EPTMisconfiguration,
            50 => VmExitReason::INVEPT,
            51 => VmExitReason::RDTSCP,
            52 => VmExitReason::VMXPreemptionTimerExpired,
            53 => VmExitReason::INVVPID,
            54 => VmExitReason::WBINVD,
            55 => VmExitReason::XSETBV,
            56 => VmExitReason::APICWrite,
            57 => VmExitReason::RDRAND,
            58 => VmExitReason::INVPCPID,
            59 => VmExitReason::VMFUNC,
            60 => VmExitReason::ENCLS,
            61 => VmExitReason::RDSEED,
            62 => VmExitReason::PageModificationLogFull,
            63 => VmExitReason::XSAVES,
            64 => VmExitReason::XRSTORS,
            _ => {
                let exit_qual = vmread(VMCS_EXIT_QUALIFICATION);
                print!("Exit Qual: {:#x}\n", exit_qual);
                panic!("Unknown VmExit Reason: {:#x}", value);
            }
        }
    }
}

#[derive(Debug, FromPrimitive)]
pub enum Segment {
    Es = 0,
    Cs = 1,
    Ss = 2,
    Ds = 3,
    Fs = 4,
    Gs = 5,
}

#[derive(Debug, FromPrimitive)]
pub enum Register {
    Rax = 0,
    Rcx = 1,
    Rdx = 2,
    Rbx = 3,
    Rsp = 4,
    Rbp = 5,
    Rsi = 6,
    Rdi = 7,
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    R13 = 13,
    R14 = 14,
    R15 = 15,
}

#[derive(Debug, Clone, Copy, FromPrimitive)]
pub enum InterruptionType {
    External = 0,
    NonMaskable = 2,
    Hardware = 3,
    Software = 6,
}

/*
impl InterruptionType {
    pub fn from_u8(value: u8) -> Option<InterruptionType> {
        match value {
            0 => Some(InterruptionType::External),
            2 => Some(InterruptionType::NonMaskable),
            3 => Some(InterruptionType::Hardware),
            6 => Some(InterruptionType::Software),
            _ => None,
        }
    }
}
*/

#[derive(Debug, PartialEq, Eq, Clone, Copy, FromPrimitive, Hash)]
pub enum ExceptionVector {
    Divider = 0,
    Debug = 1,
    Breakpoint = 3,
    BoundRangeExceeded = 5,
    InvalidOpcode = 6,
    DoubleFault = 8,
    GeneralProtection = 13,
    PageFault = 14,
    FloatingPoint = 16,
    AlignmentCheck = 17,
    SIMDFloatingPoint = 19,
    Fault1f = 0x1f,
    Fault20 = 0x20,
    Fault21 = 0x21,
    Fault22 = 0x22,
    Fault23 = 0x23,
    Fault24 = 0x24,
    Fault25 = 0x25,
    Fault26 = 0x26,
    Fault27 = 0x27,
    Fault28 = 0x28,
    Fault29 = 0x29,
    Fault2a = 0x2a,
    Fault2b = 0x2b,
    Fault2c = 0x2c,
    Fault2d = 0x2d,
    Fault2e = 0x2e,
    Fault2f = 0x2f,
}

/*
impl ExceptionVector {
    pub fn from_u8(value: u8) -> Option<ExceptionVector> {
        match value {
            0 => Some(ExceptionVector::Divider),
            1 => Some(ExceptionVector::Debug),
            3 => Some(ExceptionVector::Breakpoint),
            5 => Some(ExceptionVector::BoundRangeExceeded),
            6 => Some(ExceptionVector::InvalidOpcode),
            8 => Some(ExceptionVector::DoubleFault),
            13 => Some(ExceptionVector::GeneralProtection),
            14 => Some(ExceptionVector::PageFault),
            16 => Some(ExceptionVector::FloatingPoint),
            17 => Some(ExceptionVector::AlignmentCheck),
            19 => Some(ExceptionVector::SIMDFloatingPoint),
            _ => None,
        }
    }
}
*/

#[derive(Debug, Clone)]
pub struct InterruptionInfo {
    pub vector: ExceptionVector,
    pub interruption_type: InterruptionType,
    pub error_code_valid: bool,
    pub valid: bool,
}

impl From<u64> for InterruptionInfo {
    fn from(value: u64) -> InterruptionInfo {
        let curr_type = InterruptionType::from_u8(((value >> 8) & 0x7) as u8)
            .expect("Invalid interruption type received");

        let valid = (value >> 31) & 1 == 1;

        InterruptionInfo {
            vector: ExceptionVector::from_u8((value & 0xff) as u8)
                .expect("Invalid Exception Vector received"),
            interruption_type: curr_type,
            error_code_valid: ((value >> 11) & 1) == 1,
            valid,
        }
    }
}

impl From<InterruptionInfo> for u64 {
    fn from(exit_info: InterruptionInfo) -> u64 {
        /*
        print!(
            "{} << 31 | {} << 11 | {} << 8 | {}\n",
            exit_info.valid as u64,
            exit_info.error_code_valid as u64,
            exit_info.interruption_type as u64,
            exit_info.vector as u64,
        );
        */
        (exit_info.valid as u64) << 31
            | (exit_info.error_code_valid as u64) << 11
            | (exit_info.interruption_type as u64) << 8
            | (exit_info.vector as u64)
    }
}

impl InterruptionInfo {
    pub fn from_u64(value: u64) -> InterruptionInfo {
        let curr_type = InterruptionType::from_u8(((value >> 8) & 0x7) as u8)
            .expect("Invalid interruption type received");

        let valid = (value >> 31) & 1 == 1;

        InterruptionInfo {
            vector: ExceptionVector::from_u8((value & 0xff) as u8)
                .expect("Invalid Exception Vector received"),
            interruption_type: curr_type,
            error_code_valid: ((value >> 11) & 1) == 1,
            valid,
        }
    }

    pub fn vector(&self) -> ExceptionVector {
        self.vector
    }

    pub fn is_error_code_valid(&self) -> bool {
        self.error_code_valid
    }
}

pub struct EPTExitQualification {
    pub value: u64,
}

impl EPTExitQualification {
    pub fn new(value: u64) -> Self {
        EPTExitQualification { value }
    }

    pub fn valid_guest_linear_addr(&self) -> bool {
        self.value >> 7 & 1 == 1
    }

    pub fn print(&self) {
        print!("EPT Violation: ");
        if self.value >> 0 & 1 == 1 {
            print!("READ ");
        }
        if self.value >> 1 & 1 == 1 {
            print!("WRITE ");
        }
        if self.value >> 2 & 1 == 1 {
            print!("INSTR_FETCH ");
        }
        if self.value >> 3 & 1 == 1 {
            print!("bit 3 ");
        }
        if self.value >> 4 & 1 == 1 {
            print!("bit 4 ");
        }
        if self.value >> 5 & 1 == 1 {
            print!("bit 5 ");
        }
        if self.value >> 6 & 1 == 1 {
            print!("bit 6 ");
        }
    }
}
