use crate::num::FromPrimitive;
use crate::{Register, Segment};

#[derive(Debug)]
pub struct DescriptorTableInfo {
    pub scaling: Scaling,
    pub address_size: AddressSize,
    pub operand_size: OperandSize,
    pub segment: Segment,
    pub index_register: Option<Register>,
    pub base_register: Option<Register>,
    pub identity: Identity,
}

#[derive(Debug, FromPrimitive)]
pub enum Scaling {
    NoScale = 0,
    ScaleBy2 = 1,
    ScaleBy4 = 2,
    ScaleBy8 = 3,
}

#[derive(Debug, FromPrimitive, Eq, PartialEq)]
pub enum AddressSize {
    Bit16 = 0,
    Bit32 = 1,
    Bit64 = 2,
}

#[derive(Debug, FromPrimitive)]
pub enum OperandSize {
    Bit16 = 0,
    Bit32 = 1,
}

#[derive(Debug, FromPrimitive)]
pub enum Identity {
    SGDT = 0,
    SIDT = 1,
    LGDT = 2,
    LIDT = 3,
}

impl DescriptorTableInfo {
    pub fn from_instruction_info(value: u64) -> Self {
        /*
         * See: Table 27-10.  Format of the VM-Exit Instruction-Information Field as Used for LIDT, LGDT, SIDT, or SGDT
         * Scaling: 1:0
         * Address size: 9:7
         * Operand size: 11
         * Segment register: 17:15
         * Index register: 21:18
         * Index register invalid: 22 (0 = valid; 1 = invalid)
         * Base register: 26:23
         * Base register invalid: 27 (0 = valid; 1 = invalid)
         * Identity: 29:28
         */

        let index_register = match value >> 22 & 1 {
            0 => Some(
                Register::from_u64(value >> 18 & 0b1111)
                    .expect("Register::from_u64 failed to parse"),
            ),
            1 => None,
            _ => unreachable!(),
        };
        let base_register = match value >> 27 & 1 {
            0 => Some(
                Register::from_u64(value >> 23 & 0b1111)
                    .expect("Register::from_u64 failed for >> 23"),
            ),
            1 => None,
            _ => unreachable!(),
        };
        DescriptorTableInfo {
            scaling: Scaling::from_u64(value & 0b11).expect("Scaling::from_u64 failed for 0b11"),
            address_size: AddressSize::from_u64(value >> 7 & 0b111)
                .expect("AddressSize from_u64 failed for >> 7"),
            operand_size: OperandSize::from_u64(value >> 11 & 0b1)
                .expect("OperandSize failed for >> 11"),
            segment: Segment::from_u64(value >> 15 & 0b111)
                .expect("Segment::from_u64 failed for >> 15"),
            index_register,
            base_register,
            identity: Identity::from_u64(value >> 28 & 0b11)
                .expect("Identity::from_u64 failed for >> 28"),
        }
    }
}
