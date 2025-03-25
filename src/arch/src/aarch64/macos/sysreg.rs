pub const SYSREG_OP0_SHIFT: u32 = 20;
pub const SYSREG_OP0_MASK: u32 = 0x3;
pub const SYSREG_OP1_SHIFT: u32 = 14;
pub const SYSREG_OP1_MASK: u32 = 0x7;
pub const SYSREG_CRN_SHIFT: u32 = 10;
pub const SYSREG_CRN_MASK: u32 = 0xf;
pub const SYSREG_CRM_SHIFT: u32 = 1;
pub const SYSREG_CRM_MASK: u32 = 0xf;
pub const SYSREG_OP2_SHIFT: u32 = 17;
pub const SYSREG_OP2_MASK: u32 = 0x7;

#[macro_export]
macro_rules! arm64_sys_reg {
    ($name: tt, $op0: tt, $op1: tt, $op2: tt, $crn: tt, $crm: tt) => {
        pub const $name: u32 = ($op0 as u32) << SYSREG_OP0_SHIFT
            | ($op2 as u32) << SYSREG_OP2_SHIFT
            | ($op1 as u32) << SYSREG_OP1_SHIFT
            | ($crn as u32) << SYSREG_CRN_SHIFT
            | ($crm as u32) << SYSREG_CRM_SHIFT;
    };
}

arm64_sys_reg!(
    SYSREG_MASK,
    SYSREG_OP0_MASK,
    SYSREG_OP1_MASK,
    SYSREG_OP2_MASK,
    SYSREG_CRN_MASK,
    SYSREG_CRM_MASK
);

arm64_sys_reg!(SYSREG_OSLAR_EL1, 2, 0, 4, 1, 0);
arm64_sys_reg!(SYSREG_OSDLR_EL1, 2, 0, 4, 1, 3);

arm64_sys_reg!(SYSREG_ICC_AP0R0_EL1, 3, 0, 4, 12, 8);
arm64_sys_reg!(SYSREG_ICC_AP0R1_EL1, 3, 0, 5, 12, 8);
arm64_sys_reg!(SYSREG_ICC_AP0R2_EL1, 3, 0, 6, 12, 8);
arm64_sys_reg!(SYSREG_ICC_AP0R3_EL1, 3, 0, 7, 12, 8);
arm64_sys_reg!(SYSREG_ICC_AP1R0_EL1, 3, 0, 0, 12, 9);
arm64_sys_reg!(SYSREG_ICC_AP1R1_EL1, 3, 0, 1, 12, 9);
arm64_sys_reg!(SYSREG_ICC_AP1R2_EL1, 3, 0, 2, 12, 9);
arm64_sys_reg!(SYSREG_ICC_AP1R3_EL1, 3, 0, 3, 12, 9);
arm64_sys_reg!(SYSREG_ICC_ASGI1R_EL1, 3, 0, 6, 12, 11);
arm64_sys_reg!(SYSREG_ICC_BPR0_EL1, 3, 0, 3, 12, 8);
arm64_sys_reg!(SYSREG_ICC_BPR1_EL1, 3, 0, 3, 12, 12);
arm64_sys_reg!(SYSREG_ICC_CTLR_EL1, 3, 0, 4, 12, 12);
arm64_sys_reg!(SYSREG_ICC_DIR_EL1, 3, 0, 1, 12, 11);
arm64_sys_reg!(SYSREG_ICC_EOIR0_EL1, 3, 0, 1, 12, 8);
arm64_sys_reg!(SYSREG_ICC_EOIR1_EL1, 3, 0, 1, 12, 12);
arm64_sys_reg!(SYSREG_ICC_HPPIR0_EL1, 3, 0, 2, 12, 8);
arm64_sys_reg!(SYSREG_ICC_HPPIR1_EL1, 3, 0, 2, 12, 12);
arm64_sys_reg!(SYSREG_ICC_IAR0_EL1, 3, 0, 0, 12, 8);
arm64_sys_reg!(SYSREG_ICC_IAR1_EL1, 3, 0, 0, 12, 12);
arm64_sys_reg!(SYSREG_ICC_IGRPEN0_EL1, 3, 0, 6, 12, 12);
arm64_sys_reg!(SYSREG_ICC_IGRPEN1_EL1, 3, 0, 7, 12, 12);
arm64_sys_reg!(SYSREG_ICC_PMR_EL1, 3, 0, 0, 4, 6);
arm64_sys_reg!(SYSREG_ICC_SGI1R_EL1, 3, 0, 5, 12, 11);
arm64_sys_reg!(SYSREG_ICC_SRE_EL1, 3, 0, 5, 12, 12);

arm64_sys_reg!(SYSREG_CNTVOFF_EL2, 3, 4, 3, 14, 0);
arm64_sys_reg!(SYSREG_CNTHCTL_EL2, 3, 4, 0, 14, 1);
arm64_sys_reg!(SYSREG_CNTHP_TVAL_EL2, 3, 4, 0, 14, 2);
arm64_sys_reg!(SYSREG_CNTHP_CTL_EL2, 3, 4, 1, 14, 2);
arm64_sys_reg!(SYSREG_CNTHP_CVAL_EL2, 3, 4, 2, 14, 2);
arm64_sys_reg!(SYSREG_CNTHV_TVAL_EL2, 3, 4, 0, 14, 3);
arm64_sys_reg!(SYSREG_CNTHV_CTL_EL2, 3, 4, 1, 14, 3);
arm64_sys_reg!(SYSREG_CNTHV_CVAL_EL2, 3, 4, 2, 14, 3);

arm64_sys_reg!(SYSREG_LORC_EL1, 3, 0, 3, 10, 4);

// ICC_CTLR_EL1 (https://developer.arm.com/documentation/ddi0595/2021-06/AArch64-Registers/ICC-CTLR-EL1--Interrupt-Controller-Control-Register--EL1-)
pub const ICC_CTLR_EL1_RSS_SHIFT: u32 = 18;
pub const ICC_CTLR_EL1_A3V_SHIFT: u32 = 15;
pub const ICC_CTLR_EL1_ID_BITS_SHIFT: u32 = 11;
pub const ICC_CTLR_EL1_PRI_BITS_SHIFT: u32 = 8;

pub fn sys_reg_name(addr: u32) -> Option<&'static str> {
    match addr {
        SYSREG_ICC_IAR0_EL1 => Some("SYSREG_ICC_IAR0_EL1"),
        SYSREG_ICC_IAR1_EL1 => Some("SYSREG_ICC_IAR1_EL1"),
        SYSREG_ICC_EOIR0_EL1 => Some("SYSREG_ICC_EOIR0_EL1"),
        SYSREG_ICC_EOIR1_EL1 => Some("SYSREG_ICC_EOIR1_EL1"),
        SYSREG_ICC_AP0R0_EL1 => Some("SYSREG_ICC_AP0R0_EL1"),
        SYSREG_ICC_AP0R1_EL1 => Some("SYSREG_ICC_AP0R1_EL1"),
        SYSREG_ICC_AP0R2_EL1 => Some("SYSREG_ICC_AP0R2_EL1"),
        SYSREG_ICC_AP0R3_EL1 => Some("SYSREG_ICC_AP0R3_EL1"),
        SYSREG_ICC_AP1R0_EL1 => Some("SYSREG_ICC_AP1R0_EL1"),
        SYSREG_ICC_AP1R1_EL1 => Some("SYSREG_ICC_AP1R1_EL1"),
        SYSREG_ICC_AP1R2_EL1 => Some("SYSREG_ICC_AP1R2_EL1"),
        SYSREG_ICC_AP1R3_EL1 => Some("SYSREG_ICC_AP1R3_EL1"),
        SYSREG_ICC_ASGI1R_EL1 => Some("SYSREG_ICC_ASGI1R_EL1"),
        SYSREG_ICC_BPR0_EL1 => Some("SYSREG_ICC_BPR0_EL1"),
        SYSREG_ICC_BPR1_EL1 => Some("SYSREG_ICC_BPR1_EL1"),
        SYSREG_ICC_CTLR_EL1 => Some("SYSREG_ICC_CTLR_EL1"),
        SYSREG_ICC_DIR_EL1 => Some("SYSREG_ICC_DIR_EL1"),
        SYSREG_ICC_HPPIR0_EL1 => Some("SYSREG_ICC_HPPIR0_EL1"),
        SYSREG_ICC_HPPIR1_EL1 => Some("SYSREG_ICC_HPPIR1_EL1"),
        SYSREG_ICC_IGRPEN0_EL1 => Some("SYSREG_ICC_IGRPEN0_EL1"),
        SYSREG_ICC_IGRPEN1_EL1 => Some("SYSREG_ICC_IGRPEN1_EL1"),
        SYSREG_ICC_PMR_EL1 => Some("SYSREG_ICC_PMR_EL1"),
        SYSREG_ICC_SGI1R_EL1 => Some("SYSREG_ICC_SGI1R_EL1"),
        SYSREG_ICC_SRE_EL1 => Some("SYSREG_ICC_SRE_EL1"),

        SYSREG_CNTVOFF_EL2 => Some("SYSREG_CNTVOFF_EL2"),
        SYSREG_CNTHCTL_EL2 => Some("SYSREG_CNTHCTL_EL2"),
        SYSREG_CNTHP_TVAL_EL2 => Some("SYSREG_CNTHP_TVAL_EL2"),
        SYSREG_CNTHP_CTL_EL2 => Some("SYSREG_CNTHP_CTL_EL2"),
        SYSREG_CNTHP_CVAL_EL2 => Some("SYSREG_CNTHP_CVAL_EL2"),
        SYSREG_CNTHV_TVAL_EL2 => Some("SYSREG_CNTHV_TVAL_EL2"),
        SYSREG_CNTHV_CTL_EL2 => Some("SYSREG_CNTHV_CTL_EL2"),
        SYSREG_CNTHV_CVAL_EL2 => Some("SYSREG_CNTHV_CVAL_EL2"),

        SYSREG_LORC_EL1 => Some("SYSREG_LORC_EL1"),
        _ => None,
    }
}

pub fn sysreg_op0(sysreg: u32) -> u32 {
    (sysreg >> SYSREG_OP0_SHIFT) & SYSREG_OP0_MASK
}

pub fn sysreg_op1(sysreg: u32) -> u32 {
    (sysreg >> SYSREG_OP1_SHIFT) & SYSREG_OP1_MASK
}

pub fn sysreg_op2(sysreg: u32) -> u32 {
    (sysreg >> SYSREG_OP2_SHIFT) & SYSREG_OP2_MASK
}

pub fn sysreg_crn(sysreg: u32) -> u32 {
    (sysreg >> SYSREG_CRN_SHIFT) & SYSREG_CRN_MASK
}

pub fn sysreg_crm(sysreg: u32) -> u32 {
    (sysreg >> SYSREG_CRM_SHIFT) & SYSREG_CRM_MASK
}

pub fn is_id_sysreg(reg: u32) -> bool {
    sysreg_op0(reg) == 3
        && sysreg_op1(reg) == 0
        && sysreg_crn(reg) == 0
        && sysreg_crm(reg) >= 1
        && sysreg_crm(reg) < 8
}
