// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 IBM Corp
//
// Author: Dov Murik <dovmurik@linux.ibm.com>

pub mod check;
pub mod core;
pub mod errors;
#[cfg(all(feature = "mstpm", not(test)))]
pub mod vtpm;

use cpuarch::vmsa::{GuestVMExit, VMSA};

// SVSM protocols
pub const SVSM_CORE_PROTOCOL: u32 = 0;
pub const SVSM_VTPM_PROTOCOL: u32 = 2;
pub const SVSM_CHECK_KERNEL: u32 = 3;

#[derive(Debug, Default, Clone, Copy)]
pub struct RequestParams {
    pub guest_exit_code: GuestVMExit,
    sev_features: u64,
    rcx: u64,
    rdx: u64,
    r8: u64,
    r9: u64,
}

impl RequestParams {
    pub fn from_vmsa(vmsa: &VMSA) -> Self {
        RequestParams {
            guest_exit_code: vmsa.guest_exit_code,
            sev_features: vmsa.sev_features,
            rcx: vmsa.rcx,
            rdx: vmsa.rdx,
            r8: vmsa.r8,
            r9: vmsa.r9,
        }
    }

    pub fn write_back(&self, vmsa: &mut VMSA) {
        vmsa.rcx = self.rcx;
        vmsa.rdx = self.rdx;
        vmsa.r8 = self.r8;
        vmsa.r9 = self.r9;
    }
}
