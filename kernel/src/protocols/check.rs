// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::address::{Address, PhysAddr, VirtAddr};
use crate::error::SvsmError;
use crate::mm::{valid_phys_address, writable_phys_addr, GuestPtr};
use crate::protocols::errors::SvsmReqError;
use crate::protocols::RequestParams;

const SVSM_CHECK_SINGLE: u32 = 0;

fn check_single(params: &mut RequestParams) -> Result<(), SvsmError> {
    todo!("check a single page here")
}

pub fn check_kernel_protocol_request(
    request: u32,
    params: &mut RequestParams,
) -> Result<(), SvsmReqError> {
    match request {
        SVSM_CHECK_SINGLE => check_single(params),
        _ => Err(SvsmReqError::unsupported_call()),
    }
}
