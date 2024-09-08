// SPDX-License-Identifier: MIT OR Apache-2.0

use log::{debug, info, error};

use crate::address::{Address, PhysAddr, VirtAddr};
use crate::cpu::percpu::current_ghcb;
use crate::error::SvsmError;
use crate::greq::pld_report::{
    AttestationReport, SnpReportResponse, SnpReportResponseStatus, USER_DATA_SIZE,
};
use crate::greq::services::{self, REPORT_REQUEST_SIZE, REPORT_RESPONSE_SIZE};
use crate::mm::virtualrange::{VIRT_ALIGN_2M, VIRT_ALIGN_4K};
use crate::mm::PerCPUPageMappingGuard;
use crate::mm::{valid_phys_address, writable_phys_addr, GuestPtr};
use crate::protocols::errors::SvsmReqError;
use crate::protocols::RequestParams;
use crate::sev::ghcb::switch_to_vmpl;
use crate::types::{PageSize, PAGE_SIZE, PAGE_SIZE_2M};
use core::mem::size_of;

use crate::stream_hash_wrapper::{HashState, HashDigest}; 

const SVSM_CHECK_SINGLE: u32 = 0;
const SVSM_HASH_SINGLE: u32 = 1;

const ATTESTATION_SIZE: usize = size_of::<AttestationReport>();

// fn hash_some(prev: u64, val: u8) -> u64 {
//     let magic: u64 = 37;
//     (prev + val as u64) % magic
// }

// fn hash_range(ptr: &GuestPtr::<u8>, len: usize) {
//     let mut hash_val: [u8; 64] = [0; 64];
//
//     let range_slice = unsafe {ptr.slice_range(len)};
//    // hash_val = Hash::hash(len);
// }

fn check_single(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    let gpa = PhysAddr::from(params.rcx);

    if !gpa.is_aligned(8) || !valid_phys_address(gpa) {
        return Err(SvsmReqError::invalid_parameter());
    }

    let guard = PerCPUPageMappingGuard::create_4k(gpa)?; //? what if 2M?
    let start = guard.virt_addr();

    //TODO inline assembly with RMPQUERY

    Ok(())
}

fn attest_hash_single(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    log::warn!("entering attest_hash_single");
    let (page_size_bytes, valign) = match params.rdx & 3 {
        0 => (PAGE_SIZE, VIRT_ALIGN_4K),
        1 => (PAGE_SIZE_2M, VIRT_ALIGN_2M),
        _ => return Err(SvsmReqError::invalid_parameter()),
    };

    let res_addr = PhysAddr::from(params.r8);

    assert!(REPORT_REQUEST_SIZE < REPORT_RESPONSE_SIZE);
    let res_size = params.r9;
    if (res_size as usize) < ATTESTATION_SIZE {
        log::error!("not enough space for report");
        return Err(SvsmReqError::invalid_parameter());
    }

    let page_addr = PhysAddr::from(params.rcx);

    if !page_addr.is_aligned(page_size_bytes) {
        log::error!("page not aligned");
        return Err(SvsmReqError::invalid_parameter());
    }

    if !valid_phys_address(page_addr) {
        log::error!("page address not valid: {:?}", page_addr);
        return Err(SvsmReqError::invalid_address());
    }
    if !valid_phys_address(res_addr) {
        log::error!("result addr not valid: {:?}", res_addr);
        return Err(SvsmReqError::invalid_parameter());
    }

    log::info!("Received params:\n rcx: {}\n rdx: {}\n r8: {}\n r9: {}\n", page_addr, params.rdx, res_addr, res_size);
    
    let page_guard =
        PerCPUPageMappingGuard::create(page_addr, page_addr + page_size_bytes, valign)?;
    let page_vaddr = page_guard.virt_addr();
    // let guest_page = GuestPtr::<u8>::new(page_vaddr);

    let mut digest = HashDigest::new();
    let mut page_slice = unsafe { page_vaddr.to_slice::<u8>(page_size_bytes) };

    let hasher = HashState::hash_init();
    hasher.hash_update_slice(&mut page_slice)?;
    hasher.hash_finish(&mut digest)?;
    
    log::info!("Hashed page: {:?}", digest.digest);

    let mut exchange_buffer = [0u8; REPORT_RESPONSE_SIZE];
    
    if digest.size > USER_DATA_SIZE {
        return Err(SvsmReqError::invalid_parameter());
    }
    for index in 0..digest.size {
        exchange_buffer[index] = digest.digest[index];
    }

    let res_paddr = res_addr.page_align();
    let res_offset = res_addr.page_offset();
    
    // VMPL is supposed to be 0, KEY_SEL is supposed to be 0
    // Thus, after the report data, nothing needs to be set

    if let Ok(resp_len) = services::get_regular_report(&mut exchange_buffer) {
        let response: &SnpReportResponse = SnpReportResponse::try_from_as_ref(&exchange_buffer)?;
        let att_report = response.get_att_report();
        // get the whole page but only use the allocated buffer from the guest OS
        let res_guard =
            PerCPUPageMappingGuard::create(res_paddr, res_paddr + page_size_bytes, valign)?;
        let res_vaddr = res_guard.virt_addr();
        let res_ptr = GuestPtr::<AttestationReport>::new(res_vaddr.const_add(res_offset));
        res_ptr.write(att_report)?;
    } else {
        return Err(SvsmReqError::invalid_request());
    }

    Ok(())
}

fn attest_hash_range(params: &mut RequestParams) -> Result<(), SvsmError> {
    todo!()
}

pub fn check_kernel_protocol_request(
    request: u32,
    params: &mut RequestParams,
) -> Result<(), SvsmReqError> {
    match request {
        SVSM_CHECK_SINGLE => check_single(params),
        SVSM_HASH_SINGLE => attest_hash_single(params),
        _ => Err(SvsmReqError::unsupported_call()),
    }
}
