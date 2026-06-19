// SPDX-License-Identifier: GPL-2.0

//! Ioctl encoding and constants for bedrock device.

use std::mem::size_of;

use super::config::{EventConfig, SingleStepConfig};
use super::exit::VmExit;
use super::stats::ExitStats;
use crate::rdrand::RdrandConfig;
use crate::Regs;

/// Ioctl magic number ('B' for Bedrock).
const BEDROCK_IOC_MAGIC: u8 = b'B';

// Ioctl direction bits
pub(super) const IOC_WRITE: u64 = 1;
pub(super) const IOC_READ: u64 = 2;

// Ioctl encoding shifts
const IOC_NRSHIFT: u64 = 0;
const IOC_TYPESHIFT: u64 = 8;
const IOC_SIZESHIFT: u64 = 16;
const IOC_DIRSHIFT: u64 = 30;

/// Encode an ioctl number for reading data (_IOR).
const fn ioctl_ior(ty: u8, nr: u8, size: usize) -> u64 {
    ((IOC_READ) << IOC_DIRSHIFT)
        | ((ty as u64) << IOC_TYPESHIFT)
        | ((nr as u64) << IOC_NRSHIFT)
        | ((size as u64) << IOC_SIZESHIFT)
}

/// Encode an ioctl number for writing data (_IOW).
const fn ioctl_iow(ty: u8, nr: u8, size: usize) -> u64 {
    ((IOC_WRITE) << IOC_DIRSHIFT)
        | ((ty as u64) << IOC_TYPESHIFT)
        | ((nr as u64) << IOC_NRSHIFT)
        | ((size as u64) << IOC_SIZESHIFT)
}

/// Configuration passed to CREATE_ROOT_VM ioctl.
///
/// Userspace fills this out to configure the VM at creation time.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct CreateVmConfig {
    /// Size of guest memory to allocate in bytes.
    pub memory_size: u64,
    /// TSC frequency in Hz for deterministic time emulation.
    pub tsc_frequency: u64,
}

// Device ioctls (on /dev/bedrock)
// _IOW('B', 0, CreateVmConfig) - takes a configuration struct as argument
pub(crate) const BEDROCK_CREATE_ROOT_VM: u64 =
    ioctl_iow(BEDROCK_IOC_MAGIC, 0, size_of::<CreateVmConfig>());

// VM ioctls (on VM file descriptor)
pub(crate) const BEDROCK_VM_GET_REGS: u64 = ioctl_ior(BEDROCK_IOC_MAGIC, 1, size_of::<Regs>());
pub(crate) const BEDROCK_VM_SET_REGS: u64 = ioctl_iow(BEDROCK_IOC_MAGIC, 2, size_of::<Regs>());
pub(crate) const BEDROCK_VM_RUN: u64 = ioctl_ior(BEDROCK_IOC_MAGIC, 3, size_of::<VmExit>());
pub(crate) const BEDROCK_VM_SET_RDRAND_CONFIG: u64 =
    ioctl_iow(BEDROCK_IOC_MAGIC, 4, size_of::<RdrandConfig>());
pub(crate) const BEDROCK_VM_SET_RDRAND_VALUE: u64 =
    ioctl_iow(BEDROCK_IOC_MAGIC, 5, size_of::<u64>());
pub(crate) const BEDROCK_VM_SET_SINGLE_STEP: u64 =
    ioctl_iow(BEDROCK_IOC_MAGIC, 6, size_of::<SingleStepConfig>());
pub(crate) const BEDROCK_VM_GET_EXIT_STATS: u64 =
    ioctl_ior(BEDROCK_IOC_MAGIC, 7, size_of::<ExitStats>());
pub(crate) const BEDROCK_VM_SET_STOP_TSC: u64 = ioctl_iow(BEDROCK_IOC_MAGIC, 8, size_of::<u64>());
pub(crate) const BEDROCK_VM_GET_VM_ID: u64 = ioctl_ior(BEDROCK_IOC_MAGIC, 9, size_of::<u64>());
/// Unified event-stream configuration (enable + category mask + exit trigger).
pub(crate) const BEDROCK_VM_SET_EVENT_CONFIG: u64 =
    ioctl_iow(BEDROCK_IOC_MAGIC, 13, size_of::<EventConfig>());

/// Maximum bytes served per `HYPERCALL_GET_RANDOM`. Must stay in lockstep with
/// `bedrock_vmx::RANDOM_REPLY_MAX` — the kernel caps each request at this many
/// bytes and the guest loops for larger reads.
pub const RANDOM_REPLY_MAX: usize = 256;

/// The pending `HYPERCALL_GET_RANDOM` request, read by userspace after a
/// `VmcallGetRandom` exit so it knows how many bytes to serve and which process
/// asked.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct RandomRequest {
    /// PID (`current->tgid`) of the requesting process.
    pub pid: u32,
    /// Number of bytes requested (already capped at `RANDOM_REPLY_MAX`).
    pub len: u32,
}

/// Reply bytes staged by userspace to satisfy the pending `GET_RANDOM` request.
/// Inline buffer (like `IoActionPayload`) so the ABI is self-contained — no
/// guest-supplied pointer to `copy_from_user`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RandomBytes {
    /// Number of valid bytes in `data` (capped at `RANDOM_REPLY_MAX`).
    pub len: u32,
    /// Reserved for alignment.
    pub _reserved: u32,
    /// Reply bytes.
    pub data: [u8; RANDOM_REPLY_MAX],
}

impl Default for RandomBytes {
    fn default() -> Self {
        Self {
            len: 0,
            _reserved: 0,
            data: [0; RANDOM_REPLY_MAX],
        }
    }
}

// _IOR('B', 14, RandomRequest) - read the pending GET_RANDOM request (pid+len).
pub(crate) const BEDROCK_VM_GET_RANDOM_REQUEST: u64 =
    ioctl_ior(BEDROCK_IOC_MAGIC, 14, size_of::<RandomRequest>());

// _IOW('B', 15, RandomBytes) - stage the reply bytes for the pending request.
pub(crate) const BEDROCK_VM_SET_RANDOM_BYTES: u64 =
    ioctl_iow(BEDROCK_IOC_MAGIC, 15, size_of::<RandomBytes>());

// Device ioctls (on /dev/bedrock)
// _IOW('B', 1, u64) - takes parent VM ID as argument
pub(crate) const BEDROCK_CREATE_FORKED_VM: u64 = ioctl_iow(BEDROCK_IOC_MAGIC, 1, size_of::<u64>());

/// Request structure for getting feedback buffer info.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct FeedbackBufferInfoRequest {
    /// 0-based buffer index to query. The number of feedback buffers is
    /// unbounded; querying an unregistered index reports `registered = 0`.
    pub index: u32,
    /// Reserved for alignment.
    pub _reserved: u32,
}

// _IOR('B', 10, FeedbackBufferInfoRequest) - get feedback buffer registration info
pub(crate) const BEDROCK_VM_GET_FEEDBACK_BUFFER_INFO: u64 = ioctl_ior(
    BEDROCK_IOC_MAGIC,
    10,
    size_of::<FeedbackBufferInfoRequest>(),
);

/// Maximum size of an I/O channel request or response payload (one 4KB page).
pub const IO_CHANNEL_BUF_SIZE: usize = 4096;

/// I/O channel action payload exchanged with the kernel via ioctl.
///
/// Both `BEDROCK_VM_QUEUE_IO_ACTION` and `BEDROCK_VM_DRAIN_IO_RESPONSE`
/// use the same shape: a `u32 len` header (with reserved padding) followed
/// by up to `IO_CHANNEL_BUF_SIZE` bytes of data. Storing the whole buffer
/// inline keeps the userspace ABI self-contained — no extra pointer
/// indirection or kernel-side `copy_from_user` of a guest-supplied pointer.
///
/// Kernel-side handling stages the header through the stack (8 bytes) and
/// copies the data directly into / out of `VmState.io_channel.{request,response}_buf`,
/// avoiding a 4KB stack burst.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoActionPayload {
    /// For QUEUE: number of valid bytes the user supplies in `data`.
    /// For DRAIN: on input, the maximum capacity of `data`; on output, the
    /// actual number of response bytes the kernel wrote (capped at the
    /// input value).
    pub len: u32,
    /// Reserved for alignment.
    pub _reserved: u32,
    /// Earliest emulated-TSC value at which the queued request may fire
    /// (QUEUE only; ignored by DRAIN). Zero means "fire as soon as the
    /// guest is interruptible"; non-zero arms PEBS so the IRQ lands at
    /// the precise instruction count corresponding to this TSC.
    pub target_tsc: u64,
    /// Payload bytes.
    pub data: [u8; IO_CHANNEL_BUF_SIZE],
}

// SAFETY of the `Default` impl: `IoActionPayload` is plain old data with no
// invariants; an all-zero state means "empty payload, no data, no target".
impl Default for IoActionPayload {
    fn default() -> Self {
        Self {
            len: 0,
            _reserved: 0,
            target_tsc: 0,
            data: [0; IO_CHANNEL_BUF_SIZE],
        }
    }
}

// _IOW('B', 11, IoActionPayload) - queue an I/O channel request for the guest
pub(crate) const BEDROCK_VM_QUEUE_IO_ACTION: u64 =
    ioctl_iow(BEDROCK_IOC_MAGIC, 11, size_of::<IoActionPayload>());

// _IOR('B', 12, IoActionPayload) - drain the most recent I/O channel response
pub(crate) const BEDROCK_VM_DRAIN_IO_RESPONSE: u64 =
    ioctl_ior(BEDROCK_IOC_MAGIC, 12, size_of::<IoActionPayload>());

/// Maximum length of a feedback-buffer identifier. Must stay in lockstep with
/// `bedrock_vmx::FEEDBACK_BUFFER_ID_MAX_LEN` — the kernel module writes that
/// many bytes into the `id` field of [`FeedbackBufferInfo`].
pub const FEEDBACK_BUFFER_ID_MAX_LEN: usize = 128;

/// Feedback buffer info returned from kernel.
///
/// Describes a feedback buffer registered by the guest via the
/// `HYPERCALL_REGISTER_FEEDBACK_BUFFER` hypercall. Each registration carries
/// a byte-string identifier (e.g. the guest binary's build-id). IDs are
/// *not* required to be unique — see the docs on
/// `bedrock_vmx::FeedbackBufferInfo` for the rationale.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FeedbackBufferInfo {
    /// Original guest virtual address.
    pub gva: u64,
    /// Size in bytes.
    pub size: u64,
    /// Number of pages.
    pub num_pages: u64,
    /// Whether a feedback buffer is registered (0 = no, 1 = yes).
    pub registered: u32,
    /// 0-based slot index this entry occupies.
    pub index: u32,
    /// Length of the meaningful prefix of `id`, in bytes.
    pub id_len: u32,
    /// Reserved for alignment.
    pub _reserved: u32,
    /// Identifier bytes; trailing bytes past `id_len` are zero.
    pub id: [u8; FEEDBACK_BUFFER_ID_MAX_LEN],
}

impl Default for FeedbackBufferInfo {
    fn default() -> Self {
        Self {
            gva: 0,
            size: 0,
            num_pages: 0,
            registered: 0,
            index: 0,
            id_len: 0,
            _reserved: 0,
            id: [0u8; FEEDBACK_BUFFER_ID_MAX_LEN],
        }
    }
}

impl FeedbackBufferInfo {
    /// The identifier as a byte slice.
    pub fn id_bytes(&self) -> &[u8] {
        &self.id[..self.id_len as usize]
    }
}
