// SPDX-License-Identifier: GPL-2.0

//! File-transmission channel — the host half of the `HYPERCALL_FILE_FETCH` ABI.
//!
//! This is how the guest pulls workload files (its `compose.yaml` and
//! `images.tar`) from the host at boot. The guest registers one large feedback
//! buffer (1 MB) under
//! [`FILE_XFER_BUFFER_ID`] and then drives a chunked transfer:
//!
//! 1. The guest writes a request header into the start of the buffer
//!    (`offset`, `name_len`, then the file name) and issues
//!    `HYPERCALL_FILE_FETCH`, which exits to userspace as
//!    [`ExitKind::FileFetch`](crate::ExitKind::FileFetch).
//! 2. The host ([`FileServer::serve`]) reads the request out of the
//!    host-mapped buffer, reads up to `buffer_size - HEADER_LEN` bytes of the
//!    named file at `offset`, and overwrites the buffer with a response header
//!    (`result`) followed by the data.
//! 3. The guest reads `result` back out of the buffer, writes the bytes to its
//!    local file, advances `offset`, and loops until `result == 0` (EOF).
//!
//! The hypervisor treats the buffer as opaque — it only advances RIP and exits
//! to userspace — so this module is the single host-side definition of the
//! framing. Keep it in sync with `guest/file-fetch.c`.
//!
//! ## Determinism
//!
//! The bytes served are a pure function of the (fixed) host file, and the chunk
//! boundaries are fixed by the buffer size, so the transfer is fully
//! deterministic. It runs during the root VM's boot, before `HYPERCALL_READY`,
//! so forked VMs inherit the already-populated filesystem and never re-fetch.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::Vm;

/// Identifier the guest registers its file-transfer buffer under
/// (`HYPERCALL_REGISTER_FEEDBACK_BUFFER`). The host finds the buffer by this id.
pub const FILE_XFER_BUFFER_ID: &[u8] = b"bedrock-file-xfer";

/// Bytes reserved at the start of the shared buffer for the request/response
/// header. Data begins at this offset. The request header is
/// `u64 offset | u32 name_len | u32 reserved`; the response header is
/// `i64 result | u64 reserved`. Both are 16 bytes, and the file name (request)
/// and data (response) follow it — the host fully consumes the request before
/// writing the response, so the overlap is fine.
pub const FILE_XFER_HEADER_LEN: usize = 16;

/// Response `result` sentinel: the requested file is unknown or unreadable.
pub const FILE_XFER_RESULT_NOT_FOUND: i64 = -1;

/// Serves host files into a guest's file-transfer buffer on demand.
///
/// Construct it with the set of files to expose (the name the guest asks for
/// mapped to a host path), then call [`serve`](Self::serve) every time a
/// [`ExitKind::FileFetch`](crate::ExitKind::FileFetch) exit occurs. Open file
/// handles are cached across chunks so a multi-chunk transfer doesn't reopen
/// the file each time.
pub struct FileServer {
    files: HashMap<String, FileEntry>,
    /// Cached feedback-buffer slot the guest registered the transfer buffer
    /// under, resolved on first use (the registration happens during boot,
    /// before the first fetch).
    slot: Option<usize>,
}

struct FileEntry {
    path: PathBuf,
    /// Lazily opened on first request and kept open for subsequent chunks.
    handle: Option<File>,
}

impl FileServer {
    /// Build a server exposing `files` as `(guest_name, host_path)` pairs.
    pub fn new<I, S, P>(files: I) -> Self
    where
        I: IntoIterator<Item = (S, P)>,
        S: Into<String>,
        P: AsRef<Path>,
    {
        let files = files
            .into_iter()
            .map(|(name, path)| {
                (
                    name.into(),
                    FileEntry {
                        path: path.as_ref().to_path_buf(),
                        handle: None,
                    },
                )
            })
            .collect();
        Self { files, slot: None }
    }

    /// Whether any files are exposed. An empty server still answers fetches —
    /// every request is reported as not-found — which lets a caller wire the
    /// handler unconditionally.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// The guest names this server can satisfy.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.files.keys().map(String::as_str)
    }

    /// Serve one [`ExitKind::FileFetch`](crate::ExitKind::FileFetch): read the
    /// request framed in the guest's transfer buffer and overwrite it with the
    /// next chunk of the requested file.
    ///
    /// Returns the number of data bytes written (0 at EOF). A request for an
    /// unknown file writes the [`FILE_XFER_RESULT_NOT_FOUND`] sentinel into the
    /// buffer and returns `Ok(0)` — the guest decides whether that is fatal.
    ///
    /// # Errors
    ///
    /// Returns an error only for host-side failures that aren't expressible in
    /// the buffer (no buffer registered, mapping failure, or a read error on a
    /// file that *was* found). A missing file is not an error here.
    pub fn serve(&mut self, vm: &mut Vm) -> io::Result<usize> {
        let slot = self.resolve_slot(vm)?;

        // Ensure the buffer is mapped read-write so the response lands in the
        // guest's pages. Map it once; subsequent fetches reuse the mapping.
        if vm.feedback_buffer_mut_at(slot).is_none() {
            vm.map_feedback_buffer_mut_at(slot)?;
        }
        let buf = vm
            .feedback_buffer_mut_at(slot)
            .ok_or_else(|| io::Error::other("file-xfer buffer disappeared after mapping"))?;

        if buf.len() < FILE_XFER_HEADER_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "file-xfer buffer smaller than header",
            ));
        }

        // Parse the request header the guest wrote.
        let offset = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let name_len = u32::from_le_bytes(buf[8..12].try_into().unwrap()) as usize;
        let data_cap = buf.len() - FILE_XFER_HEADER_LEN;
        if FILE_XFER_HEADER_LEN + name_len > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("file-xfer request name_len {} overflows buffer", name_len),
            ));
        }
        let name =
            String::from_utf8_lossy(&buf[FILE_XFER_HEADER_LEN..FILE_XFER_HEADER_LEN + name_len])
                .into_owned();

        // Look up the file. Unknown name → not-found sentinel, not an error.
        let Some(entry) = self.files.get_mut(&name) else {
            write_result(buf, FILE_XFER_RESULT_NOT_FOUND);
            return Ok(0);
        };

        if entry.handle.is_none() {
            match File::open(&entry.path) {
                Ok(f) => entry.handle = Some(f),
                Err(_) => {
                    write_result(buf, FILE_XFER_RESULT_NOT_FOUND);
                    return Ok(0);
                }
            }
        }
        let file = entry.handle.as_mut().expect("handle opened above");

        file.seek(SeekFrom::Start(offset))?;
        let n = read_up_to(
            file,
            &mut buf[FILE_XFER_HEADER_LEN..FILE_XFER_HEADER_LEN + data_cap],
        )?;
        write_result(buf, n as i64);
        Ok(n)
    }

    /// Resolve (and cache) the feedback-buffer slot the guest registered the
    /// transfer buffer under.
    fn resolve_slot(&mut self, vm: &Vm) -> io::Result<usize> {
        if let Some(slot) = self.slot {
            return Ok(slot);
        }
        let slots = vm.feedback_buffer_slots_for_id(FILE_XFER_BUFFER_ID)?;
        let slot = slots.first().copied().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "guest issued HYPERCALL_FILE_FETCH but registered no bedrock-file-xfer buffer",
            )
        })?;
        self.slot = Some(slot);
        Ok(slot)
    }
}

/// Write the response `result` word into the buffer header and zero the rest of
/// the header.
fn write_result(buf: &mut [u8], result: i64) {
    buf[0..8].copy_from_slice(&result.to_le_bytes());
    buf[8..16].fill(0);
}

/// Read until `dst` is full or EOF, returning the number of bytes read. Unlike
/// `Read::read`, this keeps reading across short reads so a chunk is filled to
/// the buffer capacity whenever the file has that many bytes left — which keeps
/// the chunk boundaries (and therefore the transfer) deterministic.
fn read_up_to<R: Read>(r: &mut R, dst: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < dst.len() {
        match r.read(&mut dst[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}
