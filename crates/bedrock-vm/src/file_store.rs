// SPDX-License-Identifier: GPL-2.0

//! Host half of `HYPERCALL_FILE_STORE`: guest file chunks written to host files.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;

use crate::Vm;

/// Feedback-buffer id of the guest's file-store buffer.
pub const FILE_STORE_BUFFER_ID: &[u8] = b"bedrock-file-store";

/// Header size. Request: `u32 name_len | u32 chunk_len | u64 reserved`;
/// response: `i64 result | u64 reserved`. Matches
/// `VMCALL_FILE_STORE_HEADER_LEN` in guest/libvmcall.h.
pub const FILE_STORE_HEADER_LEN: usize = 16;

/// An error occurred while writing a chunk.
pub const FILE_STORE_IO_ERROR: i64 = -1;

/// Reads chunks of guest files and appends them to host files.
pub struct FileWriter {
    handles: HashMap<String, File>,
    slot: Option<usize>,
    base_dir: Option<PathBuf>,
}

impl Default for FileWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl FileWriter {
    pub fn new() -> Self {
        Self {
            handles: HashMap::new(),
            slot: None,
            base_dir: None,
        }
    }

    #[must_use]
    pub fn with_base_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.base_dir = Some(dir.into());
        self
    }

    /// Returns the bytes accepted, or 0 if the file name is disallowed.
    pub fn write(&mut self, vm: &mut Vm) -> io::Result<usize> {
        let slot = self.resolve_slot(vm)?;

        // Read-write so the response lands in the guest's pages.
        if vm.feedback_buffer_mut_at(slot).is_none() {
            vm.map_feedback_buffer_mut_at(slot)?;
        }
        let buf = vm
            .feedback_buffer_mut_at(slot)
            .ok_or_else(|| io::Error::other("file-store buffer disappeared after mapping"))?;

        if buf.len() < FILE_STORE_HEADER_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "file-store buffer smaller than header",
            ));
        }

        let name_len = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
        let chunk_len = u32::from_le_bytes(buf[4..8].try_into().unwrap()) as usize;

        let name_end = FILE_STORE_HEADER_LEN + name_len;
        let chunk_end = name_end + chunk_len;
        if chunk_end > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "file-store overflows buffer, name_len {}, chunk_len {}",
                    name_len, chunk_len
                ),
            ));
        }
        let name =
            String::from_utf8_lossy(&buf[FILE_STORE_HEADER_LEN..FILE_STORE_HEADER_LEN + name_len])
                .into_owned();

        // Truncate on the first chunk only.
        let base_dir = self.base_dir.clone();
        let file = match self.handles.entry(name) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => {
                let path = match &base_dir {
                    Some(dir) => {
                        std::fs::create_dir_all(dir)?;
                        dir.join(e.key())
                    }
                    None => PathBuf::from(e.key()),
                };
                let handle = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(path)?;
                e.insert(handle)
            }
        };

        match file.write_all(&buf[name_end..chunk_end]) {
            Ok(()) => {
                write_result(buf, chunk_len as i64);
                Ok(chunk_len)
            }
            Err(e) => {
                write_result(buf, FILE_STORE_IO_ERROR);
                Err(e)
            }
        }
    }

    fn resolve_slot(&mut self, vm: &Vm) -> io::Result<usize> {
        if let Some(slot) = self.slot {
            return Ok(slot);
        }
        let slots = vm.feedback_buffer_slots_for_id(FILE_STORE_BUFFER_ID)?;
        let slot = slots.first().copied().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "guest issued HYPERCALL_FILE_STORE but registered no bedrock-file-store buffer",
            )
        })?;
        self.slot = Some(slot);
        Ok(slot)
    }
}

/// Write the response header.
fn write_result(buf: &mut [u8], result: i64) {
    buf[0..8].copy_from_slice(&result.to_le_bytes());
    buf[8..16].fill(0);
}
