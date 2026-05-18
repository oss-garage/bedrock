// SPDX-License-Identifier: GPL-2.0

//! ELF kernel loading helpers.

use std::io;

use goblin::elf::Elf;

/// Load an x86-64 ELF kernel image into guest physical memory.
///
/// Copies every `PT_LOAD` segment to its `p_paddr`, zero-fills any BSS bytes
/// between `p_filesz` and `p_memsz`, and returns `(entry_point, kernel_end)`.
/// `kernel_end` is the highest guest physical address touched by a loadable
/// segment and can be passed to [`LinuxBootConfig::new`](super::LinuxBootConfig::new)
/// for initramfs placement.
pub fn load_kernel(memory: &mut [u8], kernel_data: &[u8]) -> io::Result<(u64, usize)> {
    let elf = Elf::parse(kernel_data).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("ELF parse error: {err}"),
        )
    })?;

    if elf.header.e_machine != goblin::elf::header::EM_X86_64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "kernel is not an x86_64 ELF file",
        ));
    }

    let mut kernel_end = 0;
    for phdr in elf
        .program_headers
        .iter()
        .filter(|phdr| phdr.p_type == goblin::elf::program_header::PT_LOAD)
    {
        let file_offset = phdr.p_offset as usize;
        let file_size = phdr.p_filesz as usize;
        let mem_size = phdr.p_memsz as usize;
        let load_addr = phdr.p_paddr as usize;
        let mem_end = load_addr.checked_add(mem_size).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "kernel segment address overflow",
            )
        })?;

        if mem_end > memory.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "kernel segment exceeds guest memory: {mem_end:#x} > {:#x}",
                    memory.len()
                ),
            ));
        }

        let file_end = file_offset.checked_add(file_size).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "kernel file offset overflow")
        })?;
        if file_end > kernel_data.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "kernel segment exceeds ELF file size",
            ));
        }

        memory[load_addr..load_addr + file_size]
            .copy_from_slice(&kernel_data[file_offset..file_end]);
        memory[load_addr + file_size..mem_end].fill(0);
        kernel_end = kernel_end.max(mem_end);
    }

    Ok((elf.entry, kernel_end))
}
