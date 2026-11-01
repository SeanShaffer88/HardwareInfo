//! Pure SMBIOS table parsing — no platform calls, so synthetic
//! tables are unit testable anywhere. The Windows side fetches the
//! raw table with GetSystemFirmwareTable('RSMB') and hands the
//! bytes here.
//!
//! Implemented structures (SMBIOS Reference Specification):
//! type 0 (BIOS), type 1 (System), type 2 (Baseboard), and
//! type 17 (Memory Device). Every formatted-field read is bounded
//! by the structure's declared length — newer fields (extended
//! size/speed, configured speed) only exist when the firmware's
//! structure is long enough to contain them, and a truncated or
//! malformed table stops the walk instead of guessing.

use crate::RamModule;

/// Board/system identity from SMBIOS types 0/1/2. Fields the
/// firmware didn't populate stay empty; the platform layer falls
/// back to the registry BIOS key for those.
#[derive(Debug, Default, Clone)]
pub struct SmbiosBoard {
    pub bios_vendor: String,
    pub bios_version: String,
    pub bios_date: String,
    pub system_manufacturer: String,
    pub system_product: String,
    pub system_version: String,
    pub system_serial: String,
    pub system_uuid: String,
    pub board_manufacturer: String,
    pub board_product: String,
    pub board_version: String,
    pub board_serial: String,
}

/// Unwrap the RawSMBIOSData header Windows prepends to the
/// 'RSMB' firmware table (Used20CallingMethod u8, major u8,
/// minor u8, DMI revision u8, table length u32, then the table).
/// A declared length longer than the buffer is clamped to what
/// was actually returned.
pub fn raw_smbios_table(buf: &[u8]) -> Option<&[u8]> {
    let header = buf.get(..8)?;
    let len = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
    let end = 8usize.saturating_add(len).min(buf.len());
    buf.get(8..end)
}

struct Structure<'a> {
    kind: u8,
    formatted: &'a [u8],
    strings: Vec<&'a [u8]>,
}

impl Structure<'_> {
    /// 1-based string-set lookup; index 0 and out-of-range indexes
    /// mean "not specified" per spec and yield an empty string.
    fn string(&self, index: u8) -> String {
        if index == 0 {
            return String::new();
        }
        match self.strings.get(index as usize - 1) {
            Some(bytes) => String::from_utf8_lossy(bytes).trim().to_string(),
            None => String::new(),
        }
    }

    fn byte(&self, off: usize) -> u8 {
        self.formatted.get(off).copied().unwrap_or(0)
    }

    fn word(&self, off: usize) -> u16 {
        match self.formatted.get(off..off + 2) {
            Some(b) => u16::from_le_bytes([b[0], b[1]]),
            None => 0,
        }
    }

    fn dword(&self, off: usize) -> u32 {
        match self.formatted.get(off..off + 4) {
            Some(b) => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            None => 0,
        }
    }
}

/// Walk the structure table: header (type u8, length u8, handle
/// u16), the formatted area, then the string set (NUL-terminated
/// strings closed by an extra NUL). Type 127 ends the table.
fn structures(table: &[u8]) -> Vec<Structure<'_>> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 4 <= table.len() {
        let kind = table[off];
        let slen = table[off + 1] as usize;
        if slen < 4 || off + slen > table.len() {
            break;
        }
        let formatted = &table[off..off + slen];
        let mut strings = Vec::new();
        let mut p = off + slen;
        while p < table.len() {
            match table[p..].iter().position(|&b| b == 0) {
                // An empty token is the string-set terminator.
                Some(0) => {
                    p += 1;
                    break;
                }
                Some(rel) => {
                    strings.push(&table[p..p + rel]);
                    p += rel + 1;
                }
                None => {
                    strings.push(&table[p..]);
                    p = table.len();
                }
            }
        }
        out.push(Structure {
            kind,
            formatted,
            strings,
        });
        if kind == 127 {
            break;
        }
        off = p;
    }
    out
}

fn width_bits(word: u16) -> u32 {
    // 0xFFFF means "unknown" for the width fields.
    if word == 0xFFFF {
        0
    } else {
        word as u32
    }
}

fn speed_mts(s: &Structure, word_off: usize, ext_off: usize) -> u32 {
    match s.word(word_off) {
        // 0xFFFF defers to the extended DWORD field (SMBIOS 3.3+)
        // when the structure is long enough to carry it.
        0xFFFF if s.formatted.len() >= ext_off + 4 => s.dword(ext_off),
        0xFFFF => 0,
        v => v as u32,
    }
}

fn memory_type_name(code: u8) -> String {
    let name = match code {
        0x01 => "Other",
        0x02 => "Unknown",
        0x03 => "DRAM",
        0x04 => "EDRAM",
        0x05 => "VRAM",
        0x06 => "SRAM",
        0x07 => "RAM",
        0x08 => "ROM",
        0x09 => "FLASH",
        0x0A => "EEPROM",
        0x0B => "FEPROM",
        0x0C => "EPROM",
        0x0D => "CDRAM",
        0x0E => "3DRAM",
        0x0F => "SDRAM",
        0x10 => "SGRAM",
        0x11 => "RDRAM",
        0x12 => "DDR",
        0x13 => "DDR2",
        0x14 => "DDR2 FB-DIMM",
        0x18 => "DDR3",
        0x19 => "FBD2",
        0x1A => "DDR4",
        0x1B => "LPDDR",
        0x1C => "LPDDR2",
        0x1D => "LPDDR3",
        0x1E => "LPDDR4",
        0x1F => "Logical non-volatile",
        0x20 => "HBM",
        0x21 => "HBM2",
        0x22 => "DDR5",
        0x23 => "LPDDR5",
        0x24 => "HBM3",
        0x25 => "MRAM",
        _ => return format!("unknown(0x{code:02X})"),
    };
    name.to_string()
}

fn form_factor_name(code: u8) -> String {
    let name = match code {
        0x01 => "Other",
        0x02 => "Unknown",
        0x03 => "SIMM",
        0x04 => "SIP",
        0x05 => "Chip",
        0x06 => "DIP",
        0x07 => "ZIP",
        0x08 => "Proprietary Card",
        0x09 => "DIMM",
        0x0A => "TSOP",
        0x0B => "Row of chips",
        0x0C => "RIMM",
        0x0D => "SODIMM",
        0x0E => "SRIMM",
        0x0F => "FB-DIMM",
        0x10 => "Die",
        _ => return format!("unknown(0x{code:02X})"),
    };
    name.to_string()
}

/// One type-17 (Memory Device) structure → one installed module.
/// Size 0 is an empty slot and is skipped; 0xFFFF (size unknown)
/// keeps the module with capacity 0 rather than hiding it.
fn memory_device(s: &Structure) -> Option<RamModule> {
    let size_word = s.word(0x0C);
    if size_word == 0 {
        return None;
    }
    let capacity_bytes = if size_word == 0x7FFF {
        // Extended Size (DWORD @0x1C): bits 30:0 are the size in MB.
        (s.dword(0x1C) & 0x7FFF_FFFF) as u64 * 1024 * 1024
    } else if size_word == 0xFFFF {
        0
    } else if size_word & 0x8000 != 0 {
        // Bit 15 set: value is in KB, not MB.
        (size_word & 0x7FFF) as u64 * 1024
    } else {
        size_word as u64 * 1024 * 1024
    };
    Some(RamModule {
        slot: s.string(s.byte(0x10)),
        bank: s.string(s.byte(0x11)),
        manufacturer: s.string(s.byte(0x17)),
        part_number: s.string(s.byte(0x1A)),
        serial: s.string(s.byte(0x18)),
        capacity_bytes,
        speed_mts: speed_mts(s, 0x15, 0x54),
        configured_speed_mts: speed_mts(s, 0x20, 0x58),
        memory_type: memory_type_name(s.byte(0x12)),
        form_factor: form_factor_name(s.byte(0x0E)),
        data_width_bits: width_bits(s.word(0x0A)),
        total_width_bits: width_bits(s.word(0x08)),
    })
}

/// Installed RAM modules from every type-17 structure in the
/// table, in firmware (slot) order.
pub fn parse_ram_modules(table: &[u8]) -> Vec<RamModule> {
    structures(table)
        .iter()
        .filter(|s| s.kind == 17)
        .filter_map(memory_device)
        .collect()
}

/// SMBIOS 2.6+ UUID text form: the first three fields are stored
/// little-endian. All-zero (not present) and all-0xFF (not
/// settable) read as empty.
fn format_uuid(bytes: &[u8]) -> String {
    let b = match bytes.get(..16) {
        Some(b) => b,
        None => return String::new(),
    };
    if b.iter().all(|&x| x == 0) || b.iter().all(|&x| x == 0xFF) {
        return String::new();
    }
    format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        u16::from_le_bytes([b[4], b[5]]),
        u16::from_le_bytes([b[6], b[7]]),
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    )
}

/// BIOS / system / baseboard identity from types 0, 1, and 2.
pub fn parse_board(table: &[u8]) -> SmbiosBoard {
    let mut out = SmbiosBoard::default();
    for s in structures(table) {
        match s.kind {
            0 => {
                out.bios_vendor = s.string(s.byte(0x04));
                out.bios_version = s.string(s.byte(0x05));
                out.bios_date = s.string(s.byte(0x08));
            }
            1 => {
                out.system_manufacturer = s.string(s.byte(0x04));
                out.system_product = s.string(s.byte(0x05));
                out.system_version = s.string(s.byte(0x06));
                out.system_serial = s.string(s.byte(0x07));
                if let Some(uuid) = s.formatted.get(0x08..) {
                    out.system_uuid = format_uuid(uuid);
                }
            }
            2 => {
                out.board_manufacturer = s.string(s.byte(0x04));
                out.board_product = s.string(s.byte(0x05));
                out.board_version = s.string(s.byte(0x06));
                out.board_serial = s.string(s.byte(0x07));
            }
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stamp a type/length header onto a formatted area and append
    /// its string set, SMBIOS-style.
    fn structure(kind: u8, mut formatted: Vec<u8>, strings: &[&str]) -> Vec<u8> {
        formatted[0] = kind;
        formatted[1] = formatted.len() as u8;
        let mut out = formatted;
        for s in strings {
            out.extend_from_slice(s.as_bytes());
            out.push(0);
        }
        out.push(0);
        out
    }

    fn word_at(buf: &mut [u8], off: usize, v: u16) {
        buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }

    fn dword_at(buf: &mut [u8], off: usize, v: u32) {
        buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    #[test]
    fn ram_modules_parse() {
        // 16 GB DDR5 SODIMM @5600 (configured 5200) + empty slot +
        // a 64 GB module via Extended Size.
        let mut f = vec![0u8; 0x28];
        word_at(&mut f, 0x08, 64); // total width
        word_at(&mut f, 0x0A, 64); // data width
        word_at(&mut f, 0x0C, 16384); // size, MB
        f[0x0E] = 0x0D; // SODIMM
        f[0x10] = 1; // slot string
        f[0x11] = 2; // bank string
        f[0x12] = 0x22; // DDR5
        word_at(&mut f, 0x15, 5600);
        f[0x17] = 3; // manufacturer
        f[0x18] = 4; // serial
        f[0x1A] = 5; // part number
        word_at(&mut f, 0x20, 5200); // configured speed
        let mut table = structure(
            17,
            f,
            &["SODIMM1", "BANK 0", "ACME", "SN-1", "ACME-DDR5-5600 "],
        );
        let empty = vec![0u8; 0x28]; // size 0 = no module installed
        table.extend(structure(17, empty, &["SODIMM2", "BANK 0"]));
        let mut big = vec![0u8; 0x28];
        word_at(&mut big, 0x0C, 0x7FFF); // defer to Extended Size
        dword_at(&mut big, 0x1C, 65536); // 65536 MB
        big[0x0E] = 0x09; // DIMM
        big[0x10] = 1;
        big[0x12] = 0x1A; // DDR4
        table.extend(structure(17, big, &["DIMM A1"]));
        table.extend(structure(127, vec![0u8; 4], &[]));

        let modules = parse_ram_modules(&table);
        assert_eq!(modules.len(), 2, "{modules:?}");
        let m = &modules[0];
        assert_eq!(m.slot, "SODIMM1");
        assert_eq!(m.bank, "BANK 0");
        assert_eq!(m.manufacturer, "ACME");
        assert_eq!(m.serial, "SN-1");
        assert_eq!(m.part_number, "ACME-DDR5-5600");
        assert_eq!(m.capacity_bytes, 16384 * 1024 * 1024);
        assert_eq!(m.speed_mts, 5600);
        assert_eq!(m.configured_speed_mts, 5200);
        assert_eq!(m.memory_type, "DDR5");
        assert_eq!(m.form_factor, "SODIMM");
        assert_eq!(m.data_width_bits, 64);
        assert_eq!(modules[1].capacity_bytes, 65536 * 1024 * 1024);
        assert_eq!(modules[1].memory_type, "DDR4");
    }

    #[test]
    fn ram_extended_speed_and_kb_granularity() {
        let mut f = vec![0u8; 0x5C];
        word_at(&mut f, 0x0C, 0x8000 | 512); // 512 KB
        word_at(&mut f, 0x15, 0xFFFF); // defer to Extended Speed
        dword_at(&mut f, 0x54, 6400);
        let table = structure(17, f, &[]);
        let modules = parse_ram_modules(&table);
        assert_eq!(modules.len(), 1, "{modules:?}");
        assert_eq!(modules[0].capacity_bytes, 512 * 1024);
        assert_eq!(modules[0].speed_mts, 6400);
        // A structure too short for the extended field reads 0,
        // never a neighboring structure's bytes.
        let mut short = vec![0u8; 0x15 + 2];
        word_at(&mut short, 0x0C, 1024);
        word_at(&mut short, 0x15, 0xFFFF);
        let modules = parse_ram_modules(&structure(17, short, &[]));
        assert_eq!(modules[0].speed_mts, 0);
    }

    #[test]
    fn board_parse() {
        let mut bios = vec![0u8; 0x12];
        bios[0x04] = 1;
        bios[0x05] = 2;
        bios[0x08] = 3;
        let mut table = structure(0, bios, &["ACME BIOS", "2.4.1", "03/04/2026"]);
        let mut sys = vec![0u8; 0x1B];
        sys[0x04] = 1;
        sys[0x05] = 2;
        sys[0x06] = 3;
        sys[0x07] = 4;
        sys[0x08..0x18].copy_from_slice(&[
            0x78, 0x56, 0x34, 0x12, 0xBC, 0x9A, 0xF0, 0xDE, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ]);
        table.extend(structure(
            1,
            sys,
            &["ACME", "RoadRunner 15", "Rev A", "SYS-42"],
        ));
        let mut board = vec![0u8; 0x0F];
        board[0x04] = 1;
        board[0x05] = 2;
        board[0x06] = 3;
        board[0x07] = 4;
        table.extend(structure(2, board, &["ACME", "RR-Board", "1.0", "BRD-7"]));
        let b = parse_board(&table);
        assert_eq!(b.bios_vendor, "ACME BIOS");
        assert_eq!(b.bios_version, "2.4.1");
        assert_eq!(b.bios_date, "03/04/2026");
        assert_eq!(b.system_manufacturer, "ACME");
        assert_eq!(b.system_product, "RoadRunner 15");
        assert_eq!(b.system_version, "Rev A");
        assert_eq!(b.system_serial, "SYS-42");
        assert_eq!(b.system_uuid, "12345678-9ABC-DEF0-1122-334455667788");
        assert_eq!(b.board_product, "RR-Board");
        assert_eq!(b.board_serial, "BRD-7");
    }

    #[test]
    fn raw_wrapper_and_garbage() {
        let table = structure(127, vec![0u8; 4], &[]);
        let mut raw = vec![1u8, 3, 5, 0];
        raw.extend_from_slice(&(table.len() as u32).to_le_bytes());
        raw.extend_from_slice(&table);
        assert_eq!(raw_smbios_table(&raw), Some(table.as_slice()));
        assert_eq!(raw_smbios_table(&raw[..4]), None);
        // Garbage never panics and yields no modules/board data.
        assert!(parse_ram_modules(&[0x11, 0x02, 0, 0, 1, 2, 3]).is_empty());
        assert!(parse_ram_modules(&[]).is_empty());
        assert_eq!(parse_board(&[17, 200, 0, 0]).bios_vendor, "");
    }
}
