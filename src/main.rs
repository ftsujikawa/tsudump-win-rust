use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::mem;
use std::convert::TryInto;
use std::collections::HashMap;
use clap::{Arg, Command};
use anyhow::{Result, Context};
use pdb::{PDB, SymbolData, FallibleIterator};
use capstone::{Capstone, Endian};
use capstone::arch::{BuildsCapstone, BuildsCapstoneEndian};
use capstone::arch::x86::ArchMode as X86Mode;
use capstone::arch::arm::ArchMode as ArmMode;

#[repr(C)]
#[derive(Debug)]
struct DosHeader {
    e_magic: u16,      // Magic number
    e_cblp: u16,       // Bytes on last page of file
    e_cp: u16,         // Pages in file
    e_crlc: u16,       // Relocations
    e_cparhdr: u16,    // Size of header in paragraphs
    e_minalloc: u16,   // Minimum extra paragraphs needed
    e_maxalloc: u16,   // Maximum extra paragraphs needed
    e_ss: u16,         // Initial relative SS value
    e_sp: u16,         // Initial SP value
    e_csum: u16,       // Checksum
    e_ip: u16,         // Initial IP value
    e_cs: u16,         // Initial relative CS value
    e_lfarlc: u16,     // File address of relocation table
    e_ovno: u16,       // Overlay number
    e_res: [u16; 4],   // Reserved words
    e_oemid: u16,      // OEM identifier (for e_oeminfo)
    e_oeminfo: u16,    // OEM information; e_oemid specific
    e_res2: [u16; 10], // Reserved words
    e_lfanew: u32,     // File address of new exe header
}

// PDBから行番号情報を抽出して一覧表示
fn dump_pdb_lines(pe_path: &str, pdb_path: &str, use_va: bool) -> Result<()> {
    // PEから image_base と セクションのRVA基点を取得
    let mut f = File::open(pe_path)
        .with_context(|| format!("ファイルを開けませんでした: {}", pe_path))?;

    let dos: DosHeader = read_struct(&mut f)?;
    if dos.e_magic != 0x5A4D { return Err(anyhow::anyhow!("DOSヘッダーが不正")); }
    f.seek(SeekFrom::Start(dos.e_lfanew as u64))?;

    let pe: PeHeader = read_struct(&mut f)?;
    if pe.signature != 0x00004550 { return Err(anyhow::anyhow!("PEシグネチャが不正")); }

    // OptionalHeaderを読み、image_baseを得る
    let magic: u16 = read_struct(&mut f)?;
    f.seek(SeekFrom::Current(-2))?;
    let image_base: u64;
    if magic == 0x010b {
        let opt: OptionalHeader32 = read_struct(&mut f)?;
        image_base = opt.image_base as u64;
        let read_size = std::mem::size_of::<OptionalHeader32>() as i64;
        let remaining = (pe.size_of_optional_header as i64) - read_size;
        if remaining > 0 { f.seek(SeekFrom::Current(remaining))?; }
    } else if magic == 0x020b {
        let opt: OptionalHeader64 = read_struct(&mut f)?;
        image_base = opt.image_base as u64;
        let read_size = std::mem::size_of::<OptionalHeader64>() as i64;
        let remaining = (pe.size_of_optional_header as i64) - read_size;
        if remaining > 0 { f.seek(SeekFrom::Current(remaining))?; }
    } else {
        return Err(anyhow::anyhow!(format!("未知のOptionalHeader Magic: 0x{:04X}", magic)));
    }

    // セクションヘッダーを読み、各セクション先頭RVAを保存
    let mut sections: Vec<SectionHeader> = Vec::with_capacity(pe.number_of_sections as usize);
    let mut section_rvas: Vec<u32> = Vec::with_capacity(pe.number_of_sections as usize);
    for _ in 0..pe.number_of_sections {
        let sh: SectionHeader = read_struct(&mut f)?;
        section_rvas.push(sh.virtual_address);
        sections.push(sh);
    }

    println!("\n=== PDB 行番号一覧 ===");
    println!("PDB: {}", pdb_path);

    let file = File::open(pdb_path)
        .with_context(|| format!("PDBを開けませんでした: {}", pdb_path))?;
    let mut pdb = PDB::open(file)?;

    // DBI: モジュール列挙
    if let Ok(dbi) = pdb.debug_information() {
        if let Ok(mut mods) = dbi.modules() {
            while let Ok(Some(m)) = mods.next() {
                let mod_name = m.module_name().to_string();
                let obj_name = m.object_file_name().to_string();
                // ModuleInfo を取得
                if let Ok(Some(mi)) = pdb.module_info(&m) {
                    if let Ok(lp) = mi.line_program() {
                        // ファイル一覧を収集（FileIndexはfiles()の列挙順インデックス）
                        let mut files_vec: Vec<String> = Vec::new();
                        let mut fit = lp.files();
                        while let Some(fi) = fit.next()? {
                            files_vec.push(fi.name.to_string());
                        }
                        // 行情報を列挙
                        let mut lit = lp.lines();
                        while let Some(li) = lit.next()? {
                            let sec = li.offset.section as usize;
                            let off = li.offset.offset as u64;
                            if sec == 0 || sec > section_rvas.len() { continue; }
                            let base = section_rvas[sec - 1] as u64;
                            let rva_start = base + off;
                            let rva_end = if let Some(len) = li.length { rva_start.saturating_add(len as u64) } else { rva_start };
                            let a_start = if use_va { image_base + rva_start } else { rva_start };
                            let a_end = if use_va { image_base + rva_end } else { rva_end };
                            let file_idx: u32 = li.file_index.into();
                            let file_path = files_vec.get(file_idx as usize).cloned().unwrap_or_else(|| String::from("<unknown>"));
                            // 表示
                            if use_va {
                                println!(
                                    "0x{:016X}-0x{:016X}  {}:{}-{}  [{}] ({})",
                                    a_start, a_end, file_path, li.line_start, li.line_end, mod_name, obj_name
                                );
                            } else {
                                println!(
                                    "0x{:08X}-0x{:08X}    {}:{}-{}  [{}] ({})",
                                    a_start as u32, a_end as u32, file_path, li.line_start, li.line_end, mod_name, obj_name
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

// PDBからシンボルを抽出して一覧表示
fn dump_pdb_symbols(pe_path: &str, pdb_path: &str, use_va: bool) -> Result<()> {
    // PEから image_base と セクションのRVA基点を取得
    let mut f = File::open(pe_path)
        .with_context(|| format!("ファイルを開けませんでした: {}", pe_path))?;

    let dos: DosHeader = read_struct(&mut f)?;
    if dos.e_magic != 0x5A4D { return Err(anyhow::anyhow!("DOSヘッダーが不正")); }
    f.seek(SeekFrom::Start(dos.e_lfanew as u64))?;

    let pe: PeHeader = read_struct(&mut f)?;
    if pe.signature != 0x00004550 { return Err(anyhow::anyhow!("PEシグネチャが不正")); }

    // OptionalHeaderを読み、image_baseを得る
    let magic: u16 = read_struct(&mut f)?;
    f.seek(SeekFrom::Current(-2))?;
    let image_base: u64;
    if magic == 0x010b {
        let opt: OptionalHeader32 = read_struct(&mut f)?;
        image_base = opt.image_base as u64;
        let read_size = std::mem::size_of::<OptionalHeader32>() as i64;
        let remaining = (pe.size_of_optional_header as i64) - read_size;
        if remaining > 0 { f.seek(SeekFrom::Current(remaining))?; }
    } else if magic == 0x020b {
        let opt: OptionalHeader64 = read_struct(&mut f)?;
        image_base = opt.image_base as u64;
        let read_size = std::mem::size_of::<OptionalHeader64>() as i64;
        let remaining = (pe.size_of_optional_header as i64) - read_size;
        if remaining > 0 { f.seek(SeekFrom::Current(remaining))?; }
    } else {
        return Err(anyhow::anyhow!(format!("未知のOptionalHeader Magic: 0x{:04X}", magic)));
    }

    // セクションヘッダーを読み、各セクション先頭RVAを保存
    let mut sections: Vec<SectionHeader> = Vec::with_capacity(pe.number_of_sections as usize);
    let mut section_rvas: Vec<u32> = Vec::with_capacity(pe.number_of_sections as usize);
    for _ in 0..pe.number_of_sections {
        let sh: SectionHeader = read_struct(&mut f)?;
        section_rvas.push(sh.virtual_address);
        sections.push(sh);
    }

    // セクション番号->セクション名のマップ（COFF由来）
    let section_name_map = build_section_name_map(pe_path, &pe)?;

    println!("\n=== PDB シンボル一覧 ===");
    println!("PDB: {}", pdb_path);

    let file = File::open(pdb_path)
        .with_context(|| format!("PDBを開けませんでした: {}", pdb_path))?;
    let mut pdb = PDB::open(file)?;

    // DBI: モジュール一覧とセクション寄与を取得して、section:offset -> module を解決する準備
    use std::collections::HashMap as StdHashMap;
    let mut module_names: Vec<String> = Vec::new();
    let mut contribs_by_sec: StdHashMap<u16, Vec<(u32, u32, usize)>> = StdHashMap::new();
    if let Ok(dbi) = pdb.debug_information() {
        if let Ok(mut mods) = dbi.modules() {
            while let Ok(Some(m)) = mods.next() {
                // object_file_name を優先（ライブラリ経由でもわかりやすい）
                module_names.push(m.object_file_name().to_string().into());
            }
        }
        if let Ok(mut scit) = dbi.section_contributions() {
            while let Ok(Some(sc)) = scit.next() {
                let sec = sc.offset.section;
                let start = sc.offset.offset;
                let end = start.saturating_add(sc.size);
                contribs_by_sec.entry(sec).or_default().push((start, end, sc.module));
            }
        }
        // ソートしておく（必要に応じて二分探索可能）
        for (_k, v) in contribs_by_sec.iter_mut() {
            v.sort_by_key(|e| e.0);
        }
    }

    // 収集: (addr, end, kind(FUNC/DATA), len, name, sec_no, sec_name, module)
    let mut entries: Vec<(u64, u64, &'static str, u32, String, u16, String, String)> = Vec::new();

    if let Ok(gs) = pdb.global_symbols() {
        let mut it = gs.iter();
        while let Ok(Some(sym)) = it.next() {
            match sym.parse() {
                Ok(SymbolData::Public(p)) => {
                    let sec = p.offset.section as usize;
                    let off = p.offset.offset as u64;
                    if sec >= 1 && sec <= section_rvas.len() {
                        let base = section_rvas[sec - 1] as u64;
                        let rva = base + off;
                        let addr_va = image_base + rva;
                        let addr_out = if use_va { addr_va } else { rva };
                        let sec_no = p.offset.section as u16;
                        let sec_name = section_name_map.get(&sec_no).cloned().unwrap_or_else(|| {
                            // ヘッダー名をフォールバック
                            let name_bytes = sections[sec - 1].name;
                            let end = name_bytes.iter().position(|&x| x == 0).unwrap_or(8);
                            std::str::from_utf8(&name_bytes[..end]).unwrap_or("").to_string()
                        });
                        // モジュール解決（Publicはlen=0のため点だが、属する寄与範囲があればそれを採用）
                        let mut module_name = String::new();
                        if let Some(list) = contribs_by_sec.get(&sec_no) {
                            let off32 = p.offset.offset;
                            for (s, e, mi) in list {
                                if off32 >= *s && off32 < *e {
                                    if let Some(name) = module_names.get(*mi) { module_name = name.clone(); }
                                    break;
                                }
                            }
                        }
                        // Public の種別: PDBのfunctionフラグ or 実行可能セクションで関数寄り
                        let is_exec_sec = (sections[sec - 1].characteristics & 0x2000_0000) != 0; // IMAGE_SCN_MEM_EXECUTE
                        let kind = if p.function || is_exec_sec { "FUNC" } else { "DATA" };
                        entries.push((addr_out, addr_out, kind, 0, p.name.to_string().into(), sec_no, sec_name, module_name));
                    }
                }
                Ok(SymbolData::Procedure(proc)) => {
                    let sec = proc.offset.section as usize;
                    let off = proc.offset.offset as u64;
                    if sec >= 1 && sec <= section_rvas.len() {
                        let base = section_rvas[sec - 1] as u64;
                        let rva = base + off;
                        let addr_va = image_base + rva;
                        let start_out = if use_va { addr_va } else { rva };
                        let end_out = start_out.saturating_add(proc.len as u64);
                        let sec_no = proc.offset.section as u16;
                        let sec_name = section_name_map.get(&sec_no).cloned().unwrap_or_else(|| {
                            let name_bytes = sections[sec - 1].name;
                            let end = name_bytes.iter().position(|&x| x == 0).unwrap_or(8);
                            std::str::from_utf8(&name_bytes[..end]).unwrap_or("").to_string()
                        });
                        // モジュール解決（セクション寄与に範囲が含まれるもの）
                        let mut module_name = String::new();
                        if let Some(list) = contribs_by_sec.get(&sec_no) {
                            let off32 = proc.offset.offset;
                            for (s, e, mi) in list {
                                if off32 >= *s && off32 < *e {
                                    if let Some(name) = module_names.get(*mi) { module_name = name.clone(); }
                                    break;
                                }
                            }
                        }
                        entries.push((start_out, end_out, "FUNC", proc.len, proc.name.to_string().into(), sec_no, sec_name, module_name));
                    }
                }
                _ => {}
            }
        }
    }

    // アドレス昇順で表示しつつ、関数レンジの重複を検出
    entries.sort_by_key(|e| e.0);

    // 重複検出のために直前のprocレンジを保持
    let mut last_proc_start: Option<u64> = None;
    let mut last_proc_end: Option<u64> = None;
    let mut last_proc_name: String = String::new();

    for (start, end, kind, len, name, sec_no, sec_name, module_name) in &entries {
        // 表示
        if use_va {
            if *start != *end {
                println!("0x{:016X}-0x{:016X}  {:4}  {:>6}  {}  [{}:{}] {}",
                    start, end, kind, len, name, sec_no, sec_name, module_name);
            } else {
                println!("0x{:016X}                  {:4}  {:>6}  {}  [{}:{}] {}",
                    start, kind, len, name, sec_no, sec_name, module_name);
            }
        } else {
            if *start != *end {
                println!("0x{:08X}-0x{:08X}    {:4}  {:>6}  {}  [{}:{}] {}",
                    *start as u32, *end as u32, kind, len, name, sec_no, sec_name, module_name);
            } else {
                println!("0x{:08X}                    {:4}  {:>6}  {}  [{}:{}] {}",
                    *start as u32, kind, len, name, sec_no, sec_name, module_name);
            }
        }

        // 重複検知（関数のみ）
        if *kind == "FUNC" {
            if let (Some(lp_s), Some(lp_e)) = (last_proc_start, last_proc_end) {
                if *start < lp_e {
                    // 重複
                    eprintln!(
                        "[overlap] 0x{:#X}-0x{:#X} '{}' overlaps with previous 0x{:#X}-0x{:#X} '{}'",
                        start, end, name, lp_s, lp_e, last_proc_name
                    );
                }
            }
            last_proc_start = Some(*start);
            last_proc_end = Some(*end);
            last_proc_name = name.clone();
        }
    }

    Ok(())
}

// .text セクションを逆アセンブル
fn disassemble_text(
    file_path: &str,
    pdb_path: Option<&str>,
    limit: Option<usize>,
    use_va: bool,
    force_thumb: bool,
    disasm_start: Option<u64>,
    disasm_base_text: bool,
) -> Result<()> {
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct DataDirectory {
        virtual_address: u32,
        size: u32,
    }

    fn rva_to_file_offset_and_max_read(rva: u64, sections: &[SectionHeader]) -> Option<(u64, u64)> {
        for sh in sections {
            let vstart = sh.virtual_address as u64;
            let vsize = if sh.virtual_size != 0 { sh.virtual_size as u64 } else { sh.size_of_raw_data as u64 };
            let vend = vstart.saturating_add(vsize);
            if rva >= vstart && rva < vend {
                let delta = rva - vstart;
                let raw_size = sh.size_of_raw_data as u64;
                if delta < raw_size {
                    let off = (sh.pointer_to_raw_data as u64).saturating_add(delta);
                    let max_read = raw_size - delta;
                    return Some((off, max_read));
                }
                return None;
            }
        }
        None
    }

    fn va_to_file_offset_and_max_read(va: u64, image_base: u64, use_va: bool, sections: &[SectionHeader]) -> Option<(u64, u64)> {
        let rva = if use_va { va.checked_sub(image_base)? } else { va };
        rva_to_file_offset_and_max_read(rva, sections)
    }

    fn find_section_by_name<'a>(sections: &'a [SectionHeader], name: &str) -> Option<&'a SectionHeader> {
        for sh in sections {
            let raw = &sh.name;
            let nul = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
            if let Ok(s) = std::str::from_utf8(&raw[..nul]) {
                if s == name {
                    return Some(sh);
                }
            }
        }
        None
    }

    fn read_u64_at_va(file: &File, va: u64, image_base: u64, use_va: bool, sections: &[SectionHeader]) -> Option<u64> {
        let (off, max_read) = va_to_file_offset_and_max_read(va, image_base, use_va, sections)?;
        if max_read < 8 {
            return None;
        }
        let mut f = file.try_clone().ok()?;
        let saved = f.stream_position().ok()?;
        if f.seek(SeekFrom::Start(off)).is_err() {
            return None;
        }
        let mut buf = [0u8; 8];
        if f.read_exact(&mut buf).is_err() {
            let _ = f.seek(SeekFrom::Start(saved));
            return None;
        }
        let _ = f.seek(SeekFrom::Start(saved));
        Some(u64::from_le_bytes(buf))
    }

    fn parse_rip_disp_u64(op: &str) -> Option<i64> {
        let s = op;
        let rip_pos = s.find("rip")?;
        let rest = &s[rip_pos + 3..];
        let plus = rest.find('+');
        let minus = rest.find('-');
        let (sign, idx) = match (plus, minus) {
            (Some(p), Some(m)) => if p < m { (1i64, p) } else { (-1i64, m) },
            (Some(p), None) => (1i64, p),
            (None, Some(m)) => (-1i64, m),
            (None, None) => return None,
        };
        let after = rest[idx + 1..].trim_start();

        // 0x... または 16進数列を抽出
        let bytes = after.as_bytes();
        let mut i = 0usize;
        while i < bytes.len() && (bytes[i] as char).is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            return None;
        }
        if i + 2 <= bytes.len() && bytes[i] == b'0' && (bytes[i + 1] == b'x' || bytes[i + 1] == b'X') {
            i += 2;
        }
        let mut digits = String::new();
        while i < bytes.len() {
            let c = bytes[i] as char;
            if c.is_ascii_hexdigit() {
                digits.push(c);
                i += 1;
                continue;
            }
            if c.is_ascii_whitespace() {
                i += 1;
                continue;
            }
            break;
        }
        if digits.is_empty() {
            return None;
        }
        let v = i64::from_str_radix(&digits, 16).ok()?;
        Some(sign * v)
    }

    fn parse_hex_u64(s: &str) -> Option<u64> {
        let s = s.trim();
        let s = s.strip_prefix("0x").unwrap_or(s);
        u64::from_str_radix(s, 16).ok()
    }

    fn read_cstring_at_file_offset(file: &File, off: u64) -> Option<String> {
        let mut f = file.try_clone().ok()?;
        let saved = f.stream_position().ok()?;
        if f.seek(SeekFrom::Start(off)).is_err() {
            return None;
        }
        let mut bytes: Vec<u8> = Vec::new();
        let mut buf = [0u8; 1];
        while bytes.len() < 4096 {
            if f.read_exact(&mut buf).is_err() {
                let _ = f.seek(SeekFrom::Start(saved));
                return None;
            }
            if buf[0] == 0 {
                break;
            }
            bytes.push(buf[0]);
        }
        let _ = f.seek(SeekFrom::Start(saved));
        String::from_utf8(bytes).ok()
    }

    fn read_u32_at_file_offset(file: &File, off: u64) -> Option<u32> {
        let mut f = file.try_clone().ok()?;
        let saved = f.stream_position().ok()?;
        if f.seek(SeekFrom::Start(off)).is_err() {
            return None;
        }
        let mut buf = [0u8; 4];
        if f.read_exact(&mut buf).is_err() {
            let _ = f.seek(SeekFrom::Start(saved));
            return None;
        }
        let _ = f.seek(SeekFrom::Start(saved));
        Some(u32::from_le_bytes(buf))
    }

    fn read_u64_at_file_offset(file: &File, off: u64) -> Option<u64> {
        let mut f = file.try_clone().ok()?;
        let saved = f.stream_position().ok()?;
        if f.seek(SeekFrom::Start(off)).is_err() {
            return None;
        }
        let mut buf = [0u8; 8];
        if f.read_exact(&mut buf).is_err() {
            let _ = f.seek(SeekFrom::Start(saved));
            return None;
        }
        let _ = f.seek(SeekFrom::Start(saved));
        Some(u64::from_le_bytes(buf))
    }

    let mut file = File::open(file_path)
        .with_context(|| format!("ファイルを開けませんでした: {}", file_path))?;

    let dos: DosHeader = read_struct(&mut file)?;
    if dos.e_magic != 0x5A4D { return Err(anyhow::anyhow!("DOSヘッダーが不正")); }
    file.seek(SeekFrom::Start(dos.e_lfanew as u64))?;

    let pe: PeHeader = read_struct(&mut file)?;
    if pe.signature != 0x00004550 { return Err(anyhow::anyhow!("PEシグネチャが不正")); }

    // OptionalHeaderのマジックを覗いて形式と残りスキップを決める
    let magic: u16 = read_struct(&mut file)?;
    file.seek(SeekFrom::Current(-2))?;

    let is_pe32_plus = magic == 0x020b; // 64bit
    let image_base: u64;
    let entry_point_rva: u32;
    let size_of_headers: u32;
    let exception_dir: Option<DataDirectory>;
    let import_dir: Option<DataDirectory>;
    if magic == 0x010b {
        let opt: OptionalHeader32 = read_struct(&mut file)?;
        image_base = opt.image_base as u64;
        entry_point_rva = opt.address_of_entry_point;
        size_of_headers = opt.size_of_headers;
        // DataDirectoryを読む
        let dd_count = opt.number_of_rva_and_sizes.min(16);
        let mut dds: Vec<DataDirectory> = Vec::with_capacity(dd_count as usize);
        for _ in 0..dd_count {
            dds.push(read_struct::<DataDirectory>(&mut file)?);
        }
        // 残りスキップ
        let read_size = std::mem::size_of::<OptionalHeader32>() as i64 + (dd_count as i64) * (std::mem::size_of::<DataDirectory>() as i64);
        let remaining = (pe.size_of_optional_header as i64) - read_size;
        if remaining > 0 { file.seek(SeekFrom::Current(remaining))?; }
        exception_dir = dds.get(3).copied();
        import_dir = dds.get(1).copied();
    } else if magic == 0x020b {
        let opt: OptionalHeader64 = read_struct(&mut file)?;
        image_base = opt.image_base as u64;
        entry_point_rva = opt.address_of_entry_point;
        size_of_headers = opt.size_of_headers;
        let dd_count = opt.number_of_rva_and_sizes.min(16);
        let mut dds: Vec<DataDirectory> = Vec::with_capacity(dd_count as usize);
        for _ in 0..dd_count {
            dds.push(read_struct::<DataDirectory>(&mut file)?);
        }
        let read_size = std::mem::size_of::<OptionalHeader64>() as i64 + (dd_count as i64) * (std::mem::size_of::<DataDirectory>() as i64);
        let remaining = (pe.size_of_optional_header as i64) - read_size;
        if remaining > 0 { file.seek(SeekFrom::Current(remaining))?; }
        exception_dir = dds.get(3).copied();
        import_dir = dds.get(1).copied();
    } else {
        return Err(anyhow::anyhow!(format!("未知のOptionalHeader Magic: 0x{:04X}", magic)));
    }

    // セクションヘッダーを収集しつつ、.text候補とEPを含むセクションを探す
    let mut text_hdr: Option<SectionHeader> = None;
    let mut ep_hdr: Option<SectionHeader> = None;
    let mut section_rvas: Vec<u32> = Vec::with_capacity(pe.number_of_sections as usize);
    let mut section_list: Vec<SectionHeader> = Vec::with_capacity(pe.number_of_sections as usize);
    for _ in 0..pe.number_of_sections {
        let sh: SectionHeader = read_struct(&mut file)?;
        section_rvas.push(sh.virtual_address);
        section_list.push(sh);
        let name_bytes = &sh.name;
        let end = name_bytes.iter().position(|&x| x == 0).unwrap_or(8);
        let name = std::str::from_utf8(&name_bytes[..end]).unwrap_or("");
        let is_code = (sh.characteristics & 0x00000020) != 0; // IMAGE_SCN_CNT_CODE
        if name == ".text" || (text_hdr.is_none() && is_code) {
            text_hdr = Some(sh);
        }
        let vstart = sh.virtual_address;
        let vsize = if sh.virtual_size != 0 { sh.virtual_size } else { sh.size_of_raw_data };
        let vend = vstart.saturating_add(vsize);
        if entry_point_rva >= vstart && entry_point_rva < vend {
            ep_hdr = Some(sh);
        }
    }

    // 逆アセンブル対象と開始RVAを決定
    // - disasm_start があればそれを最優先
    // - それ以外は disasm_base_text=true なら .text 先頭
    // - それ以外は EP 優先（EPがヘッダー領域ならヘッダー。なければ.text先頭）
    let mut target_sh: Option<SectionHeader> = None;
    let start_rva_in_image: u64;
    let mut in_headers = false;
    if let Some(a) = disasm_start {
        let rva = if use_va { a.saturating_sub(image_base) } else { a };
        if rva < (size_of_headers as u64) {
            in_headers = true;
            start_rva_in_image = rva;
        } else {
            for sh in &section_list {
                let vstart = sh.virtual_address as u64;
                let vsize = if sh.virtual_size != 0 { sh.virtual_size as u64 } else { sh.size_of_raw_data as u64 };
                let vend = vstart.saturating_add(vsize);
                if rva >= vstart && rva < vend {
                    target_sh = Some(*sh);
                    break;
                }
            }
            if target_sh.is_none() {
                return Err(anyhow::anyhow!("指定した開始アドレスがセクションにもヘッダーにも属しません"));
            }
            start_rva_in_image = rva;
        }
    } else if disasm_base_text {
        if let Some(h) = text_hdr {
            target_sh = Some(h);
            start_rva_in_image = h.virtual_address as u64;
        } else {
            return Err(anyhow::anyhow!("コードセクションが見つかりません"));
        }
    } else if let Some(h) = ep_hdr {
        target_sh = Some(h);
        start_rva_in_image = entry_point_rva as u64;
    } else if entry_point_rva != 0 && (entry_point_rva as u64) < (size_of_headers as u64) {
        in_headers = true;
        start_rva_in_image = entry_point_rva as u64;
    } else if let Some(h) = text_hdr {
        target_sh = Some(h);
        start_rva_in_image = h.virtual_address as u64;
    } else {
        return Err(anyhow::anyhow!("コードセクションが見つかりません"));
    }

    // 逆アセンブル対象の生データを読み出し（セクション or ヘッダー領域）
    let file_start: u64;
    let read_len: usize;
    if in_headers {
        let max_len = size_of_headers as u64;
        if start_rva_in_image >= max_len {
            return Err(anyhow::anyhow!("エントリポイントがヘッダーの範囲外です"));
        }
        file_start = start_rva_in_image;
        read_len = (max_len - start_rva_in_image) as usize;
    } else {
        let target_sh = target_sh.ok_or_else(|| anyhow::anyhow!("コードセクションが見つかりません"))?;
        if target_sh.pointer_to_raw_data == 0 || target_sh.size_of_raw_data == 0 {
            return Err(anyhow::anyhow!(".text のRawデータがありません"));
        }
        // セクション内オフセットを計算してEP位置から読み出す
        let start_offset_in_section = (start_rva_in_image as i64 - target_sh.virtual_address as i64).max(0) as u64;
        let max_len = target_sh.size_of_raw_data as u64;
        if start_offset_in_section >= max_len {
            return Err(anyhow::anyhow!("エントリポイントがセクションの範囲外です"));
        }
        file_start = (target_sh.pointer_to_raw_data as u64).saturating_add(start_offset_in_section);
        read_len = (max_len - start_offset_in_section) as usize;
    }

    println!("\n[disasm] ImageBase=0x{:X} EntryPointRVA=0x{:X} SizeOfHeaders=0x{:X} use_va={} thumb={} in_headers={} file_start=0x{:X} read_len=0x{:X}",
        image_base,
        entry_point_rva,
        size_of_headers,
        use_va,
        force_thumb,
        in_headers,
        file_start,
        read_len
    );
    if let Some(sh) = target_sh {
        let name_bytes = &sh.name;
        let end = name_bytes.iter().position(|&x| x == 0).unwrap_or(8);
        let name = std::str::from_utf8(&name_bytes[..end]).unwrap_or("");
        println!("[disasm] section='{}' VA=0x{:X} VSZ=0x{:X} RawSize=0x{:X} RawPtr=0x{:X}",
            name,
            sh.virtual_address,
            sh.virtual_size,
            sh.size_of_raw_data,
            sh.pointer_to_raw_data
        );
    }
    file.seek(SeekFrom::Start(file_start))?;
    let mut code: Vec<u8> = vec![0u8; read_len];
    file.read_exact(&mut code)?;

    // Capstone 準備（x86/x64/ARM/ARM64対応）
    let mut is_thumb_mode = false;
    let cs = match (pe.machine, is_pe32_plus) {
        (0x014c, false) => {
            // x86 32bit (LE固定)
            Capstone::new().x86().mode(X86Mode::Mode32).build()?
        }
        (0x8664, true) => {
            // x86_64 (LE固定)
            Capstone::new().x86().mode(X86Mode::Mode64).build()?
        }
        (0x01C4, false) | (0x01C2, false) | (0x01C0, false) => {
            // ARM/Thumb/ARMNT
            let mode = if force_thumb { ArmMode::Thumb } else { ArmMode::Arm };
            is_thumb_mode = force_thumb;
            Capstone::new().arm().mode(mode).endian(Endian::Little).build()?
        }
        (0xAA64, true) => {
            // ARM64
            Capstone::new().arm64().build()?
        }
        (m, _) => {
            println!("現状未対応のMachine: 0x{:04X}。x86/x64/ARM/ARM64に対応しています。", m);
            return Ok(());
        }
    };

    // PDBの公開/関数シンボルから アドレス→名前 のマップを構築（任意）
    use std::collections::BTreeMap;
    let mut labels: BTreeMap<u64, String> = BTreeMap::new();
    if let Some(ppath) = pdb_path {
        if let Ok(file) = File::open(ppath) {
            if let Ok(mut pdb) = PDB::open(file) {
                if let Ok(gs) = pdb.global_symbols() {
                    let mut it = gs.iter();
                    while let Ok(Some(sym)) = it.next() {
                        match sym.parse() {
                            Ok(SymbolData::Public(p)) => {
                                // PdbInternalSectionOffset { section, offset }
                                let sec = p.offset.section as usize;
                                let off = p.offset.offset as u64;
                                if sec >= 1 && sec <= section_rvas.len() {
                                    let base = section_rvas[sec - 1] as u64;
                                    let rva = base + off;
                                    let key = if use_va { image_base + rva } else { rva };
                                    labels.entry(key).or_insert_with(|| p.name.to_string().into());
                                    if is_thumb_mode {
                                        labels.entry(key | 1).or_insert_with(|| p.name.to_string().into());
                                    }
                                }
                            }
                            Ok(SymbolData::Procedure(proc)) => {
                                let sec = proc.offset.section as usize;
                                let off = proc.offset.offset as u64;
                                if sec >= 1 && sec <= section_rvas.len() {
                                    let base = section_rvas[sec - 1] as u64;
                                    let rva = base + off;
                                    let key = if use_va { image_base + rva } else { rva };
                                    labels.entry(key).or_insert_with(|| proc.name.to_string().into());
                                    if is_thumb_mode {
                                        labels.entry(key | 1).or_insert_with(|| proc.name.to_string().into());
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    // Import Directory から IAT(VA) -> "dll!func" を構築（間接callの解決用）
    let mut iat_names: BTreeMap<u64, String> = BTreeMap::new();
    if is_pe32_plus {
        if let Some(dd) = import_dir {
            if dd.virtual_address != 0 {
                let imp_rva = dd.virtual_address as u64;
                if let Some((imp_off, _max_read)) = rva_to_file_offset_and_max_read(imp_rva, &section_list) {
                    // IMAGE_IMPORT_DESCRIPTOR (20 bytes)
                    let mut idx = 0u64;
                    loop {
                        let base = imp_off.saturating_add(idx.saturating_mul(20));
                        let original_first_thunk = match read_u32_at_file_offset(&file, base) {
                            Some(v) => v as u64,
                            None => break,
                        };
                        let name_rva = match read_u32_at_file_offset(&file, base + 12) {
                            Some(v) => v as u64,
                            None => break,
                        };
                        let first_thunk = match read_u32_at_file_offset(&file, base + 16) {
                            Some(v) => v as u64,
                            None => break,
                        };
                        if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
                            break;
                        }

                        let dll_name = if name_rva != 0 {
                            rva_to_file_offset_and_max_read(name_rva, &section_list)
                                .and_then(|(o, _)| read_cstring_at_file_offset(&file, o))
                                .unwrap_or_else(|| String::from("<dll>"))
                        } else {
                            String::from("<dll>")
                        };

                        let ilt_rva = if original_first_thunk != 0 { original_first_thunk } else { first_thunk };
                        let mut t = 0u64;
                        loop {
                            let thunk_rva = ilt_rva.saturating_add(t.saturating_mul(8));
                            let iat_rva = first_thunk.saturating_add(t.saturating_mul(8));
                            let thunk_off = match rva_to_file_offset_and_max_read(thunk_rva, &section_list) {
                                Some((o, mr)) if mr >= 8 => o,
                                _ => break,
                            };

                            let val = match read_u64_at_file_offset(&file, thunk_off) {
                                Some(v) => v,
                                None => break,
                            };
                            if val == 0 { break; }

                            // IMAGE_ORDINAL_FLAG64
                            if (val & 0x8000_0000_0000_0000) == 0 {
                                let ibn_rva = val as u64;
                                if let Some((ibn_off, mr)) = rva_to_file_offset_and_max_read(ibn_rva, &section_list) {
                                    if mr >= 3 {
                                        // hint(u16) + name
                                        if let Some(func) = read_cstring_at_file_offset(&file, ibn_off + 2) {
                                            let iat_va = if use_va { image_base + iat_rva } else { iat_rva };
                                            iat_names.insert(iat_va, format!("{}!{}", dll_name, func));
                                        }
                                    }
                                }
                            }

                            t += 1;
                        }

                        idx += 1;
                    }
                }
            }
        }
    }

    // .pdata から RUNTIME_FUNCTION 範囲を構築（x64向け）
    let mut runtime_funcs: Vec<(u64, u64)> = Vec::new();
    if is_pe32_plus {
        // まずはException Directoryから（存在すれば）
        if let Some(dd) = exception_dir {
            if dd.virtual_address != 0 && dd.size >= 12 {
                let pdata_rva = dd.virtual_address as u64;
                let pdata_size = dd.size as u64;
                if let Some((pdata_off, max_read)) = rva_to_file_offset_and_max_read(pdata_rva, &section_list) {
                    let read_len = pdata_size.min(max_read);
                    if read_len >= 12 && read_len <= (usize::MAX as u64) {
                        let saved = file.stream_position()?;
                        file.seek(SeekFrom::Start(pdata_off))?;
                        let mut buf = vec![0u8; read_len as usize];
                        if file.read_exact(&mut buf).is_ok() {
                            let mut i = 0usize;
                            while i + 12 <= buf.len() {
                                let begin = u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]) as u64;
                                let end = u32::from_le_bytes([buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7]]) as u64;
                                if begin != 0 && end > begin {
                                    let b = if use_va { image_base + begin } else { begin };
                                    let e = if use_va { image_base + end } else { end };
                                    runtime_funcs.push((b, e));
                                }
                                i += 12;
                            }
                        }
                        file.seek(SeekFrom::Start(saved))?;
                    }
                }
            }
        }

        // フォールバック: .pdata セクションの生データ全体も読む（Exception Directoryが不完全な場合の救済）
        if let Some(pdata_sec) = find_section_by_name(&section_list, ".pdata") {
            if pdata_sec.size_of_raw_data as u64 >= 12 {
                let pdata_off = pdata_sec.pointer_to_raw_data as u64;
                let read_len = pdata_sec.size_of_raw_data as u64;
                if read_len <= (usize::MAX as u64) {
                    let saved = file.stream_position()?;
                    file.seek(SeekFrom::Start(pdata_off))?;
                    let mut buf = vec![0u8; read_len as usize];
                    if file.read_exact(&mut buf).is_ok() {
                        let mut i = 0usize;
                        while i + 12 <= buf.len() {
                            let begin = u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]) as u64;
                            let end = u32::from_le_bytes([buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7]]) as u64;
                            if begin != 0 && end > begin {
                                let b = if use_va { image_base + begin } else { begin };
                                let e = if use_va { image_base + end } else { end };
                                runtime_funcs.push((b, e));
                            }
                            i += 12;
                        }
                    }
                    file.seek(SeekFrom::Start(saved))?;
                }
            }
        }

        runtime_funcs.sort_by_key(|e| e.0);
        runtime_funcs.dedup();
    }

    if disasm_start.is_some() {
        println!("\n=== 逆アセンブル (指定アドレス起点) ===");
    } else if disasm_base_text {
        println!("\n=== 逆アセンブル (.text起点) ===");
    } else {
        println!("\n=== 逆アセンブル (EntryPoint起点) ===");
    }
    let mut start_addr = if use_va { image_base + start_rva_in_image } else { start_rva_in_image };
    if is_thumb_mode {
        start_addr |= 1;
    }

    // x86/x64: エントリポイントがjmpスタブの場合、ジャンプ先へ追従（範囲内のみ）
    let mut code_start_offset: usize = 0;
    if (pe.machine == 0x014c || pe.machine == 0x8664) && !in_headers {
        if let Ok(first) = cs.disasm_count(&code, start_addr, 1) {
            if let Some(i0) = first.iter().next() {
                if i0.mnemonic() == Some("jmp") {
                    if let Some(op) = i0.op_str() {
                        if let Some(jmp_target_addr) = parse_hex_u64(op) {
                            // Capstoneが返すオペランドは、ここではVA/RVA表示モードに従ったアドレス値のはず
                            let jmp_target_rva = if use_va {
                                jmp_target_addr.saturating_sub(image_base)
                            } else {
                                jmp_target_addr
                            };
                            if jmp_target_rva >= start_rva_in_image {
                                let delta = (jmp_target_rva - start_rva_in_image) as usize;
                                if delta < code.len() {
                                    code_start_offset = delta;
                                    start_addr = if use_va { image_base + jmp_target_rva } else { jmp_target_rva };
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let code_view = &code[code_start_offset..];
    let insns = if let Some(n) = limit { cs.disasm_count(code_view, start_addr, n)? } else { cs.disasm_all(code_view, start_addr)? };
    for i in insns.iter() {
        let mut op = i.op_str().unwrap_or("").to_string();
        let addr = i.address();
        let sym = labels.range(..=addr).next_back();
        let addr_str = if use_va {
            if is_pe32_plus {
                if let Some((sym_addr, name)) = sym {
                    let off = addr.saturating_sub(*sym_addr);
                    if off == 0 { format!("0x{:016X} <{}>", addr, name) }
                    else { format!("0x{:016X} <{}+0x{:X}>", addr, name, off) }
                } else {
                    format!("0x{:016X}", addr)
                }
            } else {
                if let Some((sym_addr, name)) = sym {
                    let off = addr.saturating_sub(*sym_addr);
                    if off == 0 { format!("0x{:08X} <{}>", addr as u32, name) }
                    else { format!("0x{:08X} <{}+0x{:X}>", addr as u32, name, off) }
                } else {
                    format!("0x{:08X}", addr as u32)
                }
            }
        } else {
            // RVAは32bit幅で表示
            if let Some((sym_addr, name)) = sym {
                let off = addr.saturating_sub(*sym_addr);
                if off == 0 { format!("0x{:08X} <{}>", addr as u32, name) }
                else { format!("0x{:08X} <{}+0x{:X}>", addr as u32, name, off) }
            } else {
                format!("0x{:08X}", addr as u32)
            }
        };

        fn parse_first_hex_u64(s: &str) -> Option<u64> {
            let bytes = s.as_bytes();
            let mut i = 0usize;
            while i + 2 <= bytes.len() {
                if bytes[i] == b'0' && (bytes[i + 1] == b'x' || bytes[i + 1] == b'X') {
                    let mut j = i + 2;
                    let mut digits = String::new();
                    while j < bytes.len() {
                        let c = bytes[j] as char;
                        if c.is_ascii_whitespace() {
                            j += 1;
                            continue;
                        }
                        if c.is_ascii_hexdigit() {
                            digits.push(c);
                            j += 1;
                            continue;
                        }
                        break;
                    }
                    if !digits.is_empty() {
                        if let Ok(v) = u64::from_str_radix(&digits, 16) {
                            return Some(v);
                        }
                    }
                }
                i += 1;
            }

            // 0x... が無い場合の救済: 十分長い16進数列(例: 1400010c0)を拾う
            let mut best: Option<String> = None;
            let mut run = String::new();
            for c in s.chars() {
                if c.is_ascii_hexdigit() {
                    run.push(c);
                } else {
                    if run.len() >= 8 {
                        best = Some(run.clone());
                        break;
                    }
                    run.clear();
                }
            }
            if best.is_none() && run.len() >= 8 {
                best = Some(run);
            }
            if let Some(d) = best {
                return u64::from_str_radix(&d, 16).ok();
            }

            None
        }

        fn find_containing_range(ranges: &[(u64, u64)], addr: u64) -> Option<(u64, u64)> {
            let mut lo = 0usize;
            let mut hi = ranges.len();
            while lo < hi {
                let mid = (lo + hi) / 2;
                if ranges[mid].0 <= addr { lo = mid + 1; } else { hi = mid; }
            }
            if lo == 0 { return None; }
            let (start, end) = ranges[lo - 1];
            if addr >= start && addr < end { Some((start, end)) } else { None }
        }

        fn resolve_func_label_in_range(
            labels: &BTreeMap<u64, String>,
            range_start: u64,
            range_end: u64,
            target: u64,
        ) -> Option<(u64, &str)> {
            if target < range_start {
                return None;
            }

            // まずは「範囲内で target 以下の直前ラベル」を採用（関数先頭のPublic/Procedureがあるケースが多い）
            if let Some((addr, name)) = labels.range(range_start..=target).next_back() {
                if *addr < range_end {
                    return Some((*addr, name.as_str()));
                }
            }

            // それも無ければ、範囲内の先頭ラベル
            labels
                .range(range_start..range_end)
                .next()
                .map(|(addr, name)| (*addr, name.as_str()))
        }

        fn is_jcc(m: &str) -> bool {
            matches!(
                m,
                "je" | "jne" | "jz" | "jnz" | "ja" | "jae" | "jb" | "jbe" | "jg" | "jge" | "jl" | "jle" | "js" | "jns" | "jo" | "jno" | "jp" | "jnp" | "jc" | "jnc" | "jcxz" | "jecxz" | "jrcxz"
            )
        }

        let mnem = i.mnemonic().unwrap_or("");
        if mnem == "call" || mnem == "jmp" || is_jcc(mnem) {
            // call/jmp/jcc qword ptr [rip + 0x....] のような間接分岐は、0x... がdisplacementであり
            // 分岐先アドレスではないため、即値パースを行わない。
            let mut resolved_target: Option<u64> = if op.contains("[rip") {
                None
            } else {
                parse_first_hex_u64(&op)
            };
            let mut indirect_mem_va: Option<u64> = None;
            if resolved_target.is_none() {
                // call/jmp/jcc qword ptr [rip +/- disp] の場合、IAT等のポインタを読んで解決
                if op.contains("[rip") {
                    if let Some(disp) = parse_rip_disp_u64(&op) {
                        let insn_size = i.bytes().len() as u64;
                        if insn_size != 0 {
                            let rip = i.address().wrapping_add(insn_size);
                            let mem_va = if disp >= 0 {
                                rip.wrapping_add(disp as u64)
                            } else {
                                rip.wrapping_sub((-disp) as u64)
                            };
                            indirect_mem_va = Some(mem_va);
                            if let Some(ptr) = read_u64_at_va(&file, mem_va, image_base, use_va, &section_list) {
                                // ptr が実関数アドレスとして .pdata 範囲に入る場合だけ採用。
                                // ファイル上のIATは IMAGE_IMPORT_BY_NAME へのRVA などになりがちで、
                                // それをターゲット扱いすると誤判定で表示が出なくなる。
                                if ptr != 0 {
                                    if find_containing_range(&runtime_funcs, ptr).is_some() {
                                        resolved_target = Some(ptr);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if let Some(target_addr) = resolved_target {
                if let Some((rstart, _rend)) = find_containing_range(&runtime_funcs, target_addr) {
                    if let Some((sym_addr, name)) = resolve_func_label_in_range(&labels, rstart, _rend, target_addr) {
                        let off = target_addr.saturating_sub(sym_addr);
                        if off == 0 { op = format!("{} <{}>", op, name); }
                        else { op = format!("{} <{}+0x{:X}>", op, name, off); }
                    } else {
                        op = format!("{} <0x{:X}>", op, target_addr);
                    }
                } else if let Some(name) = labels.get(&target_addr) {
                    op = format!("{} <{}>", op, name);
                } else if let Some((sym_addr, name)) = labels.range(..=target_addr).next_back() {
                    let off = target_addr.saturating_sub(*sym_addr);
                    if off == 0 { op = format!("{} <{}>", op, name); }
                    else { op = format!("{} <{}+0x{:X}>", op, name, off); }
                } else {
                    op = format!("{} <0x{:X}>", op, target_addr);
                }
            } else if let Some(mem_va) = indirect_mem_va {
                // IAT等: ファイル上ではポインタ値が0で解決できないことがある。
                // その場合でも __imp_... のようなラベルがあれば表示する。
                if let Some(name) = labels.get(&mem_va) {
                    op = format!("{} <{}>", op, name);
                } else if let Some(name) = iat_names.get(&mem_va) {
                    op = format!("{} <{}>", op, name);
                } else {
                    op = format!("{} <0x{:X}>", op, mem_va);
                }
            }
        }

        println!("{}:  {:7} {}", addr_str, i.mnemonic().unwrap_or(""), op);
    }

    Ok(())
}

// PDBの概要と公開シンボルを表示
fn display_pdb_info(pdb_path: &str) -> Result<()> {
    println!("\n=== PDB 情報 ===");
    println!("PDB: {}", pdb_path);

    let file = File::open(pdb_path)
        .with_context(|| format!("PDBを開けませんでした: {}", pdb_path))?;
    let mut pdb = PDB::open(file)?;

    if let Ok(pi) = pdb.pdb_information() {
        println!("Age: {}", pi.age);
        let sig = pi.guid;
        println!("GUID: {}", sig);
    }

    // モジュール一覧（先頭10件）
    if let Ok(dbi) = pdb.debug_information() {
        if let Ok(mut mods) = dbi.modules() {
            println!("モジュール(全件):");
            loop {
                match mods.next() {
                    Ok(Some(m)) => {
                        let name = m.module_name().to_string();
                        let obj = m.object_file_name().to_string();
                        println!("  - {} ({})", name, obj);
                    }
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
        }
    }

    // 公開シンボル（先頭20件）
    if let Ok(gs) = pdb.global_symbols() {
        let mut it = gs.iter();
        println!("公開シンボル(全件):");
        loop {
            match it.next() {
                Ok(Some(sym)) => {
                    if let Ok(SymbolData::Public(p)) = sym.parse() {
                        let name = p.name.to_string();
                        println!(
                            "  - {:<50} Off={:?} code={} func={} managed={} msil={}", 
                            name, p.offset, p.code, p.function, p.managed, p.msil
                        );
                    }
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
    }

    Ok(())
}

#[repr(C)]
#[derive(Debug)]
struct PeHeader {
    signature: u32,
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

#[repr(C)]
#[derive(Debug)]
struct OptionalHeader32 {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    base_of_data: u32,
    image_base: u32,
    section_alignment: u32,
    file_alignment: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    checksum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u32,
    size_of_stack_commit: u32,
    size_of_heap_reserve: u32,
    size_of_heap_commit: u32,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
}

#[repr(C)]
#[derive(Debug)]
struct OptionalHeader64 {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    checksum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SectionHeader {
    name: [u8; 8],                 // セクション名
    virtual_size: u32,             // 仮想サイズ
    virtual_address: u32,          // 仮想アドレス
    size_of_raw_data: u32,         // 生データのサイズ
    pointer_to_raw_data: u32,      // 生データへのポインタ
    pointer_to_relocations: u32,   // 再配置テーブルへのポインタ
    pointer_to_line_numbers: u32,  // 行番号テーブルへのポインタ
    number_of_relocations: u16,    // 再配置エントリ数
    number_of_line_numbers: u16,   // 行番号エントリ数
    characteristics: u32,          // セクション特性
}

fn read_struct<T>(file: &mut File) -> Result<T> {
    let mut buffer = vec![0u8; mem::size_of::<T>()];
    file.read_exact(&mut buffer)?;
    let ptr = buffer.as_ptr() as *const T;
    Ok(unsafe { ptr.read() })
}

fn get_machine_name(machine: u16) -> &'static str {
    match machine {
        0x014c => "IMAGE_FILE_MACHINE_I386",
        0x0200 => "IMAGE_FILE_MACHINE_IA64",
        0x8664 => "IMAGE_FILE_MACHINE_AMD64",
        0x01c0 => "IMAGE_FILE_MACHINE_ARM",
        0xaa64 => "IMAGE_FILE_MACHINE_ARM64",
        _ => "Unknown",
    }
}

fn get_subsystem_name(subsystem: u16) -> &'static str {
    match subsystem {
        1 => "IMAGE_SUBSYSTEM_NATIVE",
        2 => "IMAGE_SUBSYSTEM_WINDOWS_GUI",
        3 => "IMAGE_SUBSYSTEM_WINDOWS_CUI",
        5 => "IMAGE_SUBSYSTEM_OS2_CUI",
        7 => "IMAGE_SUBSYSTEM_POSIX_CUI",
        9 => "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI",
        10 => "IMAGE_SUBSYSTEM_EFI_APPLICATION",
        11 => "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER",
        12 => "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER",
        13 => "IMAGE_SUBSYSTEM_EFI_ROM",
        14 => "IMAGE_SUBSYSTEM_XBOX",
        16 => "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION",
        _ => "Unknown",
    }
}

fn display_section_characteristics(characteristics: u32) {
    println!("  セクション特性フラグ:");
    if characteristics & 0x00000008 != 0 { println!("    IMAGE_SCN_TYPE_NO_PAD"); }
    if characteristics & 0x00000020 != 0 { println!("    IMAGE_SCN_CNT_CODE"); }
    if characteristics & 0x00000040 != 0 { println!("    IMAGE_SCN_CNT_INITIALIZED_DATA"); }
    if characteristics & 0x00000080 != 0 { println!("    IMAGE_SCN_CNT_UNINITIALIZED_DATA"); }
    if characteristics & 0x00000100 != 0 { println!("    IMAGE_SCN_LNK_OTHER"); }
    if characteristics & 0x00000200 != 0 { println!("    IMAGE_SCN_LNK_INFO"); }
    if characteristics & 0x00000800 != 0 { println!("    IMAGE_SCN_LNK_REMOVE"); }
    if characteristics & 0x00001000 != 0 { println!("    IMAGE_SCN_LNK_COMDAT"); }
    if characteristics & 0x00008000 != 0 { println!("    IMAGE_SCN_GPREL"); }
    if characteristics & 0x00020000 != 0 { println!("    IMAGE_SCN_MEM_PURGEABLE"); }
    if characteristics & 0x00020000 != 0 { println!("    IMAGE_SCN_MEM_16BIT"); }
    if characteristics & 0x00040000 != 0 { println!("    IMAGE_SCN_MEM_LOCKED"); }
    if characteristics & 0x00080000 != 0 { println!("    IMAGE_SCN_MEM_PRELOAD"); }
    if characteristics & 0x01000000 != 0 { println!("    IMAGE_SCN_LNK_NRELOC_OVFL"); }
    if characteristics & 0x02000000 != 0 { println!("    IMAGE_SCN_MEM_DISCARDABLE"); }
    if characteristics & 0x04000000 != 0 { println!("    IMAGE_SCN_MEM_NOT_CACHED"); }
    if characteristics & 0x08000000 != 0 { println!("    IMAGE_SCN_MEM_NOT_PAGED"); }
    if characteristics & 0x10000000 != 0 { println!("    IMAGE_SCN_MEM_SHARED"); }
    if characteristics & 0x20000000 != 0 { println!("    IMAGE_SCN_MEM_EXECUTE"); }
    if characteristics & 0x40000000 != 0 { println!("    IMAGE_SCN_MEM_READ"); }
    if characteristics & 0x80000000 != 0 { println!("    IMAGE_SCN_MEM_WRITE"); }
}

fn display_sections(
    file: &mut File,
    pe_header: &PeHeader,
    optional_header_size: u16,
    section_name_map: &HashMap<u16, String>,
) -> Result<()> {
    // オプショナルヘッダーをスキップしてセクションヘッダーの位置に移動
    file.seek(SeekFrom::Current(optional_header_size as i64))?;
    
    println!("\n=== セクション情報 ===");
    println!("セクション数: {}", pe_header.number_of_sections);
    
    for i in 0..pe_header.number_of_sections {
        let section: SectionHeader = read_struct(file)?;
        
        // セクション名を文字列として取得（null終端を考慮）
        let name_bytes = &section.name;
        let name_end = name_bytes.iter().position(|&x| x == 0).unwrap_or(8);
        let section_name = std::str::from_utf8(&name_bytes[..name_end])
            .unwrap_or("<invalid>");
        
        println!("\n--- セクション {} ---", i + 1);
        // シンボルテーブル由来の名前があればそちらを優先
        let sym_name = section_name_map.get(&((i + 1) as u16));
        let display_name = sym_name.map(String::as_str).unwrap_or(section_name);
        println!("名前: {}", display_name);
        println!("仮想サイズ: 0x{:08X} ({} bytes)", section.virtual_size, section.virtual_size);
        println!("仮想アドレス: 0x{:08X}", section.virtual_address);
        println!("生データサイズ: 0x{:08X} ({} bytes)", section.size_of_raw_data, section.size_of_raw_data);
        println!("生データポインタ: 0x{:08X}", section.pointer_to_raw_data);
        println!("再配置ポインタ: 0x{:08X}", section.pointer_to_relocations);
        println!("行番号ポインタ: 0x{:08X}", section.pointer_to_line_numbers);
        println!("再配置数: {}", section.number_of_relocations);
        println!("行番号数: {}", section.number_of_line_numbers);
        println!("特性: 0x{:08X}", section.characteristics);
        
        // 特性フラグの詳細表示
        display_section_characteristics(section.characteristics);
    }
    
    Ok(())
}

// COFFシンボルテーブルを走査して、セクション番号 -> セクション名 のマップを作る
fn build_section_name_map(file_path: &str, pe_header: &PeHeader) -> Result<HashMap<u16, String>> {
    let mut map = HashMap::new();

    if pe_header.pointer_to_symbol_table == 0 || pe_header.number_of_symbols == 0 {
        return Ok(map);
    }

    let mut f = File::open(file_path)
        .with_context(|| format!("ファイルを開けませんでした: {}", file_path))?;

    // シンボルテーブルにシーク
    f.seek(SeekFrom::Start(pe_header.pointer_to_symbol_table as u64))?;

    // 先に全シンボルを読み切った位置に移動してストリングテーブルを読む
    let symbols_bytes_len = (pe_header.number_of_symbols as u64) * 18;
    f.seek(SeekFrom::Start(pe_header.pointer_to_symbol_table as u64 + symbols_bytes_len))?;

    // ストリングテーブル: 先頭4バイトがサイズ（この4バイトを含む総サイズ）
    let mut size_buf = [0u8; 4];
    if f.read(&mut size_buf)? != 4 {
        return Ok(map); // ストリングテーブルが無い/壊れている
    }
    let strtab_size = u32::from_le_bytes(size_buf);
    let mut strtab: Vec<u8> = vec![];
    if strtab_size >= 4 {
        let data_size = (strtab_size - 4) as usize;
        strtab.resize(data_size, 0);
        f.read_exact(&mut strtab)?;
    }

    // 再度シンボルテーブル先頭へ
    f.seek(SeekFrom::Start(pe_header.pointer_to_symbol_table as u64))?;

    let mut i: u32 = 0;
    while i < pe_header.number_of_symbols as u32 {
        let mut buf = [0u8; 18];
        f.read_exact(&mut buf)?;

        // 名前のunion
        let n_zeroes = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        let n_offset = u32::from_le_bytes(buf[4..8].try_into().unwrap());

        let value = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        let section_number = i16::from_le_bytes(buf[12..14].try_into().unwrap());
        let _type_ = u16::from_le_bytes(buf[14..16].try_into().unwrap());
        let storage_class = buf[16];
        let aux_count = buf[17];

        // 名前解決
        let name = if n_zeroes == 0 {
            // オフセット参照（ストリングテーブル先頭のサイズ4バイトを除いた領域へのオフセット）
            let off = n_offset as usize;
            if off > 0 && off < strtab.len() {
                let slice = &strtab[off..];
                let end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
                String::from_utf8_lossy(&slice[..end]).to_string()
            } else {
                String::new()
            }
        } else {
            // 短い名前（8バイト）
            let short = &buf[0..8];
            let end = short.iter().position(|&c| c == 0).unwrap_or(8);
            String::from_utf8_lossy(&short[..end]).to_string()
        };

        // セクションシンボル（STATIC）で、セクション番号が正のものを採用
        if storage_class == 3 /* IMAGE_SYM_CLASS_STATIC */ && section_number > 0 {
            let sec_no = section_number as u16;
            // 既に登録済みならスキップ（最初のものを優先）
            if !name.is_empty() && !map.contains_key(&sec_no) {
                // 一部ツールチェインではセクションシンボル名が ".text" 等
                map.insert(sec_no, name);
            }
        }

        // 補助シンボルをスキップ
        if aux_count > 0 {
            let skip = (aux_count as u64) * 18;
            f.seek(SeekFrom::Current(skip as i64))?;
            i += aux_count as u32;
        }

        i += 1;
        let _ = value; // 使わないが読み出し済みであることを明示
    }

    Ok(map)
}

// COFFシンボルテーブルの概要を表示
fn display_coff_info(file_path: &str, pe_header: &PeHeader) -> Result<()> {
    println!("\n=== COFF 情報 ===");
    println!("PointerToSymbolTable: 0x{:08X}", pe_header.pointer_to_symbol_table);
    println!("NumberOfSymbols: {}", pe_header.number_of_symbols);

    if pe_header.pointer_to_symbol_table == 0 || pe_header.number_of_symbols == 0 {
        println!("COFFシンボルテーブルは存在しません。");
        return Ok(());
    }

    let mut f = File::open(file_path)
        .with_context(|| format!("ファイルを開けませんでした: {}", file_path))?;

    // ストリングテーブルのサイズを取得
    let symbols_bytes_len = (pe_header.number_of_symbols as u64) * 18;
    f.seek(SeekFrom::Start(pe_header.pointer_to_symbol_table as u64 + symbols_bytes_len))?;
    let mut size_buf = [0u8; 4];
    let mut strtab_size: u32 = 0;
    if f.read(&mut size_buf)? == 4 {
        strtab_size = u32::from_le_bytes(size_buf);
    }
    println!("StringTableSize: {}", strtab_size);

    // 先頭の数件のシンボルを表示
    let mut strtab: Vec<u8> = vec![];
    if strtab_size >= 4 {
        let data_size = (strtab_size - 4) as usize;
        strtab.resize(data_size, 0);
        f.read_exact(&mut strtab).ok();
    }

    // シンボル先頭へ戻る
    f.seek(SeekFrom::Start(pe_header.pointer_to_symbol_table as u64))?;

    let show_count = (pe_header.number_of_symbols as usize).min(20);
    println!("先頭 {} シンボル:", show_count);
    let mut i: u32 = 0;
    let mut shown = 0usize;
    while i < pe_header.number_of_symbols as u32 && shown < show_count {
        let mut buf = [0u8; 18];
        f.read_exact(&mut buf)?;

        let n_zeroes = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        let n_offset = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        let value = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        let section_number = i16::from_le_bytes(buf[12..14].try_into().unwrap());
        let typ = u16::from_le_bytes(buf[14..16].try_into().unwrap());
        let storage_class = buf[16];
        let aux_count = buf[17];

        let name = if n_zeroes == 0 {
            let off = n_offset as usize;
            if off > 0 && off < strtab.len() {
                let slice = &strtab[off..];
                let end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
                String::from_utf8_lossy(&slice[..end]).to_string()
            } else {
                String::new()
            }
        } else {
            let short = &buf[0..8];
            let end = short.iter().position(|&c| c == 0).unwrap_or(8);
            String::from_utf8_lossy(&short[..end]).to_string()
        };

        println!(
            "[#{:>5}] name='{}' sec={} val=0x{:08X} type=0x{:04X} class=0x{:02X} aux={}",
            i,
            name,
            section_number,
            value,
            typ,
            storage_class,
            aux_count
        );

        // 補助シンボル分スキップ
        if aux_count > 0 {
            let skip = (aux_count as u64) * 18;
            f.seek(SeekFrom::Current(skip as i64))?;
            i += aux_count as u32;
        }

        i += 1;
        shown += 1;
    }

    Ok(())
}

fn display_pe_header(file_path: &str) -> Result<()> {
    let mut file = File::open(file_path)
        .with_context(|| format!("ファイルを開けませんでした: {}", file_path))?;

    // DOSヘッダーを読み込み
    let dos_header: DosHeader = read_struct(&mut file)?;
    
    if dos_header.e_magic != 0x5A4D {
        return Err(anyhow::anyhow!("有効なPEファイルではありません（DOSマジック番号が不正）"));
    }

    println!("=== DOS ヘッダー ===");
    println!("Magic: 0x{:04X} ({})", dos_header.e_magic, 
             if dos_header.e_magic == 0x5A4D { "MZ" } else { "Invalid" });
    println!("PE Header Offset: 0x{:08X}", dos_header.e_lfanew);

    // PEヘッダーの位置に移動
    file.seek(SeekFrom::Start(dos_header.e_lfanew as u64))?;

    // PEヘッダーを読み込み
    let pe_header: PeHeader = read_struct(&mut file)?;
    
    if pe_header.signature != 0x00004550 {
        return Err(anyhow::anyhow!("有効なPEファイルではありません（PEシグネチャが不正）"));
    }

    println!("\n=== PE ヘッダー ===");
    println!("Signature: 0x{:08X} (PE)", pe_header.signature);
    println!("Machine: 0x{:04X} ({})", pe_header.machine, get_machine_name(pe_header.machine));
    println!("Number of Sections: {}", pe_header.number_of_sections);
    println!("Time Date Stamp: 0x{:08X}", pe_header.time_date_stamp);
    println!("Pointer to Symbol Table: 0x{:08X}", pe_header.pointer_to_symbol_table);
    println!("Number of Symbols: {}", pe_header.number_of_symbols);
    println!("Size of Optional Header: {}", pe_header.size_of_optional_header);
    println!("Characteristics: 0x{:04X}", pe_header.characteristics);

    // 特性フラグの詳細表示
    println!("  Characteristics flags:");
    if pe_header.characteristics & 0x0001 != 0 { println!("    IMAGE_FILE_RELOCS_STRIPPED"); }
    if pe_header.characteristics & 0x0002 != 0 { println!("    IMAGE_FILE_EXECUTABLE_IMAGE"); }
    if pe_header.characteristics & 0x0004 != 0 { println!("    IMAGE_FILE_LINE_NUMBERS_STRIPPED"); }
    if pe_header.characteristics & 0x0008 != 0 { println!("    IMAGE_FILE_LOCAL_SYMS_STRIPPED"); }
    if pe_header.characteristics & 0x0010 != 0 { println!("    IMAGE_FILE_AGGR_WS_TRIM"); }
    if pe_header.characteristics & 0x0020 != 0 { println!("    IMAGE_FILE_LARGE_ADDRESS_AWARE"); }
    if pe_header.characteristics & 0x0080 != 0 { println!("    IMAGE_FILE_BYTES_REVERSED_LO"); }
    if pe_header.characteristics & 0x0100 != 0 { println!("    IMAGE_FILE_32BIT_MACHINE"); }
    if pe_header.characteristics & 0x0200 != 0 { println!("    IMAGE_FILE_DEBUG_STRIPPED"); }
    if pe_header.characteristics & 0x0400 != 0 { println!("    IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP"); }
    if pe_header.characteristics & 0x0800 != 0 { println!("    IMAGE_FILE_NET_RUN_FROM_SWAP"); }
    if pe_header.characteristics & 0x1000 != 0 { println!("    IMAGE_FILE_SYSTEM"); }
    if pe_header.characteristics & 0x2000 != 0 { println!("    IMAGE_FILE_DLL"); }
    if pe_header.characteristics & 0x4000 != 0 { println!("    IMAGE_FILE_UP_SYSTEM_ONLY"); }
    if pe_header.characteristics & 0x8000 != 0 { println!("    IMAGE_FILE_BYTES_REVERSED_HI"); }

    // COFF情報の表示（ファイルを開き直すためこの時点で安全）
    display_coff_info(file_path, &pe_header)?;

    // オプショナルヘッダーがある場合は読み込み
    if pe_header.size_of_optional_header > 0 {
        // マジック番号を先読みしてPE32かPE32+かを判定
        let magic: u16 = read_struct(&mut file)?;
        file.seek(SeekFrom::Current(-2))?; // 2バイト戻る

        println!("\n=== オプショナル ヘッダー ===");
        
        if magic == 0x010b {
            // PE32
            let opt_header: OptionalHeader32 = read_struct(&mut file)?;
            println!("Magic: 0x{:04X} (PE32)", opt_header.magic);
            println!("Linker Version: {}.{}", opt_header.major_linker_version, opt_header.minor_linker_version);
            println!("Size of Code: 0x{:08X}", opt_header.size_of_code);
            println!("Size of Initialized Data: 0x{:08X}", opt_header.size_of_initialized_data);
            println!("Size of Uninitialized Data: 0x{:08X}", opt_header.size_of_uninitialized_data);
            println!("Address of Entry Point: 0x{:08X}", opt_header.address_of_entry_point);
            println!("Base of Code: 0x{:08X}", opt_header.base_of_code);
            println!("Base of Data: 0x{:08X}", opt_header.base_of_data);
            println!("Image Base: 0x{:08X}", opt_header.image_base);
            println!("Section Alignment: 0x{:08X}", opt_header.section_alignment);
            println!("File Alignment: 0x{:08X}", opt_header.file_alignment);
            println!("OS Version: {}.{}", opt_header.major_operating_system_version, opt_header.minor_operating_system_version);
            println!("Image Version: {}.{}", opt_header.major_image_version, opt_header.minor_image_version);
            println!("Subsystem Version: {}.{}", opt_header.major_subsystem_version, opt_header.minor_subsystem_version);
            println!("Size of Image: 0x{:08X}", opt_header.size_of_image);
            println!("Size of Headers: 0x{:08X}", opt_header.size_of_headers);
            println!("Checksum: 0x{:08X}", opt_header.checksum);
            println!("Subsystem: {} ({})", opt_header.subsystem, get_subsystem_name(opt_header.subsystem));
            println!("DLL Characteristics: 0x{:04X}", opt_header.dll_characteristics);
            println!("Size of Stack Reserve: 0x{:08X}", opt_header.size_of_stack_reserve);
            println!("Size of Stack Commit: 0x{:08X}", opt_header.size_of_stack_commit);
            println!("Size of Heap Reserve: 0x{:08X}", opt_header.size_of_heap_reserve);
            println!("Size of Heap Commit: 0x{:08X}", opt_header.size_of_heap_commit);
            println!("Number of RVA and Sizes: {}", opt_header.number_of_rva_and_sizes);

            // OptionalHeaderサイズのうち、未読のデータディレクトリ分をスキップ
            let read_size = mem::size_of::<OptionalHeader32>() as i64;
            let remaining = (pe_header.size_of_optional_header as i64) - read_size;
            if remaining > 0 { file.seek(SeekFrom::Current(remaining))?; }
        } else if magic == 0x020b {
            // PE32+
            let opt_header: OptionalHeader64 = read_struct(&mut file)?;
            println!("Magic: 0x{:04X} (PE32+)", opt_header.magic);
            println!("Linker Version: {}.{}", opt_header.major_linker_version, opt_header.minor_linker_version);
            println!("Size of Code: 0x{:08X}", opt_header.size_of_code);
            println!("Size of Initialized Data: 0x{:08X}", opt_header.size_of_initialized_data);
            println!("Size of Uninitialized Data: 0x{:08X}", opt_header.size_of_uninitialized_data);
            println!("Address of Entry Point: 0x{:08X}", opt_header.address_of_entry_point);
            println!("Base of Code: 0x{:08X}", opt_header.base_of_code);
            println!("Image Base: 0x{:016X}", opt_header.image_base);
            println!("Section Alignment: 0x{:08X}", opt_header.section_alignment);
            println!("File Alignment: 0x{:08X}", opt_header.file_alignment);
            println!("OS Version: {}.{}", opt_header.major_operating_system_version, opt_header.minor_operating_system_version);
            println!("Image Version: {}.{}", opt_header.major_image_version, opt_header.minor_image_version);
            println!("Subsystem Version: {}.{}", opt_header.major_subsystem_version, opt_header.minor_subsystem_version);
            println!("Size of Image: 0x{:08X}", opt_header.size_of_image);
            println!("Size of Headers: 0x{:08X}", opt_header.size_of_headers);
            println!("Checksum: 0x{:08X}", opt_header.checksum);
            println!("Subsystem: {} ({})", opt_header.subsystem, get_subsystem_name(opt_header.subsystem));
            println!("DLL Characteristics: 0x{:04X}", opt_header.dll_characteristics);
            println!("Size of Stack Reserve: 0x{:016X}", opt_header.size_of_stack_reserve);
            println!("Size of Stack Commit: 0x{:016X}", opt_header.size_of_stack_commit);
            println!("Size of Heap Reserve: 0x{:016X}", opt_header.size_of_heap_reserve);
            println!("Size of Heap Commit: 0x{:016X}", opt_header.size_of_heap_commit);
            println!("Number of RVA and Sizes: {}", opt_header.number_of_rva_and_sizes);

            // OptionalHeaderサイズのうち、未読のデータディレクトリ分をスキップ
            let read_size = mem::size_of::<OptionalHeader64>() as i64;
            let remaining = (pe_header.size_of_optional_header as i64) - read_size;
            if remaining > 0 { file.seek(SeekFrom::Current(remaining))?; }
        } else {
            println!("不明なオプショナルヘッダー形式: 0x{:04X}", magic);
        }
        
        // セクション名をシンボルから取得（存在すれば）
        let section_name_map = build_section_name_map(file_path, &pe_header)?;

        // セクション情報を表示（シンボル名で上書き）
        display_sections(
            &mut file,
            &pe_header,
            0, // 既にオプショナルヘッダーを完全に読み終えているため追加シークは不要
            &section_name_map,
        )?;
    }

    Ok(())
}

fn main() -> Result<()> {
    let matches = Command::new("tsudump")
        .version("0.1.0")
        .about("Windows PE ファイル解析ツール")
        .arg(
            Arg::new("file")
                .help("解析するPEファイルのパス")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new("pdb")
                .long("pdb")
                .value_name("PDB")
                .help("解析するPDBファイルのパス")
                .required(false),
        )
        .arg(
            Arg::new("disasm")
                .long("disasm")
                .help(".text セクションを逆アセンブルして表示")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("thumb")
                .long("thumb")
                .help("ARMでThumbモードを強制的に使用")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("addr")
                .long("addr")
                .value_name("MODE")
                .help("アドレス表示モード: va または rva (既定: va)")
                .required(false),
        )
        .arg(
            Arg::new("disasm-limit")
                .long("disasm-limit")
                .value_name("N")
                .help("逆アセンブルする命令数の上限（未指定で全件）")
                .required(false),
        )
        .arg(
            Arg::new("disasm-start")
                .long("disasm-start")
                .value_name("HEX")
                .help("逆アセンブル開始アドレス（--addr に従い va または rva として解釈）")
                .required(false),
        )
        .arg(
            Arg::new("disasm-base")
                .long("disasm-base")
                .value_name("MODE")
                .help("逆アセンブル起点: ep または text (既定: ep)")
                .required(false),
        )
        .arg(
            Arg::new("pdb-symbols")
                .long("pdb-symbols")
                .help("PDBのPublic/Procedureシンボルをアドレス順に列挙して表示")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("pdb-info")
                .long("pdb-info")
                .help("PDBの概要情報を表示（--pdb指定時のみ有効）")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("pdb-lines")
                .long("pdb-lines")
                .help("PDBの行番号情報を列挙して表示")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    let file_path = matches.get_one::<String>("file").unwrap();
    
    println!("PEファイル解析: {}", file_path);
    println!("==========================================");
    
    display_pe_header(file_path)?;

    // PDB概要表示（明示オプション時のみ）
    if matches.get_flag("pdb-info") {
        if let Some(pdb_path) = matches.get_one::<String>("pdb") {
            let pdb_path: &str = pdb_path;
            if let Err(e) = display_pdb_info(pdb_path) {
                eprintln!("PDB解析でエラー: {:#}", e);
            }
        } else {
            eprintln!("--pdb-info を使うには --pdb <PDB> の指定が必要です。");
        }
    }

    // PDBシンボル一覧
    if matches.get_flag("pdb-symbols") {
        if let Some(pdb_path) = matches.get_one::<String>("pdb") {
            let addr_mode = matches.get_one::<String>("addr").map(|s| s.to_ascii_lowercase()).unwrap_or_else(|| "va".to_string());
            let use_va = addr_mode != "rva";
            if let Err(e) = dump_pdb_symbols(file_path, pdb_path, use_va) {
                eprintln!("PDBシンボル抽出でエラー: {:#}", e);
            }
        } else {
            eprintln!("--pdb-symbols を使うには --pdb <PDB> の指定が必要です。");
        }
    }

    // PDB行番号一覧
    if matches.get_flag("pdb-lines") {
        if let Some(pdb_path) = matches.get_one::<String>("pdb") {
            let addr_mode = matches.get_one::<String>("addr").map(|s| s.to_ascii_lowercase()).unwrap_or_else(|| "va".to_string());
            let use_va = addr_mode != "rva";
            if let Err(e) = dump_pdb_lines(file_path, pdb_path, use_va) {
                eprintln!("PDB行番号抽出でエラー: {:#}", e);
            }
        } else {
            eprintln!("--pdb-lines を使うには --pdb <PDB> の指定が必要です。");
        }
    }

    // 逆アセンブル
    if matches.get_flag("disasm") {
        let limit = matches.get_one::<String>("disasm-limit").and_then(|s| s.parse::<usize>().ok());
        let pdb_opt = matches.get_one::<String>("pdb").map(|s| s.as_str());
        let addr_mode = matches.get_one::<String>("addr").map(|s| s.to_ascii_lowercase()).unwrap_or_else(|| "va".to_string());
        let use_va = addr_mode != "rva";
        let force_thumb = matches.get_flag("thumb");
        let disasm_base = matches.get_one::<String>("disasm-base").map(|s| s.to_ascii_lowercase()).unwrap_or_else(|| "ep".to_string());
        let disasm_base_text = disasm_base == "text";
        let disasm_start = matches
            .get_one::<String>("disasm-start")
            .and_then(|s| {
                let s = s.trim();
                let s = s.strip_prefix("0x").unwrap_or(s);
                u64::from_str_radix(s, 16).ok()
            });
        if let Err(e) = disassemble_text(file_path, pdb_opt, limit, use_va, force_thumb, disasm_start, disasm_base_text) {
            eprintln!("逆アセンブルでエラー: {:#}", e);
        }
    }

    Ok(())
}
