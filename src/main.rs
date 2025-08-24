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
) -> Result<()> {
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
    if magic == 0x010b {
        let opt: OptionalHeader32 = read_struct(&mut file)?;
        image_base = opt.image_base as u64;
        entry_point_rva = opt.address_of_entry_point;
        // 残り（データディレクトリ）スキップ
        let read_size = std::mem::size_of::<OptionalHeader32>() as i64;
        let remaining = (pe.size_of_optional_header as i64) - read_size;
        if remaining > 0 { file.seek(SeekFrom::Current(remaining))?; }
    } else if magic == 0x020b {
        let opt: OptionalHeader64 = read_struct(&mut file)?;
        image_base = opt.image_base as u64;
        entry_point_rva = opt.address_of_entry_point;
        let read_size = std::mem::size_of::<OptionalHeader64>() as i64;
        let remaining = (pe.size_of_optional_header as i64) - read_size;
        if remaining > 0 { file.seek(SeekFrom::Current(remaining))?; }
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
        let vend = vstart.saturating_add(sh.size_of_raw_data.max(sh.virtual_size));
        if entry_point_rva >= vstart && entry_point_rva < vend {
            ep_hdr = Some(sh);
        }
    }

    // 逆アセンブル対象セクションと開始RVAを決定（EP優先、なければ.textの頭）
    let (target_sh, start_rva_in_image) = if let Some(h) = ep_hdr {
        (h, entry_point_rva as u64)
    } else if let Some(h) = text_hdr {
        (h, h.virtual_address as u64)
    } else {
        return Err(anyhow::anyhow!("コードセクションが見つかりません"));
    };

    // .text の生データを読み出し
    if target_sh.pointer_to_raw_data == 0 || target_sh.size_of_raw_data == 0 {
        return Err(anyhow::anyhow!(".text のRawデータがありません"));
    }
    // セクション内オフセットを計算してEP位置から読み出す
    let start_offset_in_section = (start_rva_in_image as i64 - target_sh.virtual_address as i64).max(0) as u64;
    let file_start = (target_sh.pointer_to_raw_data as u64).saturating_add(start_offset_in_section);
    let max_len = target_sh.size_of_raw_data as u64;
    if start_offset_in_section >= max_len {
        return Err(anyhow::anyhow!("エントリポイントがセクションの範囲外です"));
    }
    let read_len = (max_len - start_offset_in_section) as usize;
    file.seek(SeekFrom::Start(file_start))?;
    let mut code: Vec<u8> = vec![0u8; read_len];
    file.read_exact(&mut code)?;

    // Capstone 準備（x86/x64/ARM/ARM64対応）
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
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    println!("\n=== 逆アセンブル (EntryPoint起点) ===");
    let start_addr = if use_va { image_base + start_rva_in_image } else { start_rva_in_image };
    let insns = if let Some(n) = limit { cs.disasm_count(&code, start_addr, n)? } else { cs.disasm_all(&code, start_addr)? };
    for i in insns.iter() {
        if let Some(name) = labels.get(&i.address()) {
            println!("\n{}:", name);
        }
        let op = i.op_str().unwrap_or("");
        if use_va {
            if is_pe32_plus { println!("0x{:016X}: {:7} {}", i.address(), i.mnemonic().unwrap_or(""), op); }
            else { println!("0x{:08X}:  {:7} {}", i.address() as u32, i.mnemonic().unwrap_or(""), op); }
        } else {
            // RVAは32bit幅で表示
            println!("0x{:08X}:  {:7} {}", i.address() as u32, i.mnemonic().unwrap_or(""), op);
        }
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
            Arg::new("pdb-symbols")
                .long("pdb-symbols")
                .help("PDBのPublic/Procedureシンボルをアドレス順に列挙して表示")
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

    // 任意のPDB解析
    if let Some(pdb_path) = matches.get_one::<String>("pdb") {
        let pdb_path: &str = pdb_path;
        if let Err(e) = display_pdb_info(pdb_path) {
            eprintln!("PDB解析でエラー: {:#}", e);
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
        if let Err(e) = disassemble_text(file_path, pdb_opt, limit, use_va, force_thumb) {
            eprintln!("逆アセンブルでエラー: {:#}", e);
        }
    }

    Ok(())
}
