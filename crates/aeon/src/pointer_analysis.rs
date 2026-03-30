use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

use bad64::{Op, Operand};
use serde::{Serialize, Serializer};

use crate::elf::{FunctionInfo, LoadedBinary, SectionInfo};
use crate::il::{Expr, Reg, Stmt};
use crate::lifter;

const POINTER_SIZE: u64 = 8;
const MIN_VTABLE_FUNCTIONS: usize = 3;
const MAX_PLAUSIBLE_OFFSET_TO_TOP: i64 = 1 << 20;
const MAX_SLOT_FALLBACK_TARGETS: usize = 8;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AddressKind {
    Function,
    Code,
    Data,
    Unknown,
}

impl AddressKind {
    fn is_executable(self) -> bool {
        matches!(self, Self::Function | Self::Code)
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PointerClassification {
    DataToFunction,
    DataToCode,
    DataToData,
    DataToUnknown,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FunctionReferenceKind {
    DirectOperand,
    PcRelative,
    MemoryAddress,
    StoredPointer,
    CallTarget,
    TailCallTarget,
    IndirectCallVtable,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum CallEdgeKind {
    DirectCall,
    TailCall,
    IndirectVtableExact,
    IndirectVtableReferenced,
    IndirectVtableSlotFallback,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TargetInfo {
    #[serde(serialize_with = "serialize_hex")]
    pub addr: u64,
    pub kind: AddressKind,
    pub section: Option<String>,
    #[serde(serialize_with = "serialize_hex_opt")]
    pub function_addr: Option<u64>,
    pub name: Option<String>,
    pub string_preview: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PointerScanEntry {
    #[serde(serialize_with = "serialize_hex")]
    pub source_addr: u64,
    #[serde(serialize_with = "serialize_hex")]
    pub source_file_offset: u64,
    pub source_section: String,
    pub classification: PointerClassification,
    pub target: TargetInfo,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PointerScanReport {
    pub pointer_size: u64,
    pub scanned_sections: Vec<String>,
    pub total_entries: usize,
    pub function_pointers: usize,
    pub code_pointers: usize,
    pub data_pointers: usize,
    pub entries: Vec<PointerScanEntry>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct VTableEntry {
    #[serde(serialize_with = "serialize_hex")]
    pub entry_addr: u64,
    #[serde(serialize_with = "serialize_hex")]
    pub slot_offset: u64,
    pub target: TargetInfo,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct VTableInfo {
    pub group_id: usize,
    pub section: String,
    #[serde(serialize_with = "serialize_hex")]
    pub start_addr: u64,
    #[serde(serialize_with = "serialize_hex")]
    pub address_point: u64,
    pub size_bytes: u64,
    pub function_count: usize,
    pub offset_to_top: Option<i64>,
    #[serde(serialize_with = "serialize_hex_opt")]
    pub typeinfo_addr: Option<u64>,
    pub functions: Vec<VTableEntry>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct VTableGroup {
    pub group_id: usize,
    pub section: String,
    #[serde(serialize_with = "serialize_hex")]
    pub start_addr: u64,
    #[serde(serialize_with = "serialize_hex")]
    pub end_addr: u64,
    #[serde(serialize_with = "serialize_hex_opt")]
    pub typeinfo_addr: Option<u64>,
    #[serde(serialize_with = "serialize_hex_vec")]
    pub vtables: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct VTableScanReport {
    pub scanned_sections: Vec<String>,
    pub total_vtables: usize,
    pub total_groups: usize,
    pub groups: Vec<VTableGroup>,
    pub vtables: Vec<VTableInfo>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FunctionPointerReference {
    #[serde(serialize_with = "serialize_hex")]
    pub instruction_addr: u64,
    pub disassembly: String,
    pub kind: FunctionReferenceKind,
    pub expression: String,
    pub via_register: Option<String>,
    pub target: Option<TargetInfo>,
    #[serde(serialize_with = "serialize_hex_opt")]
    pub slot_offset: Option<u64>,
    #[serde(serialize_with = "serialize_hex_opt")]
    pub resolved_vtable_addr: Option<u64>,
    pub candidate_targets: Vec<TargetInfo>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FunctionPointerRefs {
    #[serde(serialize_with = "serialize_hex")]
    pub function_addr: u64,
    pub function_size: u64,
    pub name: Option<String>,
    pub reference_count: usize,
    pub unique_function_targets: Vec<TargetInfo>,
    pub unique_code_targets: Vec<TargetInfo>,
    pub unique_data_targets: Vec<TargetInfo>,
    pub references: Vec<FunctionPointerReference>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FunctionPointerScanReport {
    #[serde(serialize_with = "serialize_hex_opt")]
    pub query_addr: Option<u64>,
    pub total_functions: usize,
    pub offset: usize,
    pub count: usize,
    pub functions: Vec<FunctionPointerRefs>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CallGraphEdge {
    #[serde(serialize_with = "serialize_hex")]
    pub from: u64,
    pub from_name: Option<String>,
    #[serde(serialize_with = "serialize_hex")]
    pub to: u64,
    pub to_name: Option<String>,
    #[serde(serialize_with = "serialize_hex")]
    pub instruction_addr: u64,
    pub kind: CallEdgeKind,
    #[serde(serialize_with = "serialize_hex_opt")]
    pub vtable_addr: Option<u64>,
    #[serde(serialize_with = "serialize_hex_opt")]
    pub slot_offset: Option<u64>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CallPath {
    #[serde(serialize_with = "serialize_hex_vec")]
    pub functions: Vec<u64>,
    pub edges: Vec<CallGraphEdge>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CallPathSearchReport {
    pub start: TargetInfo,
    pub goal: TargetInfo,
    pub max_depth: usize,
    pub shortest_path: Option<CallPath>,
    pub all_paths: Option<Vec<CallPath>>,
    pub graph_node_count: usize,
    pub graph_edge_count: usize,
    pub direct_edge_count: usize,
    pub indirect_edge_count: usize,
    pub unresolved_indirect_sites: usize,
}

#[derive(Debug, Clone)]
struct RawSectionPointer {
    addr: u64,
    raw: u64,
    target: TargetInfo,
}

#[derive(Debug, Clone)]
struct VTableHeader {
    start_addr: u64,
    offset_to_top: i64,
    typeinfo_addr: Option<u64>,
}

#[derive(Debug, Clone)]
struct VTableSlotAccess {
    resolved_vtable_addr: Option<u64>,
    slot_offset: u64,
}

#[derive(Debug, Clone)]
struct FunctionAnalysis {
    report: FunctionPointerRefs,
    edges: Vec<CallGraphEdge>,
    unresolved_indirect_sites: usize,
}

#[derive(Debug, Default)]
struct VTableIndex {
    address_points: BTreeMap<u64, usize>,
    slot_targets: BTreeMap<u64, Vec<u64>>,
}

impl VTableIndex {
    fn build(vtables: &[VTableInfo]) -> Self {
        let mut index = Self::default();

        for (position, vtable) in vtables.iter().enumerate() {
            index.address_points.insert(vtable.address_point, position);
            for entry in &vtable.functions {
                if let Some(func_addr) = entry.target.function_addr {
                    index
                        .slot_targets
                        .entry(entry.slot_offset)
                        .or_default()
                        .push(func_addr);
                }
            }
        }

        for targets in index.slot_targets.values_mut() {
            dedup_u64_vec(targets);
        }

        index
    }

    fn normalize_vtable_addr(&self, vtables: &[VTableInfo], addr: u64) -> Option<u64> {
        if self.address_points.contains_key(&addr) {
            return Some(addr);
        }

        let (_, &position) = self.address_points.range(..=addr).next_back()?;
        let vtable = &vtables[position];
        let end = vtable.address_point + vtable.functions.len() as u64 * POINTER_SIZE;
        if addr >= vtable.address_point && addr < end {
            Some(vtable.address_point)
        } else {
            None
        }
    }

    fn resolve_slot_in_vtable(&self, vtables: &[VTableInfo], vtable_addr: u64, slot: u64) -> Vec<u64> {
        let Some(&position) = self.address_points.get(&vtable_addr) else {
            return Vec::new();
        };

        vtables[position]
            .functions
            .iter()
            .filter(|entry| entry.slot_offset == slot)
            .filter_map(|entry| entry.target.function_addr)
            .collect()
    }

    fn resolve_slot_fallback(&self, slot: u64) -> Vec<u64> {
        self.slot_targets.get(&slot).cloned().unwrap_or_default()
    }
}

pub fn scan_pointers(binary: &LoadedBinary) -> PointerScanReport {
    let mut scanned_sections = Vec::new();
    let mut entries = Vec::new();
    let mut function_pointers = 0usize;
    let mut code_pointers = 0usize;
    let mut data_pointers = 0usize;

    for section in pointer_scan_sections(binary) {
        scanned_sections.push(section.name.clone());
        for pointer in read_section_pointers(binary, section) {
            let classification = match pointer.target.kind {
                AddressKind::Function => {
                    function_pointers += 1;
                    PointerClassification::DataToFunction
                }
                AddressKind::Code => {
                    code_pointers += 1;
                    PointerClassification::DataToCode
                }
                AddressKind::Data => {
                    data_pointers += 1;
                    PointerClassification::DataToData
                }
                AddressKind::Unknown => PointerClassification::DataToUnknown,
            };

            entries.push(PointerScanEntry {
                source_addr: pointer.addr,
                source_file_offset: binary.vaddr_to_file_offset(pointer.addr).unwrap() as u64,
                source_section: section.name.clone(),
                classification,
                target: pointer.target,
            });
        }
    }

    PointerScanReport {
        pointer_size: POINTER_SIZE,
        scanned_sections,
        total_entries: entries.len(),
        function_pointers,
        code_pointers,
        data_pointers,
        entries,
    }
}

pub fn scan_vtables(binary: &LoadedBinary) -> VTableScanReport {
    let mut scanned_sections = Vec::new();
    let mut vtables = Vec::new();

    for section in vtable_sections(binary) {
        scanned_sections.push(section.name.clone());
        let entries = read_section_pointers(binary, section);
        let mut index = 0usize;
        while index < entries.len() {
            let run_len = executable_run_len(&entries, index);
            if run_len < MIN_VTABLE_FUNCTIONS {
                index += 1;
                continue;
            }

            let header = plausible_vtable_header(&entries, index);
            let previous_is_exec = index > 0 && entries[index - 1].target.kind.is_executable();
            if header.is_none() && previous_is_exec {
                index += 1;
                continue;
            }

            let start_index = index;
            let end_index = index + run_len;
            let functions: Vec<VTableEntry> = entries[start_index..end_index]
                .iter()
                .enumerate()
                .map(|(position, entry)| VTableEntry {
                    entry_addr: entry.addr,
                    slot_offset: position as u64 * POINTER_SIZE,
                    target: entry.target.clone(),
                })
                .collect();

            let start_addr = header
                .as_ref()
                .map(|header| header.start_addr)
                .unwrap_or(entries[start_index].addr);
            let address_point = entries[start_index].addr;
            let end_addr = entries[end_index - 1].addr + POINTER_SIZE;
            vtables.push(VTableInfo {
                group_id: 0,
                section: section.name.clone(),
                start_addr,
                address_point,
                size_bytes: end_addr - start_addr,
                function_count: functions.len(),
                offset_to_top: header.as_ref().map(|header| header.offset_to_top),
                typeinfo_addr: header.and_then(|header| header.typeinfo_addr),
                functions,
            });

            index = end_index;
        }
    }

    vtables.sort_by(|lhs, rhs| {
        lhs.section
            .cmp(&rhs.section)
            .then(lhs.start_addr.cmp(&rhs.start_addr))
    });

    let groups = assign_vtable_groups(&mut vtables);

    VTableScanReport {
        scanned_sections,
        total_vtables: vtables.len(),
        total_groups: groups.len(),
        groups,
        vtables,
    }
}

pub fn scan_function_pointers(
    binary: &LoadedBinary,
    query_addr: Option<u64>,
    offset: usize,
    limit: usize,
) -> Result<FunctionPointerScanReport, String> {
    let vtable_report = scan_vtables(binary);
    let vtable_index = VTableIndex::build(&vtable_report.vtables);

    let functions: Vec<&FunctionInfo> = if let Some(addr) = query_addr {
        vec![binary
            .function_containing(addr)
            .ok_or_else(|| format!("No function containing 0x{:x}", addr))?]
    } else {
        binary
            .functions
            .iter()
            .skip(offset)
            .take(limit)
            .collect::<Vec<_>>()
    };

    let reports = functions
        .into_iter()
        .map(|func| analyze_function(binary, func, &vtable_report.vtables, &vtable_index).report)
        .collect::<Vec<_>>();

    Ok(FunctionPointerScanReport {
        query_addr,
        total_functions: binary.functions.len(),
        offset,
        count: reports.len(),
        functions: reports,
    })
}

pub fn find_call_paths(
    binary: &LoadedBinary,
    start_addr: u64,
    goal_addr: u64,
    max_depth: usize,
    include_all_paths: bool,
    max_paths: usize,
) -> Result<CallPathSearchReport, String> {
    let start = binary
        .function_containing(start_addr)
        .ok_or_else(|| format!("No function containing 0x{:x}", start_addr))?;
    let goal = binary
        .function_containing(goal_addr)
        .ok_or_else(|| format!("No function containing 0x{:x}", goal_addr))?;

    if start.addr == goal.addr {
        return Ok(CallPathSearchReport {
            start: classify_target(binary, start.addr),
            goal: classify_target(binary, goal.addr),
            max_depth,
            shortest_path: Some(CallPath {
                functions: vec![start.addr],
                edges: Vec::new(),
            }),
            all_paths: include_all_paths.then(|| {
                vec![CallPath {
                    functions: vec![start.addr],
                    edges: Vec::new(),
                }]
            }),
            graph_node_count: 1,
            graph_edge_count: 0,
            direct_edge_count: 0,
            indirect_edge_count: 0,
            unresolved_indirect_sites: 0,
        });
    }

    let vtable_report = scan_vtables(binary);
    let vtable_index = VTableIndex::build(&vtable_report.vtables);

    let mut edge_seen = BTreeSet::new();
    let mut edges = Vec::new();
    let mut unresolved_indirect_sites = 0usize;

    for func in &binary.functions {
        let analysis = analyze_function(binary, func, &vtable_report.vtables, &vtable_index);
        unresolved_indirect_sites += analysis.unresolved_indirect_sites;
        for edge in analysis.edges {
            let key = (
                edge.from,
                edge.to,
                edge.instruction_addr,
                edge.kind,
                edge.vtable_addr,
                edge.slot_offset,
            );
            if edge_seen.insert(key) {
                edges.push(edge);
            }
        }
    }

    let mut adjacency: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    for (index, edge) in edges.iter().enumerate() {
        adjacency.entry(edge.from).or_default().push(index);
    }

    let shortest_path = bfs_shortest_path(start.addr, goal.addr, max_depth, &edges, &adjacency);
    let all_paths = if include_all_paths {
        Some(collect_all_paths(
            start.addr,
            goal.addr,
            max_depth,
            max_paths.max(1),
            &edges,
            &adjacency,
        ))
    } else {
        None
    };

    Ok(CallPathSearchReport {
        start: classify_target(binary, start.addr),
        goal: classify_target(binary, goal.addr),
        max_depth,
        shortest_path,
        all_paths,
        graph_node_count: binary.functions.len(),
        graph_edge_count: edges.len(),
        direct_edge_count: edges
            .iter()
            .filter(|edge| matches!(edge.kind, CallEdgeKind::DirectCall | CallEdgeKind::TailCall))
            .count(),
        indirect_edge_count: edges
            .iter()
            .filter(|edge| {
                matches!(
                    edge.kind,
                    CallEdgeKind::IndirectVtableExact
                        | CallEdgeKind::IndirectVtableReferenced
                        | CallEdgeKind::IndirectVtableSlotFallback
                )
            })
            .count(),
        unresolved_indirect_sites,
    })
}

fn pointer_scan_sections(binary: &LoadedBinary) -> impl Iterator<Item = &SectionInfo> {
    binary.sections.iter().filter(|section| {
        section.is_alloc && !section.is_executable && section.file_size >= POINTER_SIZE
    })
}

fn vtable_sections(binary: &LoadedBinary) -> impl Iterator<Item = &SectionInfo> {
    binary.sections.iter().filter(|section| {
        section.is_alloc
            && !section.is_executable
            && section.file_size >= POINTER_SIZE
            && (section.name.starts_with(".rodata") || section.name.starts_with(".data"))
    })
}

fn read_section_pointers(binary: &LoadedBinary, section: &SectionInfo) -> Vec<RawSectionPointer> {
    let start_addr = align_up(section.address, POINTER_SIZE);
    let end_addr = section.address + section.file_size;
    let mut pointers = Vec::new();
    let mut addr = start_addr;

    while addr + POINTER_SIZE <= end_addr {
        let Some(file_offset) = binary.vaddr_to_file_offset(addr) else {
            addr += POINTER_SIZE;
            continue;
        };
        let slice = &binary.data[file_offset..file_offset + POINTER_SIZE as usize];
        let raw = u64::from_le_bytes(slice.try_into().unwrap());
        if raw == 0 {
            addr += POINTER_SIZE;
            continue;
        }
        let target = classify_target(binary, raw);
        if target.kind != AddressKind::Unknown {
            pointers.push(RawSectionPointer { addr, raw, target });
        }
        addr += POINTER_SIZE;
    }

    pointers
}

fn executable_run_len(entries: &[RawSectionPointer], start: usize) -> usize {
    let mut len = 0usize;
    for entry in &entries[start..] {
        if !entry.target.kind.is_executable() {
            break;
        }
        len += 1;
    }
    len
}

fn plausible_vtable_header(entries: &[RawSectionPointer], index: usize) -> Option<VTableHeader> {
    if index < 2 {
        return None;
    }

    let offset_to_top = entries[index - 2].raw as i64;
    if offset_to_top.abs() > MAX_PLAUSIBLE_OFFSET_TO_TOP {
        return None;
    }

    let typeinfo_raw = entries[index - 1].raw;
    let typeinfo_addr = if typeinfo_raw == 0 { None } else { Some(typeinfo_raw) };
    Some(VTableHeader {
        start_addr: entries[index - 2].addr,
        offset_to_top,
        typeinfo_addr,
    })
}

fn assign_vtable_groups(vtables: &mut [VTableInfo]) -> Vec<VTableGroup> {
    let mut groups = Vec::new();
    let mut current_group: Option<VTableGroup> = None;
    let mut current_id = 0usize;

    for vtable in vtables {
        let end_addr = vtable.start_addr + vtable.size_bytes;
        let same_group = current_group.as_ref().is_some_and(|group| {
            group.section == vtable.section
                && ((group.typeinfo_addr.is_some() && group.typeinfo_addr == vtable.typeinfo_addr)
                    || vtable.start_addr <= group.end_addr + 0x20)
        });

        if !same_group {
            if let Some(group) = current_group.take() {
                groups.push(group);
            }
            current_id += 1;
            current_group = Some(VTableGroup {
                group_id: current_id,
                section: vtable.section.clone(),
                start_addr: vtable.start_addr,
                end_addr,
                typeinfo_addr: vtable.typeinfo_addr,
                vtables: vec![vtable.address_point],
            });
        } else if let Some(group) = current_group.as_mut() {
            group.end_addr = end_addr;
            if group.typeinfo_addr.is_none() {
                group.typeinfo_addr = vtable.typeinfo_addr;
            }
            group.vtables.push(vtable.address_point);
        }

        vtable.group_id = current_id;
    }

    if let Some(group) = current_group {
        groups.push(group);
    }

    groups
}

fn analyze_function(
    binary: &LoadedBinary,
    func: &FunctionInfo,
    vtables: &[VTableInfo],
    vtable_index: &VTableIndex,
) -> FunctionAnalysis {
    let bytes = binary.function_bytes(func).unwrap_or(&[]);
    let mut env = HashMap::new();
    let mut references = Vec::new();
    let mut edges = Vec::new();
    let mut known_vtables = BTreeSet::new();
    let mut unresolved_indirect_sites = 0usize;

    let mut offset = 0usize;
    let mut pc = func.addr;
    while offset + 4 <= bytes.len() {
        let word = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        let next_pc = if offset + 8 <= bytes.len() {
            Some(pc + 4)
        } else {
            None
        };

        if let Ok(insn) = bad64::decode(word, pc) {
            let lifted = lifter::lift(&insn, pc, next_pc);
            collect_label_references(
                binary,
                vtables,
                vtable_index,
                &lifted.disasm,
                pc,
                insn.op(),
                insn.operands(),
                &mut references,
                &mut known_vtables,
            );
            process_stmt(
                binary,
                func,
                vtables,
                vtable_index,
                pc,
                &lifted.disasm,
                &lifted.stmt,
                &mut env,
                &mut references,
                &mut edges,
                &mut known_vtables,
                &mut unresolved_indirect_sites,
            );
        }

        offset += 4;
        pc += 4;
    }

    let unique_function_targets = collect_unique_targets(&references, AddressKind::Function);
    let unique_code_targets = collect_unique_targets(&references, AddressKind::Code);
    let unique_data_targets = collect_unique_targets(&references, AddressKind::Data);

    FunctionAnalysis {
        report: FunctionPointerRefs {
            function_addr: func.addr,
            function_size: func.size,
            name: func.name.clone(),
            reference_count: references.len(),
            unique_function_targets,
            unique_code_targets,
            unique_data_targets,
            references,
        },
        edges,
        unresolved_indirect_sites,
    }
}

#[allow(clippy::too_many_arguments)]
fn process_stmt(
    binary: &LoadedBinary,
    func: &FunctionInfo,
    vtables: &[VTableInfo],
    vtable_index: &VTableIndex,
    instruction_addr: u64,
    disassembly: &str,
    stmt: &Stmt,
    env: &mut HashMap<Reg, Expr>,
    references: &mut Vec<FunctionPointerReference>,
    edges: &mut Vec<CallGraphEdge>,
    known_vtables: &mut BTreeSet<u64>,
    unresolved_indirect_sites: &mut usize,
) {
    match stmt {
        Stmt::Assign { dst, src } => {
            let resolved = resolve_expr(src, env, &mut HashSet::new(), 12);
            if let Some(target_addr) = pointer_value(&resolved) {
                let target = classify_target(binary, target_addr);
                if target.kind != AddressKind::Unknown {
                    if let Some(vtable_addr) = vtable_index.normalize_vtable_addr(vtables, target_addr) {
                        known_vtables.insert(vtable_addr);
                    }
                    references.push(FunctionPointerReference {
                        instruction_addr,
                        disassembly: disassembly.to_string(),
                        kind: if contains_pc_relative(src) {
                            FunctionReferenceKind::PcRelative
                        } else {
                            FunctionReferenceKind::DirectOperand
                        },
                        expression: format!("{:?}", resolved),
                        via_register: Some(reg_name(dst)),
                        target: Some(target),
                        slot_offset: None,
                        resolved_vtable_addr: None,
                        candidate_targets: Vec::new(),
                    });
                }
            } else if let Expr::Load { addr, .. } = &resolved {
                let resolved_addr = resolve_expr(addr, env, &mut HashSet::new(), 12);
                if let Some(target_addr) = pointer_value(&resolved_addr) {
                    let target = classify_target(binary, target_addr);
                    if target.kind != AddressKind::Unknown {
                        references.push(FunctionPointerReference {
                            instruction_addr,
                            disassembly: disassembly.to_string(),
                            kind: FunctionReferenceKind::MemoryAddress,
                            expression: format!("{:?}", resolved_addr),
                            via_register: Some(reg_name(dst)),
                            target: Some(target),
                            slot_offset: None,
                            resolved_vtable_addr: None,
                            candidate_targets: Vec::new(),
                        });
                    }
                }
            }
            assign_register(env, dst.clone(), resolved);
        }
        Stmt::Store { addr, value, .. } => {
            let resolved_addr = resolve_expr(addr, env, &mut HashSet::new(), 12);
            if let Some(target_addr) = pointer_value(&resolved_addr) {
                let target = classify_target(binary, target_addr);
                if target.kind != AddressKind::Unknown {
                    references.push(FunctionPointerReference {
                        instruction_addr,
                        disassembly: disassembly.to_string(),
                        kind: FunctionReferenceKind::MemoryAddress,
                        expression: format!("{:?}", resolved_addr),
                        via_register: None,
                        target: Some(target),
                        slot_offset: None,
                        resolved_vtable_addr: None,
                        candidate_targets: Vec::new(),
                    });
                }
            }

            let resolved_value = resolve_expr(value, env, &mut HashSet::new(), 12);
            if let Some(target_addr) = pointer_value(&resolved_value) {
                let target = classify_target(binary, target_addr);
                if target.kind != AddressKind::Unknown {
                    if let Some(vtable_addr) = vtable_index.normalize_vtable_addr(vtables, target_addr) {
                        known_vtables.insert(vtable_addr);
                    }
                    references.push(FunctionPointerReference {
                        instruction_addr,
                        disassembly: disassembly.to_string(),
                        kind: FunctionReferenceKind::StoredPointer,
                        expression: format!("{:?}", resolved_value),
                        via_register: None,
                        target: Some(target),
                        slot_offset: None,
                        resolved_vtable_addr: None,
                        candidate_targets: Vec::new(),
                    });
                }
            }
        }
        Stmt::Call { target } => {
            let raw_target = target.clone();
            let resolved = resolve_expr(target, env, &mut HashSet::new(), 12);
            if let Some(target_addr) = pointer_value(&resolved) {
                let target_info = classify_target(binary, target_addr);
                if target_info.kind.is_executable() {
                    references.push(FunctionPointerReference {
                        instruction_addr,
                        disassembly: disassembly.to_string(),
                        kind: FunctionReferenceKind::CallTarget,
                        expression: format!("{:?}", resolved),
                        via_register: register_name_from_expr(&raw_target),
                        target: Some(target_info.clone()),
                        slot_offset: None,
                        resolved_vtable_addr: None,
                        candidate_targets: Vec::new(),
                    });
                    if let Some(callee) = target_info.function_addr {
                        edges.push(CallGraphEdge {
                            from: func.addr,
                            from_name: func.name.clone(),
                            to: callee,
                            to_name: binary
                                .functions
                                .iter()
                                .find(|candidate| candidate.addr == callee)
                                .and_then(|candidate| candidate.name.clone()),
                            instruction_addr,
                            kind: CallEdgeKind::DirectCall,
                            vtable_addr: None,
                            slot_offset: None,
                        });
                    }
                }
            } else if let Some(slot_access) = extract_vtable_slot_access(&resolved) {
                let mut candidate_functions = BTreeSet::new();
                let mut edge_kind = None;
                let resolved_vtable_addr = slot_access
                    .resolved_vtable_addr
                    .and_then(|addr| vtable_index.normalize_vtable_addr(vtables, addr));

                if let Some(vtable_addr) = resolved_vtable_addr {
                    for target in vtable_index.resolve_slot_in_vtable(vtables, vtable_addr, slot_access.slot_offset) {
                        candidate_functions.insert(target);
                    }
                    edge_kind = Some(CallEdgeKind::IndirectVtableExact);
                }

                if candidate_functions.is_empty() && !known_vtables.is_empty() {
                    for &vtable_addr in known_vtables.iter() {
                        for target in vtable_index.resolve_slot_in_vtable(vtables, vtable_addr, slot_access.slot_offset) {
                            candidate_functions.insert(target);
                        }
                    }
                    if !candidate_functions.is_empty() {
                        edge_kind = Some(CallEdgeKind::IndirectVtableReferenced);
                    }
                }

                if candidate_functions.is_empty() {
                    let fallback = vtable_index.resolve_slot_fallback(slot_access.slot_offset);
                    if !fallback.is_empty() && fallback.len() <= MAX_SLOT_FALLBACK_TARGETS {
                        candidate_functions.extend(fallback);
                        edge_kind = Some(CallEdgeKind::IndirectVtableSlotFallback);
                    }
                }

                let candidate_targets = candidate_functions
                    .iter()
                    .copied()
                    .map(|addr| classify_target(binary, addr))
                    .collect::<Vec<_>>();

                if candidate_targets.is_empty() {
                    *unresolved_indirect_sites += 1;
                } else if let Some(kind) = edge_kind {
                    for &target in &candidate_functions {
                        edges.push(CallGraphEdge {
                            from: func.addr,
                            from_name: func.name.clone(),
                            to: target,
                            to_name: binary
                                .functions
                                .iter()
                                .find(|candidate| candidate.addr == target)
                                .and_then(|candidate| candidate.name.clone()),
                            instruction_addr,
                            kind,
                            vtable_addr: resolved_vtable_addr,
                            slot_offset: Some(slot_access.slot_offset),
                        });
                    }
                }

                references.push(FunctionPointerReference {
                    instruction_addr,
                    disassembly: disassembly.to_string(),
                    kind: FunctionReferenceKind::IndirectCallVtable,
                    expression: format!("{:?}", resolved),
                    via_register: register_name_from_expr(&raw_target),
                    target: None,
                    slot_offset: Some(slot_access.slot_offset),
                    resolved_vtable_addr,
                    candidate_targets,
                });
            }
            invalidate_caller_saved(env);
        }
        Stmt::Branch { target } => {
            let resolved = resolve_expr(target, env, &mut HashSet::new(), 12);
            if let Some(target_addr) = pointer_value(&resolved) {
                let target_info = classify_target(binary, target_addr);
                if target_info.kind.is_executable() && target_info.function_addr != Some(func.addr) {
                    references.push(FunctionPointerReference {
                        instruction_addr,
                        disassembly: disassembly.to_string(),
                        kind: FunctionReferenceKind::TailCallTarget,
                        expression: format!("{:?}", resolved),
                        via_register: register_name_from_expr(target),
                        target: Some(target_info.clone()),
                        slot_offset: None,
                        resolved_vtable_addr: None,
                        candidate_targets: Vec::new(),
                    });
                    if let Some(callee) = target_info.function_addr {
                        edges.push(CallGraphEdge {
                            from: func.addr,
                            from_name: func.name.clone(),
                            to: callee,
                            to_name: binary
                                .functions
                                .iter()
                                .find(|candidate| candidate.addr == callee)
                                .and_then(|candidate| candidate.name.clone()),
                            instruction_addr,
                            kind: CallEdgeKind::TailCall,
                            vtable_addr: None,
                            slot_offset: None,
                        });
                    }
                }
            }
        }
        Stmt::Pair(lhs, rhs) => {
            process_stmt(
                binary,
                func,
                vtables,
                vtable_index,
                instruction_addr,
                disassembly,
                lhs,
                env,
                references,
                edges,
                known_vtables,
                unresolved_indirect_sites,
            );
            process_stmt(
                binary,
                func,
                vtables,
                vtable_index,
                instruction_addr,
                disassembly,
                rhs,
                env,
                references,
                edges,
                known_vtables,
                unresolved_indirect_sites,
            );
        }
        _ => {}
    }
}

fn collect_label_references(
    binary: &LoadedBinary,
    vtables: &[VTableInfo],
    vtable_index: &VTableIndex,
    disassembly: &str,
    instruction_addr: u64,
    op: Op,
    operands: &[Operand],
    references: &mut Vec<FunctionPointerReference>,
    known_vtables: &mut BTreeSet<u64>,
) {
    if matches!(
        op,
        Op::ADR
            | Op::ADRP
            | Op::B
            | Op::BL
            | Op::B_EQ
            | Op::B_NE
            | Op::B_CS
            | Op::B_CC
            | Op::B_MI
            | Op::B_PL
            | Op::B_VS
            | Op::B_VC
            | Op::B_HI
            | Op::B_LS
            | Op::B_GE
            | Op::B_LT
            | Op::B_GT
            | Op::B_LE
            | Op::B_AL
            | Op::B_NV
            | Op::CBZ
            | Op::CBNZ
            | Op::TBZ
            | Op::TBNZ
    ) {
        return;
    }

    for operand in operands {
        let target_addr = match operand {
            Operand::Label(imm) => imm_to_u64(imm),
            _ => continue,
        };

        let target = classify_target(binary, target_addr);
        if target.kind == AddressKind::Unknown {
            continue;
        }

        if let Some(vtable_addr) = vtable_index.normalize_vtable_addr(vtables, target_addr) {
            known_vtables.insert(vtable_addr);
        }

        references.push(FunctionPointerReference {
            instruction_addr,
            disassembly: disassembly.to_string(),
            kind: FunctionReferenceKind::DirectOperand,
            expression: format!("0x{:x}", target_addr),
            via_register: None,
            target: Some(target),
            slot_offset: None,
            resolved_vtable_addr: None,
            candidate_targets: Vec::new(),
        });
    }
}

fn collect_unique_targets(
    references: &[FunctionPointerReference],
    kind: AddressKind,
) -> Vec<TargetInfo> {
    let mut targets = BTreeMap::new();
    for reference in references {
        if let Some(target) = &reference.target {
            if target.kind == kind {
                targets.entry(target.addr).or_insert_with(|| target.clone());
            }
        }
        for target in &reference.candidate_targets {
            if target.kind == kind {
                targets.entry(target.addr).or_insert_with(|| target.clone());
            }
        }
    }
    targets.into_values().collect()
}

fn classify_target(binary: &LoadedBinary, addr: u64) -> TargetInfo {
    if let Some(func) = binary.function_containing(addr) {
        return TargetInfo {
            addr,
            kind: if func.addr == addr {
                AddressKind::Function
            } else {
                AddressKind::Code
            },
            section: binary.section_containing(addr).map(|section| section.name.clone()),
            function_addr: Some(func.addr),
            name: func.name.clone(),
            string_preview: None,
        };
    }

    let alloc_section = binary.section_containing(addr).filter(|section| section.is_alloc);
    if alloc_section.is_some() || binary.contains_vaddr(addr) {
        return TargetInfo {
            addr,
            kind: AddressKind::Data,
            section: alloc_section.map(|section| section.name.clone()),
            function_addr: None,
            name: None,
            string_preview: string_preview(binary, addr),
        };
    }

    TargetInfo {
        addr,
        kind: AddressKind::Unknown,
        section: None,
        function_addr: None,
        name: None,
        string_preview: None,
    }
}

fn bfs_shortest_path(
    start: u64,
    goal: u64,
    max_depth: usize,
    edges: &[CallGraphEdge],
    adjacency: &BTreeMap<u64, Vec<usize>>,
) -> Option<CallPath> {
    if start == goal {
        return Some(CallPath {
            functions: vec![start],
            edges: Vec::new(),
        });
    }

    let mut queue = VecDeque::from([(start, 0usize)]);
    let mut visited = BTreeSet::from([start]);
    let mut predecessor: BTreeMap<u64, (u64, usize)> = BTreeMap::new();

    while let Some((node, depth)) = queue.pop_front() {
        if depth >= max_depth {
            continue;
        }

        let Some(outgoing) = adjacency.get(&node) else {
            continue;
        };

        for &edge_index in outgoing {
            let edge = &edges[edge_index];
            if visited.insert(edge.to) {
                predecessor.insert(edge.to, (node, edge_index));
                if edge.to == goal {
                    return Some(reconstruct_path(start, goal, &predecessor, edges));
                }
                queue.push_back((edge.to, depth + 1));
            }
        }
    }

    None
}

fn collect_all_paths(
    start: u64,
    goal: u64,
    max_depth: usize,
    max_paths: usize,
    edges: &[CallGraphEdge],
    adjacency: &BTreeMap<u64, Vec<usize>>,
) -> Vec<CallPath> {
    let mut results = Vec::new();
    let mut visited = BTreeSet::from([start]);
    let mut path_edges = Vec::new();
    collect_all_paths_inner(
        start,
        goal,
        0,
        max_depth,
        max_paths,
        edges,
        adjacency,
        &mut visited,
        &mut path_edges,
        &mut results,
    );
    results
}

#[allow(clippy::too_many_arguments)]
fn collect_all_paths_inner(
    node: u64,
    goal: u64,
    depth: usize,
    max_depth: usize,
    max_paths: usize,
    edges: &[CallGraphEdge],
    adjacency: &BTreeMap<u64, Vec<usize>>,
    visited: &mut BTreeSet<u64>,
    path_edges: &mut Vec<usize>,
    results: &mut Vec<CallPath>,
) {
    if results.len() >= max_paths {
        return;
    }

    if node == goal {
        results.push(call_path_from_edge_indexes(path_edges, edges));
        return;
    }

    if depth >= max_depth {
        return;
    }

    let Some(outgoing) = adjacency.get(&node) else {
        return;
    };

    for &edge_index in outgoing {
        let edge = &edges[edge_index];
        if !visited.insert(edge.to) {
            continue;
        }

        path_edges.push(edge_index);
        collect_all_paths_inner(
            edge.to,
            goal,
            depth + 1,
            max_depth,
            max_paths,
            edges,
            adjacency,
            visited,
            path_edges,
            results,
        );
        path_edges.pop();
        visited.remove(&edge.to);

        if results.len() >= max_paths {
            return;
        }
    }
}

fn reconstruct_path(
    start: u64,
    goal: u64,
    predecessor: &BTreeMap<u64, (u64, usize)>,
    edges: &[CallGraphEdge],
) -> CallPath {
    let mut edge_indexes = Vec::new();
    let mut cursor = goal;
    while cursor != start {
        let (prev, edge_index) = predecessor[&cursor];
        edge_indexes.push(edge_index);
        cursor = prev;
    }
    edge_indexes.reverse();
    call_path_from_edge_indexes(&edge_indexes, edges)
}

fn call_path_from_edge_indexes(edge_indexes: &[usize], edges: &[CallGraphEdge]) -> CallPath {
    let mut functions = Vec::new();
    let mut path_edges = Vec::new();

    if let Some((&first_index, rest)) = edge_indexes.split_first() {
        functions.push(edges[first_index].from);
        for &edge_index in std::iter::once(&first_index).chain(rest.iter()) {
            let edge = edges[edge_index].clone();
            functions.push(edge.to);
            path_edges.push(edge);
        }
    }

    CallPath {
        functions,
        edges: path_edges,
    }
}

fn assign_register(env: &mut HashMap<Reg, Expr>, dst: Reg, value: Expr) {
    match dst {
        Reg::X(index) => {
            env.remove(&Reg::W(index));
            env.insert(Reg::X(index), value);
        }
        Reg::W(index) => {
            env.remove(&Reg::X(index));
            env.insert(Reg::W(index), value);
        }
        register => {
            env.insert(register, value);
        }
    }
}

fn invalidate_caller_saved(env: &mut HashMap<Reg, Expr>) {
    for index in 0..=18 {
        env.remove(&Reg::X(index));
        env.remove(&Reg::W(index));
    }
    env.remove(&Reg::Flags);
}

fn resolve_expr(
    expr: &Expr,
    env: &HashMap<Reg, Expr>,
    visited: &mut HashSet<Reg>,
    depth: usize,
) -> Expr {
    if depth == 0 {
        return expr.clone();
    }

    match expr {
        Expr::Reg(reg) => {
            if visited.contains(reg) {
                return Expr::Reg(reg.clone());
            }
            let Some(mapped) = env.get(reg) else {
                return Expr::Reg(reg.clone());
            };
            visited.insert(reg.clone());
            let resolved = resolve_expr(mapped, env, visited, depth - 1);
            visited.remove(reg);
            resolved
        }
        Expr::Load { addr, size } => Expr::Load {
            addr: Box::new(resolve_expr(addr, env, visited, depth - 1)),
            size: *size,
        },
        Expr::Add(lhs, rhs) => Expr::Add(
            Box::new(resolve_expr(lhs, env, visited, depth - 1)),
            Box::new(resolve_expr(rhs, env, visited, depth - 1)),
        ),
        Expr::Sub(lhs, rhs) => Expr::Sub(
            Box::new(resolve_expr(lhs, env, visited, depth - 1)),
            Box::new(resolve_expr(rhs, env, visited, depth - 1)),
        ),
        Expr::Mul(lhs, rhs) => Expr::Mul(
            Box::new(resolve_expr(lhs, env, visited, depth - 1)),
            Box::new(resolve_expr(rhs, env, visited, depth - 1)),
        ),
        Expr::Div(lhs, rhs) => Expr::Div(
            Box::new(resolve_expr(lhs, env, visited, depth - 1)),
            Box::new(resolve_expr(rhs, env, visited, depth - 1)),
        ),
        Expr::UDiv(lhs, rhs) => Expr::UDiv(
            Box::new(resolve_expr(lhs, env, visited, depth - 1)),
            Box::new(resolve_expr(rhs, env, visited, depth - 1)),
        ),
        Expr::Neg(inner) => Expr::Neg(Box::new(resolve_expr(inner, env, visited, depth - 1))),
        Expr::Abs(inner) => Expr::Abs(Box::new(resolve_expr(inner, env, visited, depth - 1))),
        Expr::And(lhs, rhs) => Expr::And(
            Box::new(resolve_expr(lhs, env, visited, depth - 1)),
            Box::new(resolve_expr(rhs, env, visited, depth - 1)),
        ),
        Expr::Or(lhs, rhs) => Expr::Or(
            Box::new(resolve_expr(lhs, env, visited, depth - 1)),
            Box::new(resolve_expr(rhs, env, visited, depth - 1)),
        ),
        Expr::Xor(lhs, rhs) => Expr::Xor(
            Box::new(resolve_expr(lhs, env, visited, depth - 1)),
            Box::new(resolve_expr(rhs, env, visited, depth - 1)),
        ),
        Expr::Not(inner) => Expr::Not(Box::new(resolve_expr(inner, env, visited, depth - 1))),
        Expr::Shl(lhs, rhs) => Expr::Shl(
            Box::new(resolve_expr(lhs, env, visited, depth - 1)),
            Box::new(resolve_expr(rhs, env, visited, depth - 1)),
        ),
        Expr::Lsr(lhs, rhs) => Expr::Lsr(
            Box::new(resolve_expr(lhs, env, visited, depth - 1)),
            Box::new(resolve_expr(rhs, env, visited, depth - 1)),
        ),
        Expr::Asr(lhs, rhs) => Expr::Asr(
            Box::new(resolve_expr(lhs, env, visited, depth - 1)),
            Box::new(resolve_expr(rhs, env, visited, depth - 1)),
        ),
        Expr::Ror(lhs, rhs) => Expr::Ror(
            Box::new(resolve_expr(lhs, env, visited, depth - 1)),
            Box::new(resolve_expr(rhs, env, visited, depth - 1)),
        ),
        Expr::SignExtend { src, from_bits } => Expr::SignExtend {
            src: Box::new(resolve_expr(src, env, visited, depth - 1)),
            from_bits: *from_bits,
        },
        Expr::ZeroExtend { src, from_bits } => Expr::ZeroExtend {
            src: Box::new(resolve_expr(src, env, visited, depth - 1)),
            from_bits: *from_bits,
        },
        Expr::Extract { src, lsb, width } => Expr::Extract {
            src: Box::new(resolve_expr(src, env, visited, depth - 1)),
            lsb: *lsb,
            width: *width,
        },
        Expr::Insert {
            dst,
            src,
            lsb,
            width,
        } => Expr::Insert {
            dst: Box::new(resolve_expr(dst, env, visited, depth - 1)),
            src: Box::new(resolve_expr(src, env, visited, depth - 1)),
            lsb: *lsb,
            width: *width,
        },
        Expr::FAdd(lhs, rhs) => Expr::FAdd(
            Box::new(resolve_expr(lhs, env, visited, depth - 1)),
            Box::new(resolve_expr(rhs, env, visited, depth - 1)),
        ),
        Expr::FSub(lhs, rhs) => Expr::FSub(
            Box::new(resolve_expr(lhs, env, visited, depth - 1)),
            Box::new(resolve_expr(rhs, env, visited, depth - 1)),
        ),
        Expr::FMul(lhs, rhs) => Expr::FMul(
            Box::new(resolve_expr(lhs, env, visited, depth - 1)),
            Box::new(resolve_expr(rhs, env, visited, depth - 1)),
        ),
        Expr::FDiv(lhs, rhs) => Expr::FDiv(
            Box::new(resolve_expr(lhs, env, visited, depth - 1)),
            Box::new(resolve_expr(rhs, env, visited, depth - 1)),
        ),
        Expr::FNeg(inner) => Expr::FNeg(Box::new(resolve_expr(inner, env, visited, depth - 1))),
        Expr::FAbs(inner) => Expr::FAbs(Box::new(resolve_expr(inner, env, visited, depth - 1))),
        Expr::FSqrt(inner) => {
            Expr::FSqrt(Box::new(resolve_expr(inner, env, visited, depth - 1)))
        }
        Expr::FMax(lhs, rhs) => Expr::FMax(
            Box::new(resolve_expr(lhs, env, visited, depth - 1)),
            Box::new(resolve_expr(rhs, env, visited, depth - 1)),
        ),
        Expr::FMin(lhs, rhs) => Expr::FMin(
            Box::new(resolve_expr(lhs, env, visited, depth - 1)),
            Box::new(resolve_expr(rhs, env, visited, depth - 1)),
        ),
        Expr::FCvt(inner) => Expr::FCvt(Box::new(resolve_expr(inner, env, visited, depth - 1))),
        Expr::IntToFloat(inner) => {
            Expr::IntToFloat(Box::new(resolve_expr(inner, env, visited, depth - 1)))
        }
        Expr::FloatToInt(inner) => {
            Expr::FloatToInt(Box::new(resolve_expr(inner, env, visited, depth - 1)))
        }
        Expr::CondSelect {
            cond,
            if_true,
            if_false,
        } => Expr::CondSelect {
            cond: *cond,
            if_true: Box::new(resolve_expr(if_true, env, visited, depth - 1)),
            if_false: Box::new(resolve_expr(if_false, env, visited, depth - 1)),
        },
        Expr::Clz(inner) => Expr::Clz(Box::new(resolve_expr(inner, env, visited, depth - 1))),
        Expr::Cls(inner) => Expr::Cls(Box::new(resolve_expr(inner, env, visited, depth - 1))),
        Expr::Rev(inner) => Expr::Rev(Box::new(resolve_expr(inner, env, visited, depth - 1))),
        Expr::Rbit(inner) => Expr::Rbit(Box::new(resolve_expr(inner, env, visited, depth - 1))),
        Expr::Intrinsic { name, operands } => Expr::Intrinsic {
            name: name.clone(),
            operands: operands
                .iter()
                .map(|operand| resolve_expr(operand, env, visited, depth - 1))
                .collect(),
        },
        Expr::Imm(_) | Expr::FImm(_) | Expr::AdrpImm(_) | Expr::AdrImm(_) | Expr::MrsRead(_) => {
            expr.clone()
        }
    }
}

fn immediate_value(expr: &Expr) -> Option<u64> {
    match expr {
        Expr::Imm(value) | Expr::AdrpImm(value) | Expr::AdrImm(value) => Some(*value),
        Expr::ZeroExtend { src, .. } | Expr::SignExtend { src, .. } => immediate_value(src),
        _ => None,
    }
}

fn pointer_value(expr: &Expr) -> Option<u64> {
    match expr {
        Expr::Imm(value) | Expr::AdrpImm(value) | Expr::AdrImm(value) => Some(*value),
        Expr::Add(lhs, rhs) => {
            if let Some(base) = pointer_value(lhs) {
                return immediate_value(rhs).and_then(|offset| base.checked_add(offset));
            }
            if let Some(base) = pointer_value(rhs) {
                return immediate_value(lhs).and_then(|offset| base.checked_add(offset));
            }
            None
        }
        Expr::Sub(lhs, rhs) => {
            let base = pointer_value(lhs)?;
            let offset = immediate_value(rhs)?;
            base.checked_sub(offset)
        }
        Expr::ZeroExtend { src, .. } | Expr::SignExtend { src, .. } => pointer_value(src),
        _ => None,
    }
}

fn contains_pc_relative(expr: &Expr) -> bool {
    match expr {
        Expr::AdrpImm(_) | Expr::AdrImm(_) => true,
        Expr::Load { addr, .. } => contains_pc_relative(addr),
        Expr::Add(lhs, rhs)
        | Expr::Sub(lhs, rhs)
        | Expr::Mul(lhs, rhs)
        | Expr::Div(lhs, rhs)
        | Expr::UDiv(lhs, rhs)
        | Expr::And(lhs, rhs)
        | Expr::Or(lhs, rhs)
        | Expr::Xor(lhs, rhs)
        | Expr::Shl(lhs, rhs)
        | Expr::Lsr(lhs, rhs)
        | Expr::Asr(lhs, rhs)
        | Expr::Ror(lhs, rhs)
        | Expr::FAdd(lhs, rhs)
        | Expr::FSub(lhs, rhs)
        | Expr::FMul(lhs, rhs)
        | Expr::FDiv(lhs, rhs)
        | Expr::FMax(lhs, rhs)
        | Expr::FMin(lhs, rhs) => contains_pc_relative(lhs) || contains_pc_relative(rhs),
        Expr::Neg(inner)
        | Expr::Abs(inner)
        | Expr::Not(inner)
        | Expr::FNeg(inner)
        | Expr::FAbs(inner)
        | Expr::FSqrt(inner)
        | Expr::FCvt(inner)
        | Expr::IntToFloat(inner)
        | Expr::FloatToInt(inner)
        | Expr::Clz(inner)
        | Expr::Cls(inner)
        | Expr::Rev(inner)
        | Expr::Rbit(inner) => contains_pc_relative(inner),
        Expr::SignExtend { src, .. } | Expr::ZeroExtend { src, .. } => contains_pc_relative(src),
        Expr::Extract { src, .. } => contains_pc_relative(src),
        Expr::Insert { dst, src, .. } => contains_pc_relative(dst) || contains_pc_relative(src),
        Expr::CondSelect {
            if_true, if_false, ..
        } => contains_pc_relative(if_true) || contains_pc_relative(if_false),
        Expr::Intrinsic { operands, .. } => operands.iter().any(contains_pc_relative),
        Expr::Reg(_) | Expr::Imm(_) | Expr::FImm(_) | Expr::MrsRead(_) => false,
    }
}

fn extract_vtable_slot_access(expr: &Expr) -> Option<VTableSlotAccess> {
    let Expr::Load { addr, size } = expr else {
        return None;
    };
    if *size != 8 {
        return None;
    }

    let (base, slot_offset) = split_base_offset(addr);
    if !looks_like_vtable_base(base) {
        return None;
    }

    Some(VTableSlotAccess {
        resolved_vtable_addr: pointer_value(base),
        slot_offset,
    })
}

fn split_base_offset(expr: &Expr) -> (&Expr, u64) {
    match expr {
        Expr::Add(lhs, rhs) => {
            if let Some(offset) = immediate_value(rhs) {
                return (lhs, offset);
            }
            if let Some(offset) = immediate_value(lhs) {
                return (rhs, offset);
            }
            (expr, 0)
        }
        Expr::Sub(lhs, rhs) => {
            if let Some(offset) = immediate_value(rhs) {
                return (lhs, 0u64.wrapping_sub(offset));
            }
            (expr, 0)
        }
        _ => (expr, 0),
    }
}

fn looks_like_vtable_base(expr: &Expr) -> bool {
    pointer_value(expr).is_some()
        || matches!(expr, Expr::Load { size: 8, .. } | Expr::Reg(_) | Expr::Add(_, _) | Expr::Sub(_, _))
}

fn register_name_from_expr(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Reg(reg) => Some(reg_name(reg)),
        _ => None,
    }
}

fn reg_name(reg: &Reg) -> String {
    match reg {
        Reg::X(index) => format!("x{}", index),
        Reg::W(index) => format!("w{}", index),
        Reg::SP => "sp".to_string(),
        Reg::PC => "pc".to_string(),
        Reg::XZR => "xzr".to_string(),
        Reg::Flags => "nzcv".to_string(),
        Reg::V(index) => format!("v{}", index),
        Reg::Q(index) => format!("q{}", index),
        Reg::D(index) => format!("d{}", index),
        Reg::S(index) => format!("s{}", index),
        Reg::H(index) => format!("h{}", index),
        Reg::VByte(index) => format!("b{}", index),
    }
}

fn string_preview(binary: &LoadedBinary, addr: u64) -> Option<String> {
    let value = binary.read_string(addr, 64)?;
    if value.len() < 3 {
        return None;
    }
    if value.chars().all(|ch| ch.is_ascii_graphic() || ch == ' ') {
        Some(value)
    } else {
        None
    }
}

fn align_up(value: u64, alignment: u64) -> u64 {
    if alignment == 0 || value % alignment == 0 {
        value
    } else {
        value + (alignment - (value % alignment))
    }
}

fn dedup_u64_vec(values: &mut Vec<u64>) {
    values.sort_unstable();
    values.dedup();
}

fn imm_to_u64(imm: &bad64::Imm) -> u64 {
    match *imm {
        bad64::Imm::Signed(value) => value as u64,
        bad64::Imm::Unsigned(value) => value,
    }
}

fn serialize_hex<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&format!("0x{:x}", value))
}

fn serialize_hex_opt<S>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match value {
        Some(value) => serializer.serialize_some(&format!("0x{:x}", value)),
        None => serializer.serialize_none(),
    }
}

fn serialize_hex_vec<S>(values: &[u64], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.collect_seq(values.iter().map(|value| format!("0x{:x}", value)))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{find_call_paths, scan_function_pointers, scan_pointers, scan_vtables};
    use crate::elf::load_elf;

    fn load_libunreal() -> Option<crate::elf::LoadedBinary> {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let binary_path = manifest_dir.join("../../libUnreal.so");
        if !binary_path.exists() {
            return None;
        }
        load_elf(binary_path.to_str().unwrap()).ok()
    }

    #[test]
    fn pointer_scan_finds_internal_pointers() {
        let Some(binary) = load_libunreal() else {
            return;
        };

        let report = scan_pointers(&binary);
        assert!(report.total_entries > 0);
        assert!(report.function_pointers > 0 || report.code_pointers > 0);
    }

    #[test]
    fn vtable_scan_finds_candidates() {
        let Some(binary) = load_libunreal() else {
            return;
        };

        let report = scan_vtables(&binary);
        assert!(report.total_vtables > 0);
        assert!(report.vtables.iter().any(|vtable| vtable.function_count >= 3));
    }

    #[test]
    fn function_pointer_scan_reports_known_constructor_refs() {
        let Some(binary) = load_libunreal() else {
            return;
        };

        let report = scan_function_pointers(&binary, Some(0x05e66990), 0, 1).unwrap();
        let function = report.functions.first().expect("expected function report");
        assert!(function.reference_count > 0);
        assert!(!function.unique_data_targets.is_empty() || !function.unique_function_targets.is_empty());
    }

    #[test]
    fn call_path_search_returns_shortest_or_none() {
        let Some(binary) = load_libunreal() else {
            return;
        };

        let report = find_call_paths(&binary, 0x05e66990, 0x05e66990, 0, false, 1).unwrap();
        let shortest = report.shortest_path.expect("expected trivial path");
        assert_eq!(shortest.functions, vec![0x05e66990]);
    }
}
