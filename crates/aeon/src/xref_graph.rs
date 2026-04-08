use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::time::Instant;

use aeon_reduce::env::RegisterEnv;
use rayon::prelude::*;
use serde::{Serialize, Serializer};

use crate::elf::{FunctionInfo, LoadedBinary};
use crate::il::{Expr, Stmt};
use crate::lifter;
use crate::pointer_analysis::{scan_vtables, VTableInfo};

const POINTER_SIZE: u64 = 8;
const MAX_SLOT_FALLBACK_TARGETS: usize = 8;
const MAX_REFERENCED_VTABLES_PER_SITE: usize = 8;
const MAX_TRACKED_VTABLE_REFERENCES_PER_FUNCTION: usize = MAX_REFERENCED_VTABLES_PER_SITE + 1;
const MAX_FUNCTION_XREF_EDGES: usize = 4096;
const MAX_TRACKED_EXPR_NODES: usize = 32;
const XREF_ENV_RESOLVE_DEPTH: usize = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum XrefNodeId {
    Function(u64),
    VTable(u64),
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum XrefNodeKind {
    Function,
    VTable,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum XrefEdgeKind {
    DirectCall,
    TailCall,
    IndirectVtableExact,
    IndirectVtableReferenced,
    IndirectVtableSlotFallback,
    VtableSlot,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct XrefNodeView {
    pub kind: XrefNodeKind,
    #[serde(serialize_with = "serialize_hex")]
    pub addr: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_id: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_count: Option<usize>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct XrefEdgeView {
    pub from: XrefNodeView,
    pub to: XrefNodeView,
    pub kind: XrefEdgeKind,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_hex_opt"
    )]
    pub instruction_addr: Option<u64>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_hex_opt"
    )]
    pub slot_offset: Option<u64>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct XrefPath {
    pub nodes: Vec<XrefNodeView>,
    pub edges: Vec<XrefEdgeView>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct XrefGraphSummaryReport {
    pub total_nodes: usize,
    pub function_nodes: usize,
    pub vtable_nodes: usize,
    pub active_nodes: usize,
    pub total_edges: usize,
    pub direct_call_edges: usize,
    pub tail_call_edges: usize,
    pub indirect_vtable_exact_edges: usize,
    pub indirect_vtable_referenced_edges: usize,
    pub indirect_vtable_slot_fallback_edges: usize,
    pub vtable_slot_edges: usize,
    pub unresolved_indirect_sites: usize,
    pub truncated_functions: usize,
    pub threads_used: usize,
    pub build_elapsed_ms: u128,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
pub struct XrefGraphBuildStats {
    pub total_function_nodes: usize,
    pub total_vtable_nodes: usize,
    pub total_function_edges: usize,
    pub total_vtable_slot_edges: usize,
    pub direct_call_edges: usize,
    pub tail_call_edges: usize,
    pub indirect_vtable_exact_edges: usize,
    pub indirect_vtable_referenced_edges: usize,
    pub indirect_vtable_slot_fallback_edges: usize,
    pub functions_with_edges: usize,
    pub unresolved_indirect_sites: usize,
    pub truncated_functions: usize,
    pub max_edges_in_function: usize,
    #[serde(serialize_with = "serialize_hex")]
    pub max_edge_function_addr: u64,
    pub threads_used: usize,
    pub elapsed_ms: u128,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct XrefPathSearchReport {
    pub start: XrefNodeView,
    pub goal: XrefNodeView,
    pub max_depth: usize,
    pub shortest_path: Option<XrefPath>,
    pub all_paths: Option<Vec<XrefPath>>,
    pub graph_node_count: usize,
    pub graph_edge_count: usize,
    pub direct_edge_count: usize,
    pub vtable_edge_count: usize,
    pub unresolved_indirect_sites: usize,
}

#[derive(Debug, Clone)]
struct VTableNodeInfo {
    address_point: u64,
    function_count: usize,
    group_id: usize,
    section: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct XrefGraphEdge {
    from: XrefNodeId,
    to: XrefNodeId,
    kind: XrefEdgeKind,
    instruction_addr: Option<u64>,
    slot_offset: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct XrefGraphEdgeKey {
    from: XrefNodeId,
    to: XrefNodeId,
    kind: XrefEdgeKind,
    slot_offset: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
struct VTableSlotAccess {
    resolved_vtable_addr: Option<u64>,
    slot_offset: u64,
}

#[derive(Debug, Default)]
struct VTableLookup {
    address_points: BTreeMap<u64, usize>,
    slot_targets: BTreeMap<u64, Vec<u64>>,
}

impl VTableLookup {
    fn build(vtables: &[VTableInfo]) -> Self {
        let mut lookup = Self::default();

        for (index, vtable) in vtables.iter().enumerate() {
            lookup.address_points.insert(vtable.address_point, index);
            for entry in &vtable.functions {
                if let Some(func_addr) = entry.target.function_addr {
                    lookup
                        .slot_targets
                        .entry(entry.slot_offset)
                        .or_default()
                        .push(func_addr);
                }
            }
        }

        for targets in lookup.slot_targets.values_mut() {
            targets.sort_unstable();
            targets.dedup();
        }

        lookup
    }

    fn normalize_vtable_addr(&self, vtables: &[VTableInfo], addr: u64) -> Option<u64> {
        if self.address_points.contains_key(&addr) {
            return Some(addr);
        }

        let (_, &index) = self.address_points.range(..=addr).next_back()?;
        let vtable = &vtables[index];
        let end = vtable.address_point + vtable.functions.len() as u64 * POINTER_SIZE;
        if addr >= vtable.address_point && addr < end {
            Some(vtable.address_point)
        } else {
            None
        }
    }

    fn resolve_slot_in_vtable(
        &self,
        vtables: &[VTableInfo],
        vtable_addr: u64,
        slot: u64,
    ) -> Vec<u64> {
        let Some(&index) = self.address_points.get(&vtable_addr) else {
            return Vec::new();
        };

        vtables[index]
            .functions
            .iter()
            .filter(|entry| entry.slot_offset == slot)
            .filter_map(|entry| entry.target.function_addr)
            .collect()
    }

    fn resolve_slot_fallback(&self, slot: u64) -> &[u64] {
        self.slot_targets
            .get(&slot)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}

#[derive(Debug, Default)]
struct GraphBuildState {
    edges: Vec<XrefGraphEdge>,
    unresolved_indirect_sites: usize,
    truncated: bool,
}

pub struct XrefGraph {
    edges: Vec<XrefGraphEdge>,
    adjacency: HashMap<XrefNodeId, Vec<usize>>,
    vtables: Vec<VTableNodeInfo>,
    total_functions: usize,
    unresolved_indirect_sites: usize,
    truncated_functions: usize,
    build_elapsed_ms: u128,
    threads_used: usize,
}

impl XrefGraph {
    pub fn estimate(
        binary: &LoadedBinary,
        threads: Option<usize>,
    ) -> Result<XrefGraphBuildStats, String> {
        let mut builder = rayon::ThreadPoolBuilder::new();
        if let Some(thread_count) = threads {
            builder = builder.num_threads(thread_count.max(1));
        }
        let pool = builder
            .build()
            .map_err(|error| format!("failed to build xref graph thread pool: {}", error))?;

        let started = Instant::now();
        let vtable_report = scan_vtables(binary);
        let lookup = VTableLookup::build(&vtable_report.vtables);
        let total_vtable_slot_edges = vtable_report
            .vtables
            .iter()
            .map(|vtable| {
                vtable
                    .functions
                    .iter()
                    .filter(|entry| entry.target.function_addr.is_some())
                    .count()
            })
            .sum::<usize>();

        let tally = pool.install(|| {
            binary
                .functions
                .par_iter()
                .map(|func| {
                    let state = analyze_function(binary, func, &vtable_report.vtables, &lookup);
                    let mut tally = XrefGraphBuildStats {
                        total_function_nodes: 1,
                        total_vtable_nodes: 0,
                        total_function_edges: state.edges.len(),
                        total_vtable_slot_edges: 0,
                        functions_with_edges: usize::from(!state.edges.is_empty()),
                        unresolved_indirect_sites: state.unresolved_indirect_sites,
                        truncated_functions: usize::from(state.truncated),
                        max_edges_in_function: state.edges.len(),
                        max_edge_function_addr: func.addr,
                        threads_used: 0,
                        elapsed_ms: 0,
                        ..Default::default()
                    };

                    for edge in state.edges {
                        match edge.kind {
                            XrefEdgeKind::DirectCall => tally.direct_call_edges += 1,
                            XrefEdgeKind::TailCall => tally.tail_call_edges += 1,
                            XrefEdgeKind::IndirectVtableExact => {
                                tally.indirect_vtable_exact_edges += 1
                            }
                            XrefEdgeKind::IndirectVtableReferenced => {
                                tally.indirect_vtable_referenced_edges += 1
                            }
                            XrefEdgeKind::IndirectVtableSlotFallback => {
                                tally.indirect_vtable_slot_fallback_edges += 1
                            }
                            XrefEdgeKind::VtableSlot => {}
                        }
                    }

                    tally
                })
                .reduce(XrefGraphBuildStats::default, merge_graph_build_stats)
        });

        Ok(XrefGraphBuildStats {
            total_function_nodes: binary.functions.len(),
            total_vtable_nodes: vtable_report.vtables.len(),
            total_function_edges: tally.total_function_edges,
            total_vtable_slot_edges,
            direct_call_edges: tally.direct_call_edges,
            tail_call_edges: tally.tail_call_edges,
            indirect_vtable_exact_edges: tally.indirect_vtable_exact_edges,
            indirect_vtable_referenced_edges: tally.indirect_vtable_referenced_edges,
            indirect_vtable_slot_fallback_edges: tally.indirect_vtable_slot_fallback_edges,
            functions_with_edges: tally.functions_with_edges,
            unresolved_indirect_sites: tally.unresolved_indirect_sites,
            truncated_functions: tally.truncated_functions,
            max_edges_in_function: tally.max_edges_in_function,
            max_edge_function_addr: tally.max_edge_function_addr,
            threads_used: pool.current_num_threads(),
            elapsed_ms: started.elapsed().as_millis(),
        })
    }

    pub fn build(binary: &LoadedBinary, threads: Option<usize>) -> Result<Self, String> {
        let mut builder = rayon::ThreadPoolBuilder::new();
        if let Some(thread_count) = threads {
            builder = builder.num_threads(thread_count.max(1));
        }
        let pool = builder
            .build()
            .map_err(|error| format!("failed to build xref graph thread pool: {}", error))?;

        let started = Instant::now();
        let vtable_report = scan_vtables(binary);
        let lookup = VTableLookup::build(&vtable_report.vtables);

        let vtable_nodes = vtable_report
            .vtables
            .iter()
            .map(|vtable| VTableNodeInfo {
                address_point: vtable.address_point,
                function_count: vtable.function_count,
                group_id: vtable.group_id,
                section: vtable.section.clone(),
            })
            .collect::<Vec<_>>();

        let states = pool.install(|| {
            binary
                .functions
                .par_iter()
                .map(|func| analyze_function(binary, func, &vtable_report.vtables, &lookup))
                .collect::<Vec<_>>()
        });

        let unresolved_indirect_sites = states
            .iter()
            .map(|state| state.unresolved_indirect_sites)
            .sum::<usize>();
        let truncated_functions = states.iter().filter(|state| state.truncated).count();
        let total_function_edges = states.iter().map(|state| state.edges.len()).sum::<usize>();
        let total_vtable_slot_edges = vtable_report
            .vtables
            .iter()
            .map(|vtable| {
                vtable
                    .functions
                    .iter()
                    .filter(|entry| entry.target.function_addr.is_some())
                    .count()
            })
            .sum::<usize>();

        let mut edges = Vec::with_capacity(total_function_edges + total_vtable_slot_edges);
        let mut adjacency: HashMap<XrefNodeId, Vec<usize>> = HashMap::new();

        for vtable in &vtable_report.vtables {
            let mut seen = HashSet::new();
            for entry in &vtable.functions {
                let Some(func_addr) = entry.target.function_addr else {
                    continue;
                };

                let edge = XrefGraphEdge {
                    from: XrefNodeId::VTable(vtable.address_point),
                    to: XrefNodeId::Function(func_addr),
                    kind: XrefEdgeKind::VtableSlot,
                    instruction_addr: None,
                    slot_offset: Some(entry.slot_offset),
                };

                if seen.insert(edge_key(&edge)) {
                    let index = edges.len();
                    adjacency.entry(edge.from).or_default().push(index);
                    edges.push(edge);
                }
            }
        }

        for state in states {
            for edge in state.edges {
                let index = edges.len();
                adjacency.entry(edge.from).or_default().push(index);
                edges.push(edge);
            }
        }

        Ok(Self {
            edges,
            adjacency,
            vtables: vtable_nodes,
            total_functions: binary.functions.len(),
            unresolved_indirect_sites,
            truncated_functions,
            build_elapsed_ms: started.elapsed().as_millis(),
            threads_used: pool.current_num_threads(),
        })
    }

    pub fn summary(&self) -> XrefGraphSummaryReport {
        let mut direct_call_edges = 0usize;
        let mut tail_call_edges = 0usize;
        let mut indirect_vtable_exact_edges = 0usize;
        let mut indirect_vtable_referenced_edges = 0usize;
        let mut indirect_vtable_slot_fallback_edges = 0usize;
        let mut vtable_slot_edges = 0usize;
        let mut active_nodes = HashSet::new();

        for edge in &self.edges {
            active_nodes.insert(edge.from);
            active_nodes.insert(edge.to);
            match edge.kind {
                XrefEdgeKind::DirectCall => direct_call_edges += 1,
                XrefEdgeKind::TailCall => tail_call_edges += 1,
                XrefEdgeKind::IndirectVtableExact => indirect_vtable_exact_edges += 1,
                XrefEdgeKind::IndirectVtableReferenced => indirect_vtable_referenced_edges += 1,
                XrefEdgeKind::IndirectVtableSlotFallback => {
                    indirect_vtable_slot_fallback_edges += 1
                }
                XrefEdgeKind::VtableSlot => vtable_slot_edges += 1,
            }
        }

        XrefGraphSummaryReport {
            total_nodes: self.total_functions + self.vtables.len(),
            function_nodes: self.total_functions,
            vtable_nodes: self.vtables.len(),
            active_nodes: active_nodes.len(),
            total_edges: self.edges.len(),
            direct_call_edges,
            tail_call_edges,
            indirect_vtable_exact_edges,
            indirect_vtable_referenced_edges,
            indirect_vtable_slot_fallback_edges,
            vtable_slot_edges,
            unresolved_indirect_sites: self.unresolved_indirect_sites,
            truncated_functions: self.truncated_functions,
            threads_used: self.threads_used,
            build_elapsed_ms: self.build_elapsed_ms,
        }
    }

    pub fn find_paths(
        &self,
        binary: &LoadedBinary,
        start_addr: u64,
        goal_addr: u64,
        max_depth: usize,
        include_all_paths: bool,
        max_paths: usize,
    ) -> Result<XrefPathSearchReport, String> {
        let start = self
            .resolve_node(binary, start_addr)
            .ok_or_else(|| format!("No graph node containing 0x{:x}", start_addr))?;
        let goal = self
            .resolve_node(binary, goal_addr)
            .ok_or_else(|| format!("No graph node containing 0x{:x}", goal_addr))?;

        if start == goal {
            let node = self.node_view(binary, start);
            return Ok(XrefPathSearchReport {
                start: node.clone(),
                goal: node,
                max_depth,
                shortest_path: Some(XrefPath {
                    nodes: vec![self.node_view(binary, start)],
                    edges: Vec::new(),
                }),
                all_paths: include_all_paths.then(|| {
                    vec![XrefPath {
                        nodes: vec![self.node_view(binary, start)],
                        edges: Vec::new(),
                    }]
                }),
                graph_node_count: self.total_functions + self.vtables.len(),
                graph_edge_count: self.edges.len(),
                direct_edge_count: self
                    .edges
                    .iter()
                    .filter(|edge| {
                        matches!(edge.kind, XrefEdgeKind::DirectCall | XrefEdgeKind::TailCall)
                    })
                    .count(),
                vtable_edge_count: self
                    .edges
                    .iter()
                    .filter(|edge| {
                        !matches!(edge.kind, XrefEdgeKind::DirectCall | XrefEdgeKind::TailCall)
                    })
                    .count(),
                unresolved_indirect_sites: self.unresolved_indirect_sites,
            });
        }

        let shortest_path = bfs_shortest_path(start, goal, max_depth, &self.edges, &self.adjacency)
            .map(|path| self.path_view(binary, &path));
        let all_paths = if include_all_paths {
            Some(
                collect_all_paths(
                    start,
                    goal,
                    max_depth,
                    max_paths.max(1),
                    &self.edges,
                    &self.adjacency,
                )
                .into_iter()
                .map(|path| self.path_view(binary, &path))
                .collect(),
            )
        } else {
            None
        };

        Ok(XrefPathSearchReport {
            start: self.node_view(binary, start),
            goal: self.node_view(binary, goal),
            max_depth,
            shortest_path,
            all_paths,
            graph_node_count: self.total_functions + self.vtables.len(),
            graph_edge_count: self.edges.len(),
            direct_edge_count: self
                .edges
                .iter()
                .filter(|edge| {
                    matches!(edge.kind, XrefEdgeKind::DirectCall | XrefEdgeKind::TailCall)
                })
                .count(),
            vtable_edge_count: self
                .edges
                .iter()
                .filter(|edge| {
                    !matches!(edge.kind, XrefEdgeKind::DirectCall | XrefEdgeKind::TailCall)
                })
                .count(),
            unresolved_indirect_sites: self.unresolved_indirect_sites,
        })
    }

    fn resolve_node(&self, binary: &LoadedBinary, addr: u64) -> Option<XrefNodeId> {
        if let Some(func) = binary.function_containing(addr) {
            return Some(XrefNodeId::Function(func.addr));
        }

        self.normalize_vtable_addr(addr).map(XrefNodeId::VTable)
    }

    fn normalize_vtable_addr(&self, addr: u64) -> Option<u64> {
        let index = self
            .vtables
            .partition_point(|vtable| vtable.address_point <= addr);
        if index == 0 {
            return None;
        }

        let vtable = &self.vtables[index - 1];
        let end = vtable.address_point + vtable.function_count as u64 * POINTER_SIZE;
        if addr >= vtable.address_point && addr < end {
            Some(vtable.address_point)
        } else {
            None
        }
    }

    fn node_view(&self, binary: &LoadedBinary, node: XrefNodeId) -> XrefNodeView {
        match node {
            XrefNodeId::Function(addr) => {
                let function = binary.functions.iter().find(|func| func.addr == addr);
                XrefNodeView {
                    kind: XrefNodeKind::Function,
                    addr,
                    name: function.and_then(|func| func.name.clone()),
                    section: Some(".text".to_string()),
                    group_id: None,
                    function_count: None,
                }
            }
            XrefNodeId::VTable(addr) => {
                let vtable = self
                    .vtables
                    .iter()
                    .find(|candidate| candidate.address_point == addr)
                    .expect("vtable node should exist");
                XrefNodeView {
                    kind: XrefNodeKind::VTable,
                    addr,
                    name: None,
                    section: Some(vtable.section.clone()),
                    group_id: Some(vtable.group_id),
                    function_count: Some(vtable.function_count),
                }
            }
        }
    }

    fn edge_view(&self, binary: &LoadedBinary, edge: &XrefGraphEdge) -> XrefEdgeView {
        XrefEdgeView {
            from: self.node_view(binary, edge.from),
            to: self.node_view(binary, edge.to),
            kind: edge.kind,
            instruction_addr: edge.instruction_addr,
            slot_offset: edge.slot_offset,
        }
    }

    fn path_view(&self, binary: &LoadedBinary, path: &InternalPath) -> XrefPath {
        XrefPath {
            nodes: path
                .nodes
                .iter()
                .copied()
                .map(|node| self.node_view(binary, node))
                .collect(),
            edges: path
                .edge_indexes
                .iter()
                .map(|&index| self.edge_view(binary, &self.edges[index]))
                .collect(),
        }
    }
}

fn merge_graph_build_stats(
    mut left: XrefGraphBuildStats,
    right: XrefGraphBuildStats,
) -> XrefGraphBuildStats {
    left.total_function_nodes += right.total_function_nodes;
    left.total_vtable_nodes += right.total_vtable_nodes;
    left.total_function_edges += right.total_function_edges;
    left.total_vtable_slot_edges += right.total_vtable_slot_edges;
    left.direct_call_edges += right.direct_call_edges;
    left.tail_call_edges += right.tail_call_edges;
    left.indirect_vtable_exact_edges += right.indirect_vtable_exact_edges;
    left.indirect_vtable_referenced_edges += right.indirect_vtable_referenced_edges;
    left.indirect_vtable_slot_fallback_edges += right.indirect_vtable_slot_fallback_edges;
    left.functions_with_edges += right.functions_with_edges;
    left.unresolved_indirect_sites += right.unresolved_indirect_sites;
    left.truncated_functions += right.truncated_functions;
    if right.max_edges_in_function > left.max_edges_in_function {
        left.max_edges_in_function = right.max_edges_in_function;
        left.max_edge_function_addr = right.max_edge_function_addr;
    }
    left
}

fn analyze_function(
    binary: &LoadedBinary,
    func: &FunctionInfo,
    vtables: &[VTableInfo],
    lookup: &VTableLookup,
) -> GraphBuildState {
    let Some(bytes) = binary.function_bytes(func) else {
        return GraphBuildState::default();
    };

    let mut env = RegisterEnv::new();
    let mut known_vtables = BTreeSet::new();
    let mut edges = Vec::new();
    let mut edge_keys = HashSet::new();
    let mut unresolved_indirect_sites = 0usize;
    let mut truncated = false;

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
            process_stmt(
                func.addr,
                binary,
                vtables,
                lookup,
                pc,
                &lifted.stmt,
                &mut env,
                &mut known_vtables,
                &mut edges,
                &mut edge_keys,
                &mut unresolved_indirect_sites,
                &mut truncated,
            );
        }

        offset += 4;
        pc += 4;
    }

    GraphBuildState {
        edges,
        unresolved_indirect_sites,
        truncated,
    }
}

#[allow(clippy::too_many_arguments)]
fn process_stmt(
    func_addr: u64,
    binary: &LoadedBinary,
    vtables: &[VTableInfo],
    lookup: &VTableLookup,
    instruction_addr: u64,
    stmt: &Stmt,
    env: &mut RegisterEnv,
    known_vtables: &mut BTreeSet<u64>,
    edges: &mut Vec<XrefGraphEdge>,
    edge_keys: &mut HashSet<XrefGraphEdgeKey>,
    unresolved_indirect_sites: &mut usize,
    truncated: &mut bool,
) {
    match stmt {
        Stmt::Assign { dst, src } => {
            let resolved = resolve_for_xrefs(env, src);
            if let Some(target_addr) = pointer_value(&resolved) {
                record_vtable_reference(
                    func_addr,
                    target_addr,
                    vtables,
                    lookup,
                    known_vtables,
                    instruction_addr,
                );
            } else if let Expr::Load { addr, .. } = &resolved {
                if let Some(target_addr) = pointer_value(&resolve_for_xrefs(env, addr)) {
                    record_vtable_reference(
                        func_addr,
                        target_addr,
                        vtables,
                        lookup,
                        known_vtables,
                        instruction_addr,
                    );
                }
            }
            if expr_node_count(&resolved, MAX_TRACKED_EXPR_NODES + 1) <= MAX_TRACKED_EXPR_NODES {
                env.assign(dst.clone(), resolved);
            } else {
                env.remove(dst);
            }
        }
        Stmt::Store { addr, value, .. } => {
            if let Some(target_addr) = pointer_value(&resolve_for_xrefs(env, addr)) {
                record_vtable_reference(
                    func_addr,
                    target_addr,
                    vtables,
                    lookup,
                    known_vtables,
                    instruction_addr,
                );
            }
            if let Some(target_addr) = pointer_value(&resolve_for_xrefs(env, value)) {
                record_vtable_reference(
                    func_addr,
                    target_addr,
                    vtables,
                    lookup,
                    known_vtables,
                    instruction_addr,
                );
            }
        }
        Stmt::Call { target } => {
            let resolved = resolve_for_xrefs(env, target);
            if let Some(target_addr) = pointer_value(&resolved) {
                if let Some(callee) = binary
                    .function_containing(target_addr)
                    .map(|func| func.addr)
                {
                    record_edge(
                        edges,
                        edge_keys,
                        XrefGraphEdge {
                            from: XrefNodeId::Function(func_addr),
                            to: XrefNodeId::Function(callee),
                            kind: XrefEdgeKind::DirectCall,
                            instruction_addr: Some(instruction_addr),
                            slot_offset: None,
                        },
                        truncated,
                    );
                } else {
                    record_vtable_reference(
                        func_addr,
                        target_addr,
                        vtables,
                        lookup,
                        known_vtables,
                        instruction_addr,
                    );
                }
            } else if let Some(slot_access) = extract_vtable_slot_access(&resolved) {
                let resolved_vtable_addr = slot_access
                    .resolved_vtable_addr
                    .filter(|addr| lookup.address_points.contains_key(addr));

                let mut candidate_functions = BTreeSet::new();

                if let Some(vtable_addr) = resolved_vtable_addr {
                    for target in
                        lookup.resolve_slot_in_vtable(vtables, vtable_addr, slot_access.slot_offset)
                    {
                        candidate_functions.insert(target);
                    }

                    if !candidate_functions.is_empty() {
                        record_edge(
                            edges,
                            edge_keys,
                            XrefGraphEdge {
                                from: XrefNodeId::Function(func_addr),
                                to: XrefNodeId::VTable(vtable_addr),
                                kind: XrefEdgeKind::IndirectVtableExact,
                                instruction_addr: Some(instruction_addr),
                                slot_offset: Some(slot_access.slot_offset),
                            },
                            truncated,
                        );
                    }
                }

                if candidate_functions.is_empty()
                    && !known_vtables.is_empty()
                    && known_vtables.len() <= MAX_REFERENCED_VTABLES_PER_SITE
                {
                    for &vtable_addr in known_vtables.iter() {
                        for target in lookup.resolve_slot_in_vtable(
                            vtables,
                            vtable_addr,
                            slot_access.slot_offset,
                        ) {
                            candidate_functions.insert(target);
                        }
                    }
                }

                if candidate_functions.is_empty() {
                    let fallback = lookup.resolve_slot_fallback(slot_access.slot_offset);
                    if !fallback.is_empty() && fallback.len() <= MAX_SLOT_FALLBACK_TARGETS {
                        for &target in fallback {
                            record_edge(
                                edges,
                                edge_keys,
                                XrefGraphEdge {
                                    from: XrefNodeId::Function(func_addr),
                                    to: XrefNodeId::Function(target),
                                    kind: XrefEdgeKind::IndirectVtableSlotFallback,
                                    instruction_addr: Some(instruction_addr),
                                    slot_offset: Some(slot_access.slot_offset),
                                },
                                truncated,
                            );
                        }
                    } else {
                        *unresolved_indirect_sites += 1;
                    }
                }
            }
            env.invalidate_caller_saved();
        }
        Stmt::Branch { target } => {
            let resolved = resolve_for_xrefs(env, target);
            if let Some(target_addr) = pointer_value(&resolved) {
                if let Some(callee) = binary
                    .function_containing(target_addr)
                    .map(|func| func.addr)
                {
                    if callee != func_addr {
                        record_edge(
                            edges,
                            edge_keys,
                            XrefGraphEdge {
                                from: XrefNodeId::Function(func_addr),
                                to: XrefNodeId::Function(callee),
                                kind: XrefEdgeKind::TailCall,
                                instruction_addr: Some(instruction_addr),
                                slot_offset: None,
                            },
                            truncated,
                        );
                    }
                } else {
                    record_vtable_reference(
                        func_addr,
                        target_addr,
                        vtables,
                        lookup,
                        known_vtables,
                        instruction_addr,
                    );
                }
            }
        }
        Stmt::Pair(lhs, rhs) => {
            process_stmt(
                func_addr,
                binary,
                vtables,
                lookup,
                instruction_addr,
                lhs,
                env,
                known_vtables,
                edges,
                edge_keys,
                unresolved_indirect_sites,
                truncated,
            );
            process_stmt(
                func_addr,
                binary,
                vtables,
                lookup,
                instruction_addr,
                rhs,
                env,
                known_vtables,
                edges,
                edge_keys,
                unresolved_indirect_sites,
                truncated,
            );
        }
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn record_vtable_reference(
    func_addr: u64,
    target_addr: u64,
    vtables: &[VTableInfo],
    lookup: &VTableLookup,
    known_vtables: &mut BTreeSet<u64>,
    instruction_addr: u64,
) {
    if let Some(vtable_addr) = lookup.normalize_vtable_addr(vtables, target_addr) {
        if known_vtables.len() < MAX_TRACKED_VTABLE_REFERENCES_PER_FUNCTION {
            known_vtables.insert(vtable_addr);
        }
        let _ = func_addr;
        let _ = instruction_addr;
    }
}

fn record_edge(
    edges: &mut Vec<XrefGraphEdge>,
    edge_keys: &mut HashSet<XrefGraphEdgeKey>,
    edge: XrefGraphEdge,
    truncated: &mut bool,
) {
    let key = edge_key(&edge);
    if edge_keys.contains(&key) {
        return;
    }
    if edge_keys.len() >= MAX_FUNCTION_XREF_EDGES {
        *truncated = true;
        return;
    }
    edge_keys.insert(key);
    edges.push(edge);
}

fn edge_key(edge: &XrefGraphEdge) -> XrefGraphEdgeKey {
    XrefGraphEdgeKey {
        from: edge.from,
        to: edge.to,
        kind: edge.kind,
        slot_offset: edge.slot_offset,
    }
}

#[derive(Debug, Clone)]
struct InternalPath {
    nodes: Vec<XrefNodeId>,
    edge_indexes: Vec<usize>,
}

fn bfs_shortest_path(
    start: XrefNodeId,
    goal: XrefNodeId,
    max_depth: usize,
    edges: &[XrefGraphEdge],
    adjacency: &HashMap<XrefNodeId, Vec<usize>>,
) -> Option<InternalPath> {
    let mut queue = VecDeque::from([(start, 0usize)]);
    let mut visited = HashSet::from([start]);
    let mut predecessor: HashMap<XrefNodeId, (XrefNodeId, usize)> = HashMap::new();

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
    start: XrefNodeId,
    goal: XrefNodeId,
    max_depth: usize,
    max_paths: usize,
    edges: &[XrefGraphEdge],
    adjacency: &HashMap<XrefNodeId, Vec<usize>>,
) -> Vec<InternalPath> {
    let mut results = Vec::new();
    let mut visited = HashSet::from([start]);
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
    node: XrefNodeId,
    goal: XrefNodeId,
    depth: usize,
    max_depth: usize,
    max_paths: usize,
    edges: &[XrefGraphEdge],
    adjacency: &HashMap<XrefNodeId, Vec<usize>>,
    visited: &mut HashSet<XrefNodeId>,
    path_edges: &mut Vec<usize>,
    results: &mut Vec<InternalPath>,
) {
    if results.len() >= max_paths {
        return;
    }

    if node == goal {
        results.push(path_from_edge_indexes(path_edges, edges));
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
    start: XrefNodeId,
    goal: XrefNodeId,
    predecessor: &HashMap<XrefNodeId, (XrefNodeId, usize)>,
    edges: &[XrefGraphEdge],
) -> InternalPath {
    let mut edge_indexes = Vec::new();
    let mut cursor = goal;
    while cursor != start {
        let (prev, edge_index) = predecessor[&cursor];
        edge_indexes.push(edge_index);
        cursor = prev;
    }
    edge_indexes.reverse();
    path_from_edge_indexes(&edge_indexes, edges)
}

fn path_from_edge_indexes(edge_indexes: &[usize], edges: &[XrefGraphEdge]) -> InternalPath {
    let mut nodes = Vec::new();
    let mut path_edges = Vec::new();

    if let Some((&first_index, rest)) = edge_indexes.split_first() {
        nodes.push(edges[first_index].from);
        for &edge_index in std::iter::once(&first_index).chain(rest.iter()) {
            let edge = &edges[edge_index];
            nodes.push(edge.to);
            path_edges.push(edge_index);
        }
    }

    InternalPath {
        nodes,
        edge_indexes: path_edges,
    }
}

fn resolve_for_xrefs(env: &RegisterEnv, expr: &Expr) -> Expr {
    env.resolve_with_depth(expr, XREF_ENV_RESOLVE_DEPTH)
}

fn expr_node_count(expr: &Expr, limit: usize) -> usize {
    if limit == 0 {
        return 0;
    }

    fn bump(seen: &mut usize, limit: usize) -> bool {
        if *seen >= limit {
            return false;
        }
        *seen += 1;
        *seen < limit
    }

    fn inner(expr: &Expr, seen: &mut usize, limit: usize) {
        if !bump(seen, limit) {
            return;
        }

        match expr {
            Expr::Reg(_)
            | Expr::Imm(_)
            | Expr::FImm(_)
            | Expr::AdrpImm(_)
            | Expr::AdrImm(_)
            | Expr::MrsRead(_)
            | Expr::StackSlot { .. } => {}
            Expr::Load { addr, .. }
            | Expr::Neg(addr)
            | Expr::Abs(addr)
            | Expr::Not(addr)
            | Expr::FNeg(addr)
            | Expr::FAbs(addr)
            | Expr::FSqrt(addr)
            | Expr::FCvt(addr)
            | Expr::IntToFloat(addr)
            | Expr::FloatToInt(addr)
            | Expr::Clz(addr)
            | Expr::Cls(addr)
            | Expr::Rev(addr)
            | Expr::Rbit(addr) => inner(addr, seen, limit),
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
            | Expr::FMin(lhs, rhs)
            | Expr::Compare { lhs, rhs, .. } => {
                inner(lhs, seen, limit);
                inner(rhs, seen, limit);
            }
            Expr::SignExtend { src, .. }
            | Expr::ZeroExtend { src, .. }
            | Expr::Extract { src, .. } => inner(src, seen, limit),
            Expr::Insert { dst, src, .. } => {
                inner(dst, seen, limit);
                inner(src, seen, limit);
            }
            Expr::CondSelect {
                if_true, if_false, ..
            } => {
                inner(if_true, seen, limit);
                inner(if_false, seen, limit);
            }
            Expr::Intrinsic { operands, .. } => {
                for operand in operands {
                    inner(operand, seen, limit);
                    if *seen >= limit {
                        break;
                    }
                }
            }
        }
    }

    let mut seen = 0usize;
    inner(expr, &mut seen, limit);
    seen
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
        || matches!(
            expr,
            Expr::Load { size: 8, .. } | Expr::Reg(_) | Expr::Add(_, _) | Expr::Sub(_, _)
        )
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::PathBuf;

    use super::{XrefEdgeKind, XrefGraph, XrefGraphEdge, XrefNodeId, XrefNodeKind};
    use crate::elf::{load_elf, FunctionInfo, LoadedBinary, SectionInfo, Segment};

    fn sample_binary_path() -> String {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        manifest_dir
            .join("../../samples/hello_aarch64.elf")
            .display()
            .to_string()
    }

    fn tiny_binary() -> LoadedBinary {
        LoadedBinary {
            data: vec![0; 0x1000],
            text_section_file_offset: 0,
            text_section_addr: 0x1000,
            text_section_size: 0x100,
            functions: vec![
                FunctionInfo {
                    addr: 0x1000,
                    size: 0x10,
                    name: Some("start".to_string()),
                },
                FunctionInfo {
                    addr: 0x2000,
                    size: 0x10,
                    name: Some("target".to_string()),
                },
            ],
            segments: vec![Segment {
                file_offset: 0,
                vaddr: 0x1000,
                file_size: 0x1000,
                mem_size: 0x1000,
            }],
            sections: vec![SectionInfo {
                name: ".text".to_string(),
                address: 0x1000,
                size: 0x100,
                file_offset: 0,
                file_size: 0x100,
                is_alloc: true,
                is_writable: false,
                is_executable: true,
            }],
        }
    }

    fn tiny_graph() -> XrefGraph {
        let edges = vec![
            XrefGraphEdge {
                from: XrefNodeId::Function(0x1000),
                to: XrefNodeId::VTable(0x4008),
                kind: XrefEdgeKind::IndirectVtableExact,
                instruction_addr: Some(0x1004),
                slot_offset: Some(0),
            },
            XrefGraphEdge {
                from: XrefNodeId::VTable(0x4008),
                to: XrefNodeId::Function(0x2000),
                kind: XrefEdgeKind::VtableSlot,
                instruction_addr: None,
                slot_offset: Some(0),
            },
        ];
        let mut adjacency = HashMap::new();
        adjacency.insert(XrefNodeId::Function(0x1000), vec![0]);
        adjacency.insert(XrefNodeId::VTable(0x4008), vec![1]);

        XrefGraph {
            edges,
            adjacency,
            vtables: vec![super::VTableNodeInfo {
                address_point: 0x4008,
                function_count: 1,
                group_id: 1,
                section: ".data.rel.ro".to_string(),
            }],
            total_functions: 2,
            unresolved_indirect_sites: 0,
            truncated_functions: 0,
            build_elapsed_ms: 0,
            threads_used: 1,
        }
    }

    #[test]
    fn xref_graph_summary_builds_for_sample_binary() {
        let binary = load_elf(&sample_binary_path()).expect("sample binary should load");
        let graph = XrefGraph::build(&binary, Some(2)).expect("graph should build");
        let summary = graph.summary();
        assert!(summary.function_nodes > 0);
        assert!(summary.total_edges > 0);
        assert_eq!(
            summary.total_nodes,
            summary.function_nodes + summary.vtable_nodes
        );
    }

    #[test]
    fn xref_path_can_traverse_vtable_node() {
        let binary = tiny_binary();
        let graph = tiny_graph();
        let report = graph
            .find_paths(&binary, 0x1000, 0x2000, 3, false, 1)
            .expect("path search should succeed");

        assert_eq!(report.start.kind, XrefNodeKind::Function);
        assert_eq!(report.goal.kind, XrefNodeKind::Function);
        let shortest = report.shortest_path.expect("expected path");
        assert_eq!(shortest.nodes.len(), 3);
        assert_eq!(shortest.nodes[1].kind, XrefNodeKind::VTable);
        assert_eq!(shortest.edges.len(), 2);
    }
}
