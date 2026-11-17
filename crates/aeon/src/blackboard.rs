//! The blackboard: what an analyst (human or agent) has recorded about
//! addresses in the binary. Names, struct definitions and hypotheses live
//! here and nowhere else; everything derived from the binary itself lives in
//! [`crate::function_ir::FunctionArtifacts`].

use std::collections::HashMap;

use regex::Regex;
use serde::Serialize;

#[derive(Debug, Default)]
pub struct Blackboard {
    semantic: HashMap<u64, SemanticContext>,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct SemanticContext {
    pub symbol: Option<String>,
    pub struct_definition: Option<String>,
    pub hypotheses: Vec<String>,
}

impl SemanticContext {
    fn is_empty(&self) -> bool {
        self.symbol.is_none() && self.struct_definition.is_none() && self.hypotheses.is_empty()
    }
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct BlackboardSummary {
    pub entries: usize,
    pub renamed_symbols: usize,
    pub defined_structs: usize,
    pub hypotheses: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AnalysisNameMatch {
    pub address: u64,
    pub analysis_name: String,
}

impl Blackboard {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_analysis_name(&mut self, addr: u64, name: impl Into<String>) -> SemanticContext {
        self.rename_symbol(addr, name)
    }

    pub fn rename_symbol(&mut self, addr: u64, name: impl Into<String>) -> SemanticContext {
        let entry = self.semantic.entry(addr).or_default();
        entry.symbol = Some(name.into());
        entry.clone()
    }

    pub fn define_struct(&mut self, addr: u64, definition: impl Into<String>) -> SemanticContext {
        let entry = self.semantic.entry(addr).or_default();
        entry.struct_definition = Some(definition.into());
        entry.clone()
    }

    pub fn add_hypothesis(&mut self, addr: u64, note: impl Into<String>) -> SemanticContext {
        let note = note.into();
        let entry = self.semantic.entry(addr).or_default();
        if !entry.hypotheses.iter().any(|existing| existing == &note) {
            entry.hypotheses.push(note);
        }
        entry.clone()
    }

    pub fn semantic_context(&self, addr: u64) -> Option<SemanticContext> {
        self.semantic
            .get(&addr)
            .filter(|context| !context.is_empty())
            .cloned()
    }

    pub fn symbol_name(&self, addr: u64) -> Option<&str> {
        self.semantic
            .get(&addr)
            .and_then(|context| context.symbol.as_deref())
    }

    pub fn blackboard_summary(&self) -> BlackboardSummary {
        let mut summary = BlackboardSummary::default();

        for context in self.semantic.values().filter(|context| !context.is_empty()) {
            summary.entries += 1;
            if context.symbol.is_some() {
                summary.renamed_symbols += 1;
            }
            if context.struct_definition.is_some() {
                summary.defined_structs += 1;
            }
            summary.hypotheses += context.hypotheses.len();
        }

        summary
    }

    /// Search renamed symbols attached to addresses using a regex.
    pub fn search_analysis_names(
        &self,
        pattern: &str,
    ) -> Result<Vec<AnalysisNameMatch>, regex::Error> {
        let regex = Regex::new(pattern)?;
        let mut matches = Vec::new();
        let mut seen_addrs = std::collections::HashSet::new();

        for (&addr, context) in &self.semantic {
            if context.is_empty() {
                continue;
            }

            let symbol = context.symbol.as_deref();
            let matched = symbol.is_some_and(|s| regex.is_match(s))
                || context
                    .struct_definition
                    .as_deref()
                    .is_some_and(|s| regex.is_match(s))
                || context.hypotheses.iter().any(|h| regex.is_match(h));

            if matched && seen_addrs.insert(addr) {
                let analysis_name = symbol
                    .unwrap_or_else(|| {
                        context
                            .struct_definition
                            .as_deref()
                            .or_else(|| context.hypotheses.first().map(|h| h.as_str()))
                            .unwrap_or("")
                    })
                    .to_string();
                matches.push(AnalysisNameMatch {
                    address: addr,
                    analysis_name,
                });
            }
        }

        matches.sort_by(|lhs, rhs| {
            lhs.address
                .cmp(&rhs.address)
                .then(lhs.analysis_name.cmp(&rhs.analysis_name))
        });
        Ok(matches)
    }
}

#[cfg(test)]
mod tests {
    use super::{AnalysisNameMatch, Blackboard, SemanticContext};

    #[test]
    fn analysis_name_search_matches_regex() {
        let mut engine = Blackboard::new();
        engine.set_analysis_name(0x1010, "rc4_candidate");
        engine.set_analysis_name(0x2020, "aes_round");

        let matches = engine.search_analysis_names("^rc4_.*$").unwrap();

        assert_eq!(
            matches,
            vec![AnalysisNameMatch {
                address: 0x1010,
                analysis_name: "rc4_candidate".to_string(),
            }]
        );
    }

    #[test]
    fn semantic_context_accumulates_mutations_without_duplicate_hypotheses() {
        let mut engine = Blackboard::new();
        engine.rename_symbol(0x1000, "load_plugin_manifest");
        engine.define_struct(0x1000, "NetworkPacket { size: u32, data: char* }");
        engine.add_hypothesis(
            0x1000,
            "This looks like a custom stream cipher initialization block",
        );
        engine.add_hypothesis(
            0x1000,
            "This looks like a custom stream cipher initialization block",
        );

        assert_eq!(
            engine.semantic_context(0x1000),
            Some(SemanticContext {
                symbol: Some("load_plugin_manifest".to_string()),
                struct_definition: Some("NetworkPacket { size: u32, data: char* }".to_string()),
                hypotheses: vec![
                    "This looks like a custom stream cipher initialization block".to_string(),
                ],
            })
        );

        let summary = engine.blackboard_summary();
        assert_eq!(summary.entries, 1);
        assert_eq!(summary.renamed_symbols, 1);
        assert_eq!(summary.defined_structs, 1);
        assert_eq!(summary.hypotheses, 1);
    }
}
