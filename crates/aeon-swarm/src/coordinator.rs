use std::sync::{Arc, Mutex};
use std::thread;

use aeon_frontend::service::AeonFrontend;
use serde_json::json;

use crate::agent::AgentRunner;
use crate::blackboard::{merge_writes, BlackboardWrite};
use crate::bridge::DirectBridge;
use crate::claude::ClaudeClient;
use crate::report::build_report;
use crate::types::{AgentOutput, AgentSpec, SwarmConfig, SwarmReport, SwarmRole};

pub struct SwarmCoordinator<C> {
    config: SwarmConfig,
    make_claude: Box<dyn Fn() -> C + Send + Sync>,
    shared_frontend: Arc<Mutex<AeonFrontend>>,
}

impl<C: ClaudeClient + 'static> SwarmCoordinator<C> {
    pub fn new(
        config: SwarmConfig,
        make_claude: impl Fn() -> C + Send + Sync + 'static,
    ) -> Result<Self, String> {
        let mut frontend = AeonFrontend::new();
        frontend
            .call_tool("load_binary", &json!({ "path": config.binary_path }))
            .map_err(|e| format!("Failed to load binary: {}", e))?;

        Ok(Self {
            config,
            make_claude: Box::new(make_claude),
            shared_frontend: Arc::new(Mutex::new(frontend)),
        })
    }

    pub fn run(self) -> Result<SwarmReport, String> {
        let run_id = uuid::Uuid::new_v4().to_string();

        // Phase 1: Scout
        let (scout_outputs, scout_writes) = self.run_phase_scout()?;

        // Merge Scout writes into shared frontend.
        {
            let mut fe = self
                .shared_frontend
                .lock()
                .map_err(|e| format!("mutex poisoned: {}", e))?;
            merge_writes(&scout_writes, &mut fe);
        }

        // Collect Tracer targets.
        let mut tracer_targets: Vec<u64> = scout_outputs
            .iter()
            .flat_map(|o| o.tracer_targets.iter().copied())
            .collect();
        tracer_targets.sort_unstable();
        tracer_targets.dedup();

        // Phase 2: Tracer
        let (tracer_outputs, tracer_writes) = self.run_phase_tracer(&tracer_targets)?;

        {
            let mut fe = self
                .shared_frontend
                .lock()
                .map_err(|e| format!("mutex poisoned: {}", e))?;
            merge_writes(&tracer_writes, &mut fe);
        }

        // Phase 3: Reporter (single agent, no partition)
        let reporter_output = self.run_phase_reporter()?;

        // Assemble all writes in phase order.
        let mut all_writes: Vec<BlackboardWrite> = Vec::new();
        all_writes.extend(scout_writes);
        all_writes.extend(tracer_writes);
        all_writes.extend(reporter_output.writes.clone());

        let all_outputs: Vec<AgentOutput> = scout_outputs
            .into_iter()
            .chain(tracer_outputs)
            .chain(std::iter::once(reporter_output))
            .collect();

        Ok(build_report(
            run_id,
            self.config.binary_path.clone(),
            all_writes,
            tracer_targets,
            all_outputs,
        ))
    }

    fn run_phase_scout(&self) -> Result<(Vec<AgentOutput>, Vec<BlackboardWrite>), String> {
        let partitions = self.partition_functions()?;
        let n_scouts = partitions.len();

        let handles: Vec<_> = partitions
            .into_iter()
            .enumerate()
            .map(|(i, addrs)| {
                let spec = AgentSpec {
                    id: format!("scout-{}", i),
                    role: SwarmRole::Scout,
                    model: self.config.scout_model.clone(),
                    assigned_addrs: addrs,
                    max_tool_calls: self.config.scout_max_tool_calls,
                    max_tokens: 8192,
                };
                let claude = (self.make_claude)();
                let bridge = DirectBridge::from_arc(Arc::clone(&self.shared_frontend));

                thread::spawn(move || AgentRunner::new(spec, claude, bridge).run())
            })
            .collect();

        let mut outputs = Vec::with_capacity(n_scouts);
        for handle in handles {
            outputs.push(
                handle
                    .join()
                    .map_err(|_| "Scout thread panicked".to_string())?,
            );
        }

        let writes: Vec<BlackboardWrite> =
            outputs.iter().flat_map(|o| o.writes.iter().cloned()).collect();

        Ok((outputs, writes))
    }

    fn run_phase_tracer(
        &self,
        targets: &[u64],
    ) -> Result<(Vec<AgentOutput>, Vec<BlackboardWrite>), String> {
        if targets.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }

        let chunks: Vec<Vec<u64>> = targets
            .chunks(
                (targets.len() + self.config.tracer_parallelism - 1)
                    / self.config.tracer_parallelism,
            )
            .map(<[u64]>::to_vec)
            .collect();

        let handles: Vec<_> = chunks
            .into_iter()
            .enumerate()
            .map(|(i, addrs)| {
                let spec = AgentSpec {
                    id: format!("tracer-{}", i),
                    role: SwarmRole::Tracer,
                    model: self.config.tracer_model.clone(),
                    assigned_addrs: addrs,
                    max_tool_calls: self.config.tracer_max_tool_calls,
                    max_tokens: 16384,
                };
                let claude = (self.make_claude)();
                let bridge = DirectBridge::from_arc(Arc::clone(&self.shared_frontend));

                thread::spawn(move || AgentRunner::new(spec, claude, bridge).run())
            })
            .collect();

        let mut outputs = Vec::new();
        for handle in handles {
            outputs.push(
                handle
                    .join()
                    .map_err(|_| "Tracer thread panicked".to_string())?,
            );
        }

        let writes = outputs.iter().flat_map(|o| o.writes.iter().cloned()).collect();
        Ok((outputs, writes))
    }

    fn run_phase_reporter(&self) -> Result<AgentOutput, String> {
        let spec = AgentSpec {
            id: "reporter-0".to_string(),
            role: SwarmRole::Reporter,
            model: self.config.reporter_model.clone(),
            assigned_addrs: Vec::new(),
            max_tool_calls: self.config.reporter_max_tool_calls,
            max_tokens: 8192,
        };
        let claude = (self.make_claude)();
        let bridge = DirectBridge::from_arc(Arc::clone(&self.shared_frontend));

        Ok(AgentRunner::new(spec, claude, bridge).run())
    }

    fn partition_functions(&self) -> Result<Vec<Vec<u64>>, String> {
        let mut fe = self
            .shared_frontend
            .lock()
            .map_err(|e| format!("mutex poisoned: {}", e))?;

        let listing = fe.call_tool(
            "list_functions",
            &json!({ "offset": 0, "limit": 10000 }),
        )?;

        let all_addrs: Vec<u64> = listing["functions"]
            .as_array()
            .ok_or("list_functions returned non-array")?
            .iter()
            .filter_map(|f| {
                f["addr"]
                    .as_str()
                    .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            })
            .collect();

        let chunk_size = self.config.scout_partition_size.max(1);
        let partitions: Vec<Vec<u64>> = all_addrs
            .chunks(chunk_size)
            .map(<[u64]>::to_vec)
            .collect();

        // Limit to configured parallelism.
        let max_scouts = self.config.scout_parallelism;
        if partitions.len() > max_scouts {
            let mut merged = partitions[..max_scouts - 1].to_vec();
            let tail: Vec<u64> = partitions[max_scouts - 1..]
                .iter()
                .flat_map(|p| p.iter().copied())
                .collect();
            merged.push(tail);
            Ok(merged)
        } else {
            Ok(partitions)
        }
    }
}
