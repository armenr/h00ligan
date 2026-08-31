//! Enrichment pipeline: derives structural and risk signals from the knowledge graph.
//!
//! This module computes per-node topology metrics ([`NodeEnrichment`]) and per-file
//! risk scores ([`FileRiskScore`]) from graph structure. It runs as Phase 8c in the
//! index pipeline, after reachability classification and before graph persistence.
//!
//! Design decisions:
//! - DEC-079: structural/temporal signals only (no LLM-derived signals)
//! - DEC-090: NodeEnrichment is separate from GraphNode (enrichment data lives in
//!   EnrichmentStore, not baked into the graph snapshot)

use std::collections::{HashMap, HashSet, VecDeque};

use parking_lot::RwLock;
use tracing::instrument;
use uuid::Uuid;

use crate::git_metrics::FileChurnMetrics;
use crate::graph::{EdgeKind, KnowledgeGraph};
use crate::reachability::ReachabilityClass;

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// Per-node enrichment derived from graph topology.
#[derive(Debug, Clone)]
pub struct NodeEnrichment {
    /// Number of incoming dependency edges (how many symbols depend on this one).
    pub fan_in: u32,
    /// Number of outgoing dependency edges (how many symbols this one depends on).
    pub fan_out: u32,
    /// BFS distance from nearest entry point. `None` if unreachable.
    pub depth_from_entry: Option<u16>,
    /// Whether at least one test-only node can reach this node via forward edges.
    pub has_test_path: bool,
    /// Ratio of fan_in / (fan_in + fan_out). `None` when denominator is zero.
    pub interface_stability: Option<f32>,
    /// Approximate betweenness centrality, normalized to percentile rank [0.0, 1.0].
    pub centrality_percentile: f32,
}

/// Categorical risk factor contributing to a file's risk score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RiskFactor {
    /// File contains symbols with fan_in above the 90th percentile.
    HighFanIn,
    /// File contains symbols with centrality above the 90th percentile.
    HighCentrality,
    /// File has a high ratio of Dead/Orphan nodes relative to total.
    HighDeadRatio,
    /// File has high churn (many recent commits). Requires git metrics.
    HighChurn,
    /// File has many distinct authors. Requires git metrics.
    ManyAuthors,
    /// File has Wired symbols that lack any test path.
    UntestedWiredSymbols,
}

/// Aggregated risk assessment for a source file.
#[derive(Debug, Clone)]
pub struct FileRiskScore {
    /// Weighted risk score in [0.0, 1.0] after quantile normalization.
    pub risk_score: f32,
    /// Which risk factors contributed to this score.
    pub risk_factors: Vec<RiskFactor>,
}

// ---------------------------------------------------------------------------
// EnrichmentStore — runtime container
// ---------------------------------------------------------------------------

/// Thread-safe runtime container for enrichment data.
///
/// Uses three independent `parking_lot::RwLock`s so reads on node enrichments
/// do not block reads on file risk scores (and vice versa).
pub struct EnrichmentStore {
    node_enrichments: RwLock<HashMap<Uuid, NodeEnrichment>>,
    file_risk_scores: RwLock<HashMap<String, FileRiskScore>>,
    file_churn_metrics: RwLock<HashMap<String, FileChurnMetrics>>,
}

impl EnrichmentStore {
    /// Create an empty enrichment store.
    #[instrument(level = "debug")]
    pub fn new() -> Self {
        Self {
            node_enrichments: RwLock::new(HashMap::new()),
            file_risk_scores: RwLock::new(HashMap::new()),
            file_churn_metrics: RwLock::new(HashMap::new()),
        }
    }

    /// Look up enrichment data for a single node.
    #[instrument(level = "debug", skip(self), fields(id = %id))]
    pub fn node_enrichment(&self, id: &Uuid) -> Option<NodeEnrichment> {
        self.node_enrichments.read().get(id).cloned()
    }

    /// Look up risk score for a file path.
    #[instrument(level = "debug", skip(self))]
    pub fn file_risk(&self, path: &str) -> Option<FileRiskScore> {
        self.file_risk_scores.read().get(path).cloned()
    }

    /// Look up churn metrics for a file path.
    #[instrument(level = "debug", skip(self))]
    pub fn file_churn(&self, path: &str) -> Option<FileChurnMetrics> {
        self.file_churn_metrics.read().get(path).cloned()
    }

    /// Bulk-replace all node enrichments.
    #[instrument(level = "debug", skip(self, enrichments), fields(count = enrichments.len()))]
    pub fn set_node_enrichments(&self, enrichments: HashMap<Uuid, NodeEnrichment>) {
        *self.node_enrichments.write() = enrichments;
    }

    /// Bulk-replace all file risk scores.
    #[instrument(level = "debug", skip(self, scores), fields(count = scores.len()))]
    pub fn set_file_risk_scores(&self, scores: HashMap<String, FileRiskScore>) {
        *self.file_risk_scores.write() = scores;
    }

    /// Bulk-replace all file churn metrics.
    #[instrument(level = "debug", skip(self, metrics), fields(count = metrics.len()))]
    pub fn set_file_churn_metrics(&self, metrics: HashMap<String, FileChurnMetrics>) {
        *self.file_churn_metrics.write() = metrics;
    }
}

impl Default for EnrichmentStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Edge filter (D001: fan-in/fan-out excludes Contains)
// ---------------------------------------------------------------------------

/// Returns `true` for edge kinds that represent dependency relationships
/// suitable for fan-in/fan-out and centrality computation.
///
/// Intentionally excludes `Contains` (parent-child nesting) and other
/// structural edges that would inflate fan counts.
const fn is_enrichment_dep(kind: &EdgeKind) -> bool {
    matches!(
        kind,
        EdgeKind::Calls | EdgeKind::Implements | EdgeKind::References | EdgeKind::TypeOf
    )
}

// ---------------------------------------------------------------------------
// compute_node_enrichments
// ---------------------------------------------------------------------------

/// Compute per-node enrichment from graph topology.
///
/// Runs four passes over the graph:
/// 1. **Fan-in / fan-out** O(V+E): count dependency edges per node.
/// 2. **Depth from entry** O(V+E): multi-root BFS from entry points.
/// 3. **Has test path** O(V+E): forward BFS from TestOnly entry points.
/// 4. **Betweenness centrality** O(K*(V+E)): approximate Brandes with K sampled sources.
#[instrument(level = "debug", skip(graph))]
pub fn compute_node_enrichments(graph: &KnowledgeGraph) -> HashMap<Uuid, NodeEnrichment> {
    let nodes = graph.all_nodes();
    if nodes.is_empty() {
        return HashMap::new();
    }

    let node_ids: Vec<Uuid> = nodes.iter().map(|n| n.memory_id).collect();
    let node_count = node_ids.len();

    // Initialize enrichments with defaults.
    let mut enrichments: HashMap<Uuid, NodeEnrichment> = node_ids
        .iter()
        .map(|&id| {
            (
                id,
                NodeEnrichment {
                    fan_in: 0,
                    fan_out: 0,
                    depth_from_entry: None,
                    has_test_path: false,
                    interface_stability: None,
                    centrality_percentile: 0.0,
                },
            )
        })
        .collect();

    // ------------------------------------------------------------------
    // Pass 1: Fan-in / Fan-out  O(V+E)
    // ------------------------------------------------------------------
    let all_edges = graph.all_edges();
    for (src_id, tgt_id, edge) in &all_edges {
        if !is_enrichment_dep(&edge.kind) {
            continue;
        }
        if let Some(src_enr) = enrichments.get_mut(src_id) {
            src_enr.fan_out += 1;
        }
        if let Some(tgt_enr) = enrichments.get_mut(tgt_id) {
            tgt_enr.fan_in += 1;
        }
    }

    // Derive interface_stability = fan_in / (fan_in + fan_out).
    for enr in enrichments.values_mut() {
        let denom = enr.fan_in + enr.fan_out;
        if denom > 0 {
            enr.interface_stability = Some(enr.fan_in as f32 / denom as f32);
        }
    }

    // ------------------------------------------------------------------
    // Pass 2: Depth from entry  O(V+E)
    // Multi-root BFS from Wired/PublicApi nodes with fan_in == 0, or
    // nodes whose symbol_name contains "main".
    // ------------------------------------------------------------------
    let mut bfs_queue: VecDeque<(Uuid, u16)> = VecDeque::new();
    let mut visited_depth: HashSet<Uuid> = HashSet::new();

    for node in &nodes {
        let is_entry = match node.reachability_class {
            ReachabilityClass::Wired | ReachabilityClass::PublicApi => enrichments
                .get(&node.memory_id)
                .is_some_and(|e| e.fan_in == 0),
            _ => false,
        };
        let is_main = node.symbol_name.contains("main")
            && matches!(
                node.reachability_class,
                ReachabilityClass::Wired | ReachabilityClass::PublicApi
            );
        if is_entry || is_main {
            bfs_queue.push_back((node.memory_id, 0));
            visited_depth.insert(node.memory_id);
            if let Some(enr) = enrichments.get_mut(&node.memory_id) {
                enr.depth_from_entry = Some(0);
            }
        }
    }

    while let Some((current_id, depth)) = bfs_queue.pop_front() {
        let next_depth = depth.saturating_add(1);
        for (neighbor_id, edge) in graph.neighbors(&current_id) {
            if !is_enrichment_dep(&edge.kind) {
                continue;
            }
            if visited_depth.insert(neighbor_id) {
                if let Some(enr) = enrichments.get_mut(&neighbor_id) {
                    enr.depth_from_entry = Some(next_depth);
                }
                bfs_queue.push_back((neighbor_id, next_depth));
            }
        }
    }

    // ------------------------------------------------------------------
    // Pass 3: Has test path  O(V+E)
    // Forward BFS from TestOnly entry points; reached nodes get has_test_path = true.
    // ------------------------------------------------------------------
    let mut test_queue: VecDeque<Uuid> = VecDeque::new();
    let mut visited_test: HashSet<Uuid> = HashSet::new();

    for node in &nodes {
        if node.reachability_class == ReachabilityClass::TestOnly
            && visited_test.insert(node.memory_id)
        {
            test_queue.push_back(node.memory_id);
        }
    }

    while let Some(current_id) = test_queue.pop_front() {
        if let Some(enr) = enrichments.get_mut(&current_id) {
            enr.has_test_path = true;
        }
        for (neighbor_id, edge) in graph.neighbors(&current_id) {
            if !is_enrichment_dep(&edge.kind) {
                continue;
            }
            if visited_test.insert(neighbor_id) {
                test_queue.push_back(neighbor_id);
            }
        }
    }

    // ------------------------------------------------------------------
    // Pass 4: Approximate betweenness centrality  O(K*(V+E))
    // Brandes algorithm with K = min(100, node_count) sampled source nodes.
    // ------------------------------------------------------------------
    let k = node_count.min(100);
    let mut centrality: HashMap<Uuid, f64> = node_ids.iter().map(|&id| (id, 0.0)).collect();

    // Build a quick adjacency list for BFS (outgoing enrichment deps only).
    let mut adj: HashMap<Uuid, Vec<Uuid>> = HashMap::with_capacity(node_count);
    for &id in &node_ids {
        adj.insert(id, Vec::new());
    }
    for (src, tgt, edge) in &all_edges {
        if is_enrichment_dep(&edge.kind)
            && let Some(neighbors) = adj.get_mut(src)
        {
            neighbors.push(*tgt);
        }
    }

    // Sample K source nodes (evenly spaced to reduce bias vs random).
    let step = node_count.checked_div(k).unwrap_or(1);
    let sampled: Vec<Uuid> = node_ids
        .iter()
        .step_by(step.max(1))
        .take(k)
        .copied()
        .collect();

    for &source in &sampled {
        // Brandes BFS from `source`.
        let mut stack: Vec<Uuid> = Vec::new();
        let mut predecessors: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
        let mut sigma: HashMap<Uuid, f64> = HashMap::new(); // shortest-path count
        let mut dist: HashMap<Uuid, i32> = HashMap::new();

        for &id in &node_ids {
            sigma.insert(id, 0.0);
            dist.insert(id, -1);
            predecessors.insert(id, Vec::new());
        }
        sigma.insert(source, 1.0);
        dist.insert(source, 0);

        let mut queue: VecDeque<Uuid> = VecDeque::new();
        queue.push_back(source);

        while let Some(v) = queue.pop_front() {
            stack.push(v);
            let d_v = dist[&v];
            if let Some(neighbors) = adj.get(&v) {
                for &w in neighbors {
                    let d_w = dist.get(&w).copied().unwrap_or(-1);
                    if d_w < 0 {
                        dist.insert(w, d_v + 1);
                        queue.push_back(w);
                    }
                    if dist.get(&w).copied().unwrap_or(-1) == d_v + 1 {
                        let s_v = sigma[&v];
                        *sigma.entry(w).or_insert(0.0) += s_v;
                        predecessors.entry(w).or_default().push(v);
                    }
                }
            }
        }

        // Back-propagation.
        let mut delta: HashMap<Uuid, f64> = node_ids.iter().map(|&id| (id, 0.0)).collect();
        while let Some(w) = stack.pop() {
            let s_w = sigma[&w];
            if s_w > 0.0 {
                let d_w = delta[&w];
                if let Some(preds) = predecessors.get(&w) {
                    for &v in preds {
                        let s_v = sigma[&v];
                        let contribution = (s_v / s_w) * (1.0 + d_w);
                        *delta.entry(v).or_insert(0.0) += contribution;
                    }
                }
            }
            if w != source {
                *centrality.entry(w).or_insert(0.0) += delta[&w];
            }
        }
    }

    // Normalize centrality to percentile rank [0.0, 1.0].
    let mut centrality_values: Vec<(Uuid, f64)> = centrality.into_iter().collect();
    centrality_values.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

    let total = centrality_values.len();
    for (rank, (id, _value)) in centrality_values.iter().enumerate() {
        if let Some(enr) = enrichments.get_mut(id) {
            enr.centrality_percentile = if total > 1 {
                rank as f32 / (total - 1) as f32
            } else {
                0.0
            };
        }
    }

    enrichments
}

// ---------------------------------------------------------------------------
// compute_file_risk_scores
// ---------------------------------------------------------------------------

/// Compute per-file risk scores from node enrichments and optional churn metrics.
///
/// Groups nodes by `file_path`, detects risk factors using population-level thresholds,
/// computes a weighted raw score, and quantile-normalizes to [0.0, 1.0].
#[instrument(level = "debug", skip(enrichments, graph, churn))]
pub fn compute_file_risk_scores(
    enrichments: &HashMap<Uuid, NodeEnrichment>,
    graph: &KnowledgeGraph,
    churn: Option<&HashMap<String, FileChurnMetrics>>,
) -> HashMap<String, FileRiskScore> {
    let nodes = graph.all_nodes();
    if nodes.is_empty() {
        return HashMap::new();
    }

    // Compute population-level thresholds (90th percentile).
    let mut all_fan_in: Vec<u32> = enrichments.values().map(|e| e.fan_in).collect();
    let mut all_centrality: Vec<f32> = enrichments
        .values()
        .map(|e| e.centrality_percentile)
        .collect();
    all_fan_in.sort_unstable();
    all_centrality.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let p90_fan_in = percentile_u32(&all_fan_in, 0.90);
    let p90_centrality = percentile_f32(&all_centrality, 0.90);

    // Group nodes by file_path.
    let mut file_nodes: HashMap<&str, Vec<&Uuid>> = HashMap::new();
    for node in &nodes {
        file_nodes
            .entry(node.file_path.as_str())
            .or_default()
            .push(&node.memory_id);
    }

    // Build per-file raw scores.
    let mut raw_scores: HashMap<String, (f32, Vec<RiskFactor>)> = HashMap::new();

    for (file_path, node_ids) in &file_nodes {
        let mut factors: Vec<RiskFactor> = Vec::new();
        let mut raw: f32 = 0.0;
        let count = node_ids.len() as f32;

        // Check HighFanIn: any node above the 90th percentile.
        let has_high_fan_in = node_ids
            .iter()
            .any(|id| enrichments.get(*id).is_some_and(|e| e.fan_in > p90_fan_in));
        if has_high_fan_in {
            factors.push(RiskFactor::HighFanIn);
            raw += 2.0;
        }

        // Check HighCentrality: any node above the 90th percentile.
        let has_high_centrality = node_ids.iter().any(|id| {
            enrichments
                .get(*id)
                .is_some_and(|e| e.centrality_percentile > p90_centrality)
        });
        if has_high_centrality {
            factors.push(RiskFactor::HighCentrality);
            raw += 2.0;
        }

        // Check HighDeadRatio: fraction of Dead/Orphan nodes > 0.5.
        let dead_count = node_ids
            .iter()
            .filter(|id| {
                graph.node(id).is_some_and(|n| {
                    matches!(
                        n.reachability_class,
                        ReachabilityClass::Dead | ReachabilityClass::Orphan
                    )
                })
            })
            .count() as f32;
        if count > 0.0 && dead_count / count > 0.5 {
            factors.push(RiskFactor::HighDeadRatio);
            raw += 1.0;
        }

        // Check UntestedWiredSymbols: Wired nodes without a test path.
        let untested_wired = node_ids.iter().any(|id| {
            let is_wired = graph
                .node(id)
                .is_some_and(|n| n.reachability_class == ReachabilityClass::Wired);
            let has_test = enrichments.get(*id).is_some_and(|e| e.has_test_path);
            is_wired && !has_test
        });
        if untested_wired {
            factors.push(RiskFactor::UntestedWiredSymbols);
            raw += 1.5;
        }

        // Check git-based risk factors when churn data is available.
        if let Some(churn_map) = churn
            && let Some(churn_data) = churn_map.get(*file_path)
        {
            if churn_data.is_high_churn() {
                factors.push(RiskFactor::HighChurn);
                raw += 1.5;
            }
            if churn_data.is_many_authors() {
                factors.push(RiskFactor::ManyAuthors);
                raw += 1.0;
            }
        }

        raw_scores.insert(file_path.to_string(), (raw, factors));
    }

    // Quantile-normalize raw scores to [0.0, 1.0].
    let mut sorted_raws: Vec<(String, f32, Vec<RiskFactor>)> = raw_scores
        .into_iter()
        .map(|(path, (raw, factors))| (path, raw, factors))
        .collect();
    sorted_raws.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

    let total_files = sorted_raws.len();
    let mut result: HashMap<String, FileRiskScore> = HashMap::with_capacity(total_files);

    for (rank, (path, _raw, factors)) in sorted_raws.into_iter().enumerate() {
        let normalized = if total_files > 1 {
            rank as f32 / (total_files - 1) as f32
        } else {
            0.0
        };
        result.insert(
            path,
            FileRiskScore {
                risk_score: normalized,
                risk_factors: factors,
            },
        );
    }

    result
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Return the value at a given percentile from a sorted slice.
fn percentile_u32(sorted: &[u32], p: f64) -> u32 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).ceil() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

/// Return the value at a given percentile from a sorted f32 slice.
fn percentile_f32(sorted: &[f32], p: f64) -> f32 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).ceil() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{GraphEdge, GraphNode};

    /// Helper: build a minimal edge with the given kind.
    fn edge(kind: EdgeKind) -> GraphEdge {
        GraphEdge {
            kind,
            weight: 1.0,
            access_count: 0,
            last_accessed_ms: None,
            created_at_ms: None,
            source: Default::default(),
            confidence: 1.0,
            scope: Default::default(),
        }
    }

    /// Helper: build a minimal graph node.
    fn node(name: &str, file: &str) -> GraphNode {
        GraphNode {
            memory_id: Uuid::new_v4(),
            symbol_name: name.to_string(),
            kind: "function".to_string(),
            file_path: file.to_string(),
            content_hash: format!("hash_{name}"),
            signature: format!("fn {name}()"),
            reachability_class: ReachabilityClass::Unclassified,
            line_start: Some(1),
            line_end: Some(10),
            has_body: None,
            visibility: String::new(),
            is_test_only: None,
            is_test_root: false,
            has_platform_cfg: false,
            rustc_flagged_dead: false,
            entry_retain: Default::default(),
            has_uncaptured_items: false,
            oracle_receipt: None,
        }
    }

    #[test]
    fn enrichment_store_concurrent_read_write() {
        let store = EnrichmentStore::new();

        // Initially empty.
        assert!(store.node_enrichment(&Uuid::new_v4()).is_none());
        assert!(store.file_risk("foo.rs").is_none());
        assert!(store.file_churn("foo.rs").is_none());

        // Set and retrieve node enrichments.
        let id = Uuid::new_v4();
        let mut enrichments = HashMap::new();
        enrichments.insert(
            id,
            NodeEnrichment {
                fan_in: 5,
                fan_out: 3,
                depth_from_entry: Some(2),
                has_test_path: true,
                interface_stability: Some(0.625),
                centrality_percentile: 0.8,
            },
        );
        store.set_node_enrichments(enrichments);
        let retrieved = store.node_enrichment(&id).expect("should exist");
        assert_eq!(retrieved.fan_in, 5);
        assert_eq!(retrieved.fan_out, 3);
        assert_eq!(retrieved.depth_from_entry, Some(2));
        assert!(retrieved.has_test_path);

        // Set and retrieve file risk scores.
        let mut risks = HashMap::new();
        risks.insert(
            "foo.rs".to_string(),
            FileRiskScore {
                risk_score: 0.75,
                risk_factors: vec![RiskFactor::HighFanIn],
            },
        );
        store.set_file_risk_scores(risks);
        let risk = store.file_risk("foo.rs").expect("should exist");
        assert!((risk.risk_score - 0.75).abs() < f32::EPSILON);
        assert_eq!(risk.risk_factors, vec![RiskFactor::HighFanIn]);
    }

    #[test]
    fn compute_enrichments_empty_graph() {
        let graph = KnowledgeGraph::new();
        let result = compute_node_enrichments(&graph);
        assert!(result.is_empty());
    }

    #[test]
    fn compute_enrichments_fan_in_fan_out() {
        let mut graph = KnowledgeGraph::new();

        // A -> B -> C  (Calls edges)
        let a = node("a", "src/a.rs");
        let b = node("b", "src/b.rs");
        let c = node("c", "src/c.rs");
        let a_id = a.memory_id;
        let b_id = b.memory_id;
        let c_id = c.memory_id;

        graph.add_node(a).expect("add a");
        graph.add_node(b).expect("add b");
        graph.add_node(c).expect("add c");
        graph
            .add_edge(a_id, b_id, edge(EdgeKind::Calls))
            .expect("a->b");
        graph
            .add_edge(b_id, c_id, edge(EdgeKind::Calls))
            .expect("b->c");

        // Also add a Contains edge that should NOT count.
        graph
            .add_edge(a_id, c_id, edge(EdgeKind::Contains))
            .expect("a->c contains");

        let enrichments = compute_node_enrichments(&graph);

        // A: fan_out=1 (calls B), fan_in=0
        let ea = &enrichments[&a_id];
        assert_eq!(ea.fan_out, 1);
        assert_eq!(ea.fan_in, 0);

        // B: fan_out=1 (calls C), fan_in=1 (called by A)
        let eb = &enrichments[&b_id];
        assert_eq!(eb.fan_out, 1);
        assert_eq!(eb.fan_in, 1);

        // C: fan_out=0, fan_in=1 (called by B)
        let ec = &enrichments[&c_id];
        assert_eq!(ec.fan_out, 0);
        assert_eq!(ec.fan_in, 1);

        // Interface stability: B = 1 / (1+1) = 0.5
        assert!((eb.interface_stability.unwrap() - 0.5).abs() < f32::EPSILON);
        // A: fan_in=0, denom=1, stability = 0.0
        assert!((ea.interface_stability.unwrap() - 0.0).abs() < f32::EPSILON);
        // C: fan_in=1, denom=1, stability = 1.0
        assert!((ec.interface_stability.unwrap() - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn compute_enrichments_depth_and_test_path() {
        let mut graph = KnowledgeGraph::new();

        // Entry -> A -> B  (A is wired, entry is wired with fan_in=0)
        let mut entry = node("main", "src/main.rs");
        entry.reachability_class = ReachabilityClass::Wired;
        let mut a = node("handler", "src/handler.rs");
        a.reachability_class = ReachabilityClass::Wired;
        let b = node("util", "src/util.rs");

        // Test entry -> B (test covers B)
        let mut test = node("test_util", "tests/test.rs");
        test.reachability_class = ReachabilityClass::TestOnly;

        let entry_id = entry.memory_id;
        let a_id = a.memory_id;
        let b_id = b.memory_id;
        let test_id = test.memory_id;

        graph.add_node(entry).expect("add entry");
        graph.add_node(a).expect("add a");
        graph.add_node(b).expect("add b");
        graph.add_node(test).expect("add test");

        graph
            .add_edge(entry_id, a_id, edge(EdgeKind::Calls))
            .expect("entry->a");
        graph
            .add_edge(a_id, b_id, edge(EdgeKind::Calls))
            .expect("a->b");
        graph
            .add_edge(test_id, b_id, edge(EdgeKind::Calls))
            .expect("test->b");

        let enrichments = compute_node_enrichments(&graph);

        // Depth from entry: main=0, handler=1, util=2.
        assert_eq!(enrichments[&entry_id].depth_from_entry, Some(0));
        assert_eq!(enrichments[&a_id].depth_from_entry, Some(1));
        assert_eq!(enrichments[&b_id].depth_from_entry, Some(2));

        // Test path: test_util itself + util (reachable from test).
        assert!(enrichments[&test_id].has_test_path);
        assert!(enrichments[&b_id].has_test_path);
        // Entry and handler are NOT reachable from test entry.
        assert!(!enrichments[&entry_id].has_test_path);
        assert!(!enrichments[&a_id].has_test_path);
    }

    #[test]
    fn compute_file_risk_scores_basic() {
        let mut graph = KnowledgeGraph::new();

        // 3 nodes in same file, one with high fan-in.
        let mut a = node("popular", "src/lib.rs");
        a.reachability_class = ReachabilityClass::Wired;
        let b = node("helper_1", "src/lib.rs");
        let c = node("helper_2", "src/lib.rs");
        let d = node("other", "src/other.rs");

        let a_id = a.memory_id;
        let b_id = b.memory_id;
        let c_id = c.memory_id;
        let d_id = d.memory_id;

        graph.add_node(a).expect("add a");
        graph.add_node(b).expect("add b");
        graph.add_node(c).expect("add c");
        graph.add_node(d).expect("add d");

        // Give "popular" high fan_in by adding many Calls edges to it.
        graph
            .add_edge(b_id, a_id, edge(EdgeKind::Calls))
            .expect("b->a");
        graph
            .add_edge(c_id, a_id, edge(EdgeKind::Calls))
            .expect("c->a");
        graph
            .add_edge(d_id, a_id, edge(EdgeKind::Calls))
            .expect("d->a");

        let enrichments = compute_node_enrichments(&graph);
        let risk_scores = compute_file_risk_scores(&enrichments, &graph, None);

        // We should get scores for both files.
        assert!(risk_scores.contains_key("src/lib.rs"));
        assert!(risk_scores.contains_key("src/other.rs"));

        // lib.rs should have higher risk (has the popular node + untested wired symbol).
        let lib_risk = &risk_scores["src/lib.rs"];
        let other_risk = &risk_scores["src/other.rs"];
        assert!(lib_risk.risk_score >= other_risk.risk_score);
    }

    #[test]
    fn enrichment_store_default() {
        let store = EnrichmentStore::default();
        assert!(store.node_enrichment(&Uuid::new_v4()).is_none());
    }
}
