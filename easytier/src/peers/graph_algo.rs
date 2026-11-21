use core::cmp::Ordering;
use petgraph::{
    Directed,
    algo::Measure,
    graph::{Graph, NodeIndex},
    visit::{EdgeRef, IntoEdges, NodeIndexable, VisitMap, Visitable},
};
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::{collections::BinaryHeap, hash::Hash};

/// `MinScored<K, T>` holds a score `K` and a scored object `T` in
/// a pair for use with a `BinaryHeap`.
///
/// `MinScored` compares in reverse order by the score, so that we can
/// use `BinaryHeap` as a min-heap to extract the score-value pair with the
/// least score.
///
/// **Note:** `MinScored` implements a total order (`Ord`), so that it is
/// possible to use float types as scores.
#[derive(Copy, Clone, Debug)]
pub struct MinScored<K, T>(pub K, pub T);

impl<K: PartialOrd, T> PartialEq for MinScored<K, T> {
    #[inline]
    fn eq(&self, other: &MinScored<K, T>) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl<K: PartialOrd, T> Eq for MinScored<K, T> {}

impl<K: PartialOrd, T> PartialOrd for MinScored<K, T> {
    #[inline]
    fn partial_cmp(&self, other: &MinScored<K, T>) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<K: PartialOrd, T> Ord for MinScored<K, T> {
    #[inline]
    fn cmp(&self, other: &MinScored<K, T>) -> Ordering {
        let a = &self.0;
        let b = &other.0;
        if a == b {
            Ordering::Equal
        } else if a < b {
            Ordering::Greater
        } else if a > b {
            Ordering::Less
        } else if a.ne(a) && b.ne(b) {
            // these are the NaN cases
            Ordering::Equal
        } else if a.ne(a) {
            // Order NaN less, so that it is last in the MinScore order
            Ordering::Less
        } else {
            Ordering::Greater
        }
    }
}

pub type DijkstraResult<K, NodeId> = (HashMap<NodeId, K>, HashMap<NodeId, (NodeId, usize)>);

pub fn dijkstra_with_first_hop<G, F, K>(
    graph: G,
    start: G::NodeId,
    mut edge_cost: F,
) -> DijkstraResult<K, G::NodeId>
where
    G: IntoEdges + Visitable,
    G::NodeId: Eq + Hash + Clone,
    F: FnMut(G::EdgeRef) -> K,
    K: Measure + Copy,
{
    let mut visited = graph.visit_map();
    let mut scores = HashMap::new();
    let mut first_hop = HashMap::new();
    let mut visit_next = BinaryHeap::new();
    let zero_score = K::default();
    scores.insert(start, zero_score);
    visit_next.push(MinScored(zero_score, start));
    first_hop.insert(start, (start, 0));

    while let Some(MinScored(node_score, node)) = visit_next.pop() {
        if visited.is_visited(&node) {
            continue;
        }
        for edge in graph.edges(node) {
            let next = edge.target();
            if visited.is_visited(&next) {
                continue;
            }
            let next_score = node_score + edge_cost(edge);
            match scores.entry(next) {
                Occupied(mut ent) => {
                    if next_score < *ent.get() {
                        *ent.get_mut() = next_score;
                        visit_next.push(MinScored(next_score, next));
                        // 继承前驱的 first_hop，或自己就是第一跳
                        let hop = if node == start {
                            (next, 0)
                        } else {
                            first_hop[&node]
                        };
                        first_hop.insert(next, (hop.0, hop.1 + 1));
                    }
                }
                Vacant(ent) => {
                    ent.insert(next_score);
                    visit_next.push(MinScored(next_score, next));
                    let hop = if node == start {
                        (next, 0)
                    } else {
                        first_hop[&node]
                    };
                    first_hop.insert(next, (hop.0, hop.1 + 1));
                }
            }
        }
        visited.visit(node);
    }

    (scores, first_hop)
}

// ============================ edge-disjoint top-k ============================
//
// Multipath data plane needs, per destination, a set of paths whose links do
// NOT overlap (only non-shared links add real aggregate bandwidth). Generic
// k-shortest allows overlap (`A→B→C→D` and `A→C→D` share `C→D`); we instead
// enumerate EDGE-DISJOINT paths via Bhandari's algorithm. See MP_SQM_PLAN.md §8.

/// Sentinel "unreachable" distance, shared by the residual Bellman-Ford and its
/// callers so the caller's reachability test compares against the exact value
/// the search seeds unreachable nodes with. `i64::MAX / 4` leaves headroom so a
/// `dist[u] + cost` relaxation can never overflow.

/// One edge-disjoint path as an ordered sequence of node ids (`src..=dst`)
/// together with the sum of the original edge costs along it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisjointPath {
    pub nodes: Vec<usize>,
    pub cost: u64,
}

/// Same as [`DisjointPath`] but with `petgraph` `NodeIndex` ids, produced by
/// [`k_edge_disjoint_paths_in_graph`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisjointPathIdx {
    pub nodes: Vec<NodeIndex>,
    pub cost: u64,
}

/// Find up to `k` **edge-disjoint** paths from `src` to `dst` that minimize the
/// total cost, via **Bhandari's algorithm**: iteratively find a shortest path in
/// a residual graph that permits *reversing* arcs of previously-found paths
/// (reversed arc = negative cost), then flow-decompose the union. Unlike naive
/// "remove the shortest path's edges and repeat", this is optimal and never
/// misses an existing disjoint set (a naive removal can wall itself off).
///
/// Nodes are identified by `0..n`. `edges` are directed arcs `(from, to, cost)`;
/// parallel arcs between the same ordered pair collapse to their min cost,
/// self-loops are ignored. Paths are returned sorted by ascending cost; fewer
/// than `k` are returned when the src→dst edge-connectivity is below `k`.
///
/// `budget_factor = Some(a)` drops any returned path whose cost exceeds
/// `a * cheapest_path_cost` (an over-long detour carries ~zero weight anyway);
/// `None` keeps every path found.
pub fn k_edge_disjoint_paths(
    n: usize,
    edges: &[(usize, usize, u64)],
    src: usize,
    dst: usize,
    k: usize,
    budget_factor: Option<f64>,
) -> Vec<DisjointPath> {
    if k == 0 || src == dst || src >= n || dst >= n {
        return Vec::new();
    }

    // Collapse parallel arcs to their min cost.
    let mut cost: HashMap<(usize, usize), u64> = HashMap::new();
    for &(u, v, c) in edges {
        if u == v || u >= n || v >= n {
            continue;
        }
        cost.entry((u, v))
            .and_modify(|e| {
                if c < *e {
                    *e = c;
                }
            })
            .or_insert(c);
    }

    // Forward arcs currently carrying a unit of flow.
    let mut used: HashSet<(usize, usize)> = HashSet::new();

    for _round in 0..k {
        // Residual: unused arcs go forward at +cost; a used arc exposes its
        // reverse at -cost (taking it cancels that forward flow). petgraph's
        // Bellman-Ford takes float weights; path costs are integers well
        // below 2^53, so they stay exact.
        let mut residual: Graph<(), f64> = Graph::with_capacity(n, cost.len());
        for _ in 0..n {
            residual.add_node(());
        }
        for (&(u, v), &c) in &cost {
            if used.contains(&(u, v)) {
                residual.add_edge(NodeIndex::new(v), NodeIndex::new(u), -(c as f64));
            } else {
                residual.add_edge(NodeIndex::new(u), NodeIndex::new(v), c as f64);
            }
        }

        let Ok(paths) = petgraph::algo::bellman_ford(&residual, NodeIndex::new(src)) else {
            break; // defensive: negative cycle
        };
        let dist = &paths.distances;
        if !dist[dst].is_finite() {
            break; // dst no longer reachable → no more disjoint paths
        }

        // Walk dst→src via predecessors, applying each residual arc to `used`.
        let mut cur = dst;
        let mut guard = 0usize;
        while cur != src {
            let Some(prev) = paths.predecessors[cur].map(|node| node.index()) else {
                break;
            };
            // The arc taken was the reversed used arc cur→prev iff its
            // negative cost accounts for the distance step.
            let back = used.contains(&(cur, prev))
                && dist[prev] - cost[&(cur, prev)] as f64 == dist[cur];
            if back {
                // reverse arc prev→cur cancels the forward flow cur→prev
                used.remove(&(cur, prev));
            } else {
                used.insert((prev, cur));
            }
            cur = prev;
            guard += 1;
            if guard > n {
                break; // defensive
            }
        }
    }

    // Flow-decompose `used` (only forward arcs remain) into src→dst paths.
    let mut out: HashMap<usize, Vec<usize>> = HashMap::new();
    for &(u, v) in &used {
        out.entry(u).or_default().push(v);
    }
    let mut paths: Vec<DisjointPath> = Vec::new();
    let branches = out.get(&src).map_or(0, |v| v.len());
    for _ in 0..branches {
        let mut nodes = vec![src];
        let mut total = 0u64;
        let mut cur = src;
        let mut guard = 0usize;
        while cur != dst {
            let Some(nexts) = out.get_mut(&cur) else {
                break;
            };
            let Some(nv) = nexts.pop() else {
                break;
            };
            total += cost.get(&(cur, nv)).copied().unwrap_or(0);
            nodes.push(nv);
            cur = nv;
            guard += 1;
            if guard > n {
                break; // defensive against a malformed residual
            }
        }
        if cur == dst {
            paths.push(DisjointPath { nodes, cost: total });
        }
    }

    paths.sort_by_key(|p| p.cost);
    if let (Some(bf), Some(first)) = (budget_factor, paths.first()) {
        let c0 = first.cost;
        let limit = (((c0 as f64) * bf) as u64).max(c0);
        paths.retain(|p| p.cost <= limit);
    }
    paths
}

/// [`k_edge_disjoint_paths`] adapter for a `petgraph` `Graph` with `usize` edge
/// costs (ET's `PeerGraph`). Node ids are the graph's `NodeIndex`.
pub fn k_edge_disjoint_paths_in_graph<N>(
    graph: &Graph<N, usize, Directed>,
    src: NodeIndex,
    dst: NodeIndex,
    k: usize,
    budget_factor: Option<f64>,
) -> Vec<DisjointPathIdx> {
    let n = graph.node_bound();
    let mut edges = Vec::with_capacity(graph.edge_count());
    for e in graph.edge_indices() {
        if let Some((a, b)) = graph.edge_endpoints(e) {
            let w = graph.edge_weight(e).copied().unwrap_or(0);
            edges.push((a.index(), b.index(), w as u64));
        }
    }
    k_edge_disjoint_paths(n, &edges, src.index(), dst.index(), k, budget_factor)
        .into_iter()
        .map(|p| DisjointPathIdx {
            nodes: p.nodes.into_iter().map(NodeIndex::new).collect(),
            cost: p.cost,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use petgraph::graph::DiGraph;

    #[test]
    fn test_dijkstra_with_first_hop_4node() {
        let mut graph = DiGraph::<&str, u32>::new();
        let a = graph.add_node("a");
        let b = graph.add_node("b");
        let c = graph.add_node("c");
        let d = graph.add_node("d");

        graph.extend_with_edges([(a, b, 1)]);
        graph.extend_with_edges([(b, c, 1)]);
        graph.extend_with_edges([(c, d, 2)]);

        let (scores, first_hop) = dijkstra_with_first_hop(&graph, a, |edge| *edge.weight());

        assert_eq!(scores[&b], 1);
        assert_eq!(scores[&c], 2);
        assert_eq!(scores[&d], 4);

        assert_eq!(first_hop[&b], (b, 1));
        assert_eq!(first_hop[&c], (b, 2));
        assert_eq!(first_hop[&d], (b, 3));
    }

    #[test]
    fn test_dijkstra_with_first_hop() {
        let mut graph = DiGraph::<&str, u32>::new();
        let a = graph.add_node("a");
        let b = graph.add_node("b");
        let c = graph.add_node("c");
        let d = graph.add_node("d");
        let e = graph.add_node("e");

        graph.extend_with_edges([(a, b, 1), (a, c, 2), (b, d, 1), (c, d, 3), (d, e, 1)]);

        let (scores, first_hop) = dijkstra_with_first_hop(&graph, a, |edge| *edge.weight());

        assert_eq!(scores[&b], 1);
        assert_eq!(scores[&c], 2);
        assert_eq!(scores[&d], 2);
        assert_eq!(scores[&e], 3);

        assert_eq!(first_hop[&b], (b, 1));
        assert_eq!(first_hop[&c], (c, 1));
        assert_eq!(first_hop[&d], (b, 2)); // d is reached via b
        assert_eq!(first_hop[&e], (b, 3)); // e is reached via d
    }

    // Assert the returned paths are pairwise edge-disjoint and each runs src→dst.
    fn assert_disjoint(paths: &[DisjointPath], src: usize, dst: usize) {
        let mut arcs = HashSet::new();
        for p in paths {
            assert_eq!(*p.nodes.first().unwrap(), src);
            assert_eq!(*p.nodes.last().unwrap(), dst);
            for w in p.nodes.windows(2) {
                assert!(
                    arcs.insert((w[0], w[1])),
                    "paths share arc {:?}",
                    (w[0], w[1])
                );
            }
        }
    }

    #[test]
    fn k_disjoint_trap_graph_beats_naive_removal() {
        // Classic Bhandari "trap": the shortest path s-a-b-t consumes the middle
        // link a-b, so naively removing it strands any 2nd path — yet two link-
        // disjoint paths (s-a-t, s-b-t) DO exist. Each undirected link = two arcs.
        // s=0 a=1 b=2 t=3
        let edges = vec![
            (0, 1, 1),
            (1, 0, 1), // s-a
            (0, 2, 3),
            (2, 0, 3), // s-b
            (1, 2, 1),
            (2, 1, 1), // a-b
            (1, 3, 3),
            (3, 1, 3), // a-t
            (2, 3, 1),
            (3, 2, 1), // b-t
        ];
        let paths = k_edge_disjoint_paths(4, &edges, 0, 3, 2, None);
        assert_eq!(paths.len(), 2, "must find 2 edge-disjoint paths");
        // optimal total cost is 4 + 4 = 8 (s-a-t and s-b-t), not the greedy trap
        assert_eq!(paths.iter().map(|p| p.cost).sum::<u64>(), 8);
        assert_disjoint(&paths, 0, 3);
    }

    #[test]
    fn k_disjoint_single_path_when_bottleneck() {
        // A sole bridge arc 1->2 caps edge-connectivity at 1, so even k=3 yields
        // one path.
        let edges = vec![
            (0, 1, 1),
            (0, 4, 1),
            (4, 1, 1),
            (1, 2, 1), // sole bridge
            (2, 3, 1),
            (2, 5, 1),
            (5, 3, 1),
        ];
        let paths = k_edge_disjoint_paths(6, &edges, 0, 3, 3, None);
        assert_eq!(paths.len(), 1, "bridge 1->2 admits only one disjoint path");
        assert_disjoint(&paths, 0, 3);
    }

    #[test]
    fn k_disjoint_two_parallel_sorted_by_cost() {
        let edges = vec![
            (0, 1, 5),
            (1, 3, 5), // path A cost 10
            (0, 2, 7),
            (2, 3, 7), // path B cost 14
        ];
        let paths = k_edge_disjoint_paths(4, &edges, 0, 3, 2, None);
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0].cost, 10);
        assert_eq!(paths[1].cost, 14);
        assert_disjoint(&paths, 0, 3);
    }

    #[test]
    fn k_disjoint_budget_filters_long_detour() {
        let edges = vec![
            (0, 1, 5),
            (1, 3, 5), // 10
            (0, 2, 7),
            (2, 3, 7), // 14 > 1.2*10 = 12 → filtered
        ];
        let paths = k_edge_disjoint_paths(4, &edges, 0, 3, 2, Some(1.2));
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].cost, 10);
    }

    #[test]
    fn k_disjoint_in_graph_adapter() {
        let mut g = DiGraph::<&str, usize>::new();
        let s = g.add_node("s");
        let a = g.add_node("a");
        let b = g.add_node("b");
        let t = g.add_node("t");
        g.extend_with_edges([(s, a, 1usize), (a, t, 1usize), (s, b, 1usize), (b, t, 1usize)]);
        let paths = k_edge_disjoint_paths_in_graph(&g, s, t, 2, None);
        assert_eq!(paths.len(), 2);
        for p in &paths {
            assert_eq!(*p.nodes.first().unwrap(), s);
            assert_eq!(*p.nodes.last().unwrap(), t);
        }
    }
}
