use ascent::ascent;

ascent! {
    pub struct AeonAnalysis;

    // Input relations
    relation inst_in_func(u64, u64);   // (func_addr, inst_addr)
    relation edge(u64, u64);           // (src_addr, dst_addr)

    // Derived: edges where both endpoints belong to the same function
    relation internal_edge(u64, u64, u64); // (func, src, dst)
    internal_edge(func, src, dst) <--
        edge(src, dst),
        inst_in_func(func, src),
        inst_in_func(func, dst);

    // Transitive closure of internal edges within a function
    relation reachable(u64, u64, u64); // (func, src, dst)
    reachable(func, src, dst) <--
        internal_edge(func, src, dst);
    reachable(func, src, dst) <--
        reachable(func, src, mid),
        internal_edge(func, mid, dst);

    // Terminal blocks: instructions in a function with no outgoing internal edge
    relation terminal(u64, u64); // (func, addr)
    terminal(func, addr) <--
        inst_in_func(func, addr),
        !internal_edge(func, addr, _);
}
