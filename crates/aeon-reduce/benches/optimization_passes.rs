use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use aeon_reduce::pipeline::reduce_block_local;
use aeonil::{Stmt, Expr, Reg};

// Create a simple linear sequence of assignments for benchmarking
fn create_linear_stmts(n: usize) -> Vec<Stmt> {
    let mut stmts = Vec::with_capacity(n);
    for i in 0..n {
        stmts.push(Stmt::Assign {
            dst: Reg::X((i % 31) as u8),
            src: Expr::Imm((i * 7) as u64),
        });
    }
    stmts
}

// Create IL with constant folding opportunities
fn create_const_fold_stmts() -> Vec<Stmt> {
    vec![
        Stmt::Assign {
            dst: Reg::X(0),
            src: Expr::Imm(0x1000),
        },
        Stmt::Assign {
            dst: Reg::X(1),
            src: Expr::Add(
                Box::new(Expr::Imm(100)),
                Box::new(Expr::Imm(50)),
            ),
        },
        Stmt::Assign {
            dst: Reg::X(2),
            src: Expr::Imm(150),
        },
    ]
}

// Benchmark local IL reductions
fn bench_local_reductions(c: &mut Criterion) {
    let mut group = c.benchmark_group("local_reductions");

    for size in [10, 50, 100, 500].iter() {
        let stmts = create_linear_stmts(*size);
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            size,
            |b, _| {
                b.iter(|| reduce_block_local(black_box(stmts.clone())))
            },
        );
    }
    group.finish();
}

// Benchmark constant folding
fn bench_constant_folding(c: &mut Criterion) {
    c.bench_function("const_fold_simple", |b| {
        let stmts = create_const_fold_stmts();
        b.iter(|| reduce_block_local(black_box(stmts.clone())))
    });
}

// Benchmark small block reduction
fn bench_small_blocks(c: &mut Criterion) {
    let mut group = c.benchmark_group("small_blocks");

    for stmt_count in [1, 5, 10, 20].iter() {
        let stmts = create_linear_stmts(*stmt_count);
        group.bench_with_input(
            BenchmarkId::new("reduce_block", stmt_count),
            stmt_count,
            |b, _| {
                b.iter(|| reduce_block_local(black_box(stmts.clone())))
            },
        );
    }

    group.finish();
}

// Benchmark realistic-sized blocks
fn bench_medium_blocks(c: &mut Criterion) {
    let mut group = c.benchmark_group("medium_blocks");

    for stmt_count in [50, 100, 200].iter() {
        let stmts = create_linear_stmts(*stmt_count);
        group.bench_with_input(
            BenchmarkId::new("reduce_block", stmt_count),
            stmt_count,
            |b, _| {
                b.iter(|| reduce_block_local(black_box(stmts.clone())))
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_local_reductions,
    bench_constant_folding,
    bench_small_blocks,
    bench_medium_blocks,
);

criterion_main!(benches);
