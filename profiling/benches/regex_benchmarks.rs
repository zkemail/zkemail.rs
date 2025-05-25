use criterion::{black_box, criterion_group, criterion_main, Criterion};
use zkemail_core::{process_regex_parts, CompiledRegex, DFA};

fn create_test_regex_parts() -> Vec<CompiledRegex> {
    // Load the regex DFA data for dollar amount pattern
    vec![
        CompiledRegex {
            verify_re: DFA {
                fwd: include_bytes!("../tests/data/regex_amount_fwd.bin").to_vec(),
                bwd: include_bytes!("../tests/data/regex_amount_bwd.bin").to_vec(),
            },
            captures: Some(vec!["$1,234.56".to_string()]),
        },
        CompiledRegex {
            verify_re: DFA {
                fwd: include_bytes!("../tests/data/regex_txid_fwd.bin").to_vec(),
                bwd: include_bytes!("../tests/data/regex_txid_bwd.bin").to_vec(),
            },
            captures: Some(vec!["ABC123XYZ".to_string()]),
        },
    ]
}

fn bench_process_regex_parts(c: &mut Criterion) {
    let regex_parts = create_test_regex_parts();

    // Create various test inputs with different complexities
    let simple_input = b"This email mentions $123.45 and a transaction ID ABC123.";
    let complex_input = b"This is a more complex email body with multiple matches: $1,234.56, $5,678.90 and transaction IDs: ABC123XYZ and DEF456UVW.";
    let html_input = b"<html><body><p>This is an HTML email with <strong>$1,234.56</strong> and transaction ID <code>ABC123XYZ</code></p></body></html>";

    let mut group = c.benchmark_group("process_regex");

    group.bench_function("simple_input", |b| {
        b.iter(|| process_regex_parts(black_box(&regex_parts), black_box(simple_input)))
    });

    group.bench_function("complex_input", |b| {
        b.iter(|| process_regex_parts(black_box(&regex_parts), black_box(complex_input)))
    });

    group.bench_function("html_input", |b| {
        b.iter(|| process_regex_parts(black_box(&regex_parts), black_box(html_input)))
    });

    group.finish();
}

// Benchmark just the DFA creation part which might be expensive
fn bench_dfa_creation(c: &mut Criterion) {
    use regex_automata::dfa::dense;

    let fwd_data = include_bytes!("../tests/data/regex_amount_fwd.bin");
    let bwd_data = include_bytes!("../tests/data/regex_amount_bwd.bin");

    c.bench_function("dfa_creation", |b| {
        b.iter(|| {
            let fwd = dense::DFA::from_bytes(black_box(fwd_data)).unwrap().0;
            let bwd = dense::DFA::from_bytes(black_box(bwd_data)).unwrap().0;
            black_box((fwd, bwd))
        })
    });
}

criterion_group!(regex_benches, bench_process_regex_parts, bench_dfa_creation);
criterion_main!(regex_benches);
