use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use mailparse::parse_mail;
use slog::{o, Discard, Logger};
use zkemail_core::{
    extract_email_body, hash_bytes, verify_dkim, verify_email,
    Email, PublicKey,
};

/// Create test emails of various sizes for realistic benchmarking
fn create_test_emails() -> (Email, Email, Email) {
    // Small email (under 1KB)
    let small_email_data = include_bytes!("../tests/data/sample_email.eml").to_vec();

    // Medium email (DKIM email, around 2KB)
    let medium_email_data = include_bytes!("../tests/data/dkim_test_email.eml").to_vec();

    // Large email (artificially extended for performance testing)
    let mut large_email_data = medium_email_data.clone();
    let large_body = "A".repeat(50000); // 50KB additional content
    large_email_data.extend_from_slice(large_body.as_bytes());

    let key_data = b"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1JiK4l6Y9M2Z5C9xTHm1
G9tC2pF3Y6K1x1Y9B8qT5rQ3+Z5C9xTHm1G9tC2pF3Y6K1x1Y9B8qT5rQ3+Z5C9x
THm1G9tC2pF3Y6K1x1Y9B8qT5rQ3+Z5C9xTHm1G9tC2pF3Y6K1x1Y9B8qT5rQ3+Z
5C9xTHm1G9tC2pF3Y6K1x1Y9B8qT5rQ3+Z5C9xTHm1G9tC2pF3Y6K1x1Y9B8qT5r
Q3+Z5C9xTHm1G9tC2pF3Y6K1x1Y9B8qT5rQ3+Z5C9xTHm1G9tC2pF3Y6K1x1Y9B8
qT5rQ3+Z5C9xTHm1G9tC2pF3Y6K1x1Y9B8qT5rQ3+Z5C9xTHm1G9tC2pF3Y6K1x1
Y9B8qT5rQ3+Z5C9xTHm1QIDAQAB
-----END PUBLIC KEY-----";

    let public_key = PublicKey {
        key: key_data.to_vec(),
        key_type: "rsa".to_string(),
    };

    (
        Email {
            raw_email: small_email_data,
            from_domain: "example.com".to_string(),
            public_key: public_key.clone(),
            external_inputs: vec![],
        },
        Email {
            raw_email: medium_email_data,
            from_domain: "gmail.com".to_string(),
            public_key: public_key.clone(),
            external_inputs: vec![],
        },
        Email {
            raw_email: large_email_data,
            from_domain: "bigcorp.com".to_string(),
            public_key,
            external_inputs: vec![],
        },
    )
}

/// Comprehensive email parsing benchmarks across different email sizes
fn bench_email_parsing_comprehensive(c: &mut Criterion) {
    let (small_email, medium_email, large_email) = create_test_emails();

    let mut group = c.benchmark_group("email_parsing_comprehensive");

    // Set throughput for better reporting
    group.throughput(Throughput::Bytes(small_email.raw_email.len() as u64));
    group.bench_with_input(
        BenchmarkId::new("small_email", small_email.raw_email.len()),
        &small_email.raw_email,
        |b, email_data| b.iter(|| parse_mail(black_box(email_data)).unwrap_or_else(|_| Default::default())),
    );

    group.throughput(Throughput::Bytes(medium_email.raw_email.len() as u64));
    group.bench_with_input(
        BenchmarkId::new("medium_email", medium_email.raw_email.len()),
        &medium_email.raw_email,
        |b, email_data| b.iter(|| parse_mail(black_box(email_data)).unwrap_or_else(|_| Default::default())),
    );

    group.throughput(Throughput::Bytes(large_email.raw_email.len() as u64));
    group.bench_with_input(
        BenchmarkId::new("large_email", large_email.raw_email.len()),
        &large_email.raw_email,
        |b, email_data| b.iter(|| parse_mail(black_box(email_data)).unwrap_or_else(|_| Default::default())),
    );

    group.finish();
}

/// Benchmark email body extraction across different sizes
fn bench_email_body_extraction_comprehensive(c: &mut Criterion) {
    let (small_email, medium_email, large_email) = create_test_emails();
    let small_parsed = parse_mail(&small_email.raw_email).unwrap_or_else(|_| Default::default());
    let medium_parsed = parse_mail(&medium_email.raw_email).unwrap_or_else(|_| Default::default());
    let large_parsed = parse_mail(&large_email.raw_email).unwrap_or_else(|_| Default::default());

    let mut group = c.benchmark_group("email_body_extraction_comprehensive");

    group.bench_function("small_email_body", |b| {
        b.iter(|| extract_email_body(black_box(&small_parsed)))
    });

    group.bench_function("medium_email_body", |b| {
        b.iter(|| extract_email_body(black_box(&medium_parsed)))
    });

    group.bench_function("large_email_body", |b| {
        b.iter(|| extract_email_body(black_box(&large_parsed)))
    });

    group.finish();
}

/// Benchmark hash operations with different data sizes
fn bench_hash_operations_comprehensive(c: &mut Criterion) {
    let (small_email, medium_email, large_email) = create_test_emails();

    let mut group = c.benchmark_group("hash_operations_comprehensive");

    // Set throughput for hash operations
    group.throughput(Throughput::Bytes(small_email.raw_email.len() as u64));
    group.bench_function("hash_small_data", |b| {
        b.iter(|| hash_bytes(black_box(&small_email.raw_email)))
    });

    group.throughput(Throughput::Bytes(medium_email.raw_email.len() as u64));
    group.bench_function("hash_medium_data", |b| {
        b.iter(|| hash_bytes(black_box(&medium_email.raw_email)))
    });

    group.throughput(Throughput::Bytes(large_email.raw_email.len() as u64));
    group.bench_function("hash_large_data", |b| {
        b.iter(|| hash_bytes(black_box(&large_email.raw_email)))
    });

    // Individual hash operations for comparison
    group.bench_function("hash_multiple_individual", |b| {
        b.iter(|| {
            let _hash1 = hash_bytes(black_box(&small_email.raw_email));
            let _hash2 = hash_bytes(black_box(&medium_email.raw_email));
            let _hash3 = hash_bytes(black_box(&large_email.raw_email));
        })
    });

    group.finish();
}

/// Benchmark DKIM verification with realistic scenarios
fn bench_dkim_verification_comprehensive(c: &mut Criterion) {
    let (_, medium_email, large_email) = create_test_emails();
    let logger = Logger::root(Discard, o!());

    let mut group = c.benchmark_group("dkim_verification_comprehensive");

    group.bench_function("verify_medium_email", |b| {
        b.iter(|| verify_dkim(black_box(&medium_email), black_box(&logger)))
    });

    group.bench_function("verify_large_email", |b| {
        b.iter(|| verify_dkim(black_box(&large_email), black_box(&logger)))
    });

    group.finish();
}

/// Benchmark complete email verification workflow
fn bench_complete_email_verification(c: &mut Criterion) {
    let (small_email, medium_email, large_email) = create_test_emails();

    let mut group = c.benchmark_group("complete_verification_comprehensive");

    group.bench_function("verify_small_email_complete", |b| {
        b.iter(|| verify_email(black_box(&small_email)))
    });

    group.bench_function("verify_medium_email_complete", |b| {
        b.iter(|| verify_email(black_box(&medium_email)))
    });

    group.bench_function("verify_large_email_complete", |b| {
        b.iter(|| verify_email(black_box(&large_email)))
    });

    group.finish();
}

/// Benchmark realistic workloads simulating production usage
fn bench_realistic_workloads(c: &mut Criterion) {
    let (small_email, medium_email, large_email) = create_test_emails();
    let emails = vec![&small_email, &medium_email, &large_email];

    let mut group = c.benchmark_group("realistic_workloads_comprehensive");

    // Simulate processing a batch of emails
    group.bench_function("process_email_batch", |b| {
        b.iter(|| {
            let results: Vec<_> = emails
                .iter()
                .map(|email| verify_email(black_box(email)))
                .collect();
            black_box(results)
        })
    });

    // Simulate high-frequency single email processing
    group.bench_function("high_frequency_single_email", |b| {
        b.iter(|| verify_email(black_box(&medium_email)))
    });

    group.finish();
}

criterion_group!(
    comprehensive_benches,
    bench_email_parsing_comprehensive,
    bench_email_body_extraction_comprehensive,
    bench_hash_operations_comprehensive,
    bench_dkim_verification_comprehensive,
    bench_complete_email_verification,
    bench_realistic_workloads
);

criterion_main!(comprehensive_benches);
