use criterion::{black_box, criterion_group, criterion_main, Criterion};
use mailparse::parse_mail;
use slog::{o, Discard, Logger};
use zkemail_core::{
    extract_email_body, extract_email_bodies_batch, hash_bytes, hash_bytes_batch, hash_bytes_concat, 
    hash_bytes_small, verify_dkim, verify_dkim_batch, Email, PublicKey,
};

fn create_test_email() -> Email {
    let email_data = include_bytes!("../tests/data/sample_email.eml").to_vec();
    let key_data = b"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1JiK4l6Y9M2Z5C9xTHm1
G9tC2pF3Y6K1x1Y9B8qT5rQ3+Z5C9xTHm1G9tC2pF3Y6K1x1Y9B8qT5rQ3+Z5C9x
THm1G9tC2pF3Y6K1x1Y9B8qT5rQ3+Z5C9xTHm1G9tC2pF3Y6K1x1Y9B8qT5rQ3+Z
5C9xTHm1G9tC2pF3Y6K1x1Y9B8qT5rQ3+Z5C9xTHm1G9tC2pF3Y6K1x1Y9B8qT5r
Q3+Z5C9xTHm1G9tC2pF3Y6K1x1Y9B8qT5rQ3+Z5C9xTHm1G9tC2pF3Y6K1x1Y9B8
qT5rQ3+Z5C9xTHm1G9tC2pF3Y6K1x1Y9B8qT5rQ3+Z5C9xTHm1G9tC2pF3Y6K1x1
Y9B8qT5rQ3+Z5C9xTHm1QIDAQAB
-----END PUBLIC KEY-----";

    Email {
        raw_email: email_data,
        from_domain: "example.com".to_string(),
        public_key: PublicKey {
            key: key_data.to_vec(),
            key_type: "rsa".to_string(),
        },
        external_inputs: vec![],
    }
}

fn bench_parse_email(c: &mut Criterion) {
    let small_email_data = include_bytes!("../tests/data/sample_email.eml");
    let large_email_data = {
        let mut data = small_email_data.to_vec();
        data.extend_from_slice(&vec![b'A'; 50000]); // Make it larger
        data
    };

    c.bench_function("parse_email/small_email", |b| {
        b.iter(|| parse_mail(black_box(small_email_data)).unwrap())
    });

    c.bench_function("parse_email/large_email", |b| {
        b.iter(|| parse_mail(black_box(&large_email_data)).unwrap())
    });
}

fn bench_extract_email_body(c: &mut Criterion) {
    let email_data = include_bytes!("../tests/data/sample_email.eml");
    let parsed_email = parse_mail(email_data).unwrap();

    c.bench_function("extract_email_body", |b| {
        b.iter(|| extract_email_body(black_box(&parsed_email)))
    });
}

fn bench_verify_dkim(c: &mut Criterion) {
    let email = create_test_email();
    let logger = Logger::root(Discard, o!());

    c.bench_function("verify_dkim", |b| {
        b.iter(|| verify_dkim(black_box(&email), black_box(&logger)))
    });
}

fn bench_hash_bytes(c: &mut Criterion) {
    let data = b"Hello, world! This is a test message for hashing.";

    c.bench_function("hash_bytes", |b| {
        b.iter(|| hash_bytes(black_box(data)))
    });
}

fn bench_email_components(c: &mut Criterion) {
    let email_data = include_bytes!("../tests/data/sample_email.eml");
    let parsed_email = parse_mail(email_data).unwrap();

    let mut group = c.benchmark_group("email_components");

    group.bench_function("get_headers", |b| {
        b.iter(|| parsed_email.get_headers())
    });

    group.bench_function("get_body_raw", |b| {
        b.iter(|| parsed_email.get_body_raw())
    });

    group.finish();
}

// New benchmarks for optimized batch functions
fn bench_batch_operations(c: &mut Criterion) {
    let email_data = include_bytes!("../tests/data/sample_email.eml");
    let parsed_email = parse_mail(email_data).unwrap();
    let parsed_emails = vec![&parsed_email; 10];  // 10 identical emails
    
    let small_data = b"Small hash test";
    let medium_data = b"This is a medium-sized piece of data for hash testing with more content";
    let large_data = &vec![b'X'; 1000];
    let batch_data = vec![small_data.as_slice(), medium_data.as_slice(), large_data.as_slice()];
    
    let email = create_test_email();
    let emails = vec![&email; 5];  // 5 identical emails
    let logger = Logger::root(Discard, o!());

    let mut group = c.benchmark_group("batch_operations");

    // Batch email body extraction
    group.bench_function("extract_email_bodies_batch", |b| {
        b.iter(|| extract_email_bodies_batch(black_box(&parsed_emails)))
    });

    // Batch hash operations
    group.bench_function("hash_bytes_batch", |b| {
        b.iter(|| hash_bytes_batch(black_box(&batch_data)))
    });

    group.bench_function("hash_bytes_concat", |b| {
        b.iter(|| hash_bytes_concat(black_box(&batch_data)))
    });
    
    // Small hash optimization
    group.bench_function("hash_bytes_small", |b| {
        b.iter(|| hash_bytes_small(black_box(small_data)))
    });

    // Batch DKIM verification
    group.bench_function("verify_dkim_batch", |b| {
        b.iter(|| verify_dkim_batch(black_box(&emails), black_box(&logger)))
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_parse_email,
    bench_extract_email_body,
    bench_verify_dkim,
    bench_hash_bytes,
    bench_email_components,
    bench_batch_operations
);
criterion_main!(benches);
