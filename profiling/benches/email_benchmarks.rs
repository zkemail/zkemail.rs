use criterion::{black_box, criterion_group, criterion_main, Criterion};
use mailparse::parse_mail;
use slog::{o, Discard, Logger};
use zkemail_core::{extract_email_body, hash_bytes, verify_dkim, Email, PublicKey};

fn create_test_email(use_dkim_email: bool) -> Email {
    // Load either the regular test email or the DKIM test email
    let raw_email = if use_dkim_email {
        include_bytes!("../tests/data/dkim_test_email.eml").to_vec()
    } else {
        include_bytes!("../tests/data/sample_email.eml").to_vec()
    };

    // Create a mock public key for benchmarking
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

    Email {
        raw_email,
        from_domain: if use_dkim_email {
            "gmail.com"
        } else {
            "example.com"
        }
        .to_string(),
        public_key,
        external_inputs: vec![],
    }
}

fn bench_extract_email_body(c: &mut Criterion) {
    let email = create_test_email(false);
    let parsed_email = parse_mail(&email.raw_email).unwrap();

    c.bench_function("extract_email_body", |b| {
        b.iter(|| extract_email_body(black_box(&parsed_email)))
    });
}

fn bench_verify_dkim(c: &mut Criterion) {
    let email = create_test_email(true);
    let logger = Logger::root(Discard, o!());

    c.bench_function("verify_dkim", |b| {
        b.iter(|| verify_dkim(black_box(&email), black_box(&logger)))
    });
}

fn bench_hash_bytes(c: &mut Criterion) {
    let email = create_test_email(false);

    c.bench_function("hash_bytes", |b| {
        b.iter(|| hash_bytes(black_box(&email.raw_email)))
    });
}

fn bench_parse_email(c: &mut Criterion) {
    // Benchmark with both small and large emails
    let small_email = create_test_email(false);
    let large_email = create_test_email(true); // DKIM email is larger

    let mut group = c.benchmark_group("parse_email");

    group.bench_function("small_email", |b| {
        b.iter(|| parse_mail(black_box(&small_email.raw_email)))
    });

    group.bench_function("large_email", |b| {
        b.iter(|| parse_mail(black_box(&large_email.raw_email)))
    });

    group.finish();
}

// Add more detailed benchmarks for specific operations
fn bench_email_components(c: &mut Criterion) {
    let email = create_test_email(true);
    let parsed_email = parse_mail(&email.raw_email).unwrap();

    let mut group = c.benchmark_group("email_components");

    // Benchmark header extraction
    group.bench_function("get_headers", |b| {
        b.iter(|| {
            black_box(&parsed_email.headers);
        })
    });

    // Benchmark body raw extraction with error handling
    group.bench_function("get_body_raw", |b| {
        b.iter(|| {
            if let Ok(body) = parsed_email.get_body_raw() {
                black_box(body);
            }
        })
    });

    group.finish();
}

criterion_group!(
    email_benches,
    bench_parse_email,
    bench_extract_email_body,
    bench_verify_dkim,
    bench_hash_bytes,
    bench_email_components
);
criterion_main!(email_benches);
