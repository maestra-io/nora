//! Benchmarks of the request hot paths (R4-P19): what a proxied npm packument, a
//! NuGet registration document and a cached artifact cost per request.
//!
//! `cargo bench -p nora-registry --bench hotpath`. The functions are the server's
//! own (the library half of the crate), not copies.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use nora_registry::npm_links::{place_document, Links};
use nora_registry::upstream_rewrite::rewrite_registration_urls;
use nora_registry::verified::{Blob, Verified};
use sha2::{Digest, Sha256};
use std::hint::black_box;

const NPM_UPSTREAM: &str = "https://registry.npmjs.org";
const NUGET_UPSTREAM: &str = "https://api.nuget.org";
const NORA: &str = "https://packages.example.com";

/// An upstream packument of `versions` versions, about 800 bytes each.
fn packument(versions: usize) -> Vec<u8> {
    let versions: serde_json::Map<String, serde_json::Value> = (0..versions)
        .map(|i| {
            let v = format!("1.{}.{}", i / 100, i % 100);
            let doc = serde_json::json!({
                "name": "pkg", "version": v, "description": "d".repeat(300),
                "dependencies": {"left-pad": "^1.3.0", "lodash": "^4.17.21", "react": "^18.0.0"},
                "scripts": {"test": "jest", "build": "tsc -p ."},
                "dist": {
                    "tarball": format!("{NPM_UPSTREAM}/pkg/-/pkg-{v}.tgz"),
                    "shasum": "0".repeat(40),
                    "integrity": format!("sha512-{}", "A".repeat(88)),
                },
            });
            (v, doc)
        })
        .collect();
    serde_json::to_vec(&serde_json::json!({
        "name": "pkg", "dist-tags": {"latest": "1.0.0"},
        "readme": "r".repeat(20_000), "versions": versions,
    }))
    .expect("a json value serializes")
}

/// A NuGet registration index with `leaves` inlined leaves.
fn registration(leaves: usize) -> String {
    let base = format!("{NUGET_UPSTREAM}/v3/registration5-gz-semver2/pkg");
    let items: Vec<serde_json::Value> = (0..leaves)
        .map(|i| {
            let v = format!("1.0.{i}");
            serde_json::json!({
                "@id": format!("{base}/{v}.json"),
                "catalogEntry": {
                    "@id": format!("{NUGET_UPSTREAM}/v3/catalog0/data/2024.01.01/pkg.{v}.json"),
                    "id": "Pkg", "version": v, "description": "d".repeat(200),
                },
                "packageContent": format!("{NUGET_UPSTREAM}/v3-flatcontainer/pkg/{v}/pkg.{v}.nupkg"),
                "registration": format!("{base}/index.json"),
            })
        })
        .collect();
    serde_json::json!({
        "@id": format!("{base}/index.json"), "count": 1,
        "items": [{"@id": format!("{base}/index.json#page"), "count": leaves, "items": items}],
    })
    .to_string()
}

/// Packument serve: the rewrite every cache miss of the rendered document pays.
fn bench_packument(c: &mut Criterion) {
    let mut group = c.benchmark_group("packument_place");
    for versions in [50usize, 10_000] {
        let doc = packument(versions);
        group.throughput(Throughput::Bytes(doc.len() as u64));
        group.sample_size(if versions > 1000 { 10 } else { 100 });
        group.bench_with_input(BenchmarkId::from_parameter(versions), &doc, |b, doc| {
            b.iter(|| {
                place_document(
                    black_box(doc),
                    NORA,
                    NPM_UPSTREAM,
                    Some("pkg"),
                    Links::Served,
                    &|_| true,
                )
                .map(|placed| placed.body.len())
                .unwrap_or_default()
            })
        });
    }
    group.finish();
}

fn bench_registration(c: &mut Criterion) {
    let mut group = c.benchmark_group("registration_rewrite");
    for leaves in [10usize, 2000] {
        let doc = registration(leaves);
        group.throughput(Throughput::Bytes(doc.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(leaves), &doc, |b, doc| {
            b.iter(|| rewrite_registration_urls(black_box(doc), NUGET_UPSTREAM, NORA).len())
        });
    }
    group.finish();
}

/// Cached artifact serve: `one_pass` is what a cache hit costs since R4-P05 (the
/// storage gate's verification, whose digest every later gate reuses); `four_passes`
/// is what it cost before (the gate, the witness, curation, quarantine each hashed).
fn bench_artifact(c: &mut Criterion) {
    let mut group = c.benchmark_group("cached_artifact_digest");
    group.sample_size(20);
    for mib in [1usize, 16] {
        let body = vec![0x5au8; mib << 20];
        let pin = hex::encode(Sha256::digest(&body));
        group.throughput(Throughput::Bytes(body.len() as u64));
        group.bench_with_input(BenchmarkId::new("one_pass", mib), &body, |b, body| {
            b.iter(|| {
                let blob = Blob::<Verified, _>::verify(black_box(&body[..]), &pin);
                blob.map(|blob| blob.sha256().len()).unwrap_or_default()
            })
        });
        group.bench_with_input(BenchmarkId::new("four_passes", mib), &body, |b, body| {
            b.iter(|| {
                let ok = Blob::<Verified, _>::verify(black_box(&body[..]), &pin).is_ok();
                let again: usize = (0..3)
                    .map(|_| hex::encode(Sha256::digest(black_box(&body[..]))).len())
                    .sum();
                (ok, again)
            })
        });
    }
    group.finish();
}

criterion_group!(benches, bench_packument, bench_registration, bench_artifact);
criterion_main!(benches);
