//! DNS resolver implementation for DKIM public key retrieval.
//! Supports fetching from Google DNS and ZK Email Archive as fallback.

use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;

/// Default timeout for HTTP requests in seconds
const HTTP_TIMEOUT_SECS: u64 = 10;
/// Google DNS TXT record type
const DNS_TXT_RECORD_TYPE: i32 = 16;
/// DKIM public key tag prefix
const DKIM_KEY_PREFIX: &str = "p=";

/// Response structure for Google DNS API
#[derive(Debug, Deserialize)]
struct DnsResponse {
    #[serde(rename = "Status")]
    status: i32,
    #[serde(rename = "Answer")]
    answer: Vec<DnsAnswer>,
}

/// DNS answer record structure
#[derive(Debug, Deserialize)]
struct DnsAnswer {
    #[serde(rename = "type")]
    record_type: i32,
    data: String,
}

/// DKIM record structure for ZK Email Archive API
#[derive(Debug, Deserialize)]
struct DkimRecord {
    selector: String,
    value: String,
}

/// Resolver for fetching DKIM public keys from DNS
#[derive(Debug)]
pub struct DkimResolver {
    client: Client,
}

impl DkimResolver {
    /// Creates a new DkimResolver with configured HTTP client
    ///
    /// # Returns
    /// * `Result<DkimResolver>` - Configured resolver or error
    ///
    /// # Errors
    /// * When HTTP client creation fails
    pub fn new() -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
            .build()
            .context("Failed to create HTTP client")?;
        Ok(Self { client })
    }

    /// Fetches DKIM public key for given selector and domain
    ///
    /// # Arguments
    /// * `selector` - DKIM selector
    /// * `domain` - Domain name
    ///
    /// # Returns
    /// * `Result<String>` - PEM formatted public key
    ///
    /// # Errors
    /// * When both Google DNS and ZK Email Archive fetches fail
    /// * When public key extraction fails
    pub async fn fetch_dkim_key(&self, selector: &str, domain: &str) -> Result<String> {
        // Try Google DNS first, fallback to ZK Email Archive
        let record = match self.fetch_from_google_dns(selector, domain).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Google DNS fetch failed: {}, trying ZK Email Archive", e);
                self.fetch_from_zkemail_archive(selector, domain)
                    .await
                    .context("Both DNS lookups failed")?
            }
        };

        self.extract_and_format_key(&record)
    }

    /// Fetches DKIM record from Google DNS
    async fn fetch_from_google_dns(&self, selector: &str, domain: &str) -> Result<String> {
        let lookup_name = format!("{}._domainkey.{}", selector, domain);
        let url = format!("https://dns.google/resolve?name={}&type=16", lookup_name);

        let response: DnsResponse = self
            .client
            .get(&url)
            .header("accept", "application/dns-json")
            .send()
            .await
            .context("Failed to send Google DNS request")?
            .json()
            .await
            .context("Failed to parse Google DNS response")?;

        if response.status != 0 {
            return Err(anyhow::anyhow!(
                "DNS query failed with status: {}",
                response.status
            ));
        }

        response
            .answer
            .iter()
            .find(|ans| ans.record_type == DNS_TXT_RECORD_TYPE)
            .map(|ans| ans.data.replace('\"', ""))
            .context("No TXT record found in DNS response")
    }

    /// Fetches DKIM record from ZK Email Archive
    async fn fetch_from_zkemail_archive(&self, selector: &str, domain: &str) -> Result<String> {
        let url = format!("https://archive.prove.email/api/key?domain={}", domain);

        let records: Vec<DkimRecord> = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to fetch from ZK Email Archive")?
            .json()
            .await
            .context("Failed to parse ZK Email Archive response")?;

        records
            .into_iter()
            .find(|r| r.selector == selector)
            .map(|r| r.value)
            .context("DKIM record not found in archive")
    }

    /// Extracts and formats public key from DKIM record
    fn extract_and_format_key(&self, record: &str) -> Result<String> {
        let key = record
            .split(';')
            .find(|part| part.trim().starts_with(DKIM_KEY_PREFIX))
            .context("No public key found in DKIM record")?
            .trim()
            .strip_prefix(DKIM_KEY_PREFIX)
            .context("Failed to strip key prefix")?
            .trim_matches('"');

        // Format key with 64-character line wrapping
        let key_wrapped = key
            .chars()
            .collect::<Vec<_>>()
            .chunks(64)
            .map(|c| c.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join("\n");

        Ok(format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
            key_wrapped
        ))
    }
}
