//! Common test utilities and helpers
//!
//! Provides infrastructure for creating test scenarios including:
//! - Temporary directories with test files
//! - Git repositories with complex history
//! - Secret fixtures for all supported detectors

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

/// A temporary test directory that cleans up after itself
pub struct TestDir {
    pub path: PathBuf,
}

impl TestDir {
    pub fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("libreleak-test-{}-{}", name, std::process::id()));
        if path.exists() {
            fs::remove_dir_all(&path).unwrap();
        }
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn path_str(&self) -> &str {
        self.path.to_str().unwrap()
    }

    pub fn write_file(&self, name: &str, content: &str) -> PathBuf {
        let file_path = self.path.join(name);
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut file = File::create(&file_path).unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file_path
    }

    pub fn create_dir(&self, name: &str) -> PathBuf {
        let dir_path = self.path.join(name);
        fs::create_dir_all(&dir_path).unwrap();
        dir_path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// A temporary git repository for testing history scanning
pub struct TestGitRepo {
    pub dir: TestDir,
}

impl TestGitRepo {
    pub fn new(name: &str) -> Self {
        let dir = TestDir::new(name);

        // Initialize git repo with 'main' as default branch
        Command::new("git")
            .args(["init", "-b", "main"])
            .current_dir(dir.path())
            .output()
            .expect("Failed to init git repo");

        // Configure git user for commits
        Command::new("git")
            .args(["config", "user.email", "test@libreleak.local"])
            .current_dir(dir.path())
            .output()
            .unwrap();

        Command::new("git")
            .args(["config", "user.name", "Test User"])
            .current_dir(dir.path())
            .output()
            .unwrap();

        Self { dir }
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    pub fn path_str(&self) -> &str {
        self.dir.path_str()
    }

    pub fn write_file(&self, name: &str, content: &str) -> PathBuf {
        self.dir.write_file(name, content)
    }

    pub fn commit(&self, message: &str) {
        Command::new("git")
            .args(["add", "-A"])
            .current_dir(self.path())
            .output()
            .unwrap();

        Command::new("git")
            .args(["commit", "-m", message, "--allow-empty"])
            .current_dir(self.path())
            .output()
            .unwrap();
    }

    pub fn create_branch(&self, name: &str) {
        Command::new("git")
            .args(["checkout", "-b", name])
            .current_dir(self.path())
            .output()
            .unwrap();
    }

    pub fn checkout(&self, branch: &str) {
        Command::new("git")
            .args(["checkout", branch])
            .current_dir(self.path())
            .output()
            .unwrap();
    }

    pub fn delete_file(&self, name: &str) {
        let path = self.path().join(name);
        if path.exists() {
            fs::remove_file(path).unwrap();
        }
    }

    pub fn get_current_branch(&self) -> String {
        let output = Command::new("git")
            .args(["branch", "--show-current"])
            .current_dir(self.path())
            .output()
            .unwrap();
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    pub fn get_commit_count(&self) -> usize {
        let output = Command::new("git")
            .args(["rev-list", "--count", "HEAD"])
            .current_dir(self.path())
            .output()
            .unwrap();
        String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse()
            .unwrap_or(0)
    }

    pub fn get_all_branches(&self) -> Vec<String> {
        let output = Command::new("git")
            .args(["branch", "-a"])
            .current_dir(self.path())
            .output()
            .unwrap();
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(|s| s.trim().trim_start_matches("* ").to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }
}

// ============================================================================
// FAKE SECRET GENERATORS
// These generate realistic-looking but FAKE secrets for testing
// ============================================================================

pub mod fake_secrets {
    //! Generates fake secrets for testing. These are NOT real credentials.
    //! All secrets follow the correct format but use obviously fake values.

    // AWS
    pub const AWS_ACCESS_KEY_ID: &str = "AKIAIOSFODNN7EXAMPLE";
    pub const AWS_SECRET_ACCESS_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    // GitHub - realistic alphanumeric patterns
    pub const GITHUB_PAT: &str = "ghp_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8";
    pub const GITHUB_OAUTH: &str = "gho_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8";
    pub const GITHUB_APP: &str = "ghu_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8";
    pub const GITHUB_REFRESH: &str = "ghr_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8";
    pub const GITHUB_FINE_GRAINED: &str = "github_pat_11AAAAAA_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2";

    // GitLab
    pub const GITLAB_PAT: &str = "glpat-a1b2c3d4e5f6g7h8i9j0";
    pub const GITLAB_PIPELINE: &str = "glptt-a1b2c3d4e5f6g7h8i9j0k1l2m3n4";
    pub const GITLAB_RUNNER: &str = "glrt-a1b2c3d4e5f6g7h8i9j0k1l2m3n4";

    // OpenAI
    pub const OPENAI_API_KEY: &str = "sk-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4";
    pub const OPENAI_PROJECT_KEY: &str = "sk-proj-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6";

    // Anthropic / Claude
    pub const ANTHROPIC_API_KEY: &str = "sk-ant-api03-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8";

    // Google / Gemini
    pub const GOOGLE_API_KEY: &str = "AIzaSyA1b2C3d4E5f6G7h8I9j0K1L2m3N4o5P6q";
    pub const GEMINI_API_KEY: &str = "AIzaSyDa1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q";

    // OpenRouter
    pub const OPENROUTER_API_KEY: &str = "sk-or-v1-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0";

    // xAI / Grok
    pub const XAI_API_KEY: &str = "xai-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0";

    // Groq
    pub const GROQ_API_KEY: &str = "gsk_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4";

    // Emerging AI Providers (2025-2026)
    pub const CLAUDE_3_API_KEY: &str = "sk-ant-api03-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2g3h4i5j6k7l8m9n0o1p2q3r4s5t6u7v8w9x0y1z2a3b4c5d6e7f8g9h0i1j2k3l4m5n6o7p8q9r0s1t2u3v4w5x6y7z8a9b0c1d2e3f4g5h6i7j8k9l0m1n2o3p4q5r6s7t8u9v0w1x2y3z4a5b6c7d8e9f0g1h2i3j4k5l6m7n8o9p0q1r2s3t4u5v6w7x8y9z0a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6";
    pub const GROK_2_API_KEY: &str = "xai-grok2-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2g3h4i5j6k7l8m9n0";
    pub const GPT_5_API_KEY: &str = "sk-gpt5-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2g3h4i5j6k7l8m9n0";
    pub const GEMINI_ULTRA_API_KEY: &str = "AIzaSyDa1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V2w3X4y5Z6";
    pub const MIDJOURNEY_V6_API_KEY: &str = "mj-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2";
    pub const STABILITY_AI_V3_KEY: &str = "sk-stability-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2g3h4i5j6k7l8m9n0";

    // Quantum-Resistant Cryptography (2025-2026)
    pub const PQ_KYBER_KEY: &str = "kyber-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2g3h4i5j6k7l8m9n0";
    pub const PQ_DILITHIUM_KEY: &str = "dilithium-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2g3h4i5j6k7l8m9n0";
    pub const PQ_FALCON_KEY: &str = "falcon-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2g3h4i5j6k7l8m9n0";
    pub const PQ_SPHINCS_KEY: &str = "sphincs-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2g3h4i5j6k7l8m9n0";
    pub const PQ_BIKE_KEY: &str = "bike-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2g3h4i5j6k7l8m9n0";
    pub const PQ_HQC_KEY: &str = "hqc-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2g3h4i5j6k7l8m9n0";
    pub const PQ_NEWHOPE_KEY: &str = "newhope-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2g3h4i5j6k7l8m9n0";
    pub const PQ_FRODO_KEY: &str = "frodo-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2g3h4i5j6k7l8m9n0";
    pub const QKD_KEY: &str = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2g3h4i5j6k7l8m9n0o1p2q3r4s5t6u7v8w9x0y1z2a3b4c5d6e7f8g9h0i1j2k3l4m5n6o7p8q9r0s1t2u3v4w5x6y7z8a9b0c1d2e3f4g5h6i7j8k9l0m1n2o3p4q5r6s7t8u9v0w1x2y3z4a5b6c7d8e9f0g1h2i3j4k5l6m7n8o9p0q1r2s3t4u5v6w7x8y9z0a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6";

    // AI Model Weights & Cloud Storage (2025-2026)
    pub const HF_MODEL_TOKEN: &str = "hf_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2";
    pub const REPLICATE_MODEL_TOKEN: &str = "r8_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2";
    pub const OPENAI_MODEL_TOKEN: &str = "sk-model-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2";
    pub const MLFLOW_TRACKING_URI: &str = "http://mlflow.example.com:5000";
    pub const WANDB_API_KEY: &str = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2";
    pub const COMET_API_KEY: &str = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2";
    pub const NEPTUNE_API_TOKEN: &str = "eyJhcGlfYWRkcmVzcyI6Imh0dHBzOi8vYXBwLm5lcHR1bmUuYWkiLCJhcGlfdXJsIjoiaHR0cHM6Ly9hcHAubmVwdHVuZS5haSIsImFwaV9rZXkiOiJhMWJjZGUyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5In0=";
    pub const AWS_MODEL_BUCKET: &str = "s3://ai-models-bucket/models/";
    pub const GCP_MODEL_BUCKET: &str = "gs://ai-models-bucket/models/";
    pub const AZURE_MODEL_BLOB: &str = "https://aimodels.blob.core.windows.net/models/";
    pub const DVC_REMOTE_TOKEN: &str = "dvc_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2";

    // Federated Identity Tokens (2025-2026)
    pub const OAUTH21_ACCESS_TOKEN: &str = "oauth21_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2";
    pub const JWT_ACCESS_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    pub const JWT_REFRESH_TOKEN: &str = "refresh_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2";
    pub const SAML_ASSERTION: &str = "PHNhbWw6QXNzZXJ0aW9uIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iIElEPSJfYTFiMmMzZDRlNWY2ZzdoOGk5ajBrMWwybTNuNG81cDZxN3I4czl0MHUxI";
    pub const OIDC_ID_TOKEN: &str = "oidc_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2";
    pub const GCP_SA_TOKEN: &str = "ya29.a0AfH6SMA1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2g3h4i5j6k7l8m9n0o1p2q3r4s5t6u7v8w9x0y1z2a3b4c5d6e7f8g9h0i1j2k3l4m5n6o7p8q9r0s1t2u3v4w5x6y7z8a9b0c1d2e3f4g5h6i7j8k9l0m1n2o3p4q5r6s7t8u9v0w1x2y3z4a5b6c7d8e9f0g1h2i3j4k5l6m7n8o9p0q1r2s3t4u5v6w7x8y9z0a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6";
    pub const AWS_SA_TOKEN: &str = "aws_sa_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2";
    pub const FEDERATED_IDENTITY_TOKEN: &str = "fed_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2";
    pub const WORKLOAD_IDENTITY_TOKEN: &str = "workload_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2";

    // Web3/Blockchain Keys (2025-2026)
    pub const ETHEREUM_PRIVATE_KEY: &str = "0xa1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2g3h4i5j6k7l8m9n0";
    pub const ETHEREUM_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    pub const SOLANA_PRIVATE_KEY: &str = "[174,47,154,16,202,193,206,113,199,190,53,133,169,175,31,56,222,53,138,189,224,216,117,173,10,149,53,45,73,46,49,128]";
    pub const POLYGON_PRIVATE_KEY: &str = "0xb1c2d3e4f5g6h7i8j9k0l1m2n3o4p5q6r7s8t9u0v1w2x3y4z5a6b7c8d9e0f1g2h3i4j5k6l7m8n9";
    pub const AVALANCHE_PRIVATE_KEY: &str = "0xc1d2e3f4g5h6i7j8k9l0m1n2o3p4q5r6s7t8u9v0w1x2y3z4a5b6c7d8e9f0g1h2i3j4k5l6m7n8o9";
    pub const BSC_PRIVATE_KEY: &str = "0xd1e2f3g4h5i6j7k8l9m0n1o2p3q4r5s6t7u8v9w0x1y2z3a4b5c6d7e8f9g0h1i2j3k4l5m6n7o8p9";
    pub const ARBITRUM_PRIVATE_KEY: &str = "0xe1f2g3h4i5j6k7l8m9n0o1p2q3r4s5t6u7v8w9x0y1z2a3b4c5d6e7f8g9h0i1j2k3l4m5n6o7p8q9";
    pub const OPTIMISM_PRIVATE_KEY: &str = "0xf1g2h3i4j5k6l7m8n9o0p1q2r3s4t5u6v7w8x9y0z1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9";
    pub const WALLET_CONNECT_URI: &str = "wc:a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2g3h4i5j6k7l8m9n0";
    pub const METAMASK_SEED: &str = "witch collapse practice feed shame open despair creek road again ice least";
    pub const COINBASE_SEED: &str = "maximum attend light bulb genuine all fashion blind border girl insane acoustic";

    // Perplexity
    pub const PERPLEXITY_API_KEY: &str = "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";

    // Fireworks
    pub const FIREWORKS_API_KEY: &str = "fw_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0";

    // Cerebras
    pub const CEREBRAS_API_KEY: &str = "csk-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0";

    // Hugging Face
    pub const HUGGINGFACE_TOKEN: &str = "hf_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8";

    // Replicate
    pub const REPLICATE_TOKEN: &str = "r8_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0";

    // Slack - using FAKE marker to avoid GitHub push protection
    pub const SLACK_BOT_TOKEN: &str = "xoxb-000000000000-0000000000000-FAKEFAKEFAKEFAKEFAKEFAKE";
    pub const SLACK_USER_TOKEN: &str = "xoxp-000000000000-0000000000000-FAKEFAKEFAKEFAKEFAKEFAKE";
    pub const SLACK_APP_TOKEN: &str = "xapp-0-A00000000-0000000000000-FAKEFAKEFAKEFAKEFAKEFAKE";

    // Stripe - using test prefix pattern to avoid GitHub push protection
    pub const STRIPE_SECRET_KEY: &str = "sk_live_TESTFAKEKEYTESTFAKEKEYTESTFAKE";
    pub const STRIPE_RESTRICTED_KEY: &str = "rk_live_TESTFAKEKEYTESTFAKEKEYTESTFAKE";

    // Twilio
    pub const TWILIO_API_KEY: &str = "SKa1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6";

    // SendGrid
    pub const SENDGRID_API_KEY: &str = "SG.a1b2c3d4e5f6g7h8i9j0.k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2g3";

    // npm
    pub const NPM_TOKEN: &str = "npm_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8";

    // PyPI
    pub const PYPI_TOKEN: &str = "pypi-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4";

    // Discord
    pub const DISCORD_BOT_TOKEN: &str = "MTA1234567890.a1b2c3.d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1";

    // Voyage AI
    pub const VOYAGE_API_KEY: &str = "pa-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0";

    // Anyscale
    pub const ANYSCALE_API_KEY: &str = "esecret_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0";

    // Private Keys
    pub const RSA_PRIVATE_KEY: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MvZ0fh+rZgfPzV5P
EXAMPLEKEYNOTREALFAKEFORTESTINGONLYXXXXXXXXXXXXXXXXXXXXXXXX
-----END RSA PRIVATE KEY-----"#;

    pub const OPENSSH_PRIVATE_KEY: &str = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
EXAMPLEKEYNOTREALFAKEFORTESTINGONLYXXXXXXXXXXXXXXXXXXXXXXXX
-----END OPENSSH PRIVATE KEY-----"#;

    pub const EC_PRIVATE_KEY: &str = r#"-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIBYwFQXWFHCeBRWNJBZCUQKCAQEA0Z3VS5JJcds3xfn/EXAMPLEONLY
-----END EC PRIVATE KEY-----"#;

    // Database Connection Strings
    pub const POSTGRES_URI: &str = "postgres://user:password123@localhost:5432/mydb";
    pub const POSTGRESQL_URI: &str = "postgresql://admin:secretpass@db.example.com:5432/production";
    pub const MYSQL_URI: &str = "mysql://root:hunter2@mysql.example.com:3306/app";
    pub const MONGODB_URI: &str = "mongodb://admin:mongopass123@cluster0.example.mongodb.net:27017/mydb";
    pub const MONGODB_SRV_URI: &str = "mongodb+srv://user:pass@cluster0.xxxxx.mongodb.net/myapp?retryWrites=true";
    pub const MONGODB_ATLAS: &str = "mongodb+srv://dbuser:dbpass@cluster0.abcde.mongodb.net";
    pub const REDIS_URI: &str = "redis://default:redispassword@redis.example.com:6379/0";

    // JDBC
    pub const JDBC_POSTGRES: &str = "jdbc:postgresql://localhost:5432/mydb?user=admin&password=secret";
    pub const JDBC_MYSQL: &str = "jdbc:mysql://localhost:3306/mydb?user=root&password=hunter2";

    // Local AI Endpoints
    pub const OLLAMA_ENDPOINT: &str = "http://localhost:11434";
    pub const LMSTUDIO_ENDPOINT: &str = "http://localhost:1234/v1";
    pub const EXO_ENDPOINT: &str = "http://localhost:52415";
    pub const LOCALAI_ENDPOINT: &str = "http://localhost:8080/v1";
    pub const VLLM_ENDPOINT: &str = "http://localhost:8000/v1";
    pub const KOBOLD_ENDPOINT: &str = "http://localhost:5001/api";

    // =========================================================================
    // HIGH-VALUE BUG BOUNTY TARGETS (2024-2025)
    // =========================================================================

    // Shopify (up to $50k bounties)
    pub const SHOPIFY_ACCESS_TOKEN: &str = "shpat_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6";
    pub const SHOPIFY_CUSTOM_APP_TOKEN: &str = "shpca_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6";
    pub const SHOPIFY_PRIVATE_APP_TOKEN: &str = "shppa_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6";
    pub const SHOPIFY_SHARED_SECRET: &str = "shpss_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6";

    // Databricks
    pub const DATABRICKS_PAT: &str = "dapia1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6";

    // Square (payment processing)
    pub const SQUARE_ACCESS_TOKEN: &str = "EAAAEa1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4";
    pub const SQUARE_SANDBOX_TOKEN: &str = "EAAAla1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4";

    // PlanetScale - using FAKE marker to avoid GitHub push protection
    pub const PLANETSCALE_PASSWORD: &str = "pscale_pw_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE00";
    pub const PLANETSCALE_TOKEN: &str = "pscale_tkn_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE00";

    // Linear
    pub const LINEAR_API_KEY: &str = "lin_api_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8";

    // Figma
    pub const FIGMA_PAT: &str = "figd_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0";

    // DigitalOcean (tokens need to be 64+ chars total)
    pub const DIGITALOCEAN_TOKEN: &str = "dop_v1_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0";
    pub const DIGITALOCEAN_PAT: &str = "doo_v1_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0";
    pub const DIGITALOCEAN_REFRESH: &str = "dor_v1_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0";

    // Doppler
    pub const DOPPLER_TOKEN: &str = "dp.pt.a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8";

    // New Relic
    pub const NEWRELIC_API_KEY: &str = "NRAK-a1b2c3d4e5f6g7h8i9j0k1l2m3n4";

    // Mapbox
    pub const MAPBOX_ACCESS_TOKEN: &str = "pk.eyJhIjoiYTFiMmMzZDRlNWY2ZzdoOGk5ajBrMWwybTNuNG81cDZxN3I4czl0MHUxdjJ3M3g0eTUiLCJiIjoiY2xhMWIyYzNkNGU1ZjZnN2g4aTlqMGsxbDJtM240bzVwNnE3cjhzOXQwdTF2MncifQ.a1b2c3d4e5f6g7h8i9j0";
    pub const MAPBOX_SECRET_TOKEN: &str = "sk.eyJhIjoiYTFiMmMzZDRlNWY2ZzdoOGk5ajBrMWwybTNuNG81cDZxN3I4czl0MHUxdjJ3M3g0eTUiLCJiIjoiY2xhMWIyYzNkNGU1ZjZnN2g4aTlqMGsxbDJtM240bzVwNnE3cjhzOXQwdTF2MncifQ.a1b2c3d4e5f6g7h8i9j0";

    // Age encryption
    pub const AGE_SECRET_KEY: &str = "AGE-SECRET-KEY-1A2B3C4D5E6F7G8H9I0J1K2L3M4N5O6P7Q8R9S0T1U2V3W4X5Y6Z7";

    // Notion
    pub const NOTION_TOKEN: &str = "secret_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0";

    // Discord MTI variant (min 59 chars)
    pub const DISCORD_BOT_TOKEN_MTI: &str = "MTI1234567890.a1b2c3.d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2";
}

// ============================================================================
// SAMPLE FILE CONTENT GENERATORS
// ============================================================================

pub mod sample_files {
    use super::fake_secrets::*;

    /// Generate a .env file with various secrets
    pub fn env_file() -> String {
        format!(
            r#"# Application Configuration
DATABASE_URL={}
REDIS_URL={}

# API Keys
OPENAI_API_KEY={}
ANTHROPIC_API_KEY={}
GITHUB_TOKEN={}

# AWS
AWS_ACCESS_KEY_ID={}
AWS_SECRET_ACCESS_KEY={}

# Local AI
OLLAMA_HOST={}
"#,
            POSTGRES_URI,
            REDIS_URI,
            OPENAI_API_KEY,
            ANTHROPIC_API_KEY,
            GITHUB_PAT,
            AWS_ACCESS_KEY_ID,
            AWS_SECRET_ACCESS_KEY,
            OLLAMA_ENDPOINT
        )
    }

    /// Generate a config.json with embedded secrets
    pub fn config_json() -> String {
        format!(
            r#"{{
  "database": {{
    "url": "{}"
  }},
  "api": {{
    "openai_key": "{}",
    "anthropic_key": "{}"
  }},
  "mongodb": {{
    "uri": "{}"
  }}
}}"#,
            POSTGRES_URI, OPENAI_API_KEY, ANTHROPIC_API_KEY, MONGODB_SRV_URI
        )
    }

    /// Generate a Python config file with secrets
    pub fn python_config() -> String {
        format!(
            r#"# config.py
import os

# API Keys
OPENAI_API_KEY = "{}"
ANTHROPIC_API_KEY = "{}"
GITHUB_TOKEN = "{}"

# Database
DATABASE_URL = "{}"
MONGODB_URI = "{}"

# Local AI
OLLAMA_HOST = "{}"
LMSTUDIO_URL = "{}"
"#,
            OPENAI_API_KEY,
            ANTHROPIC_API_KEY,
            GITHUB_PAT,
            POSTGRES_URI,
            MONGODB_URI,
            OLLAMA_ENDPOINT,
            LMSTUDIO_ENDPOINT
        )
    }

    /// Generate a JavaScript/TypeScript config file
    pub fn javascript_config() -> String {
        format!(
            r#"// config.js
const config = {{
  openai: {{
    apiKey: '{}',
  }},
  anthropic: {{
    apiKey: '{}',
  }},
  database: {{
    url: '{}',
  }},
  github: {{
    token: '{}',
  }},
}};

module.exports = config;
"#,
            OPENAI_API_KEY, ANTHROPIC_API_KEY, MONGODB_SRV_URI, GITHUB_PAT
        )
    }

    /// Generate a YAML config file
    pub fn yaml_config() -> String {
        format!(
            r#"# config.yaml
database:
  url: "{}"

api_keys:
  openai: "{}"
  anthropic: "{}"
  stripe: "{}"

aws:
  access_key_id: "{}"
  secret_access_key: "{}"
"#,
            POSTGRES_URI,
            OPENAI_API_KEY,
            ANTHROPIC_API_KEY,
            STRIPE_SECRET_KEY,
            AWS_ACCESS_KEY_ID,
            AWS_SECRET_ACCESS_KEY
        )
    }

    /// Generate a file with a private key
    pub fn private_key_file() -> String {
        RSA_PRIVATE_KEY.to_string()
    }

    /// Generate a docker-compose file with secrets
    pub fn docker_compose() -> String {
        format!(
            r#"version: '3.8'
services:
  app:
    environment:
      - DATABASE_URL={}
      - OPENAI_API_KEY={}
      - REDIS_URL={}
  db:
    image: postgres:15
    environment:
      - POSTGRES_PASSWORD=supersecretpassword
"#,
            POSTGRES_URI, OPENAI_API_KEY, REDIS_URI
        )
    }

    /// Generate a Kubernetes secret manifest (base64 encoded but detectable)
    pub fn k8s_secret() -> String {
        format!(
            r#"apiVersion: v1
kind: Secret
metadata:
  name: api-secrets
type: Opaque
stringData:
  openai-key: "{}"
  github-token: "{}"
  database-url: "{}"
"#,
            OPENAI_API_KEY, GITHUB_PAT, POSTGRES_URI
        )
    }

    /// Generate a Terraform file with secrets
    pub fn terraform_file() -> String {
        format!(
            r#"# main.tf
variable "openai_api_key" {{
  default = "{}"
}}

variable "aws_access_key" {{
  default = "{}"
}}

resource "aws_instance" "example" {{
  ami           = "ami-12345678"
  instance_type = "t2.micro"

  tags = {{
    Name = "example"
  }}
}}
"#,
            OPENAI_API_KEY, AWS_ACCESS_KEY_ID
        )
    }
}

// ============================================================================
// CLEAN FILE SAMPLES (NO SECRETS)
// ============================================================================

pub mod clean_files {
    /// A clean Python file with no secrets
    pub fn python_clean() -> &'static str {
        r#"# app.py
import os

# Load API key from environment
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
DATABASE_URL = os.environ.get("DATABASE_URL")

def main():
    print("Hello, World!")

if __name__ == "__main__":
    main()
"#
    }

    /// A clean config with placeholders
    pub fn config_with_placeholders() -> &'static str {
        r#"{
  "api_key": "${OPENAI_API_KEY}",
  "database": {
    "url": "{{DATABASE_URL}}"
  },
  "secret": "<your-secret-here>",
  "token": "your_token_here"
}
"#
    }

    /// A clean .env.example file
    pub fn env_example() -> &'static str {
        r#"# Copy this to .env and fill in your values
OPENAI_API_KEY=your_api_key_here
DATABASE_URL=postgres://user:password@localhost:5432/db
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
"#
    }

    /// Documentation mentioning secrets but not containing real ones
    pub fn documentation() -> &'static str {
        r#"# Configuration Guide

## Setting up API Keys

1. Get your OpenAI API key from https://platform.openai.com
2. Set the `OPENAI_API_KEY` environment variable:
   ```
   export OPENAI_API_KEY=sk-your-key-here
   ```

## Database Configuration

The database URL format is:
```
postgres://username:password@host:port/database
```

Example: `postgres://myuser:mypassword@localhost:5432/myapp`

Note: Never commit real credentials to version control!
"#
    }

    /// Code with test/mock credentials
    pub fn test_file_with_mocks() -> &'static str {
        r#"# test_api.py
import unittest

class TestAPI(unittest.TestCase):
    def setUp(self):
        # These are fake test credentials
        self.api_key = "test_key_not_real"
        self.token = "fake_token_for_testing"

    def test_authentication(self):
        # Mock authentication
        pass
"#
    }
}

// ============================================================================
// EDGE CASE SAMPLES
// ============================================================================

pub mod edge_cases {
    use super::fake_secrets::*;

    /// Secrets in comments
    pub fn secrets_in_comments() -> String {
        format!(
            r#"// Old API key (revoked): {}
/*
 * Previous MongoDB connection:
 * {}
 */
# TODO: Remove this: {}
"#,
            OPENAI_API_KEY, MONGODB_URI, GITHUB_PAT
        )
    }

    /// Secrets split across lines (should not match)
    pub fn split_secrets() -> &'static str {
        r#"const key = "ghp_" +
    "xxxxxxxxxxxx" +
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxx";
"#
    }

    /// Multiple secrets on same line
    pub fn multiple_on_line() -> String {
        format!(
            r#"KEYS="{}" "{}" "{}""#,
            OPENAI_API_KEY, ANTHROPIC_API_KEY, GITHUB_PAT
        )
    }

    /// Secrets with weird whitespace
    pub fn weird_whitespace() -> String {
        format!(
            "OPENAI_API_KEY=   {}   \nGITHUB_TOKEN\t=\t{}\n",
            OPENAI_API_KEY, GITHUB_PAT
        )
    }

    /// Secrets in minified code
    pub fn minified_js() -> String {
        format!(
            r#"var a="{}",b="{}",c=function(){{return a+b}};"#,
            OPENAI_API_KEY, GITHUB_PAT
        )
    }

    /// Base64 encoded (should we detect?)
    pub fn base64_encoded() -> &'static str {
        // Base64 of "sk-test1234567890abcdefghijklmnopqrstuvwxyzABCD"
        r#"eyJhcGlfa2V5IjogInNrLXRlc3QxMjM0NTY3ODkwYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXpBQkNEIn0="#
    }

    /// URL-encoded secrets
    pub fn url_encoded() -> &'static str {
        "mongodb://user:p%40ssw%3Ard@localhost:27017/db"
    }

    /// Secrets in log output format
    pub fn log_format() -> String {
        format!(
            r#"2024-01-15 10:30:45 INFO  Using API key: {}
2024-01-15 10:30:46 DEBUG Connected to: {}
"#,
            OPENAI_API_KEY, MONGODB_URI
        )
    }

    /// Very long lines
    pub fn very_long_line() -> String {
        let padding = "x".repeat(10000);
        format!("{}OPENAI_API_KEY={}{}", padding, super::fake_secrets::OPENAI_API_KEY, padding)
    }

    /// Unicode in file
    pub fn unicode_content() -> String {
        format!(
            "# 配置文件 🔐\nOPENAI_API_KEY={}\n# Ключ API: {}",
            super::fake_secrets::OPENAI_API_KEY,
            super::fake_secrets::GITHUB_PAT
        )
    }

    /// Empty lines around secrets
    pub fn secrets_with_empty_lines() -> String {
        format!(
            "\n\n\nOPENAI_API_KEY={}\n\n\n\nGITHUB_TOKEN={}\n\n\n",
            super::fake_secrets::OPENAI_API_KEY,
            super::fake_secrets::GITHUB_PAT
        )
    }

    /// Secrets in heredoc
    pub fn heredoc() -> String {
        format!(
            r#"cat <<EOF > config.env
OPENAI_API_KEY={}
DATABASE_URL={}
EOF
"#,
            super::fake_secrets::OPENAI_API_KEY,
            super::fake_secrets::POSTGRES_URI
        )
    }

    /// Almost-valid secrets (should not match)
    pub fn almost_valid() -> &'static str {
        r#"
# Too short
ghp_abc123
sk-short

# Wrong prefix
gph_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
ks-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Contains invalid chars
ghp_xxxx!xxxx@xxxx#xxxxxxxxxxxxxxxxxxxxxxx
"#
    }
}
