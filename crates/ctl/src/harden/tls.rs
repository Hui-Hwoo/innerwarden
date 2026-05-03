use super::env::HardenEnv;
use super::types::{CheckResult, Finding, Severity};

const WEAK_CIPHERS: &[&str] = &["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT"];

/// Analyse Nginx config file contents for TLS issues.
pub(super) fn check_tls_nginx_files(
    files: &[(String, String)],
    passed: &mut Vec<String>,
    findings: &mut Vec<Finding>,
) {
    let cat = "TLS/SSL";
    let mut found_ssl_protocols = false;
    let mut found_ssl_ciphers = false;
    let mut found_prefer_server_ciphers = false;
    let mut found_hsts = false;

    for (path, content) in files {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') || trimmed.is_empty() {
                continue;
            }

            // ssl_protocols
            if trimmed.starts_with("ssl_protocols") {
                found_ssl_protocols = true;
                let lower = trimmed.to_lowercase();
                if lower.contains("tlsv1.1") || {
                    // Match bare "tlsv1" but not "tlsv1.2" / "tlsv1.3"
                    let without_prefix = lower
                        .replace("tlsv1.1", "")
                        .replace("tlsv1.2", "")
                        .replace("tlsv1.3", "");
                    without_prefix.contains("tlsv1")
                } {
                    findings.push(Finding {
                        category: cat,
                        severity: Severity::High,
                        title: format!("Nginx: deprecated TLS protocol(s) in {path}"),
                        fix: format!("Set 'ssl_protocols TLSv1.2 TLSv1.3;' in {path}"),
                    });
                }
            }

            // ssl_ciphers
            if trimmed.starts_with("ssl_ciphers") {
                found_ssl_ciphers = true;
                let upper = trimmed.to_uppercase();
                for weak in WEAK_CIPHERS {
                    if upper.contains(weak) {
                        findings.push(Finding {
                            category: cat,
                            severity: Severity::High,
                            title: format!("Nginx: weak cipher {weak} in {path}"),
                            fix: format!("Remove {weak} from ssl_ciphers in {path}"),
                        });
                    }
                }
            }

            // ssl_prefer_server_ciphers
            if trimmed.starts_with("ssl_prefer_server_ciphers") && trimmed.contains("on") {
                found_prefer_server_ciphers = true;
            }

            // HSTS
            if trimmed.contains("Strict-Transport-Security") {
                found_hsts = true;
            }
        }
    }

    if !found_ssl_protocols {
        findings.push(Finding {
            category: cat,
            severity: Severity::Medium,
            title: "Nginx: ssl_protocols not explicitly set (relying on defaults)".into(),
            fix: "Add 'ssl_protocols TLSv1.2 TLSv1.3;' to your Nginx config".into(),
        });
    }

    if found_ssl_protocols
        && found_ssl_ciphers
        && !findings.iter().any(|f| f.title.contains("Nginx"))
    {
        passed.push("Nginx: TLS protocols and ciphers look good".into());
    }

    if !found_prefer_server_ciphers {
        findings.push(Finding {
            category: cat,
            severity: Severity::Low,
            title: "Nginx: ssl_prefer_server_ciphers not enabled".into(),
            fix: "Add 'ssl_prefer_server_ciphers on;' to your Nginx config".into(),
        });
    } else {
        passed.push("Nginx: server cipher preference enabled".into());
    }

    if !found_hsts {
        findings.push(Finding {
            category: cat,
            severity: Severity::Medium,
            title: "Nginx: HSTS header not found".into(),
            fix: "Add 'add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains\" always;' to your Nginx server blocks".into(),
        });
    } else {
        passed.push("Nginx: HSTS header present".into());
    }
}

/// Analyse Apache config file contents for TLS issues.
pub(super) fn check_tls_apache_files(
    files: &[(String, String)],
    passed: &mut Vec<String>,
    findings: &mut Vec<Finding>,
) {
    let cat = "TLS/SSL";
    let mut found_ssl_protocol = false;
    let mut found_ssl_cipher_suite = false;
    let mut found_hsts = false;

    for (path, content) in files {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') || trimmed.is_empty() {
                continue;
            }

            // SSLProtocol
            if trimmed.starts_with("SSLProtocol") {
                found_ssl_protocol = true;
                let lower = trimmed.to_lowercase();
                if lower.contains("sslv3") || lower.contains("tlsv1.1") || {
                    let without = lower
                        .replace("tlsv1.1", "")
                        .replace("tlsv1.2", "")
                        .replace("tlsv1.3", "");
                    without.contains("tlsv1")
                } {
                    findings.push(Finding {
                        category: cat,
                        severity: Severity::High,
                        title: format!("Apache: deprecated TLS/SSL protocol(s) in {path}"),
                        fix: format!("Set 'SSLProtocol -all +TLSv1.2 +TLSv1.3' in {path}"),
                    });
                }
            }

            // SSLCipherSuite
            if trimmed.starts_with("SSLCipherSuite") {
                found_ssl_cipher_suite = true;
                let upper = trimmed.to_uppercase();
                for weak in WEAK_CIPHERS {
                    if upper.contains(weak) {
                        findings.push(Finding {
                            category: cat,
                            severity: Severity::High,
                            title: format!("Apache: weak cipher {weak} in {path}"),
                            fix: format!("Remove {weak} from SSLCipherSuite in {path}"),
                        });
                    }
                }
            }

            // HSTS
            if trimmed.contains("Strict-Transport-Security") {
                found_hsts = true;
            }
        }
    }

    if !found_ssl_protocol {
        findings.push(Finding {
            category: cat,
            severity: Severity::Medium,
            title: "Apache: SSLProtocol not explicitly set (relying on defaults)".into(),
            fix: "Add 'SSLProtocol -all +TLSv1.2 +TLSv1.3' to your Apache config".into(),
        });
    }

    if found_ssl_protocol
        && found_ssl_cipher_suite
        && !findings.iter().any(|f| f.title.contains("Apache"))
    {
        passed.push("Apache: TLS protocols and ciphers look good".into());
    }

    if !found_hsts {
        findings.push(Finding {
            category: cat,
            severity: Severity::Medium,
            title: "Apache: HSTS header not found".into(),
            fix: "Add 'Header always set Strict-Transport-Security \"max-age=63072000; includeSubDomains\"' to your Apache config".into(),
        });
    } else {
        passed.push("Apache: HSTS header present".into());
    }
}

/// Analyse OpenSSL config content for MinProtocol issues.
pub(super) fn check_tls_openssl_content(
    content: &str,
    passed: &mut Vec<String>,
    findings: &mut Vec<Finding>,
) {
    let cat = "TLS/SSL";
    let mut min_protocol_ok = true;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("MinProtocol") {
            let value = trimmed.split_once('=').map(|x| x.1).unwrap_or("").trim();
            let lower = value.to_lowercase();
            // Anything below TLSv1.2 is flagged.
            if lower.contains("tlsv1.1")
                || lower.contains("tlsv1.0")
                || lower == "tlsv1"
                || lower.contains("sslv")
            {
                min_protocol_ok = false;
                findings.push(Finding {
                    category: cat,
                    severity: Severity::High,
                    title: format!("OpenSSL: MinProtocol set to {value} (below TLSv1.2)"),
                    fix: "Set 'MinProtocol = TLSv1.2' in /etc/ssl/openssl.cnf".into(),
                });
            }
        }
    }
    if min_protocol_ok {
        passed.push("OpenSSL: MinProtocol is TLSv1.2 or higher (or not set)".into());
    }
}

pub(super) fn check_tls(env: &impl HardenEnv) -> CheckResult {
    let mut passed = Vec::new();
    let mut findings = Vec::new();

    // ----- helpers ----------------------------------------------------------

    /// Read all files in a directory (one level).
    fn read_dir_files(env: &impl HardenEnv, dir: &str) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for entry in env.read_dir(dir) {
            if entry.is_file {
                if let Some(content) = env.read_to_string(&entry.path) {
                    out.push((entry.path, content));
                }
            }
        }
        out
    }

    // ----- Nginx ------------------------------------------------------------

    let mut nginx_files: Vec<(String, String)> = Vec::new();
    if let Some(content) = env.read_to_string("/etc/nginx/nginx.conf") {
        nginx_files.push(("/etc/nginx/nginx.conf".into(), content));
    }
    nginx_files.extend(read_dir_files(env, "/etc/nginx/sites-enabled"));
    nginx_files.extend(read_dir_files(env, "/etc/nginx/conf.d"));

    let nginx_present = !nginx_files.is_empty();

    if nginx_present {
        check_tls_nginx_files(&nginx_files, &mut passed, &mut findings);
    }

    // ----- Apache -----------------------------------------------------------

    let mut apache_files: Vec<(String, String)> = Vec::new();
    for path in &["/etc/apache2/apache2.conf", "/etc/httpd/conf/httpd.conf"] {
        if let Some(content) = env.read_to_string(path) {
            apache_files.push(((*path).to_string(), content));
        }
    }
    apache_files.extend(read_dir_files(env, "/etc/apache2/sites-enabled"));
    apache_files.extend(read_dir_files(env, "/etc/httpd/conf.d"));

    let apache_present = !apache_files.is_empty();

    if apache_present {
        check_tls_apache_files(&apache_files, &mut passed, &mut findings);
    }

    // ----- System-wide OpenSSL ----------------------------------------------

    if let Some(content) = env.read_to_string("/etc/ssl/openssl.cnf") {
        check_tls_openssl_content(&content, &mut passed, &mut findings);
    }

    // ----- No web server detected -------------------------------------------

    if !nginx_present && !apache_present {
        passed.push("No web server detected (Nginx/Apache)".into());
    }

    CheckResult {
        category: "TLS/SSL",
        passed,
        findings,
    }
}

// ---------------------------------------------------------------------------
// 11. Firmware / Boot Integrity
// ---------------------------------------------------------------------------
