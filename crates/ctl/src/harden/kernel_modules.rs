use super::env::HardenEnv;
use super::types::{CheckResult, Finding, Severity};

pub(super) fn classify_loaded_modules(
    lsmod_output: &str,
    rootkit_modules: &[&str],
    known_good: &[&str],
) -> (Vec<String>, Vec<String>) {
    let mut rootkits = Vec::new();
    let mut unknowns = Vec::new();

    for line in lsmod_output.lines().skip(1) {
        let Some(module) = line.split_whitespace().next() else {
            continue;
        };
        if rootkit_modules
            .iter()
            .any(|rootkit| module.eq_ignore_ascii_case(rootkit))
        {
            rootkits.push(module.to_string());
            continue;
        }
        if !known_good.contains(&module) {
            unknowns.push(module.to_string());
        }
    }

    (rootkits, unknowns)
}

// ---------------------------------------------------------------------------
// Individual checks
// ---------------------------------------------------------------------------

pub(super) fn check_kernel_modules(env: &impl HardenEnv) -> CheckResult {
    let mut passed = Vec::new();
    let mut findings = Vec::new();
    let cat = "Kernel Modules";

    // Known rootkit modules - always flag as Critical.
    let rootkit_modules: &[&str] = &[
        "diamorphine",
        "reptile",
        "jynx",
        "adore",
        "knark",
        "suterusu",
    ];

    // Known-good modules (common, legitimate kernel modules).
    let known_good: &[&str] = &[
        // Filesystems
        "ext4",
        "xfs",
        "btrfs",
        "vfat",
        "fat",
        "nfs",
        "nfsd",
        "cifs",
        "fuse",
        "overlay",
        "isofs",
        "squashfs",
        "udf",
        "ntfs",
        "ntfs3",
        // Networking
        "ip_tables",
        "ip6_tables",
        "iptable_filter",
        "iptable_nat",
        "iptable_mangle",
        "nf_conntrack",
        "nf_nat",
        "nf_tables",
        "nft_chain_nat",
        "nft_compat",
        "nf_conntrack_ftp",
        "nf_nat_ftp",
        "nf_conntrack_netlink",
        "nf_defrag_ipv4",
        "nf_defrag_ipv6",
        "nf_reject_ipv4",
        "nf_reject_ipv6",
        "nft_reject",
        "br_netfilter",
        "bridge",
        "stp",
        "llc",
        "veth",
        "tun",
        "tap",
        "bonding",
        "8021q",
        "vxlan",
        "geneve",
        "wireguard",
        "openvswitch",
        "tcp_bbr",
        "tcp_cubic",
        // Block / storage
        "dm_mod",
        "dm_crypt",
        "dm_mirror",
        "dm_snapshot",
        "dm_thin_pool",
        "dm_zero",
        "dm_log",
        "dm_region_hash",
        "raid0",
        "raid1",
        "raid10",
        "raid456",
        "md_mod",
        "loop",
        "nbd",
        "scsi_mod",
        "sd_mod",
        "sr_mod",
        "sg",
        "ahci",
        "libahci",
        "libata",
        "virtio_blk",
        "virtio_scsi",
        "nvme",
        "nvme_core",
        // Virtio / KVM / hypervisor
        "virtio",
        "virtio_pci",
        "virtio_net",
        "virtio_ring",
        "virtio_balloon",
        "virtio_console",
        "virtio_gpu",
        "virtio_mmio",
        "virtio_rng",
        "kvm",
        "kvm_intel",
        "kvm_amd",
        "vhost",
        "vhost_net",
        "vhost_vsock",
        "vmw_balloon",
        "vmw_vmci",
        "vmw_vsock_vmci_transport",
        "vmxnet3",
        "hv_vmbus",
        "hv_storvsc",
        "hv_netvsc",
        "hv_utils",
        "hv_balloon",
        "xen_blkfront",
        "xen_netfront",
        "xen_pcifront",
        // Input / HID
        "hid",
        "hid_generic",
        "usbhid",
        "evdev",
        "input_leds",
        "psmouse",
        "i2c_hid",
        "i2c_core",
        // USB
        "usbcore",
        "usb_common",
        "ehci_hcd",
        "ehci_pci",
        "ohci_hcd",
        "ohci_pci",
        "uhci_hcd",
        "xhci_hcd",
        "xhci_pci",
        // Graphics / DRM
        "drm",
        "drm_kms_helper",
        "fb_sys_fops",
        "syscopyarea",
        "sysfillrect",
        "sysimgblt",
        "i915",
        "amdgpu",
        "nouveau",
        "bochs",
        "cirrus",
        "qxl",
        // Sound
        "snd",
        "snd_pcm",
        "snd_timer",
        "snd_hda_intel",
        "snd_hda_core",
        "snd_hda_codec",
        "snd_hda_codec_generic",
        "snd_hda_codec_hdmi",
        "snd_hda_codec_realtek",
        "snd_hwdep",
        "soundcore",
        // Crypto
        "aes_x86_64",
        "aesni_intel",
        "aes_generic",
        "sha256_generic",
        "sha256_ssse3",
        "sha512_generic",
        "sha512_ssse3",
        "sha1_generic",
        "sha1_ssse3",
        "crc32c_intel",
        "crc32_pclmul",
        "crct10dif_pclmul",
        "ghash_clmulni_intel",
        "poly1305_x86_64",
        "chacha20_x86_64",
        "cryptd",
        "crypto_simd",
        "authenc",
        "echainiv",
        // ACPI / power / platform
        "acpi_cpufreq",
        "battery",
        "button",
        "thermal",
        "processor",
        "intel_rapl_msr",
        "intel_rapl_common",
        "intel_pstate",
        // Misc common
        "joydev",
        "serio_raw",
        "pcspkr",
        "lp",
        "ppdev",
        "parport",
        "parport_pc",
        "nls_utf8",
        "nls_iso8859_1",
        "nls_cp437",
        "configfs",
        "efivarfs",
        "autofs4",
        "sunrpc",
        "rpcsec_gss_krb5",
        "cuse",
        "vboxguest",
        "vboxsf",
        "vboxvideo",
        "ip_vs",
        "ip_vs_rr",
        "ip_vs_wrr",
        "ip_vs_sh",
        "xt_conntrack",
        "xt_MASQUERADE",
        "xt_addrtype",
        "xt_comment",
        "xt_mark",
        "xt_nat",
        "xt_tcpudp",
        "xt_multiport",
        "xt_state",
        "xt_LOG",
        "xt_limit",
        "xt_recent",
        "xt_set",
        "ip_set",
        "ip_set_hash_ip",
        "ip_set_hash_net",
        "cls_cgroup",
        "sch_fq_codel",
        "sch_htb",
        "rng_core",
        "tpm",
        "tpm_crb",
        "tpm_tis",
        "tpm_tis_core",
        "lz4",
        "lz4_compress",
        "lzo",
        "lzo_compress",
        "lzo_decompress",
        "zstd_compress",
        "zstd_decompress",
        "deflate",
        "zlib_deflate",
        "zlib_inflate",
        "af_packet",
        "unix",
        "ipv6",
        "mousedev",
        "mac_hid",
        "msr",
        "cpuid",
        "iscsi_tcp",
        "libiscsi",
        "libiscsi_tcp",
        "scsi_transport_iscsi",
        "ceph",
        "libceph",
        "rbd",
        // Docker / containerd common
        "xt_connmark",
        "xt_REDIRECT",
        "nf_log_syslog",
        "nf_log_ipv4",
        // Networking diagnostics / misc
        "tcp_diag",
        "inet_diag",
        "udp_diag",
        "tls",
        "xfrm_user",
        "xfrm_algo",
        "ip6t_REJECT",
        "ip6t_rt",
        "xt_hl",
        "nft_limit",
        "xt_owner",
        "nft_fib",
        "nft_fib_inet",
        "nft_fib_ipv4",
        "nft_fib_ipv6",
        "nft_ct",
        "nft_counter",
        "nft_log",
        "nft_masq",
        "nft_nat",
        "nft_reject",
        "nft_reject_inet",
        "nft_reject_ipv4",
        "nft_reject_ipv6",
        "ip6table_filter",
        "ip6table_nat",
        "ip6table_mangle",
        "ip6_tables",
        "iptable_raw",
        "ip_set_hash_ipport",
        "ip_set_hash_ipportnet",
        // Oracle Cloud / ARM common
        "veth",
        "dummy",
        "nfnetlink",
        "nfnetlink_queue",
        "nfnetlink_log",
        "nf_log_common",
    ];

    match env.command_stdout("lsmod", &[]) {
        Some(output) => {
            let (rootkits, unknown_modules) =
                classify_loaded_modules(&output, rootkit_modules, known_good);
            for module in &rootkits {
                findings.push(Finding {
                    category: cat,
                    severity: Severity::Critical,
                    title: format!("Known rootkit module loaded: {module}"),
                    fix: format!(
                        "Investigate immediately - remove with: sudo rmmod {module} && audit the system"
                    ),
                });
            }

            if !unknown_modules.is_empty() {
                findings.push(Finding {
                    category: cat,
                    severity: Severity::Low,
                    title: format!("{} unusual kernel module(s) loaded", unknown_modules.len()),
                    fix: format!(
                        "Review if expected: {}",
                        unknown_modules
                            .iter()
                            .take(10)
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                });
            }

            if findings.is_empty() {
                passed.push("All loaded kernel modules are known-good".into());
            }
        }
        None => {
            passed.push("lsmod not available (skipped)".into());
        }
    }

    CheckResult {
        category: cat,
        passed,
        findings,
    }
}
