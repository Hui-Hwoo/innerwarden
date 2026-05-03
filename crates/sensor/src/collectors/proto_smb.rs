//! SMB protocol parser for reassembled TCP streams.
//!
//! Detects SMB lateral movement patterns: file access, share enumeration,
//! remote execution via named pipes (psexec, smbexec).
//! Works on any port (not just 445).
//!
//! Consumed by the Linux-only tcp_stream `run()` loop. SMB session
//! fields (shares_accessed, files_accessed) and the Smb3 variant are
//! populated by the parser but not yet read by downstream detectors.
//! Silence dead_code unconditionally at the module level.
#![allow(dead_code)]

/// Parsed SMB session info.
#[derive(Debug, Clone)]
pub struct SmbSession {
    pub version: SmbVersion,
    pub shares_accessed: Vec<String>,
    pub files_accessed: Vec<String>,
    pub named_pipes: Vec<String>,
    pub signals: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SmbVersion {
    Smb1,
    Smb2,
    Smb3,
    Unknown,
}

/// Parse SMB session from reassembled client data.
pub fn parse_session(client_data: &[u8]) -> Option<SmbSession> {
    if client_data.len() < 8 {
        return None;
    }

    let mut session = SmbSession {
        version: SmbVersion::Unknown,
        shares_accessed: Vec::new(),
        files_accessed: Vec::new(),
        named_pipes: Vec::new(),
        signals: Vec::new(),
    };

    // Detect SMB version from magic bytes
    // SMB1: \xFF\x53\x4D\x42 ("SMB")
    // SMB2/3: \xFE\x53\x4D\x42 ("SMB2")
    let mut offset = 0;
    while offset + 8 < client_data.len() {
        // NetBIOS session header (4 bytes) + SMB header
        let nb_len = if client_data[offset] == 0x00 && offset + 4 < client_data.len() {
            let len = u32::from_be_bytes([
                0,
                client_data[offset + 1],
                client_data[offset + 2],
                client_data[offset + 3],
            ]) as usize;
            offset += 4;
            len
        } else {
            break;
        };

        if offset + 4 > client_data.len() {
            break;
        }

        // SMB1 magic
        if client_data[offset] == 0xFF
            && client_data[offset + 1] == b'S'
            && client_data[offset + 2] == b'M'
            && client_data[offset + 3] == b'B'
        {
            session.version = SmbVersion::Smb1;
            // SMB1 command byte at offset+4
            if offset + 5 <= client_data.len() {
                let cmd = client_data[offset + 4];
                match cmd {
                    0x75 => session.signals.push("tree_connect".into()), // Tree Connect
                    0x2D => session.signals.push("open_file".into()),    // Open
                    0x32 => session.signals.push("transaction".into()),  // Transaction
                    0xA2 => session.signals.push("nt_create".into()),    // NT Create AndX
                    _ => {}
                }
            }
        }
        // SMB2 magic
        else if client_data[offset] == 0xFE
            && client_data[offset + 1] == b'S'
            && client_data[offset + 2] == b'M'
            && client_data[offset + 3] == b'B'
        {
            if session.version == SmbVersion::Unknown {
                session.version = SmbVersion::Smb2;
            }
            // SMB2 command at offset+12 (2 bytes LE)
            if offset + 14 <= client_data.len() {
                let cmd = u16::from_le_bytes([client_data[offset + 12], client_data[offset + 13]]);
                match cmd {
                    0x0003 => session.signals.push("tree_connect".into()), // TREE_CONNECT
                    0x0005 => session.signals.push("create_file".into()),  // CREATE
                    0x0008 => session.signals.push("read_file".into()),    // READ
                    0x0009 => session.signals.push("write_file".into()),   // WRITE
                    0x000B => session.signals.push("ioctl".into()), // IOCTL (psexec uses this)
                    _ => {}
                }
            }
        }
        // SMB3 transform/compression-style magic.
        else if client_data[offset] == 0xFD
            && client_data[offset + 1] == b'S'
            && client_data[offset + 2] == b'M'
            && client_data[offset + 3] == b'B'
        {
            session.version = SmbVersion::Smb3;
            session.signals.push("smb3_transform".into());
        }

        // Move to next message
        offset += nb_len;
        if nb_len == 0 {
            break;
        }
    }

    // Scan for named pipe strings (lateral movement indicators)
    let pipe_patterns = [
        ("\\IPC$", "ipc_share"),
        ("\\ADMIN$", "admin_share"),
        ("\\C$", "c_share"),
        ("svcctl", "remote_service_control"), // psexec
        ("atsvc", "remote_task_scheduler"),   // at.exe
        ("srvsvc", "server_service"),         // share enumeration
        ("samr", "sam_enumeration"),          // user enumeration
        ("lsarpc", "lsa_enumeration"),        // policy enumeration
        ("winreg", "remote_registry"),        // registry access
        ("PSEXESVC", "psexec_service"),       // psexec indicator
    ];

    let data_str = String::from_utf8_lossy(client_data);
    for (pattern, signal_name) in &pipe_patterns {
        if data_str.contains(pattern) {
            session.named_pipes.push(pattern.to_string());
            session.signals.push(signal_name.to_string());
        }
    }

    // Only return if we detected something meaningful
    if session.version == SmbVersion::Unknown && session.signals.is_empty() {
        return None;
    }

    // Flag high-risk combinations
    if session.signals.contains(&"ipc_share".to_string())
        && (session
            .signals
            .contains(&"remote_service_control".to_string())
            || session.signals.contains(&"psexec_service".to_string()))
    {
        session.signals.push("LATERAL_MOVEMENT_PSEXEC".into());
    }

    if session.signals.contains(&"sam_enumeration".to_string())
        || session.signals.contains(&"lsa_enumeration".to_string())
    {
        session.signals.push("CREDENTIAL_ENUMERATION".into());
    }

    Some(session)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nb_message(payload: &[u8]) -> Vec<u8> {
        let len = payload.len() as u32;
        let mut data = vec![
            0x00,
            ((len >> 16) & 0xff) as u8,
            ((len >> 8) & 0xff) as u8,
            (len & 0xff) as u8,
        ];
        data.extend_from_slice(payload);
        data
    }

    fn smb1_message(command: u8) -> Vec<u8> {
        let mut payload = vec![0xFF, b'S', b'M', b'B', command];
        payload.resize(32, 0);
        nb_message(&payload)
    }

    fn smb2_message(command: u16) -> Vec<u8> {
        let mut payload = vec![0xFE, b'S', b'M', b'B'];
        payload.resize(14, 0);
        let bytes = command.to_le_bytes();
        payload[12] = bytes[0];
        payload[13] = bytes[1];
        payload.resize(64, 0);
        nb_message(&payload)
    }

    fn smb3_transform_message() -> Vec<u8> {
        let mut payload = vec![0xFD, b'S', b'M', b'B'];
        payload.resize(64, 0);
        nb_message(&payload)
    }

    #[test]
    fn test_detect_psexec_named_pipes() {
        // Build a minimal SMB2 message with named pipe strings in the data
        let mut data = vec![0x00, 0x00, 0x00, 0x50]; // NB header, len=80
        data.extend_from_slice(&[0xFE, b'S', b'M', b'B']); // SMB2 magic
        data.extend_from_slice(&[0; 72]); // Pad to fill NB length
                                          // Append named pipe strings (scanned by string matching)
        data.extend_from_slice(b"\\IPC$\x00svcctl\x00PSEXESVC\x00");

        let session = parse_session(&data).unwrap();
        assert_eq!(session.version, SmbVersion::Smb2);
        assert!(session.signals.contains(&"ipc_share".to_string()));
        assert!(session
            .signals
            .contains(&"remote_service_control".to_string()));
        assert!(session.signals.contains(&"psexec_service".to_string()));
        assert!(session
            .signals
            .contains(&"LATERAL_MOVEMENT_PSEXEC".to_string()));
    }

    #[test]
    fn test_no_smb() {
        let data = b"GET / HTTP/1.1\r\n\r\n";
        assert!(parse_session(data).is_none());
    }

    #[test]
    fn empty_buffer_returns_none() {
        assert!(parse_session(&[]).is_none());
    }

    #[test]
    fn truncated_netbios_header_returns_none() {
        assert!(parse_session(&[0x00, 0x00, 0x00]).is_none());
    }

    #[test]
    fn detects_smb1_negotiate_header() {
        let session = parse_session(&smb1_message(0x75)).expect("smb1 session");

        assert_eq!(session.version, SmbVersion::Smb1);
        assert!(session.signals.contains(&"tree_connect".to_string()));
    }

    #[test]
    fn detects_smb2_tree_connect_command() {
        let session = parse_session(&smb2_message(0x0003)).expect("smb2 session");

        assert_eq!(session.version, SmbVersion::Smb2);
        assert!(session.signals.contains(&"tree_connect".to_string()));
    }

    #[test]
    fn detects_smb3_transform_header() {
        let session = parse_session(&smb3_transform_message()).expect("smb3 session");

        assert_eq!(session.version, SmbVersion::Smb3);
        assert!(session.signals.contains(&"smb3_transform".to_string()));
    }

    #[test]
    fn garbage_first_byte_only_does_not_match() {
        let data = nb_message(&[0xFE, b'N', b'O', b'P', 0, 0, 0, 0]);

        assert!(parse_session(&data).is_none());
    }

    #[test]
    fn test_smb1_commands() {
        let open_file = parse_session(&smb1_message(0x2D)).unwrap();
        assert!(open_file.signals.contains(&"open_file".to_string()));

        let transaction = parse_session(&smb1_message(0x32)).unwrap();
        assert!(transaction.signals.contains(&"transaction".to_string()));

        let nt_create = parse_session(&smb1_message(0xA2)).unwrap();
        assert!(nt_create.signals.contains(&"nt_create".to_string()));
    }

    #[test]
    fn test_smb2_commands() {
        let create_file = parse_session(&smb2_message(0x0005)).unwrap();
        assert!(create_file.signals.contains(&"create_file".to_string()));

        let read_file = parse_session(&smb2_message(0x0008)).unwrap();
        assert!(read_file.signals.contains(&"read_file".to_string()));

        let write_file = parse_session(&smb2_message(0x0009)).unwrap();
        assert!(write_file.signals.contains(&"write_file".to_string()));

        let ioctl = parse_session(&smb2_message(0x000B)).unwrap();
        assert!(ioctl.signals.contains(&"ioctl".to_string()));
    }

    #[test]
    fn test_credential_enumeration_samr() {
        let mut data = smb2_message(0x0005);
        data.extend_from_slice(b"samr\x00");
        let session = parse_session(&data).unwrap();
        assert!(session.signals.contains(&"sam_enumeration".to_string()));
        assert!(session
            .signals
            .contains(&"CREDENTIAL_ENUMERATION".to_string()));
    }

    #[test]
    fn test_credential_enumeration_lsarpc() {
        let mut data = smb2_message(0x0005);
        data.extend_from_slice(b"lsarpc\x00");
        let session = parse_session(&data).unwrap();
        assert!(session.signals.contains(&"lsa_enumeration".to_string()));
        assert!(session
            .signals
            .contains(&"CREDENTIAL_ENUMERATION".to_string()));
    }

    #[test]
    fn test_admin_share() {
        let mut data = smb2_message(0x0005);
        data.extend_from_slice(b"\\ADMIN$\x00");
        let session = parse_session(&data).unwrap();
        assert!(session.signals.contains(&"admin_share".to_string()));
    }

    #[test]
    fn test_c_share() {
        let mut data = smb2_message(0x0005);
        data.extend_from_slice(b"\\C$\x00");
        let session = parse_session(&data).unwrap();
        assert!(session.signals.contains(&"c_share".to_string()));
    }

    #[test]
    fn test_zero_length_netbios() {
        let data = vec![0x00, 0x00, 0x00, 0x00, 0xFF, b'S', b'M', b'B'];
        assert!(parse_session(&data).is_none());
    }
}
