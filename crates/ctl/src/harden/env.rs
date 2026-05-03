use std::fs;
use std::path::Path;
use std::process::Command;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DirEntry {
    pub(super) path: String,
    pub(super) is_file: bool,
    pub(super) is_dir: bool,
}

pub(super) trait HardenEnv {
    fn read_to_string(&self, path: &str) -> Option<String>;
    fn read_bytes(&self, path: &str) -> Option<Vec<u8>>;
    fn read_dir(&self, path: &str) -> Vec<DirEntry>;
    fn metadata_mode(&self, path: &str) -> Option<u32>;
    fn path_exists(&self, path: &str) -> bool;
    fn command_stdout(&self, program: &str, args: &[&str]) -> Option<String>;
}

pub(super) struct RealHardenEnv;

impl HardenEnv for RealHardenEnv {
    fn read_to_string(&self, path: &str) -> Option<String> {
        fs::read_to_string(path).ok()
    }

    fn read_bytes(&self, path: &str) -> Option<Vec<u8>> {
        fs::read(path).ok()
    }

    fn read_dir(&self, path: &str) -> Vec<DirEntry> {
        fs::read_dir(path)
            .into_iter()
            .flat_map(|entries| entries.flatten())
            .filter_map(|entry| {
                let path = entry.path();
                let metadata = entry.metadata().ok()?;
                Some(DirEntry {
                    path: path.display().to_string(),
                    is_file: metadata.is_file(),
                    is_dir: metadata.is_dir(),
                })
            })
            .collect()
    }

    fn metadata_mode(&self, path: &str) -> Option<u32> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::metadata(path)
                .ok()
                .map(|meta| meta.permissions().mode())
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            None
        }
    }

    fn path_exists(&self, path: &str) -> bool {
        Path::new(path).exists()
    }

    fn command_stdout(&self, program: &str, args: &[&str]) -> Option<String> {
        Command::new(program)
            .args(args)
            .output()
            .ok()
            .map(|out| String::from_utf8_lossy(&out.stdout).to_string())
    }
}
