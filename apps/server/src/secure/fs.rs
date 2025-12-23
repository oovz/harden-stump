use std::path::{Path, PathBuf};

pub fn secure_dir_for<P: AsRef<Path>>(library_path: P) -> PathBuf {
	library_path.as_ref().join(".secure")
}

pub fn exists_secure_dir<P: AsRef<Path>>(library_path: P) -> bool {
	secure_dir_for(library_path).exists()
}

pub fn catalog_paths_for<P: AsRef<Path>>(library_path: P) -> (PathBuf, PathBuf) {
	let dir = secure_dir_for(library_path);
	(dir.join("catalog.enc"), dir.join("catalog.meta.json"))
}

pub fn media_paths_for<P: AsRef<Path>>(
	library_path: P,
	media_id: &str,
) -> (PathBuf, PathBuf) {
	let dir = secure_dir_for(library_path);
	(
		dir.join(format!("{media_id}.enc")),
		dir.join(format!("{media_id}.meta.json")),
	)
}

pub fn thumbnail_paths_for<P: AsRef<Path>>(
	library_path: P,
	media_id: &str,
) -> (PathBuf, PathBuf) {
	let dir = secure_dir_for(library_path);
	(
		dir.join(format!("{media_id}.thumb.enc")),
		dir.join(format!("{media_id}.thumb.meta.json")),
	)
}
