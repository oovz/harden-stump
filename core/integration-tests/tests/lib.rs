mod secure_encryption_job_queue;
mod secure_jobs_concurrency;
mod secure_libraries_list_endpoint;
mod secure_library;
mod secure_library_path_lifecycle;
mod secure_rescan;
mod secure_smk_verification;

// NOTE: The following test modules are not included because they test edge cases
// that require additional implementation work:
// - secure_encryption_job_retry: Tests idempotent retry behavior (Post-MVP)
// - secure_libraries_endpoints: Tests catalog regeneration from v2 to v1 (Post-MVP)
