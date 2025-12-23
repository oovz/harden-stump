use axum::middleware;
use axum::Router;
use stump_core::db::entity::*;

use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::config::state::AppState;
use crate::middleware::auth::auth_middleware;

use super::api::{self, v1::secure_library::*};

// TODO: investigate https://github.com/ProbablyClem/utoipauto

// NOTE: it is very easy to indirectly cause fmt failures by not adhering to the
// rustfmt rules, since cargo fmt will not format the code in the macro.
#[derive(OpenApi)]
#[openapi(
    paths(
        api::v1::secure_library::create_secure_library,
        api::v1::secure_library::delete_secure_library,
        api::v1::secure_library::scan_secure_library,
        api::v1::secure_library::get_secure_library_status,
        api::v1::secure_library::grant_library_access,
        api::v1::secure_library::revoke_library_access,
        api::v1::secure_library::get_library_access_list,
        api::v1::secure_library::list_secure_libraries,
        api::v1::secure_library::get_secure_library_access_status,
        api::v1::secure_library::get_wrapped_lmk,
        api::v1::secure_library::get_secure_library_catalog,
        api::v1::secure_library::get_secure_media_file_v2,
        api::v1::secure_library::get_secure_media_thumbnail
    ),
    components(
        schemas(
            SecureLibraryAccess,
            SecureLibraryStatus, JobProgressStatus, SecureLibrarySummary, AccessStatusResponse,
            CreateSecureLibraryRequest, CreateSecureLibraryResponse,
            DeleteSecureLibraryResponse, ScanSecureLibraryResponse,
            GrantAccessRequest, GrantAccessResponse,
            RevokeAccessRequest, RevokeAccessResponse,
            AccessListUser, AccessListResponse,
            WrappedLmkResponse
        )
    ),
    tags(
        (name = "secure-library", description = "Secure Libraries API"),
    )
)]
struct ApiDoc;

pub(crate) fn mount(app_state: AppState) -> Router<AppState> {
	Router::new()
		.merge(swagger_ui())
		.layer(middleware::from_fn_with_state(app_state, auth_middleware))
}

pub(crate) fn swagger_ui() -> SwaggerUi {
	SwaggerUi::new("/swagger-ui").url("/api-doc/openapi.json", ApiDoc::openapi())
}
