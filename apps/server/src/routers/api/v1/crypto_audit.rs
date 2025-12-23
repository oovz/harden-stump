use axum::{extract::State, middleware, routing::get, Extension, Json, Router};
use prisma_client_rust::Direction;
use stump_core::{
	db::entity::CryptoAuditLog,
	prisma::{crypto_audit_log, PrismaClient},
};

use crate::{
	config::state::AppState,
	errors::APIResult,
	middleware::auth::{auth_middleware, RequestContext},
};

pub(crate) fn mount(app_state: AppState) -> Router<AppState> {
	Router::new()
		.route("/audit/logs", get(list_audit_logs))
		.layer(middleware::from_fn_with_state(app_state, auth_middleware))
}

/// List crypto audit logs (server-owner only)
#[utoipa::path(
    get,
    path = "/api/v1/audit/logs",
    tag = "audit",
    responses(
        (status = 200, description = "Fetched crypto audit logs", body = Vec<CryptoAuditLog>),
        (status = 403, description = "Forbidden"),
    )
)]
async fn list_audit_logs(
	State(ctx): State<AppState>,
	Extension(req): Extension<RequestContext>,
) -> APIResult<Json<Vec<CryptoAuditLog>>> {
	// Only server owners can read audit logs
	req.enforce_server_owner()?;

	let client: &PrismaClient = &ctx.db;

	let logs = client
		.crypto_audit_log()
		.find_many(vec![])
		.order_by(crypto_audit_log::timestamp::order(Direction::Desc))
		.exec()
		.await?
		.into_iter()
		.map(CryptoAuditLog::from)
		.collect::<Vec<_>>();

	Ok(Json(logs))
}
