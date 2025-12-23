use stump_core::{
	db::entity::User,
	prisma::{
		library::{self, WhereParam},
		user,
	},
};

use crate::{
	filter::{
		chain_optional_iter, decode_path_filter, LibraryBaseFilter, LibraryFilter,
		LibraryRelationFilter,
	},
	routers::api::filters::apply_series_base_filters,
};

pub(crate) fn apply_library_base_filters(filters: LibraryBaseFilter) -> Vec<WhereParam> {
	chain_optional_iter(
		[],
		[
			(!filters.id.is_empty()).then(|| library::id::in_vec(filters.id)),
			(!filters.name.is_empty()).then(|| library::name::in_vec(filters.name)),
			(!filters.path.is_empty()).then(|| {
				let decoded_paths = decode_path_filter(filters.path);
				library::path::in_vec(decoded_paths)
			}),
			filters.search.map(library::name::contains),
		],
	)
}

pub(crate) fn apply_library_relation_filters(
	filters: LibraryRelationFilter,
) -> Vec<WhereParam> {
	chain_optional_iter(
		[],
		[filters
			.series
			.map(apply_series_base_filters)
			.map(library::series::some)],
	)
}

pub(crate) fn library_not_hidden_from_user_filter(user: &User) -> WhereParam {
	library::hidden_from_users::none(vec![user::id::equals(user.id.clone())])
}

// FIXME: hidden libraries introduced a bug here, need to fix!
// TODO: ACL filtering should be integrated here using library_acl::library_acl_filter()
// The challenge is that this function is synchronous but ACL filtering requires async DB access.
// Options:
// 1. Make this function async and update all call sites
// 2. Move ACL filtering to the query level in get_libraries()
// 3. Pre-fetch accessible library IDs and pass them to this function
//
// For now, ACL filtering is handled separately in get_libraries() endpoint.
// See library_acl.rs for the ACL filtering implementation.

pub(crate) fn apply_library_filters_for_user(
	filters: LibraryFilter,
	user: &User,
) -> Vec<WhereParam> {
	let not_hidden_filter = library_not_hidden_from_user_filter(user);
	apply_library_base_filters(filters.base_filter)
		.into_iter()
		.chain(apply_library_relation_filters(filters.relation_filter))
		.chain([not_hidden_filter])
		.collect()
}
