import {
	BookOpenText,
	FlaskRound,
	Image,
	Lock,
	NotebookTabs,
	PackageX,
	ScanSearch,
	ShieldCheck,
} from 'lucide-react'

import { RouteGroup } from '@/hooks/useRouteGroups'

export function buildLibrarySettingsRouteGroups(isSecure: boolean): RouteGroup[] {
	if (isSecure) {
		return [
			{
				defaultRoute: 'basics',
				items: [
					{
						icon: NotebookTabs,
						label: 'Basics',
						localeKey: 'basics',
						permission: 'library:edit',
						to: 'basics',
					},
				],
			},
			{
				defaultRoute: 'secure-scan',
				items: [
					{
						icon: Lock,
						label: 'Secure Scan',
						localeKey: 'options/secure-scan',
						permission: 'library:manage',
						to: 'secure-scan',
					},
				],
				label: 'Options',
			},
			{
				defaultRoute: 'danger',
				items: [
					{
						icon: ShieldCheck,
						label: 'Access Control',
						localeKey: 'danger-zone/access-control',
						permission: 'library:manage',
						to: 'access-control',
					},
					{
						icon: PackageX,
						label: 'Delete',
						localeKey: 'danger-zone/delete',
						permission: 'library:delete',
						to: 'delete',
					},
				],
				label: 'Danger Zone',
			},
		]
	}

	// Normal libraries
	return [
		{
			defaultRoute: 'basics',
			items: [
				{
					icon: NotebookTabs,
					label: 'Basics',
					localeKey: 'basics',
					permission: 'library:edit',
					to: 'basics',
				},
			],
		},
		{
			defaultRoute: 'options/scanning',
			items: [
				{
					icon: BookOpenText,
					label: 'Reading',
					localeKey: 'options/reading',
					permission: 'library:edit',
					to: 'reading',
				},
				{
					icon: ScanSearch,
					label: 'Scanning',
					localeKey: 'options/scanning',
					permission: 'library:manage',
					to: 'scanning',
				},
				{
					icon: Image,
					label: 'Thumbnails',
					localeKey: 'options/thumbnails',
					permission: 'library:manage',
					to: 'thumbnails',
				},
				{
					icon: FlaskRound,
					label: 'Analysis',
					localeKey: 'options/analysis',
					permission: 'library:manage',
					to: 'analysis',
				},
			],
			label: 'Options',
		},
		{
			defaultRoute: 'danger',
			items: [
				{
					icon: ShieldCheck,
					label: 'Access Control',
					localeKey: 'danger-zone/access-control',
					permission: 'library:manage',
					to: 'access-control',
				},
				{
					icon: PackageX,
					label: 'Delete',
					localeKey: 'danger-zone/delete',
					permission: 'library:delete',
					to: 'delete',
				},
			],
			label: 'Danger Zone',
		},
	]
}

// Backwards compatibility for callers not yet migrated
export const routeGroups: RouteGroup[] = buildLibrarySettingsRouteGroups(false)
