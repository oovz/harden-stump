import { useLocaleContext } from '@stump/i18n'
import { Helmet } from 'react-helmet'

import { ContentContainer, SceneContainer } from '@/components/container'

import ChangePasswordForm from './ChangePasswordForm'
import LocalePreferences from './LocalePreferences'
import ProfileForm from './ProfileForm'

export default function GeneralSettingsScene() {
	const { t } = useLocaleContext()

	return (
		<SceneContainer>
			<Helmet>
				<title>Stump | {t('settingsScene.app/account.helmet')}</title>
			</Helmet>

			<ContentContainer>
				<ProfileForm />
				<ChangePasswordForm />
				<LocalePreferences />
			</ContentContainer>
		</SceneContainer>
	)
}
