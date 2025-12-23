module.exports = function importMetaEnvPlugin({ types: t }) {
	return {
		name: 'transform-import-meta-env',
		visitor: {
			MemberExpression(path) {
				const { node } = path
				// Match import.meta.env.X
				if (!t.isMemberExpression(node.object)) return
				const metaEnv = node.object
				if (
					t.isMetaProperty(metaEnv.object) &&
					metaEnv.object.meta.name === 'import' &&
					metaEnv.object.property.name === 'meta' &&
					t.isIdentifier(metaEnv.property, { name: 'env' })
				) {
					if (t.isIdentifier(node.property, { name: 'DEV' })) {
						path.replaceWith(t.booleanLiteral(false))
					} else if (t.isIdentifier(node.property, { name: 'API_VERSION' })) {
						path.replaceWith(t.stringLiteral('v1'))
					}
				}
			},
		},
	}
}
