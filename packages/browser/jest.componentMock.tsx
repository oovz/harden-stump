import React from 'react'

export default function JestComponentMock(props: { children?: React.ReactNode }) {
	return <>{props.children}</>
}
