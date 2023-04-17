/// <reference types="@sveltejs/kit" />
/// <reference no-default-lib="true"/>
/// <reference lib="esnext" />
/// <reference lib="webworker" />

const sw = /** @type {ServiceWorkerGlobalScope} */ (/** @type {unknown} */ (self));

sw.addEventListener('push', (event) => {
	const { body, title } = event.data.json();

	event.waitUntil(sw.registration.showNotification(title, { body }));
});
