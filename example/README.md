# cf-webpush example

This is an example sveltekit project using cf-webpush hosted on Cloudflare Pages.

The usage here is pretty simple, the public key (required to subscribe to push notification) is sent through [server load function](./src/routes/%2Bpage.server.ts) ([docs](https://kit.svelte.dev/docs/load)) and when user submitted the form, it's processed by the [form action](./src/routes/%2Bpage.server.ts) ([docs](https://kit.svelte.dev/docs/form-actions)) to send the notification.

You can generate your own [JWK](./.env) by running the code below in your browser console or Node.js REPL.

```js
await crypto.subtle
	.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
	.then(({ privateKey }) => crypto.subtle.exportKey('jwk', privateKey));
```
