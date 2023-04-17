# cf-webpush example

This is an example sveltekit project using cf-webpush hosted on Cloudflare Pages. Read https://web.dev/notifications for more information.

The usage here is pretty simple, basically the public key (required to subscribe to push notification) through [server load function](./src/routes/%2Bpage.server.ts) ([docs](https://kit.svelte.dev/docs/load)). When user submitted the form, it's then processed by the [default form action](./src/routes/%2Bpage.server.ts) ([docs](https://kit.svelte.dev/docs/form-actions)) to send the notification.

You can create your own [JWK](./.env) by running the code below in your browser console or Node.js REPL.

```js
await crypto.subtle
	.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
	.then(({ privateKey }) => crypto.subtle.exportKey('jwk', privateKey));
```
