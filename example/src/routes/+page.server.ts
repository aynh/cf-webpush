import { JWK } from '$env/static/private';

import { error, type Actions } from '@sveltejs/kit';
import { buildRequest, getPublicKeyFromJwk, type PushSubscription } from 'cf-webpush';

import type { PageServerLoad } from './$types';

export const actions = {
	default: async ({ request }) => {
		const data = await request.formData();
		const get = (k: string) => data.get(k) as string;

		const title = get('title');
		const body = get('body');
		const payload = JSON.stringify({ title, body });

		const subscription: PushSubscription = JSON.parse(get('subscription'));

		const jwk = JSON.parse(JWK);
		const ttl = 20 * 60 * 60; // 20 hours
		const host = new URL(subscription.endpoint).origin;
		const pushRequest = await buildRequest(
			{
				jwk,
				ttl,
				jwt: {
					aud: host,
					exp: Math.floor(Date.now() / 1000) + ttl,
					sub: '99479536+aynh@users.noreply.github.com',
				},
				payload,
			},
			subscription,
		);

		const response = await fetch(pushRequest);
		if (!response.ok) {
			throw error(500, `received http code ${response.status}`);
		}
	},
} satisfies Actions;

export const load = (() => {
	return { publicKey: getPublicKeyFromJwk(JSON.parse(JWK)) };
}) satisfies PageServerLoad;
