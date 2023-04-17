<script lang="ts">
	import { enhance, type SubmitFunction } from '$app/forms';
	import { checkWebpushCompability, getSubscription } from '$lib/utilities';

	import type { PageData } from './$types';

	export let data: PageData;

	const submit = (async ({ data: formData }) => {
		try {
			checkWebpushCompability();
			const subscription = await getSubscription(data.publicKey);
			formData.set('subscription', JSON.stringify(subscription));
		} catch (error) {
			alert(error);
			throw error;
		}
	}) satisfies SubmitFunction;
</script>

<form use:enhance={submit} method="post">
	<label for="title">
		title
		<input type="text" name="title" id="title" />
	</label>

	<label for="body">
		body
		<input type="text" name="body" id="body" />
	</label>

	<button type="submit">Send notification</button>
</form>
