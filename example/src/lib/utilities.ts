// https://web.dev/push-notifications-subscribing-a-user/#subscribe-a-user-with-pushmanager
export const getSubscription = async (publicKey: string): Promise<PushSubscription> => {
	const serviceWorker = await navigator.serviceWorker.register('/service-worker.js');
	const subscription = await serviceWorker.pushManager.subscribe({
		userVisibleOnly: true,
		applicationServerKey: publicKey,
	});

	return subscription;
};

// https://web.dev/push-notifications-subscribing-a-user/#requesting-permission
export const askNotificationPermission = (): Promise<NotificationPermission> =>
	new Promise(function (resolve, reject) {
		const permissionResult = Notification.requestPermission(resolve);

		if (permissionResult) {
			permissionResult.then(resolve, reject);
		}
	});

export const checkWebpushCompability = (): void => {
	if (!('serviceWorker' in navigator)) {
		throw new Error('Service worker is not supported in this browser.');
	} else if (!('PushManager' in window)) {
		throw new Error('Push notification is not supported in this browser.');
	}
};
