<script lang="ts">
	import { goto } from '$app/navigation';
	import { hasKey } from '$lib/storage';

	$effect(() => {
		goto(hasKey() ? '/unlock' : '/setup', { replaceState: true });
	});
</script>
