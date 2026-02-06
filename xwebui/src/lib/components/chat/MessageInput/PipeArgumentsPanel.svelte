<script lang="ts">
	import { createEventDispatcher, getContext, onMount } from 'svelte';
	import { models } from '$lib/stores';
	import { getPipeArgumentsById, type PipeArgument, type PipeArgumentsSpec } from '$lib/apis/functions';
	import Tooltip from '$lib/components/common/Tooltip.svelte';
	import Spinner from '$lib/components/common/Spinner.svelte';
	import Plus from '$lib/components/icons/Plus.svelte';

	const i18n = getContext('i18n');
	const dispatch = createEventDispatcher();

	// The currently selected model IDs
	export let selectedModels: string[] = [];
	// Arguments that have already been added to the prompt
	export let activeArguments: Map<string, string> = new Map();
	// Whether to show the panel
	export let show: boolean = false;

	let loading = false;
	let pipeArguments: PipeArgument[] = [];
	let currentPipeId: string | null = null;
	let error: string | null = null;

	// Get the pipe function ID from the model
	function getPipeIdFromModel(modelId: string): string | null {
		const model = $models.find((m) => m.id === modelId);
		if (!model) return null;

		// Check if it's a pipe model
		// Pipe models have the format "functionId" or "functionId.subPipeId"
		if (model.pipe || model.owned_by === 'openai') {
			// For pipes, the function ID is the model ID (possibly with a sub-pipe suffix)
			const pipeId = modelId.includes('.') ? modelId.split('.')[0] : modelId;
			return pipeId;
		}
		return null;
	}

	// Reactive: when selected models change, fetch arguments for the first pipe model
	$: {
		const firstPipeId = selectedModels.map(getPipeIdFromModel).find((id) => id !== null) || null;
		if (firstPipeId !== currentPipeId) {
			currentPipeId = firstPipeId;
			if (currentPipeId) {
				loadPipeArguments(currentPipeId);
			} else {
				pipeArguments = [];
			}
		}
	}

	async function loadPipeArguments(pipeId: string) {
		loading = true;
		error = null;
		try {
			const spec = await getPipeArgumentsById(localStorage.token, pipeId);
			if (spec && spec.arguments) {
				pipeArguments = spec.arguments;
			} else {
				pipeArguments = [];
			}
		} catch (e) {
			console.error('Failed to load pipe arguments:', e);
			error = e?.toString() || 'Failed to load arguments';
			pipeArguments = [];
		} finally {
			loading = false;
		}
	}

	function handleAddArgument(arg: PipeArgument) {
		dispatch('add', {
			argument: arg,
			value: arg.default || ''
		});
	}

	// Filter out arguments that are already active
	$: availableArguments = pipeArguments.filter((arg) => !activeArguments.has(arg.name));
	$: hasArguments = pipeArguments.length > 0;
	$: hasPipe = currentPipeId !== null;
</script>

{#if show && hasPipe && (hasArguments || loading)}
	<div
		class="flex flex-wrap gap-1.5 px-2 py-1.5 bg-gray-50 dark:bg-gray-850 rounded-lg
			border border-gray-100 dark:border-gray-800 text-xs"
	>
		{#if loading}
			<div class="flex items-center gap-2 text-gray-500 dark:text-gray-400">
				<Spinner className="size-3" />
				<span>{$i18n.t('Loading arguments...')}</span>
			</div>
		{:else if error}
			<div class="text-red-500 dark:text-red-400">
				{error}
			</div>
		{:else if availableArguments.length > 0}
			<span class="text-gray-500 dark:text-gray-400 self-center mr-1">
				{$i18n.t('Arguments')}:
			</span>
			{#each availableArguments as arg (arg.name)}
				<Tooltip content={arg.description || `Add ${arg.prefix || '—'}${arg.name} argument`}>
					<button
						type="button"
						class="inline-flex items-center gap-1 px-2 py-1 rounded-md
							bg-gray-100 dark:bg-gray-800 hover:bg-blue-100 dark:hover:bg-blue-900/40
							text-gray-700 dark:text-gray-300 hover:text-blue-700 dark:hover:text-blue-300
							border border-gray-200 dark:border-gray-700 hover:border-blue-300 dark:hover:border-blue-600
							transition-colors duration-150"
						on:click={() => handleAddArgument(arg)}
					>
						<Plus className="size-3" />
						<span class="font-medium">{arg.prefix || '—'}{arg.name}</span>
						{#if arg.type === 'boolean'}
							<span class="text-gray-400 dark:text-gray-500">(flag)</span>
						{:else if arg.type === 'number'}
							<span class="text-gray-400 dark:text-gray-500">(num)</span>
						{:else if arg.type === 'select'}
							<span class="text-gray-400 dark:text-gray-500">(select)</span>
						{/if}
					</button>
				</Tooltip>
			{/each}
		{:else if activeArguments.size > 0}
			<span class="text-gray-400 dark:text-gray-500 italic">
				{$i18n.t('All arguments added')}
			</span>
		{:else}
			<span class="text-gray-400 dark:text-gray-500 italic">
				{$i18n.t('No arguments available for this pipe')}
			</span>
		{/if}
	</div>
{/if}
