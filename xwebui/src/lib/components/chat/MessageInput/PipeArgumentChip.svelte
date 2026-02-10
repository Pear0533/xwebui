<script lang="ts">
	import { createEventDispatcher, getContext } from 'svelte';
	import XMark from '$lib/components/icons/XMark.svelte';
	import Tooltip from '$lib/components/common/Tooltip.svelte';
	import type { PipeArgument } from '$lib/apis/functions';

	const i18n = getContext('i18n');
	const dispatch = createEventDispatcher();

	export let argument: PipeArgument;
	export let value: string = '';
	export let removable: boolean = true;

	let inputElement: HTMLInputElement | HTMLSelectElement;
	let isFocused = false;

	$: displayPrefix = argument.prefix || '—';
	$: isBoolean = argument.type === 'boolean';
	$: isSelect = argument.type === 'select' && argument.options && argument.options.length > 0;
	$: isNumber = argument.type === 'number';

	function handleRemove() {
		dispatch('remove', { name: argument.name });
	}

	function handleValueChange() {
		dispatch('change', { name: argument.name, value });
	}

	function focusInput() {
		if (inputElement && !isBoolean) {
			inputElement.focus();
		}
	}

	export function focus() {
		focusInput();
	}
</script>

<div
	class="inline-flex items-center gap-0.5 px-2 py-1 rounded-lg text-sm
		bg-blue-100 dark:bg-blue-900/40 text-blue-800 dark:text-blue-200
		border border-blue-200 dark:border-blue-700
		transition-all duration-150
		{isFocused ? 'ring-2 ring-blue-400 dark:ring-blue-500' : ''}"
	role="button"
	tabindex="-1"
	on:click={focusInput}
>
	<!-- Argument Name Label -->
	<Tooltip content={argument.description || `${displayPrefix}${argument.name}`}>
		<span class="font-medium text-blue-700 dark:text-blue-300 select-none">
			{displayPrefix}{argument.name}
		</span>
	</Tooltip>

	{#if !isBoolean}
		<span class="text-blue-400 dark:text-blue-500 mx-0.5"></span>

		<!-- Value Input -->
		{#if isSelect}
			<select
				bind:this={inputElement}
				bind:value
				on:change={handleValueChange}
				on:focus={() => (isFocused = true)}
				on:blur={() => (isFocused = false)}
				class="bg-transparent border-none outline-none text-blue-800 dark:text-blue-100
					min-w-[60px] max-w-[120px] text-sm cursor-pointer
					focus:ring-0"
			>
				{#if argument.default === undefined && !argument.required}
					<option value="">--</option>
				{/if}
				{#each argument.options || [] as option}
					<option value={option}>{option}</option>
				{/each}
			</select>
		{:else if isNumber}
			<input
				bind:this={inputElement}
				bind:value
				on:input={handleValueChange}
				on:focus={() => (isFocused = true)}
				on:blur={() => (isFocused = false)}
				type="number"
				placeholder={argument.default || '0'}
				class="bg-transparent border-none outline-none text-blue-800 dark:text-blue-100
					w-[60px] min-w-[40px] max-w-[100px] text-sm
					placeholder:text-blue-400 dark:placeholder:text-blue-600
					focus:ring-0"
				style="width: {Math.max(40, Math.min(100, (value?.length || 3) * 8 + 16))}px"
			/>
		{:else}
			<input
				bind:this={inputElement}
				bind:value
				on:input={handleValueChange}
				on:focus={() => (isFocused = true)}
				on:blur={() => (isFocused = false)}
				type="text"
				placeholder={argument.default || '...'}
				class="bg-transparent border-none outline-none text-blue-800 dark:text-blue-100
					w-[60px] min-w-[40px] max-w-[100px] text-sm
					placeholder:text-blue-400 dark:placeholder:text-blue-600
					focus:ring-0"
				style="width: {Math.max(40, Math.min(100, (value?.length || 3) * 8 + 16))}px"
			/>
		{/if}
	{/if}

	<!-- Remove Button -->
	{#if removable}
		<button
			type="button"
			class="ml-0.5 p-0.5 rounded hover:bg-blue-200 dark:hover:bg-blue-800
				text-blue-500 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-200
				transition-colors duration-150"
			on:click|stopPropagation={handleRemove}
			aria-label={$i18n.t('Remove {{name}}', { name: argument.name })}
		>
			<XMark className="size-3.5" />
		</button>
	{/if}
</div>
