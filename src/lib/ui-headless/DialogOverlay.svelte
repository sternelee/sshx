<script lang="ts">
  let { class: className = "" }: { class?: string } = $props();
</script>

<div class={className}></div>
