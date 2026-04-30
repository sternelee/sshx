<script lang="ts">
  import { MinusIcon, PlusIcon, XIcon } from "svelte-feather-icons";

  let {
    kind,
    onclick,
    onmousedown,
  }: {
    kind: keyof typeof details;
    onclick?: (e: MouseEvent) => void;
    onmousedown?: (e: MouseEvent) => void;
  } = $props();

  const details = {
    red: { cls: "bg-red-500 active:bg-red-700", icon: XIcon },
    yellow: { cls: "bg-yellow-500 active:bg-yellow-700", icon: MinusIcon },
    green: { cls: "bg-green-500 active:bg-green-700", icon: PlusIcon },
  };

  const Icon = $derived(details[kind].icon);
</script>

<button
  class="w-3 h-3 p-[1px] rounded-full {details[kind].cls}"
  onmousedown={(e) => {
    e.stopPropagation();
    onmousedown?.(e);
  }}
  {onclick}
>
  <Icon class="w-full h-full" strokeWidth={3} />
</button>
