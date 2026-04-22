<script lang="ts">
  import { ChevronDownIcon } from "svelte-feather-icons";

  import { settings, updateSettings } from "$lib/settings";
  import OverlayMenu from "./OverlayMenu.svelte";
  import themes, { type ThemeName } from "./themes";

  export let open: boolean;

  let inputName: string;
  let inputTheme: ThemeName;
  let inputScrollback: number;

  let initialized = false;
  $: open, (initialized = false);
  $: if (!initialized) {
    initialized = true;
    inputName = $settings.name;
    inputTheme = $settings.theme;
    inputScrollback = $settings.scrollback;
  }
</script>

<OverlayMenu
  title="Terminal Settings"
  description="Customize your collaborative terminal."
  showCloseButton
  {open}
  on:close
>
  <div class="flex flex-col gap-4">
    <div class="item">
      <div>
        <p class="item-title">Name</p>
        <p class="item-subtitle">Choose how you appear to other users.</p>
      </div>
      <div>
        <input
          class="input-common"
          placeholder="Your name"
          bind:value={inputName}
          maxlength="50"
          on:input={() => {
            if (inputName.length >= 2) {
              updateSettings({ name: inputName });
            }
          }}
        />
      </div>
    </div>
    <div class="item">
      <div>
        <p class="item-title">Color palette</p>
        <p class="item-subtitle">Color theme for text in terminals.</p>
      </div>
      <div class="relative">
        <ChevronDownIcon
          class="absolute top-[11px] right-2.5 w-4 h-4 text-zinc-400"
        />
        <select
          class="input-common !pr-5"
          bind:value={inputTheme}
          on:change={() => updateSettings({ theme: inputTheme })}
        >
          {#each Object.keys(themes) as themeName (themeName)}
            <option value={themeName}>{themeName}</option>
          {/each}
        </select>
      </div>
    </div>
    <div class="item">
      <div>
        <p class="item-title">Scrollback</p>
        <p class="item-subtitle">
          Lines of previous text displayed in the terminal window.
        </p>
      </div>
      <div>
        <input
          type="number"
          class="input-common"
          bind:value={inputScrollback}
          on:input={() => {
            if (inputScrollback >= 0) {
              updateSettings({ scrollback: inputScrollback });
            }
          }}
          step="100"
        />
      </div>
    </div>
    <!-- <div class="item">
      <div>
        <p class="item-title">Cursor style</p>
        <p class="item-subtitle">Style of live cursors.</p>
      </div>
      <div class="text-red-500">Coming soon</div>
    </div> -->
  </div>

  <!-- svelte-ignore missing-declaration -->
  <p class="mt-6 text-sm text-right text-zinc-400">
    <a target="_blank" rel="noreferrer" href="https://github.com/ekzhang/sshx"
      >sshx-server v{__APP_VERSION__}</a
    >
  </p>
</OverlayMenu>

<style>
  .item {
    background-color: rgba(40, 40, 40, 0.25);
    border-radius: 0.5rem;
    padding: 1rem;
    display: flex;
    column-gap: 1rem;
    flex-direction: column;
    align-items: flex-start;
  }

  @media (min-width: 640px) {
    .item {
      flex-direction: row;
    }
  }

  .item > div:first-child {
    flex: 1;
  }

  .item-title {
    font-weight: 500;
    color: rgb(229, 229, 229);
    margin-bottom: 0.25rem;
  }

  .item-subtitle {
    font-size: 0.875rem;
    color: rgb(161, 161, 170);
  }

  .input-common {
    width: 13rem;
    padding: 0.5rem 0.75rem;
    font-size: 0.875rem;
    border-radius: 0.375rem;
    background-color: transparent;
    border: 1px solid rgb(63 63 70);
    outline: none;
    transition: box-shadow 200ms, background-color 200ms;
  }

  .input-common:focus {
    box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.5);
  }

  .input-common:hover {
    background-color: rgba(255, 255, 255, 0.05);
  }

  .input-common {
    appearance: none;
    transition: background-color 200ms, border-color 200ms;
  }
</style>
