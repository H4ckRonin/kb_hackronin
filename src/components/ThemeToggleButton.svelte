<script>
  import { onMount } from 'svelte';
  
  const themes = ['light', 'dark'];
  let theme = ''
  let mounted = false;

  // Initialize theme
  if (typeof window !== 'undefined') {
    const storedTheme = localStorage.getItem('theme');
    if (storedTheme) {
      theme = storedTheme;
    } else {
      theme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }
  }

  function handleChange(event) {
    theme = event.target.value;
    localStorage.setItem('theme', theme);
    if (mounted) {
      applyTheme(theme);
    }
  }

  function applyTheme(newTheme) {
    if (typeof document === 'undefined') return;
    
    const root = document.documentElement;
    const body = document.body;
    
    if (newTheme === 'light') {
      root.classList.remove('theme-dark');
      root.setAttribute('data-theme', 'light');
      if (body) body.classList.remove('theme-dark');
    } else {
      root.classList.add('theme-dark');
      root.setAttribute('data-theme', 'dark');
      if (body) body.classList.add('theme-dark');
    }
  }

  // Apply theme on mount
  onMount(() => {
    mounted = true;
    if (theme) {
      applyTheme(theme);
    }
  });

  // Apply theme when it changes (only after mount)
  $: if (mounted && theme && typeof document !== 'undefined') {
    applyTheme(theme);
  }

  const icons = [
    `<svg
      xmlns="http://www.w3.org/2000/svg"
      width="20"
      height="20"
      viewBox="0 0 20 20"
      fill="currentColor"
    >
      <path
        fill-rule="evenodd"
        d="M10 2a1 1 0 011 1v1a1 1 0 11-2 0V3a1 1 0 011-1zm4 8a4 4 0 11-8 0 4 4 0 018 0zm-.464 4.95l.707.707a1 1 0 001.414-1.414l-.707-.707a1 1 0 00-1.414 1.414zm2.12-10.607a1 1 0 010 1.414l-.706.707a1 1 0 11-1.414-1.414l.707-.707a1 1 0 011.414 0zM17 11a1 1 0 100-2h-1a1 1 0 100 2h1zm-7 4a1 1 0 011 1v1a1 1 0 11-2 0v-1a1 1 0 011-1zM5.05 6.464A1 1 0 106.465 5.05l-.708-.707a1 1 0 00-1.414 1.414l.707.707zm1.414 8.486l-.707.707a1 1 0 01-1.414-1.414l.707-.707a1 1 0 011.414 1.414zM4 11a1 1 0 100-2H3a1 1 0 000 2h1z"
        clip-rule="evenodd"
      />
    </svg>`,
    `<svg
      xmlns="http://www.w3.org/2000/svg"
      width="20"
      height="20"
      viewBox="0 0 20 20"
      fill="currentColor"
    >
      <path d="M17.293 13.293A8 8 0 016.707 2.707a8.001 8.001 0 1010.586 10.586z" />
    </svg>`,
  ];
</script>

<div class="theme-toggle">
  {#each themes as t, i}
    <label class={theme === t ? 'checked' : ''}>
      {@html icons[i]}
      <input
        type="radio"
        name="theme-toggle"
        checked={theme === t}
        value={t}
        title={`Use ${t} theme`}
        aria-label={`Use ${t} theme`}
        on:change={handleChange}
      />
    </label>
  {/each}
</div>

<style>
  .theme-toggle {
    display: inline-flex;
    align-items: center;
    height: 100%;
    padding: 0.33em 0.67em;
    gap: 0.6em;
    border-radius: 99em;
    background-color: rgba(212, 183, 140, 0.1);
    border: 1px solid var(--border-color, rgba(212, 183, 140, 0.2));
    transition: background-color 0.3s, border-color 0.3s;
  }

  [data-theme="light"] .theme-toggle {
    background-color: rgba(212, 183, 140, 0.15);
    border-color: rgba(212, 183, 140, 0.3);
  }

  .theme-toggle > label {
    color: var(--accent-color, #d4b78c);
    position: relative;
    display: flex;
    align-items: center;
    justify-content: center;
    opacity: 0.5;
    cursor: pointer;
    transition: opacity 0.2s;
  }

  .theme-toggle > label.checked {
    opacity: 1;
  }

  input[name='theme-toggle'] {
    position: absolute;
    opacity: 0;
    top: 0;
    right: 0;
    bottom: 0;
    left: 0;
    z-index: -1;
  }
</style>

