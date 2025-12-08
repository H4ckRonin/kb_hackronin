import { defineConfig } from 'astro/config'
import svelte from '@astrojs/svelte'
import mdx from '@astrojs/mdx'
import remarkGfm from 'remark-gfm'
import remarkSmartypants from 'remark-smartypants'
import rehypeExternalLinks from 'rehype-external-links'

// https://astro.build/config
export default defineConfig({
  // Base path will be set by GitHub Actions workflow via --base flag
  // For local development, this defaults to '/' (can be overridden via CLI)
  // base: '/kb_hackronin/', // Uncomment and set if needed for local testing
  site: 'https://kb.h4ckronin.com',
  integrations: [mdx(), svelte()],
  markdown: {
    shikiConfig: {
      theme: 'nord',
      wrap: true,
    },
    remarkPlugins: [remarkGfm, remarkSmartypants],
    rehypePlugins: [
      [
        rehypeExternalLinks,
        {
          target: '_blank',
        },
      ],
    ],
  },
  output: 'static',
  build: {
    inlineStylesheets: 'auto',
    assets: '_assets',
  },
  compressHTML: true,
  vite: {
    optimizeDeps: {
      include: ['lucide-astro'],
      force: false,
    },
    build: {
      minify: 'esbuild',
      cssMinify: true,
      rollupOptions: {
        output: {
          manualChunks: (id) => {
            if (id.includes('node_modules')) {
              if (id.includes('lucide')) {
                return 'vendor-lucide';
              }
              return 'vendor';
            }
          },
          chunkSizeWarningLimit: 1000,
        },
      },
      sourcemap: false,
    },
  },
})

