// Utility functions for generating paths with base URL support
// This ensures links work correctly when deployed to GitHub Pages with a base path

/**
 * Get the base URL from environment or Astro config
 * For GitHub Pages, this will be something like "/kb_hackronin"
 */
export function getBaseUrl(): string {
  // In Astro, BASE_URL includes the trailing slash if base is set
  // For example: "/kb_hackronin/" or "/"
  return import.meta.env.BASE_URL || '/';
}

/**
 * Generate a path with the base URL prepended
 * @param path - The path (should start with /)
 * @returns The path with base URL prepended
 */
export function withBase(path: string): string {
  const base = getBaseUrl();
  // Remove trailing slash from base if present (we'll add it back)
  const baseClean = base.endsWith('/') ? base.slice(0, -1) : base;
  // Ensure path starts with /
  const pathClean = path.startsWith('/') ? path : `/${path}`;
  // Combine base and path
  return `${baseClean}${pathClean}`;
}

/**
 * Generate a URL for an asset (images, etc.)
 * @param assetPath - The asset path (should start with /)
 * @returns The asset path with base URL prepended
 */
export function assetUrl(assetPath: string): string {
  return withBase(assetPath);
}

