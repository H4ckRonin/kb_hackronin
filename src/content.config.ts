import { defineCollection, z } from "astro:content";
import { glob } from "astro/loaders";

const certifications = defineCollection({
	loader: glob({ pattern: "**/*.md", base: "./certifications" }),
	schema: z.object({
		title: z.string().optional(),
		category: z.string().optional(),
		vendor: z.string().optional(),
		certification: z.string().optional(),
		description: z.string().optional(),
		difficulty: z.string().optional(),
		status: z.string().optional(),
		order: z.number().optional(),
	}),
});

const methodologies = defineCollection({
	loader: glob({ pattern: "**/*.md", base: "./methodologies" }),
	schema: z.object({
		title: z.string().optional(),
		category: z.string().optional(),
		description: z.string().optional(),
		difficulty: z.enum(["beginner", "intermediate", "advanced", "expert"]).optional(),
		timeEstimate: z.string().optional(),
		prerequisites: z.array(z.string()).optional(),
		useCases: z.array(z.string()).optional(),
		phases: z.number().optional(),
		lastUpdated: z.date().optional(),
		tags: z.array(z.string()).optional(),
		relatedMethodologies: z.array(z.string()).optional(),
	}),
});

const tools = defineCollection({
	loader: glob({ pattern: "**/*.md", base: "./tools" }),
	schema: z.object({
		title: z.string().optional(),
		category: z.string().optional(),
		description: z.string().optional(),
	}),
});

const unifiedKillChain = defineCollection({
	loader: glob({ pattern: "**/*.md", base: "./unified-kill-chain" }),
	schema: z.object({
		title: z.string().optional(),
		phase: z.string().optional(),
		description: z.string().optional(),
	}),
});

const guides = defineCollection({
	loader: glob({ pattern: "**/*.md", base: "./guides" }),
	schema: z.object({
		title: z.string().optional(),
		category: z.string().optional(),
		vendor: z.string().optional(),
		certification: z.string().optional(),
		description: z.string().optional(),
		difficulty: z.string().optional(),
		status: z.string().optional(),
		order: z.number().optional(),
	}),
});

export const collections = { 
	certifications,
	methodologies,
	tools,
	unifiedKillChain,
	guides,
};
