import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import type { FastifyInstance } from 'fastify';
import { parse } from 'yaml';

const SPEC_PATH = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../openapi/openapi.yaml',
);

export interface OpenApiDocument {
  openapi: string;
  info: { title: string; version: string };
  paths: Record<string, Record<string, unknown>>;
}

/** The hand-written API description. A test keeps it in step with the routes. */
export async function loadOpenApiDocument(): Promise<OpenApiDocument> {
  return parse(await readFile(SPEC_PATH, 'utf8')) as OpenApiDocument;
}

/** Serves the spec at /docs/json and /docs/yaml, and Swagger UI at /docs. */
export async function registerApiDocs(app: FastifyInstance): Promise<void> {
  const document = await loadOpenApiDocument();
  await app.register(swagger, { mode: 'static', specification: { document: document as never } });
  await app.register(swaggerUi, { routePrefix: '/docs' });
}
