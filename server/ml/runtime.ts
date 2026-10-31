/**
 * Model persistence, versioning, and rollback registry.
 *
 * Stores serialized model artifacts as JSON files on disk, with a manifest
 * tracking version, trainedAt, and rollback status. On load, the active model
 * is the newest *validated* artifact; a validation failure on load triggers
 * automatic rollback to the last known-good version.
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import type { ModelArtifact, ModelMetadata, ModelRegistryEntry, ModelStorageOptions, TrainableModel } from './types.ts';

interface ManifestArtifactEntry {
  version: string;
  path: string;
  trainedAt: string;
  rollbackTrigger?: string;
  status: 'ACTIVE' | 'STANDBY_ROLLBACK' | 'DEGRADED';
}

interface ModelManifestEntry {
  activeVersion: string;
  artifacts: ManifestArtifactEntry[];
}

interface ModelManifest {
  [modelId: string]: ModelManifestEntry;
}

const MANIFEST_FILE = 'model-manifest.json';

export class ModelRegistry {
  private models = new Map<string, ModelRegistryEntry>();
  private manifest: ModelManifest = {};
  private directory: string;

  constructor(options: ModelStorageOptions) {
    this.directory = options.directory;
    if (!existsSync(this.directory)) {
      mkdirSync(this.directory, { recursive: true });
    }
    this.loadManifest();
  }

  private loadManifest(): void {
    try {
      const path = join(this.directory, MANIFEST_FILE);
      if (existsSync(path)) {
        this.manifest = JSON.parse(readFileSync(path, 'utf8')) as ModelManifest;
      }
    } catch {
      this.manifest = {};
    }
  }

  private saveManifest(): void {
    const path = join(this.directory, MANIFEST_FILE);
    writeFileSync(path, JSON.stringify(this.manifest, null, 2), 'utf8');
  }

  /** Register an in-memory model instance for immediate use (testing/bootstrap). */
  register(model: TrainableModel, metadata: ModelMetadata): void {
    this.models.set(metadata.id, {
      model,
      metadata,
      loadedAt: new Date().toISOString(),
      status: 'ACTIVE',
    });
  }

  /**
   * Load the active model artifact for a given modelId into `model`.
   * Returns false if no artifact exists or all artifacts fail to load.
   */
  async load(model: TrainableModel, modelId: string): Promise<boolean> {
    return this.loadArtifact(model, modelId);
  }

  /**
   * Load the active model artifact for a given modelId into `model`.
   * Accepts any object with a `load` method — used for models that don't
   * fully implement TrainableModel (e.g., AutoDispatchThresholdModel).
   * Returns false if no artifact exists or all artifacts fail to load.
   */
  async loadArtifact(model: { load(artifact: ModelArtifact): void }, modelId: string): Promise<boolean> {
    const entry = this.manifest[modelId];
    if (!entry) return false;

    const active = entry.artifacts.find((a) => a.version === entry.activeVersion);
    if (!active || active.status === 'DEGRADED') {
      return this.rollback(model, modelId, 'DEGRADED_OR_MISSING');
    }

    try {
      const data = JSON.parse(
        readFileSync(join(this.directory, active.path), 'utf8'),
      ) as ModelArtifact;
       model.load(data);
       this.models.set(modelId, {
         model: model as TrainableModel,
         metadata: data.metadata,
         loadedAt: new Date().toISOString(),
         status: 'ACTIVE',
       });
       return true;
     } catch {
       return this.rollback(model, modelId, 'LOAD_FAILURE');
     }
   }

  private async rollback(model: { load(artifact: ModelArtifact): void }, modelId: string, reason: string): Promise<boolean> {
    const entry = this.manifest[modelId];
    if (!entry) return false;

    const active = entry.artifacts.find((a) => a.version === entry.activeVersion);
    if (active) {
      active.status = 'DEGRADED';
      active.rollbackTrigger = reason;
    }

    const candidates = entry.artifacts.filter(
      (a) => a.version !== entry.activeVersion && a.status !== 'DEGRADED',
    );
    if (candidates.length === 0) {
      this.saveManifest();
      return false;
    }

    const prev = candidates.sort((a, b) => b.trainedAt.localeCompare(a.trainedAt))[0];
    try {
      const data = JSON.parse(readFileSync(join(this.directory, prev.path), 'utf8')) as ModelArtifact;
      model.load(data);
      prev.status = 'STANDBY_ROLLBACK';
      this.models.set(modelId, {
        model: model as TrainableModel,
        metadata: data.metadata,
        loadedAt: new Date().toISOString(),
        status: 'STANDBY_ROLLBACK',
      });
      this.saveManifest();
      return true;
    } catch {
      this.saveManifest();
      return false;
    }
  }

  /**
   * Persist a trained model artifact to disk.
   * Overwrites the active version tag on success.
   */
  async save(model: TrainableModel, modelId: string, metadata: ModelMetadata): Promise<void> {
    const dir = join(this.directory, modelId);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });

    const artifact: ModelArtifact = model.serialize();
    const filename = `${metadata.version}.json`;
    const path = join(dir, filename);
    writeFileSync(path, JSON.stringify(artifact, null, 2), 'utf8');

    const manifestEntry = this.manifest[modelId] ?? {
      activeVersion: metadata.version,
      artifacts: [],
    };

    manifestEntry.activeVersion = metadata.version;
    manifestEntry.artifacts = manifestEntry.artifacts.filter((a) => a.version !== metadata.version);
    manifestEntry.artifacts.push({
      version: metadata.version,
      path: join(modelId, filename),
      trainedAt: metadata.trainedAt,
      status: 'ACTIVE',
    });

    this.manifest[modelId] = manifestEntry;
    this.saveManifest();
  }

  /**
   * Persist a model artifact directly to disk — use when a model doesn't
   * implement TrainableModel but can serialize/load (e.g. AutoDispatchThresholdModel).
   */
  async saveArtifact(model: TrainableModel | { serialize: () => ModelArtifact }, modelId: string, metadata: ModelMetadata): Promise<void> {
    const artifact = model.serialize();
    const dir = join(this.directory, modelId);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });

    const filename = `${metadata.version}.json`;
    const path = join(dir, filename);
    writeFileSync(path, JSON.stringify(artifact, null, 2), 'utf8');

    const manifestEntry = this.manifest[modelId] ?? {
      activeVersion: metadata.version,
      artifacts: [],
    };

    manifestEntry.activeVersion = metadata.version;
    manifestEntry.artifacts = manifestEntry.artifacts.filter((a) => a.version !== metadata.version);
    manifestEntry.artifacts.push({
      version: metadata.version,
      path: join(modelId, filename),
      trainedAt: metadata.trainedAt,
      status: 'ACTIVE',
    });

    this.manifest[modelId] = manifestEntry;
    this.saveManifest();
  }

  get(modelId: string): ModelRegistryEntry | undefined {
    return this.models.get(modelId);
  }

  list(): ModelRegistryEntry[] {
    return [...this.models.values()];
  }

  clear(modelId: string): void {
    const entry = this.manifest[modelId];
    if (!entry) return;
    for (const artifact of entry.artifacts) {
      const full = join(this.directory, artifact.path);
      try {
        if (existsSync(full)) unlinkSync(full);
      } catch {
        /* file already gone — safe to ignore */
      }
    }
    delete this.manifest[modelId];
    this.models.delete(modelId);
    this.saveManifest();
  }
}
