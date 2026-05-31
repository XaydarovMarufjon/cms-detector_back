ALTER TABLE "nuclei_results"
  ADD COLUMN "source" TEXT NOT NULL DEFAULT 'NUCLEI',
  ADD COLUMN "confidence" INTEGER NOT NULL DEFAULT 90,
  ADD COLUMN "evidence" JSONB NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN "referenceUrl" TEXT;

CREATE INDEX "nuclei_results_cveId_idx" ON "nuclei_results"("cveId");
CREATE INDEX "nuclei_results_source_idx" ON "nuclei_results"("source");
