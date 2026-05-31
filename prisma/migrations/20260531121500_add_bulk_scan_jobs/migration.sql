CREATE TYPE "BulkScanJobStatus" AS ENUM ('PENDING', 'RUNNING', 'COMPLETED', 'CANCELLED', 'FAILED');
CREATE TYPE "BulkScanItemStatus" AS ENUM ('PENDING', 'RUNNING', 'DONE', 'FAILED', 'SKIPPED');

CREATE TABLE "bulk_scan_jobs" (
    "id" TEXT NOT NULL,
    "status" "BulkScanJobStatus" NOT NULL DEFAULT 'PENDING',
    "mode" TEXT NOT NULL DEFAULT 'FAST',
    "concurrency" INTEGER NOT NULL DEFAULT 16,
    "timeoutMs" INTEGER NOT NULL DEFAULT 5000,
    "includeRecentlyScanned" BOOLEAN NOT NULL DEFAULT false,
    "skipRecentHours" INTEGER NOT NULL DEFAULT 6,
    "total" INTEGER NOT NULL DEFAULT 0,
    "pending" INTEGER NOT NULL DEFAULT 0,
    "running" INTEGER NOT NULL DEFAULT 0,
    "completed" INTEGER NOT NULL DEFAULT 0,
    "failed" INTEGER NOT NULL DEFAULT 0,
    "skipped" INTEGER NOT NULL DEFAULT 0,
    "errorMessage" TEXT,
    "startedAt" TIMESTAMP(3),
    "finishedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "bulk_scan_jobs_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "bulk_scan_job_items" (
    "id" TEXT NOT NULL,
    "jobId" TEXT NOT NULL,
    "websiteId" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "status" "BulkScanItemStatus" NOT NULL DEFAULT 'PENDING',
    "scanResultId" TEXT,
    "errorMessage" TEXT,
    "startedAt" TIMESTAMP(3),
    "finishedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "bulk_scan_job_items_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "bulk_scan_jobs_status_idx" ON "bulk_scan_jobs"("status");
CREATE INDEX "bulk_scan_jobs_createdAt_idx" ON "bulk_scan_jobs"("createdAt");
CREATE UNIQUE INDEX "bulk_scan_job_items_jobId_websiteId_key" ON "bulk_scan_job_items"("jobId", "websiteId");
CREATE INDEX "bulk_scan_job_items_jobId_idx" ON "bulk_scan_job_items"("jobId");
CREATE INDEX "bulk_scan_job_items_websiteId_idx" ON "bulk_scan_job_items"("websiteId");
CREATE INDEX "bulk_scan_job_items_status_idx" ON "bulk_scan_job_items"("status");

ALTER TABLE "bulk_scan_job_items" ADD CONSTRAINT "bulk_scan_job_items_jobId_fkey"
FOREIGN KEY ("jobId") REFERENCES "bulk_scan_jobs"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "bulk_scan_job_items" ADD CONSTRAINT "bulk_scan_job_items_websiteId_fkey"
FOREIGN KEY ("websiteId") REFERENCES "websites"("id") ON DELETE CASCADE ON UPDATE CASCADE;
