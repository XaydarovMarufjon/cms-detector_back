CREATE TABLE "db_dumps" (
    "id" TEXT NOT NULL,
    "filename" TEXT NOT NULL,
    "filePath" TEXT NOT NULL,
    "format" TEXT NOT NULL DEFAULT 'custom',
    "status" TEXT NOT NULL DEFAULT 'RUNNING',
    "trigger" TEXT NOT NULL DEFAULT 'MANUAL',
    "sizeBytes" BIGINT,
    "checksumSha256" TEXT,
    "errorMessage" TEXT,
    "createdById" TEXT,
    "createdByName" TEXT,
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "finishedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "db_dumps_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "db_dumps_status_idx" ON "db_dumps"("status");
CREATE INDEX "db_dumps_trigger_idx" ON "db_dumps"("trigger");
CREATE INDEX "db_dumps_startedAt_idx" ON "db_dumps"("startedAt");
