CREATE TABLE "defacement_snapshots" (
    "id" TEXT NOT NULL,
    "websiteId" TEXT NOT NULL,
    "domain" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "title" TEXT,
    "titleHash" TEXT,
    "contentHash" TEXT NOT NULL,
    "structuralHash" TEXT,
    "textLength" INTEGER NOT NULL DEFAULT 0,
    "assetCount" INTEGER NOT NULL DEFAULT 0,
    "formCount" INTEGER NOT NULL DEFAULT 0,
    "scriptCount" INTEGER NOT NULL DEFAULT 0,
    "keywordHits" TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    "status" TEXT NOT NULL DEFAULT 'BASELINE',
    "changeScore" INTEGER NOT NULL DEFAULT 0,
    "changeReasons" TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    "previousTitle" TEXT,
    "previousContentHash" TEXT,
    "lastChangedAt" TIMESTAMP(3),
    "lastCheckedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "defacement_snapshots_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "defacement_snapshots_websiteId_key" ON "defacement_snapshots"("websiteId");
CREATE INDEX "defacement_snapshots_domain_idx" ON "defacement_snapshots"("domain");
CREATE INDEX "defacement_snapshots_status_idx" ON "defacement_snapshots"("status");
CREATE INDEX "defacement_snapshots_lastChangedAt_idx" ON "defacement_snapshots"("lastChangedAt");

ALTER TABLE "defacement_snapshots" ADD CONSTRAINT "defacement_snapshots_websiteId_fkey" FOREIGN KEY ("websiteId") REFERENCES "websites"("id") ON DELETE CASCADE ON UPDATE CASCADE;
