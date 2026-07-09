-- CreateTable
CREATE TABLE "osint_dork_findings" (
    "id" TEXT NOT NULL,
    "domain" TEXT NOT NULL,
    "websiteId" TEXT,
    "url" TEXT NOT NULL,
    "title" TEXT,
    "category" TEXT NOT NULL,
    "severity" TEXT NOT NULL DEFAULT 'MEDIUM',
    "query" TEXT NOT NULL,
    "source" TEXT NOT NULL DEFAULT 'GOOGLE_CSE',
    "evidence" TEXT,
    "sensitiveHits" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "rawSignals" JSONB NOT NULL DEFAULT '{}',
    "status" TEXT NOT NULL DEFAULT 'OPEN',
    "dismissed" BOOLEAN NOT NULL DEFAULT false,
    "falsePositive" BOOLEAN NOT NULL DEFAULT false,
    "foundAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "osint_dork_findings_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "osint_dork_findings_url_category_key" ON "osint_dork_findings"("url", "category");

-- CreateIndex
CREATE INDEX "osint_dork_findings_domain_idx" ON "osint_dork_findings"("domain");

-- CreateIndex
CREATE INDEX "osint_dork_findings_category_idx" ON "osint_dork_findings"("category");

-- CreateIndex
CREATE INDEX "osint_dork_findings_severity_idx" ON "osint_dork_findings"("severity");

-- CreateIndex
CREATE INDEX "osint_dork_findings_status_idx" ON "osint_dork_findings"("status");

-- CreateIndex
CREATE INDEX "osint_dork_findings_falsePositive_idx" ON "osint_dork_findings"("falsePositive");

-- CreateIndex
CREATE INDEX "osint_dork_findings_foundAt_idx" ON "osint_dork_findings"("foundAt");

-- AddForeignKey
ALTER TABLE "osint_dork_findings" ADD CONSTRAINT "osint_dork_findings_websiteId_fkey" FOREIGN KEY ("websiteId") REFERENCES "websites"("id") ON DELETE SET NULL ON UPDATE CASCADE;
