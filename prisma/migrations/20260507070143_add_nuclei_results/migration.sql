-- CreateTable
CREATE TABLE "nuclei_results" (
    "id" TEXT NOT NULL,
    "websiteId" TEXT NOT NULL,
    "subdomain" TEXT NOT NULL,
    "templateId" TEXT NOT NULL,
    "cveId" TEXT,
    "severity" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "matchedAt" TEXT,
    "scannedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "nuclei_results_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "nuclei_results_websiteId_idx" ON "nuclei_results"("websiteId");

-- AddForeignKey
ALTER TABLE "nuclei_results" ADD CONSTRAINT "nuclei_results_websiteId_fkey" FOREIGN KEY ("websiteId") REFERENCES "websites"("id") ON DELETE CASCADE ON UPDATE CASCADE;
