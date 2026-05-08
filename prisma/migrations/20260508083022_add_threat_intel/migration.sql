-- CreateEnum
CREATE TYPE "FeedType" AS ENUM ('NVD', 'CISA_KEV', 'EPSS', 'MISP', 'OTX', 'VIRUSTOTAL');

-- CreateTable
CREATE TABLE "threat_feeds" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "type" "FeedType" NOT NULL,
    "url" TEXT,
    "apiKey" TEXT,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "lastSync" TIMESTAMP(3),
    "lastStatus" TEXT,
    "lastError" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "threat_feeds_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "cve_enrichments" (
    "id" TEXT NOT NULL,
    "cveId" TEXT NOT NULL,
    "cvssScore" DOUBLE PRECISION,
    "cvssVector" TEXT,
    "cvssVersion" TEXT,
    "epssScore" DOUBLE PRECISION,
    "epssPercent" DOUBLE PRECISION,
    "isKev" BOOLEAN NOT NULL DEFAULT false,
    "kevDueDate" TEXT,
    "description" TEXT,
    "references" TEXT[],
    "cweIds" TEXT[],
    "otxPulses" INTEGER,
    "vtMalicious" INTEGER,
    "mispEvents" INTEGER,
    "sources" TEXT[],
    "enrichedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "cve_enrichments_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "cve_enrichments_cveId_key" ON "cve_enrichments"("cveId");
