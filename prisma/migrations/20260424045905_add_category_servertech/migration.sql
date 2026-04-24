-- CreateTable
CREATE TABLE "websites" (
    "id" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "label" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "websites_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "scan_results" (
    "id" TEXT NOT NULL,
    "websiteId" TEXT NOT NULL,
    "cms" TEXT,
    "version" TEXT,
    "category" TEXT,
    "confidence" INTEGER NOT NULL DEFAULT 0,
    "detectionMethods" TEXT[],
    "serverTech" TEXT[],
    "jsFrameworks" TEXT[],
    "rawSignals" JSONB NOT NULL DEFAULT '{}',
    "scannedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "errorMessage" TEXT,

    CONSTRAINT "scan_results_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "websites_url_key" ON "websites"("url");

-- CreateIndex
CREATE INDEX "scan_results_websiteId_idx" ON "scan_results"("websiteId");

-- AddForeignKey
ALTER TABLE "scan_results" ADD CONSTRAINT "scan_results_websiteId_fkey" FOREIGN KEY ("websiteId") REFERENCES "websites"("id") ON DELETE CASCADE ON UPDATE CASCADE;
