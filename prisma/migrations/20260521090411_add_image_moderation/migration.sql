-- CreateEnum
CREATE TYPE "ImageScanStatus" AS ENUM ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED');

-- CreateTable
CREATE TABLE "image_scans" (
    "id" TEXT NOT NULL,
    "websiteId" TEXT NOT NULL,
    "status" "ImageScanStatus" NOT NULL DEFAULT 'PENDING',
    "totalImages" INTEGER NOT NULL DEFAULT 0,
    "scannedImages" INTEGER NOT NULL DEFAULT 0,
    "flaggedCount" INTEGER NOT NULL DEFAULT 0,
    "sexualCount" INTEGER NOT NULL DEFAULT 0,
    "violentCount" INTEGER NOT NULL DEFAULT 0,
    "religiousCount" INTEGER NOT NULL DEFAULT 0,
    "errorMessage" TEXT,
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "finishedAt" TIMESTAMP(3),

    CONSTRAINT "image_scans_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "image_results" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "imageUrl" TEXT NOT NULL,
    "pageUrl" TEXT,
    "sexualScore" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "violentScore" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "religiousScore" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "categories" TEXT[],
    "rawSignals" JSONB NOT NULL DEFAULT '{}',
    "flagged" BOOLEAN NOT NULL DEFAULT false,
    "errorMessage" TEXT,
    "scannedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "image_results_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "image_scans_websiteId_idx" ON "image_scans"("websiteId");

-- CreateIndex
CREATE INDEX "image_scans_startedAt_idx" ON "image_scans"("startedAt");

-- CreateIndex
CREATE INDEX "image_results_scanId_idx" ON "image_results"("scanId");

-- CreateIndex
CREATE INDEX "image_results_flagged_idx" ON "image_results"("flagged");

-- AddForeignKey
ALTER TABLE "image_scans" ADD CONSTRAINT "image_scans_websiteId_fkey" FOREIGN KEY ("websiteId") REFERENCES "websites"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "image_results" ADD CONSTRAINT "image_results_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "image_scans"("id") ON DELETE CASCADE ON UPDATE CASCADE;
