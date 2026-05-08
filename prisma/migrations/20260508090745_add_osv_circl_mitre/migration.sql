-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "FeedType" ADD VALUE 'OSV';
ALTER TYPE "FeedType" ADD VALUE 'CIRCL';
ALTER TYPE "FeedType" ADD VALUE 'MITRE_CVE';

-- AlterTable
ALTER TABLE "cve_enrichments" ADD COLUMN     "osvAliases" TEXT[],
ADD COLUMN     "osvFound" BOOLEAN NOT NULL DEFAULT false;
