-- CreateEnum
CREATE TYPE "CveStatus" AS ENUM ('PENDING', 'FALSE_POSITIVE', 'CONFIRMED');

-- AlterTable
ALTER TABLE "nuclei_results" ADD COLUMN     "status" "CveStatus" NOT NULL DEFAULT 'PENDING';
