ALTER TABLE "alerts" ADD COLUMN "falsePositiveUntil" TIMESTAMP(3);

UPDATE "alerts"
SET "falsePositiveUntil" = NOW() + INTERVAL '1 day'
WHERE "falsePositive" = true AND "falsePositiveUntil" IS NULL;

CREATE INDEX "alerts_falsePositiveUntil_idx" ON "alerts"("falsePositiveUntil");
