ALTER TABLE "alerts" ADD COLUMN "falsePositive" BOOLEAN NOT NULL DEFAULT false;

CREATE INDEX "alerts_falsePositive_idx" ON "alerts"("falsePositive");
