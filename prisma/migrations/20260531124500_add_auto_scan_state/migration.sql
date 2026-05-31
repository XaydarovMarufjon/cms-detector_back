CREATE TABLE "auto_scan_states" (
    "id" TEXT NOT NULL,
    "key" TEXT NOT NULL,
    "cursorWebsiteId" TEXT,
    "intervalMinutes" INTEGER NOT NULL DEFAULT 360,
    "lastStartedAt" TIMESTAMP(3),
    "lastFinishedAt" TIMESTAMP(3),
    "lastStatus" TEXT,
    "lastError" TEXT,
    "scannedInLastWindow" INTEGER NOT NULL DEFAULT 0,
    "totalAtLastWindow" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "auto_scan_states_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "auto_scan_states_key_key" ON "auto_scan_states"("key");
