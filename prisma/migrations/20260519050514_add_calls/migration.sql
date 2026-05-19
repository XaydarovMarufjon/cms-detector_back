-- CreateTable
CREATE TABLE "call_categories" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "call_categories_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "calls" (
    "id" TEXT NOT NULL,
    "category" TEXT NOT NULL,
    "phoneNumber" TEXT,
    "note" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "calls_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "call_categories_name_key" ON "call_categories"("name");

-- CreateIndex
CREATE INDEX "calls_category_idx" ON "calls"("category");

-- CreateIndex
CREATE INDEX "calls_createdAt_idx" ON "calls"("createdAt");
