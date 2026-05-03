-- CreateTable
CREATE TABLE "alerts" (
    "id" TEXT NOT NULL,
    "domain" TEXT NOT NULL,
    "websiteId" TEXT,
    "type" TEXT NOT NULL,
    "message" TEXT NOT NULL,
    "dueDate" TIMESTAMP(3) NOT NULL,
    "dismissed" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "alerts_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "alerts_domain_type_key" ON "alerts"("domain", "type");
