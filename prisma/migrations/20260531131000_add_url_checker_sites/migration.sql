CREATE TABLE "url_checker_sites" (
    "id" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "label" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "url_checker_sites_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "url_checker_sites_url_key" ON "url_checker_sites"("url");
