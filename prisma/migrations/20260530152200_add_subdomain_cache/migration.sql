CREATE TABLE "subdomain_cache" (
    "id" TEXT NOT NULL,
    "websiteId" TEXT,
    "domain" TEXT NOT NULL,
    "subdomain" TEXT NOT NULL,
    "source" TEXT[],
    "statusCode" INTEGER,
    "title" TEXT,
    "discoveredAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "subdomain_cache_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "subdomain_cache_domain_subdomain_key" ON "subdomain_cache"("domain", "subdomain");
CREATE INDEX "subdomain_cache_websiteId_idx" ON "subdomain_cache"("websiteId");
CREATE INDEX "subdomain_cache_domain_idx" ON "subdomain_cache"("domain");

ALTER TABLE "subdomain_cache" ADD CONSTRAINT "subdomain_cache_websiteId_fkey"
FOREIGN KEY ("websiteId") REFERENCES "websites"("id") ON DELETE CASCADE ON UPDATE CASCADE;
