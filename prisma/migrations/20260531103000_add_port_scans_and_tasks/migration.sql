CREATE TABLE "port_scan_results" (
    "id" TEXT NOT NULL,
    "websiteId" TEXT NOT NULL,
    "host" TEXT NOT NULL,
    "port" INTEGER NOT NULL,
    "protocol" TEXT NOT NULL DEFAULT 'TCP',
    "status" TEXT NOT NULL,
    "service" TEXT,
    "latencyMs" INTEGER,
    "error" TEXT,
    "scanId" TEXT NOT NULL,
    "scannedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "port_scan_results_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "security_tasks" (
    "id" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT,
    "source" TEXT NOT NULL DEFAULT 'MANUAL',
    "status" TEXT NOT NULL DEFAULT 'OPEN',
    "priority" TEXT NOT NULL DEFAULT 'MEDIUM',
    "dueDate" TIMESTAMP(3),
    "websiteId" TEXT,
    "assigneeId" TEXT,
    "createdById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "security_tasks_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "port_scan_results_websiteId_idx" ON "port_scan_results"("websiteId");
CREATE INDEX "port_scan_results_scanId_idx" ON "port_scan_results"("scanId");
CREATE INDEX "port_scan_results_host_port_idx" ON "port_scan_results"("host", "port");

CREATE INDEX "security_tasks_status_idx" ON "security_tasks"("status");
CREATE INDEX "security_tasks_priority_idx" ON "security_tasks"("priority");
CREATE INDEX "security_tasks_assigneeId_idx" ON "security_tasks"("assigneeId");
CREATE INDEX "security_tasks_websiteId_idx" ON "security_tasks"("websiteId");

ALTER TABLE "port_scan_results" ADD CONSTRAINT "port_scan_results_websiteId_fkey" FOREIGN KEY ("websiteId") REFERENCES "websites"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "security_tasks" ADD CONSTRAINT "security_tasks_websiteId_fkey" FOREIGN KEY ("websiteId") REFERENCES "websites"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "security_tasks" ADD CONSTRAINT "security_tasks_assigneeId_fkey" FOREIGN KEY ("assigneeId") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "security_tasks" ADD CONSTRAINT "security_tasks_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;
