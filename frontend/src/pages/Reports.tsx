import { FileBarChart, Download, Loader2 } from "lucide-react";
import { useState } from "react";
import api from "@/services/api";

const reportTypes = [
  { id: "executive_summary", title: "Executive Summary", description: "High-level overview of all scan results", formats: ["html", "json"] },
  { id: "full_inventory", title: "Full File Inventory", description: "Complete list of all indexed files with metadata", formats: ["csv", "json"] },
  { id: "sensitivity_audit", title: "Sensitivity Audit", description: "All sensitive findings organized by severity", formats: ["csv"] },
  { id: "duplicate_files", title: "Duplicate Files Report", description: "Groups of duplicate files with storage waste analysis", formats: ["csv"] },
  { id: "largest_files", title: "Largest Files", description: "Top 100 largest files found during scans", formats: ["csv"] },
  { id: "category_distribution", title: "Category Distribution", description: "Files grouped by AI-assigned category", formats: ["html", "json"] },
];

const formatLabels: Record<string, string> = {
  csv: "CSV",
  html: "HTML",
  json: "JSON",
};

async function downloadReport(reportType: string, format: string) {
  const { data, headers } = await api.get(`/reports/${reportType}`, {
    params: { fmt: format },
    responseType: "blob",
  });
  const disposition = headers["content-disposition"] || "";
  const match = disposition.match(/filename="?(.+?)"?$/);
  const filename = match?.[1] || `${reportType}.${format}`;
  const url = URL.createObjectURL(data);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export default function Reports() {
  const [loading, setLoading] = useState<Record<string, boolean>>({});

  async function handleDownload(reportId: string, fmt: string) {
    const key = `${reportId}_${fmt}`;
    setLoading((prev) => ({ ...prev, [key]: true }));
    try {
      await downloadReport(reportId, fmt);
    } catch (err: any) {
      console.error("Download failed:", err);
    } finally {
      setLoading((prev) => ({ ...prev, [key]: false }));
    }
  }

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold">Reports</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Export and download intelligence reports
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {reportTypes.map((report) => (
          <div
            key={report.id}
            className="rounded-lg border border-border bg-card p-4 hover:bg-accent/50 transition-colors"
          >
            <div className="flex items-start gap-3">
              <FileBarChart className="mt-1 h-5 w-5 text-blue-500 shrink-0" />
              <div>
                <h3 className="font-medium">{report.title}</h3>
                <p className="mt-1 text-xs text-muted-foreground">
                  {report.description}
                </p>
                <div className="mt-3 flex flex-wrap gap-2">
                  {report.formats.map((fmt) => {
                    const key = `${report.id}_${fmt}`;
                    return (
                      <button
                        key={fmt}
                        onClick={() => handleDownload(report.id, fmt)}
                        disabled={loading[key]}
                        className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-1 text-xs hover:bg-accent disabled:opacity-50"
                      >
                        {loading[key] ? (
                          <Loader2 className="h-3 w-3 animate-spin" />
                        ) : (
                          <Download className="h-3 w-3" />
                        )}
                        {formatLabels[fmt] || fmt.toUpperCase()}
                      </button>
                    );
                  })}
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
