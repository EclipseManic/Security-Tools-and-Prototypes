import { useQuery } from "@tanstack/react-query";
import { useParams, Link } from "react-router-dom";
import api from "@/services/api";
import { ScanJob, ScanInsightsResponse } from "@/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { formatDate } from "@/lib/utils";
import { ArrowLeft, Loader2, ShieldAlert, Lightbulb, AlertTriangle, TrendingUp, FileText } from "lucide-react";

async function fetchScan(id: string): Promise<ScanJob> {
  const { data } = await api.get(`/scans/${id}`);
  return data;
}

async function fetchInsights(id: string): Promise<ScanInsightsResponse> {
  const { data } = await api.get(`/scans/${id}/insights`);
  return data;
}

const severityColors: Record<string, string> = {
  low: "bg-blue-500/10 text-blue-500 border-blue-500/20",
  medium: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
  high: "bg-orange-500/10 text-orange-500 border-orange-500/20",
  critical: "bg-red-500/10 text-red-500 border-red-500/20",
};

const priorityColors: Record<string, string> = {
  low: "bg-gray-500/10 text-gray-500 border-gray-500/20",
  medium: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
  high: "bg-orange-500/10 text-orange-500 border-orange-500/20",
};

export default function ScanDetail() {
  const { id } = useParams<{ id: string }>();

  const { data: scan, isLoading: scanLoading } = useQuery({
    queryKey: ["scan", id],
    queryFn: () => fetchScan(id!),
    enabled: !!id,
  });

  const { data: insights, isLoading: insightsLoading } = useQuery({
    queryKey: ["scan-insights", id],
    queryFn: () => fetchInsights(id!),
    enabled: !!id,
  });

  const isLoading = scanLoading || insightsLoading;

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-muted-foreground">Scan not found</div>
      </div>
    );
  }

  const insightMap = new Map<string, any>();
  for (const ins of insights?.insights ?? []) {
    insightMap.set(ins.type, ins.content);
  }

  const execSummary = insightMap.get("executive_summary");
  const threats: any[] = (insightMap.get("threats_found") as any)?.items ?? [];
  const safeFiles: any[] = (insightMap.get("known_safe_files") as any)?.items ?? [];
  const recommendations: any[] = (insightMap.get("recommendations") as any)?.items ?? [];
  const anomalies: any[] = (insightMap.get("anomalies") as any)?.items ?? [];
  const priority: any[] = (insightMap.get("priority_ranking") as any)?.items ?? [];
  const hasAiData = insights?.has_ai_data ?? false;

  return (
    <div>
      <div className="mb-6">
        <div className="flex items-center gap-3 mb-2">
          <Link to="/scans">
            <Button variant="ghost" size="icon">
              <ArrowLeft className="h-4 w-4" />
            </Button>
          </Link>
          <h1 className="text-2xl font-bold">Scan Details</h1>
        </div>
        <div className="flex items-center gap-3 text-sm text-muted-foreground ml-11">
          <span className="font-medium truncate max-w-md">{scan.path}</span>
          <Badge className={
            scan.status === "completed" ? "bg-green-500/10 text-green-500 border-green-500/20" :
            scan.status === "running" ? "bg-blue-500/10 text-blue-500 border-blue-500/20" :
            scan.status === "failed" ? "bg-red-500/10 text-red-500 border-red-500/20" :
            "bg-gray-500/10 text-gray-500 border-gray-500/20"
          }>{scan.status}</Badge>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4 mb-6">
        <div className="rounded-lg border border-border bg-card p-4">
          <div className="text-xs text-muted-foreground">Total Files</div>
          <div className="mt-1 text-xl font-bold">{scan.total_files}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-4">
          <div className="text-xs text-muted-foreground">Scanned Files</div>
          <div className="mt-1 text-xl font-bold">{scan.scanned_files}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-4">
          <div className="text-xs text-muted-foreground">Errors</div>
          <div className="mt-1 text-xl font-bold">{scan.error_count}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-4">
          <div className="text-xs text-muted-foreground">Started</div>
          <div className="mt-1 text-xl font-bold">{formatDate(scan.started_at)}</div>
        </div>
      </div>

      {!hasAiData && (
        <div className="rounded-lg border border-border bg-muted/30 p-6 text-center mb-6">
          <FileText className="h-8 w-8 mx-auto mb-2 text-muted-foreground" />
          <h3 className="font-medium">No AI insights available</h3>
          <p className="text-sm text-muted-foreground mt-1">
            AI analysis was not completed for this scan. This can happen if the AI provider quota was exhausted or if the scan was very small.
          </p>
        </div>
      )}

      {execSummary && (
        <div className="rounded-lg border border-border bg-card p-4 mb-6">
          <div className="flex items-center gap-2 mb-3">
            <FileText className="h-4 w-4 text-blue-500" />
            <h3 className="text-sm font-medium text-muted-foreground uppercase">Executive Summary</h3>
          </div>
          <p className="text-sm leading-relaxed">{(execSummary as any).summary || ""}</p>
        </div>
      )}

      {threats.length > 0 && (
        <div className="rounded-lg border border-border bg-card p-4 mb-6">
          <div className="flex items-center gap-2 mb-3">
            <ShieldAlert className="h-4 w-4 text-red-500" />
            <h3 className="text-sm font-medium text-muted-foreground uppercase">Threats Found</h3>
          </div>
          <div className="space-y-2">
            {threats.map((t, i) => (
              <div key={i} className="flex items-start gap-3 rounded-md border border-border p-3">
                <Badge className={severityColors[t.confidence] || ""}>
                  {t.confidence}
                </Badge>
                <div>
                  <div className="text-sm font-medium">{t.id}</div>
                  <div className="text-xs text-muted-foreground">{t.details || t.threat_type}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {safeFiles.length > 0 && (
        <div className="rounded-lg border border-border bg-card p-4 mb-6">
          <div className="flex items-center gap-2 mb-3">
            <ShieldAlert className="h-4 w-4 text-green-500" />
            <h3 className="text-sm font-medium text-muted-foreground uppercase">Known Safe Files</h3>
          </div>
          <div className="space-y-2">
            {safeFiles.map((s, i) => (
              <div key={i} className="flex items-start gap-3 rounded-md border border-border p-3">
                <Badge className={severityColors[s.confidence] || ""}>
                  {s.confidence}
                </Badge>
                <div>
                  <div className="text-sm font-medium">{s.id}</div>
                  <div className="text-xs text-muted-foreground">{s.description}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {recommendations.length > 0 && (
        <div className="rounded-lg border border-border bg-card p-4 mb-6">
          <div className="flex items-center gap-2 mb-3">
            <Lightbulb className="h-4 w-4 text-yellow-500" />
            <h3 className="text-sm font-medium text-muted-foreground uppercase">Recommendations</h3>
          </div>
          <div className="space-y-2">
            {recommendations.map((r, i) => (
              <div key={i} className="rounded-md border border-border p-3">
                <div className="flex items-center gap-2 mb-1">
                  <Badge className={priorityColors[r.priority] || ""}>
                    {r.priority}
                  </Badge>
                  <span className="text-sm font-medium">{r.recommendation}</span>
                </div>
                {r.context && (
                  <p className="text-xs text-muted-foreground ml-1">{r.context}</p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {anomalies.length > 0 && (
        <div className="rounded-lg border border-border bg-card p-4 mb-6">
          <div className="flex items-center gap-2 mb-3">
            <AlertTriangle className="h-4 w-4 text-orange-500" />
            <h3 className="text-sm font-medium text-muted-foreground uppercase">Anomalies</h3>
          </div>
          <div className="space-y-2">
            {anomalies.map((a, i) => (
              <div key={i} className="rounded-md border border-border p-3">
                <div className="flex items-center gap-2 mb-1">
                  <Badge className={severityColors[a.severity] || ""}>
                    {a.severity}
                  </Badge>
                  <span className="text-sm font-medium">{a.description}</span>
                </div>
                {a.file_ids && a.file_ids.length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-1">
                    {(a.file_ids as string[]).map((fid) => (
                      <span key={fid} className="text-xs bg-muted px-1.5 py-0.5 rounded">{fid}</span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {priority.length > 0 && (
        <div className="rounded-lg border border-border bg-card p-4 mb-6">
          <div className="flex items-center gap-2 mb-3">
            <TrendingUp className="h-4 w-4 text-purple-500" />
            <h3 className="text-sm font-medium text-muted-foreground uppercase">Priority Ranking</h3>
          </div>
          <div className="space-y-1">
            {priority.map((p, i) => (
              <div key={i} className="flex items-start gap-3 rounded-md border border-border p-3">
                <span className="text-sm font-mono font-bold text-foreground shrink-0 w-6 text-right">{p.priority_score}</span>
                <div className="min-w-0 flex-1">
                  <div className="text-sm font-medium break-all">{p.id}</div>
                  <div className="text-xs text-muted-foreground mt-0.5 leading-relaxed">{p.reason}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
