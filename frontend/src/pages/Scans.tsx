import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import api from "@/services/api";
import { ScanJob } from "@/types";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { formatDate } from "@/lib/utils";
import { Link } from "react-router-dom";
import { Play, Pause, XCircle, Trash2, Plus, Loader2, Eye } from "lucide-react";

async function fetchScans(): Promise<{ items: ScanJob[]; total: number }> {
  const { data } = await api.get("/scans");
  return data;
}

async function createScan(path: string): Promise<ScanJob> {
  const { data } = await api.post("/scans", { path, scan_type: "full" });
  return data;
}

async function startScan(id: number) {
  await api.post(`/scans/${id}/start`);
}

async function pauseScan(id: number) {
  await api.post(`/scans/${id}/pause`);
}

async function resumeScan(id: number) {
  await api.post(`/scans/${id}/resume`);
}

async function cancelScan(id: number) {
  await api.post(`/scans/${id}/cancel`);
}

async function deleteScan(id: number) {
  await api.delete(`/scans/${id}`);
}

const statusColors: Record<string, string> = {
  pending: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
  running: "bg-blue-500/10 text-blue-500 border-blue-500/20",
  paused: "bg-orange-500/10 text-orange-500 border-orange-500/20",
  completed: "bg-green-500/10 text-green-500 border-green-500/20",
  failed: "bg-red-500/10 text-red-500 border-red-500/20",
  cancelled: "bg-gray-500/10 text-gray-500 border-gray-500/20",
};

export default function Scans() {
  const queryClient = useQueryClient();
  const [scanPath, setScanPath] = useState("");
  const [showNew, setShowNew] = useState(false);

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["scans"],
    queryFn: fetchScans,
    refetchInterval: (q) => {
      const scans = q?.state?.data?.items ?? [];
      const hasActive = scans.some((s: any) => s.status === "running" || s.status === "pending");
      return hasActive ? 1000 : 5000;
    },
    refetchIntervalInBackground: true,
    staleTime: 3000,
  });

  const createMutation = useMutation({
    mutationFn: createScan,
    onSuccess: async (job) => {
      toast.success("Scan created");
      setShowNew(false);
      setScanPath("");
      const started = { ...job, status: "running", started_at: new Date().toISOString() };
      queryClient.setQueryData(["scans"], (old: any) => {
        const items = old?.items ?? [];
        return { items: [started, ...items], total: (old?.total ?? 0) + 1 };
      });
      try {
        await api.post(`/scans/${job.id}/start`);
      } catch {}
    },
    onError: (err: any) => toast.error(err?.response?.data?.detail || err?.message || "Failed to create scan"),
  });

  const startMutation = useMutation({
    mutationFn: startScan,
    onSuccess: () => queryClient.refetchQueries({ queryKey: ["scans"] }),
  });

  const pauseMutation = useMutation({
    mutationFn: pauseScan,
    onMutate: async (id) => {
      queryClient.setQueryData(["scans"], (old: any) => {
        if (!old?.items) return old;
        return { ...old, items: old.items.map((s: any) => s.id === id ? { ...s, status: "paused" } : s) };
      });
    },
    onSuccess: () => queryClient.refetchQueries({ queryKey: ["scans"] }),
  });

  const resumeMutation = useMutation({
    mutationFn: resumeScan,
    onMutate: async (id) => {
      queryClient.setQueryData(["scans"], (old: any) => {
        if (!old?.items) return old;
        return { ...old, items: old.items.map((s: any) => s.id === id ? { ...s, status: "running" } : s) };
      });
    },
    onSuccess: () => queryClient.refetchQueries({ queryKey: ["scans"] }),
  });

  const cancelMutation = useMutation({
    mutationFn: cancelScan,
    onMutate: async (id) => {
      queryClient.setQueryData(["scans"], (old: any) => {
        if (!old?.items) return old;
        return { ...old, items: old.items.map((s: any) => s.id === id ? { ...s, status: "cancelled", progress: s.progress } : s) };
      });
    },
    onSuccess: () => queryClient.refetchQueries({ queryKey: ["scans"] }),
  });

  const deleteMutation = useMutation({
    mutationFn: deleteScan,
    onSuccess: () => {
      toast.success("Scan deleted");
      queryClient.refetchQueries({ queryKey: ["scans"] });
    },
  });

  return (
    <div>
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Scans</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Manage file system scans
          </p>
        </div>
        <Button onClick={() => setShowNew(!showNew)}>
          <Plus className="mr-2 h-4 w-4" />
          New Scan
        </Button>
      </div>

      {showNew && (
        <div className="mb-6 rounded-lg border border-border bg-card p-4">
          <div className="flex gap-3">
            <input
              type="text"
              value={scanPath}
              onChange={(e) => setScanPath(e.target.value)}
              placeholder="Enter path to scan (e.g., C:\\Users or D:\\)"
              className="flex-1 rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            />
            <Button
              onClick={() => createMutation.mutate(scanPath)}
              disabled={!scanPath || createMutation.isPending}
            >
              {createMutation.isPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : null}
              Start Scan
            </Button>
          </div>
        </div>
      )}

      {isError ? (
        <div className="flex items-center justify-center h-64">
          <div className="text-center">
            <div className="text-destructive font-bold text-lg">Failed to load scans</div>
            <div className="text-sm text-muted-foreground mt-1">
              {(error as any)?.message || "An unexpected error occurred"}
            </div>
            <button
              className="mt-4 rounded-md border border-border px-4 py-2 text-sm hover:bg-accent"
              onClick={() => queryClient.refetchQueries({ queryKey: ["scans"] })}
            >
              Retry
            </button>
          </div>
        </div>
      ) : isLoading ? (
        <div className="flex items-center justify-center h-64">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      ) : (
        <div className="rounded-lg border border-border">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border bg-muted/50">
                <th className="px-4 py-3 text-left text-xs font-medium text-muted-foreground uppercase">Path</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-muted-foreground uppercase">Status</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-muted-foreground uppercase">Progress</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-muted-foreground uppercase">Files</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-muted-foreground uppercase">Errors</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-muted-foreground uppercase">Started</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-muted-foreground uppercase">Actions</th>
              </tr>
            </thead>
            <tbody>
              {data?.items.map((scan) => (
                <tr key={scan.id} className="border-b border-border hover:bg-accent/50">
                  <td className="px-4 py-3 text-sm font-medium">{scan.path}</td>
                  <td className="px-4 py-3">
                    <Badge className={statusColors[scan.status] || ""}>
                      {scan.status}
                    </Badge>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="h-2 w-24 rounded-full bg-muted">
                        <div
                          className="h-full rounded-full bg-blue-500 transition-all"
                          style={{ width: `${scan.progress}%` }}
                        />
                      </div>
                      <span className="text-xs text-muted-foreground">
                        {scan.progress.toFixed(0)}%
                      </span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-sm">
                    {scan.scanned_files}/{scan.total_files}
                  </td>
                  <td className="px-4 py-3 text-sm">{scan.error_count}</td>
                  <td className="px-4 py-3 text-sm text-muted-foreground">
                    {formatDate(scan.started_at)}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex gap-1">
                      {scan.status === "pending" && (
                        <Button
                          size="icon"
                          variant="ghost"
                          onClick={() => startMutation.mutate(scan.id)}
                          title="Start"
                        >
                          <Play className="h-4 w-4" />
                        </Button>
                      )}
                      {scan.status === "running" && (
                        <>
                          <Button
                            size="icon"
                            variant="ghost"
                            onClick={() => pauseMutation.mutate(scan.id)}
                            title="Pause"
                          >
                            <Pause className="h-4 w-4" />
                          </Button>
                          <Button
                            size="icon"
                            variant="ghost"
                            onClick={() => cancelMutation.mutate(scan.id)}
                            title="Cancel"
                          >
                            <XCircle className="h-4 w-4" />
                          </Button>
                        </>
                      )}
                      {scan.status === "paused" && (
                        <Button
                          size="icon"
                          variant="ghost"
                          onClick={() => resumeMutation.mutate(scan.id)}
                          title="Resume"
                        >
                          <Play className="h-4 w-4" />
                        </Button>
                      )}
                      {["completed", "failed", "cancelled"].includes(
                        scan.status
                      ) && (
                        <>
                          <Link to={`/scans/${scan.id}`}>
                            <Button size="icon" variant="ghost" title="Details">
                              <Eye className="h-4 w-4" />
                            </Button>
                          </Link>
                          <Button
                            size="icon"
                            variant="ghost"
                            onClick={() => deleteMutation.mutate(scan.id)}
                            title="Delete"
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
              {(!data || data.items.length === 0) && (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-muted-foreground">
                    No scans yet. Click "New Scan" to get started.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
