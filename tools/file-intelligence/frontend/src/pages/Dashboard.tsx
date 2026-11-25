import { useQuery } from "@tanstack/react-query";
import { useNavigate, Link } from "react-router-dom";
import api from "@/services/api";
import { formatBytes } from "@/lib/utils";
import { DashboardSummary } from "@/types";
import { HardDrive, Activity, FolderKanban } from "lucide-react";
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

interface Distributions {
  categories: { name: string; value: number }[];
  sensitivity: { name: string; value: number }[];
  extensions: { name: string; value: number }[];
  file_types: { name: string; value: number }[];
}

async function fetchSummary(): Promise<DashboardSummary> {
  const { data } = await api.get("/stats/summary");
  return data;
}

async function fetchDistributions(): Promise<Distributions> {
  const { data } = await api.get("/stats/distributions");
  return data;
}

const COLORS = [
  "#3b82f6", "#ef4444", "#22c55e", "#f59e0b", "#a855f7",
  "#ec4899", "#14b8a6", "#f97316", "#6366f1", "#84cc16",
  "#06b6d4", "#d946ef",
];

const PIE_COLORS: Record<string, string> = {
  Public: "#22c55e",
  Internal: "#3b82f6",
  Confidential: "#f59e0b",
  "Highly Confidential": "#f97316",
  Critical: "#ef4444",
};

export default function Dashboard() {
  const navigate = useNavigate();
  const { data, isPending, error } = useQuery({
    queryKey: ["dashboard-summary"],
    queryFn: fetchSummary,
    staleTime: 30000,
    retry: 2,
  });

  const shouldFetchDist = data && data.total_files > 0;
  const { data: dist } = useQuery({
    queryKey: ["dashboard-distributions"],
    queryFn: fetchDistributions,
    staleTime: 60000,
    retry: 1,
    enabled: !!shouldFetchDist,
  });

  if (isPending) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-muted-foreground">Loading dashboard...</div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-muted-foreground">
          {error ? "Backend not ready yet. Refresh the page." : "No data yet. Run a scan first."}
        </div>
      </div>
    );
  }

  const categoryTotal = dist
    ? dist.categories.reduce((sum, cat) => sum + cat.value, 0)
    : data.total_files;
  const categoryCount = dist?.categories.length ?? 0;

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold">Dashboard</h1>
        <p className="text-sm text-muted-foreground mt-1">
          File Intelligence Platform overview
        </p>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
        <div className="rounded-lg border border-border bg-card p-4">
          <div className="flex items-center gap-3">
            <HardDrive className="h-5 w-5 text-blue-500" />
            <span className="text-xs text-muted-foreground">Total Files</span>
          </div>
          <div className="mt-2 text-2xl font-bold">{data.total_files.toLocaleString()}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-4">
          <div className="flex items-center gap-3">
            <HardDrive className="h-5 w-5 text-blue-500" />
            <span className="text-xs text-muted-foreground">Total Storage</span>
          </div>
          <div className="mt-2 text-2xl font-bold">{formatBytes(data.total_storage)}</div>
        </div>
        <Link
          to={data.latest_scan_id ? `/scans/${data.latest_scan_id}` : "#"}
          className={`rounded-lg border border-border bg-card p-4 transition-colors text-left ${data.latest_scan_id ? "hover:bg-accent/50" : ""}`}
        >
          <div className="flex items-center gap-3">
            <Activity className="h-5 w-5 text-gray-500" />
            <span className="text-xs text-muted-foreground">Latest Scan</span>
          </div>
          <div className="mt-2 text-2xl font-bold">{data.scan_count.toLocaleString()}</div>
          {data.latest_scan_path && (
            <div className="mt-0.5 text-xs text-muted-foreground truncate max-w-full">
              {data.latest_scan_path} →
            </div>
          )}
        </Link>
        <button
          onClick={() => navigate("/categories")}
          className="rounded-lg border border-border bg-card p-4 hover:bg-accent/50 transition-colors text-left"
        >
          <div className="flex items-center gap-3">
            <FolderKanban className="h-5 w-5 text-blue-500" />
            <span className="text-xs text-muted-foreground">Files by Category</span>
          </div>
          <div className="mt-2 text-2xl font-bold">{categoryTotal.toLocaleString()}</div>
          <div className="mt-0.5 text-xs text-muted-foreground">{categoryCount} categories →</div>
        </button>
      </div>

      {dist && (
        <div className="mt-6 grid gap-6 lg:grid-cols-2">
          {/* File Types Bar Chart */}
          <div className="rounded-lg border border-border bg-card p-4">
            <h3 className="mb-4 text-sm font-medium text-muted-foreground uppercase">
              Files by Category
            </h3>
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={dist.file_types.filter(d => d.value > 0)}>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                <XAxis dataKey="name" tick={{ fontSize: 11 }} />
                <YAxis tick={{ fontSize: 11 }} />
                <Tooltip />
                <Bar dataKey="value" fill="#3b82f6" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Sensitivity Pie Chart */}
          <div className="rounded-lg border border-border bg-card p-4">
            <h3 className="mb-4 text-sm font-medium text-muted-foreground uppercase">
              Sensitivity Distribution
            </h3>
            <ResponsiveContainer width="100%" height={280}>
              <PieChart>
                <Pie
                  data={dist.sensitivity.length > 0 ? dist.sensitivity : [{ name: "No Data", value: 1 }]}
                  cx="50%"
                  cy="50%"
                  outerRadius={100}
                  dataKey="value"
                  label={({ name, value }) => `${name}: ${value}`}
                >
                  {(dist.sensitivity.length > 0 ? dist.sensitivity : [{ name: "No Data", value: 1 }]).map((entry, i) => (
                    <Cell
                      key={i}
                      fill={PIE_COLORS[entry.name] || COLORS[i % COLORS.length]}
                    />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>

          {/* Top Extensions Bar Chart */}
          {dist.extensions.length > 0 && (
            <div className="rounded-lg border border-border bg-card p-4 lg:col-span-2">
              <h3 className="mb-4 text-sm font-medium text-muted-foreground uppercase">
                Top Extensions
              </h3>
              <ResponsiveContainer width="100%" height={280}>
                <BarChart
                  data={dist.extensions.slice(0, 10)}
                  layout="vertical"
                >
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                  <XAxis type="number" tick={{ fontSize: 11 }} />
                  <YAxis
                    type="category"
                    dataKey="name"
                    tick={{ fontSize: 11 }}
                    width={60}
                  />
                  <Tooltip />
                  <Bar dataKey="value" fill="#a855f7" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
