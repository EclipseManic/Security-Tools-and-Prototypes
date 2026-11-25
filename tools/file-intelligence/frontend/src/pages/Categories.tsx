import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import api from "@/services/api";
import { DashboardSummary } from "@/types";
import {
  ShieldAlert,
  Copy,
  FileText,
  Binary,
  Archive,
  Code2,
  Image,
  Music,
  Activity,
} from "lucide-react";

const categoryList = [
  { key: "sensitive_files", type: "sensitive", label: "Sensitive", icon: ShieldAlert, color: "text-red-500", desc: "Files with confidential data" },
  { key: "duplicate_files", type: "duplicates", label: "Duplicates", icon: Copy, color: "text-yellow-500", desc: "Duplicate files across volumes" },
  { key: "document_files", type: "documents", label: "Documents", icon: FileText, color: "text-green-500", desc: "PDF, Office, text files" },
  { key: "executable_files", type: "executables", label: "Executables", icon: Binary, color: "text-purple-500", desc: "EXE, DLL, scripts" },
  { key: "archive_files", type: "archives", label: "Archives", icon: Archive, color: "text-orange-500", desc: "ZIP, RAR, 7z, tar" },
  { key: "source_code_files", type: "source_code", label: "Source Code", icon: Code2, color: "text-cyan-500", desc: "Source files" },
  { key: "image_files", type: "images", label: "Images", icon: Image, color: "text-pink-500", desc: "Image files" },
  { key: "media_files", type: "media", label: "Media", icon: Music, color: "text-indigo-500", desc: "Audio & video files" },
  { key: "recently_modified", type: "recently_modified", label: "Recently Modified", icon: Activity, color: "text-teal-500", desc: "Modified in last 7 days" },
];

export default function Categories() {
  const navigate = useNavigate();
  const { data, isPending } = useQuery({
    queryKey: ["dashboard-summary"],
    queryFn: () => api.get("/stats/summary").then(r => r.data),
    staleTime: 30000,
  });

  if (isPending) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-muted-foreground">Loading categories...</div>
      </div>
    );
  }

  return (
    <div>
      <div className="mb-6">
        <button
          onClick={() => navigate("/")}
          className="text-sm text-muted-foreground hover:text-foreground mb-2 flex items-center gap-1"
        >
          ← Back to Dashboard
        </button>
        <h1 className="text-2xl font-bold">Files by Category</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Browse files grouped by category type
        </p>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
        {categoryList.map((cat) => {
          const Icon = cat.icon;
          const value = data?.[cat.key as keyof DashboardSummary] ?? 0;
          return (
            <button
              key={cat.type}
              onClick={() => navigate(`/category/${cat.type}`)}
              className="rounded-lg border border-border bg-card p-5 text-left hover:bg-accent/50 transition-colors"
            >
              <div className="flex items-center gap-3">
                <div className={`p-2 rounded-md bg-background ${cat.color}`}>
                  <Icon className="h-5 w-5" />
                </div>
                <div>
                  <div className="font-semibold">{cat.label}</div>
                  <div className="text-xs text-muted-foreground">{cat.desc}</div>
                </div>
              </div>
              <div className="mt-3 text-3xl font-bold">{value.toLocaleString()}</div>
              <div className="mt-1 text-xs text-muted-foreground">files</div>
            </button>
          );
        })}
      </div>
    </div>
  );
}
