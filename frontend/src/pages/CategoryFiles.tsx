import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate, useParams } from "react-router-dom";
import api from "@/services/api";
import { FileRecord } from "@/types";
import { formatBytes, formatDate } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import {
  ArrowUpDown,
  ChevronLeft,
  ChevronRight,
  FileText,
  ShieldAlert,
  Copy,
  Binary,
  Archive,
  Code2,
  Image,
  Music,
  Activity,
} from "lucide-react";

const categoryMeta: Record<string, { label: string; icon: typeof FileText; color: string }> = {
  sensitive: { label: "Sensitive", icon: ShieldAlert, color: "text-red-500" },
  duplicates: { label: "Duplicates", icon: Copy, color: "text-yellow-500" },
  documents: { label: "Documents", icon: FileText, color: "text-green-500" },
  executables: { label: "Executables", icon: Binary, color: "text-purple-500" },
  archives: { label: "Archives", icon: Archive, color: "text-orange-500" },
  source_code: { label: "Source Code", icon: Code2, color: "text-cyan-500" },
  images: { label: "Images", icon: Image, color: "text-pink-500" },
  media: { label: "Media", icon: Music, color: "text-indigo-500" },
  recently_modified: { label: "Recently Modified", icon: Activity, color: "text-teal-500" },
};

async function fetchFiles(
  page: number,
  pageSize: number,
  sortBy: string,
  sortOrder: string,
  category: string
) {
  const { data } = await api.get("/files", {
    params: { page, page_size: pageSize, sort_by: sortBy, sort_order: sortOrder, category },
  });
  return data;
}

export default function CategoryFiles() {
  const { type } = useParams<{ type: string }>();
  const navigate = useNavigate();
  const [page, setPage] = useState(1);
  const [sortBy, setSortBy] = useState("name");
  const [sortOrder, setSortOrder] = useState("asc");
  const pageSize = 50;

  const meta = type ? categoryMeta[type] : null;
  const categoryLabel = meta?.label ?? type ?? "Unknown";
  const IconComponent = meta?.icon ?? FileText;

  const { data, isLoading } = useQuery({
    queryKey: ["category-files", type, page, sortBy, sortOrder],
    queryFn: () => fetchFiles(page, pageSize, sortBy, sortOrder, type!),
    enabled: !!type,
  });

  const toggleSort = (col: string) => {
    if (sortBy === col) {
      setSortOrder(sortOrder === "asc" ? "desc" : "asc");
    } else {
      setSortBy(col);
      setSortOrder("asc");
    }
  };

  return (
    <div>
      <div className="mb-6">
        <button
          onClick={() => navigate("/categories")}
          className="text-sm text-muted-foreground hover:text-foreground mb-2 flex items-center gap-1"
        >
          ← All Categories
        </button>
        <div className="flex items-center gap-3">
          <IconComponent className={`h-6 w-6 ${meta?.color ?? ""}`} />
          <div>
            <h1 className="text-2xl font-bold">{categoryLabel}</h1>
            <p className="text-sm text-muted-foreground mt-1">
              {data ? `${data.total} files` : "Loading..."}
            </p>
          </div>
        </div>
      </div>

      <div className="rounded-lg border border-border">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border bg-muted/50">
                {[
                  { key: "name", label: "Name" },
                  { key: "extension", label: "Type" },
                  { key: "size", label: "Size" },
                  { key: "modified_at", label: "Modified" },
                  { key: "mime_type", label: "MIME Type" },
                  { key: "volume", label: "Volume" },
                ].map((col) => (
                  <th
                    key={col.key}
                    className="cursor-pointer px-4 py-3 text-left text-xs font-medium text-muted-foreground uppercase hover:text-foreground"
                    onClick={() => toggleSort(col.key)}
                  >
                    <div className="flex items-center gap-1">
                      {col.label}
                      <ArrowUpDown className="h-3 w-3" />
                    </div>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data?.items.map((file: FileRecord) => (
                <tr
                  key={file.id}
                  className="cursor-pointer border-b border-border hover:bg-accent/50"
                  onClick={() => navigate(`/files/${file.id}`)}
                >
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <FileText className="h-4 w-4 text-muted-foreground shrink-0" />
                      <span className="text-sm font-medium truncate max-w-[300px]">
                        {file.name}
                      </span>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <Badge variant="outline">{file.extension || "N/A"}</Badge>
                  </td>
                  <td className="px-4 py-3 text-sm">
                    {formatBytes(file.size)}
                  </td>
                  <td className="px-4 py-3 text-sm text-muted-foreground">
                    {formatDate(file.modified_at)}
                  </td>
                  <td className="px-4 py-3 text-xs text-muted-foreground truncate max-w-[200px]">
                    {file.mime_type || "-"}
                  </td>
                  <td className="px-4 py-3 text-sm text-muted-foreground">
                    {file.volume || "-"}
                  </td>
                </tr>
              ))}
              {(!data || data.items.length === 0) && (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-muted-foreground">
                    {isLoading ? "Loading..." : "No files in this category."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {data && data.total_pages > 1 && (
        <div className="mt-4 flex items-center justify-between">
          <span className="text-sm text-muted-foreground">
            Showing {(page - 1) * pageSize + 1}-
            {Math.min(page * pageSize, data.total)} of {data.total}
          </span>
          <div className="flex gap-2">
            <button
              className="rounded-md border border-border px-3 py-1 text-sm hover:bg-accent disabled:opacity-50"
              onClick={() => setPage(page - 1)}
              disabled={page <= 1}
            >
              <ChevronLeft className="h-4 w-4" />
            </button>
            <button
              className="rounded-md border border-border px-3 py-1 text-sm hover:bg-accent disabled:opacity-50"
              onClick={() => setPage(page + 1)}
              disabled={page >= data.total_pages}
            >
              <ChevronRight className="h-4 w-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
