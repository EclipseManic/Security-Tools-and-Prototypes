import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import api from "@/services/api";
import { FileRecord } from "@/types";
import { formatBytes, formatDate } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Search, FileText, Loader2 } from "lucide-react";

async function searchFiles(
  q: string,
  page: number
): Promise<{ items: FileRecord[]; total: number; total_pages: number }> {
  const { data } = await api.get("/search", {
    params: { q, page, page_size: 50 },
  });
  return data;
}

export default function SearchPage() {
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [page, setPage] = useState(1);

  const { data, isLoading } = useQuery({
    queryKey: ["search", searchQuery, page],
    queryFn: () => searchFiles(searchQuery, page),
    enabled: searchQuery.length > 0,
  });

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setSearchQuery(query);
    setPage(1);
  };

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold">Search</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Search across all indexed files
        </p>
      </div>

      <form onSubmit={handleSearch} className="mb-6">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search files by name, content, or AI summary..."
            className="w-full rounded-md border border-input bg-background pl-10 pr-4 py-3 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          />
        </div>
      </form>

      {isLoading && (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      )}

      {data && (
        <div className="space-y-2">
          <p className="text-sm text-muted-foreground mb-4">
            Found {data.total} result{data.total !== 1 ? "s" : ""}
          </p>

          {data.items.map((file: FileRecord) => (
            <div
              key={file.id}
              className="cursor-pointer rounded-lg border border-border bg-card p-4 hover:bg-accent/50 transition-colors"
              onClick={() => navigate(`/files/${file.id}`)}
            >
              <div className="flex items-start gap-3">
                <FileText className="mt-0.5 h-4 w-4 text-blue-500 shrink-0" />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium truncate">{file.name}</p>
                  <p className="text-xs text-muted-foreground truncate mt-0.5">
                    {file.path}
                  </p>
                  <div className="flex items-center gap-2 mt-2">
                    <Badge variant="outline" className="text-xs">
                      {file.extension || "Unknown"}
                    </Badge>
                    <span className="text-xs text-muted-foreground">
                      {formatBytes(file.size)}
                    </span>
                    <span className="text-xs text-muted-foreground">
                      Modified {formatDate(file.modified_at)}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          ))}

          {data.total_pages > 1 && (
            <div className="flex justify-center gap-2 pt-4">
              <button
                className="rounded-md border border-border px-3 py-1 text-sm hover:bg-accent disabled:opacity-50"
                onClick={() => setPage(page - 1)}
                disabled={page <= 1}
              >
                Previous
              </button>
              <span className="px-3 py-1 text-sm text-muted-foreground">
                Page {page} of {data.total_pages}
              </span>
              <button
                className="rounded-md border border-border px-3 py-1 text-sm hover:bg-accent disabled:opacity-50"
                onClick={() => setPage(page + 1)}
                disabled={page >= data.total_pages}
              >
                Next
              </button>
            </div>
          )}
        </div>
      )}

      {!isLoading && !data && searchQuery && (
        <div className="text-center py-12 text-muted-foreground">
          No results found for "{searchQuery}"
        </div>
      )}

      {!searchQuery && (
        <div className="text-center py-12 text-muted-foreground">
          Enter a search term to find files
        </div>
      )}
    </div>
  );
}
