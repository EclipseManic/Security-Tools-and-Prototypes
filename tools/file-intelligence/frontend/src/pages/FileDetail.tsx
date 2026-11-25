import { useQuery } from "@tanstack/react-query";
import { useParams, useNavigate } from "react-router-dom";
import api from "@/services/api";
import { FileDetail } from "@/types";
import { formatBytes, formatDate } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  ArrowLeft,
  FileText,
  Hash,
  Calendar,
  User,
  AlertTriangle,
  Shield,
  Tag,
  Code2,
  Activity,
} from "lucide-react";

async function fetchFileDetail(id: number): Promise<FileDetail> {
  const { data } = await api.get(`/files/${id}`);
  return data;
}

export default function FileDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const { data: file, isLoading, error } = useQuery({
    queryKey: ["file", id],
    queryFn: () => fetchFileDetail(Number(id)),
    enabled: !!id,
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-muted-foreground">Loading file details...</div>
      </div>
    );
  }

  if (error || !file) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-muted-foreground">File not found</div>
      </div>
    );
  }

  return (
    <div>
      <div className="mb-6">
        <Button variant="ghost" onClick={() => navigate(-1)}>
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back
        </Button>
      </div>

      <div className="mb-6">
        <div className="flex items-start gap-3">
          <FileText className="mt-1 h-6 w-6 text-blue-500" />
          <div>
            <h1 className="text-2xl font-bold break-all">{file.name}</h1>
            <p className="mt-1 text-sm text-muted-foreground break-all">
              {file.path}
            </p>
          </div>
        </div>
      </div>

      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
        {/* Summary */}
        {file.content?.summary && (
          <div className="col-span-full rounded-lg border border-border bg-card p-4">
            <h3 className="mb-2 text-sm font-medium text-muted-foreground uppercase">
              AI Summary
            </h3>
            <p className="text-sm">{file.content.summary}</p>
          </div>
        )}

        {/* Metadata */}
        <div className="rounded-lg border border-border bg-card p-4">
          <h3 className="mb-3 text-sm font-medium text-muted-foreground uppercase flex items-center gap-2">
            <FileText className="h-4 w-4" />
            File Info
          </h3>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-muted-foreground">Size</span>
              <span>{formatBytes(file.size)}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Type</span>
              <span>{file.mime_type || file.extension || "Unknown"}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Extension</span>
              <Badge variant="outline">{file.extension || "N/A"}</Badge>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Entropy</span>
              <span>{file.entropy?.toFixed(4) || "N/A"}</span>
            </div>
          </div>
        </div>

        {/* Timestamps */}
        <div className="rounded-lg border border-border bg-card p-4">
          <h3 className="mb-3 text-sm font-medium text-muted-foreground uppercase flex items-center gap-2">
            <Calendar className="h-4 w-4" />
            Timestamps
          </h3>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-muted-foreground">Created</span>
              <span>{formatDate(file.created_at)}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Modified</span>
              <span>{formatDate(file.modified_at)}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Accessed</span>
              <span>{formatDate(file.accessed_at)}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">First Scanned</span>
              <span>{formatDate(file.first_scanned_at)}</span>
            </div>
          </div>
        </div>

        {/* Ownership */}
        <div className="rounded-lg border border-border bg-card p-4">
          <h3 className="mb-3 text-sm font-medium text-muted-foreground uppercase flex items-center gap-2">
            <User className="h-4 w-4" />
            Ownership & Attributes
          </h3>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-muted-foreground">Owner</span>
              <span>{file.owner || "N/A"}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Volume</span>
              <span>{file.volume || "N/A"}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Hidden</span>
              <span>{file.is_hidden ? "Yes" : "No"}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Read Only</span>
              <span>{file.is_readonly ? "Yes" : "No"}</span>
            </div>
          </div>
        </div>

        {/* Hashes */}
        <div className="rounded-lg border border-border bg-card p-4 md:col-span-2">
          <h3 className="mb-3 text-sm font-medium text-muted-foreground uppercase flex items-center gap-2">
            <Hash className="h-4 w-4" />
            Cryptographic Hashes
          </h3>
          <div className="space-y-2 text-sm">
            <div>
              <span className="text-muted-foreground">SHA-256</span>
              <div className="mt-1 font-mono text-xs break-all bg-muted rounded p-1">
                {file.sha256 || "N/A"}
              </div>
            </div>
            <div>
              <span className="text-muted-foreground">MD5</span>
              <div className="mt-1 font-mono text-xs break-all bg-muted rounded p-1">
                {file.md5 || "N/A"}
              </div>
            </div>
          </div>
        </div>

        {/* Category */}
        {file.category && (
          <div className="rounded-lg border border-border bg-card p-4">
            <h3 className="mb-3 text-sm font-medium text-muted-foreground uppercase flex items-center gap-2">
              <Tag className="h-4 w-4" />
              Classification
            </h3>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Category</span>
                <Badge>{file.category.category}</Badge>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Confidence</span>
                <span>{(file.category.confidence * 100).toFixed(0)}%</span>
              </div>
              {file.category.explanation && (
                <div>
                  <span className="text-muted-foreground">Why</span>
                  <p className="mt-1 text-xs text-muted-foreground">
                    {file.category.explanation}
                  </p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Sensitivity */}
        {file.sensitivity && (
          <div className="rounded-lg border border-border bg-card p-4">
            <h3 className="mb-3 text-sm font-medium text-muted-foreground uppercase flex items-center gap-2">
              <Shield className="h-4 w-4" />
              Sensitivity
            </h3>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Level</span>
                <Badge
                  className={
                    file.sensitivity.sensitivity_level === "Critical"
                      ? "bg-red-500/10 text-red-500"
                      : file.sensitivity.sensitivity_level === "Highly Confidential"
                      ? "bg-orange-500/10 text-orange-500"
                      : file.sensitivity.sensitivity_level === "Confidential"
                      ? "bg-yellow-500/10 text-yellow-500"
                      : ""
                  }
                >
                  {file.sensitivity.sensitivity_level}
                </Badge>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Risk Score</span>
                <span
                  className={
                    file.sensitivity.risk_score > 70
                      ? "text-red-500 font-bold"
                      : file.sensitivity.risk_score > 40
                      ? "text-yellow-500"
                      : ""
                  }
                >
                  {file.sensitivity.risk_score.toFixed(0)}/100
                </span>
              </div>
            </div>
          </div>
        )}

        {/* Sensitive Findings */}
        {file.sensitive_findings && file.sensitive_findings.length > 0 && (
          <div className="col-span-full rounded-lg border border-border bg-card p-4">
            <h3 className="mb-3 text-sm font-medium text-muted-foreground uppercase flex items-center gap-2">
              <AlertTriangle className="h-4 w-4" />
              Sensitive Findings
            </h3>
            <div className="space-y-2">
              {file.sensitive_findings.map((finding, i) => (
                <div
                  key={i}
                  className="flex items-center gap-2 rounded bg-muted/50 p-2 text-sm"
                >
                  <Badge
                    className={
                      finding.severity === "high"
                        ? "bg-red-500/10 text-red-500"
                        : finding.severity === "medium"
                        ? "bg-yellow-500/10 text-yellow-500"
                        : "bg-blue-500/10 text-blue-500"
                    }
                  >
                    {finding.finding_type}
                  </Badge>
                  <span className="flex-1 truncate">{finding.value}</span>
                  {finding.context && (
                    <span className="text-xs text-muted-foreground truncate max-w-[200px]">
                      {finding.context}
                    </span>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Technical Artifacts */}
        {file.technical_artifacts && file.technical_artifacts.length > 0 && (
          <div className="col-span-full rounded-lg border border-border bg-card p-4">
            <h3 className="mb-3 text-sm font-medium text-muted-foreground uppercase flex items-center gap-2">
              <Code2 className="h-4 w-4" />
              Technical Artifacts
            </h3>
            <div className="flex flex-wrap gap-2">
              {file.technical_artifacts.map((artifact, i) => (
                <Badge key={i} variant="secondary" className="text-xs">
                  {artifact.artifact_type}: {artifact.value}
                </Badge>
              ))}
            </div>
          </div>
        )}

        {/* Analysis Results */}
        {file.analyses && file.analyses.length > 0 && (
          <div className="col-span-full rounded-lg border border-border bg-card p-4">
            <h3 className="mb-3 text-sm font-medium text-muted-foreground uppercase flex items-center gap-2">
              <Activity className="h-4 w-4" />
              Analysis Results
            </h3>
            <div className="space-y-3">
              {file.analyses.map((analysis, i) => (
                <div key={i} className="rounded bg-muted/30 p-3">
                  <div className="flex items-center gap-2 mb-2">
                    <Badge>{analysis.analyzer_type}</Badge>
                    <Badge
                      className={
                        analysis.status === "completed"
                          ? "bg-green-500/10 text-green-500"
                          : "bg-red-500/10 text-red-500"
                      }
                    >
                      {analysis.status}
                    </Badge>
                  </div>
                  {analysis.result && (
                    <pre className="text-xs text-muted-foreground overflow-auto max-h-40">
                      {JSON.stringify(analysis.result, null, 2)}
                    </pre>
                  )}
                  {analysis.error_message && (
                    <p className="text-xs text-red-500 mt-1">
                      Error: {analysis.error_message}
                    </p>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Extracted Content */}
        {file.content?.extracted_text && (
          <div className="col-span-full rounded-lg border border-border bg-card p-4">
            <h3 className="mb-3 text-sm font-medium text-muted-foreground uppercase flex items-center gap-2">
              <FileText className="h-4 w-4" />
              Extracted Content
            </h3>
            <pre className="text-xs text-muted-foreground overflow-auto max-h-96 whitespace-pre-wrap break-all rounded bg-muted/30 p-3">
              {file.content.extracted_text.slice(0, 10000)}
              {file.content.extracted_text.length > 10000 && "\n\n... (truncated)"}
            </pre>
          </div>
        )}

        {/* Entities */}
        {file.entities && file.entities.length > 0 && (
          <div className="col-span-full rounded-lg border border-border bg-card p-4">
            <h3 className="mb-3 text-sm font-medium text-muted-foreground uppercase flex items-center gap-2">
              <Tag className="h-4 w-4" />
              Named Entities
            </h3>
            <div className="flex flex-wrap gap-2">
              {file.entities.map((entity, i) => (
                <Badge key={i} variant="outline" className="text-xs">
                  {entity.entity_type}: {entity.entity_value}
                </Badge>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
