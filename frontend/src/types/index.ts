export interface FileRecord {
  id: number;
  path: string;
  name: string;
  extension: string | null;
  size: number;
  mime_type: string | null;
  magic_bytes: string | null;
  created_at: string | null;
  modified_at: string | null;
  accessed_at: string | null;
  owner: string | null;
  permissions: string | null;
  is_hidden: boolean;
  is_system: boolean;
  is_readonly: boolean;
  is_symlink: boolean;
  volume: string | null;
  sha256: string | null;
  md5: string | null;
  entropy: number | null;
  duplicate_group_id: string | null;
  first_scanned_at: string | null;
  last_scanned_at: string | null;
}

export interface FileDetail extends FileRecord {
  content: FileContent | null;
  category: FileCategory | null;
  sensitivity: FileSensitivity | null;
  sensitive_findings: SensitiveFinding[];
  entities: EntityExtraction[];
  technical_artifacts: TechnicalArtifact[];
  analyses: FileAnalysis[];
  timeline_events: FileTimeline[];
}

export interface FileContent {
  extracted_text: string | null;
  ocr_text: string | null;
  raw_metadata: Record<string, unknown> | null;
  summary: string | null;
  detailed_summary: string | null;
}

export interface FileCategory {
  category: string;
  subcategory: string | null;
  confidence: number;
  explanation: string | null;
}

export interface FileSensitivity {
  sensitivity_level: string;
  risk_score: number;
  explanation: string | null;
}

export interface SensitiveFinding {
  finding_type: string;
  value: string | null;
  context: string | null;
  count: number;
  severity: string;
}

export interface EntityExtraction {
  entity_type: string;
  entity_value: string;
  context: string | null;
}

export interface TechnicalArtifact {
  artifact_type: string;
  value: string;
  context: string | null;
}

export interface FileAnalysis {
  analyzer_type: string;
  status: string;
  result: Record<string, unknown> | null;
  error_message: string | null;
}

export interface FileTimeline {
  event_type: string;
  event_time: string;
  old_value: string | null;
  new_value: string | null;
}

export interface ScanJob {
  id: number;
  scan_type: string;
  path: string;
  status: string;
  progress: number;
  total_files: number;
  scanned_files: number;
  error_count: number;
  started_at: string | null;
  completed_at: string | null;
}

export interface SearchQuery {
  q?: string;
  extensions?: string[];
  mime_types?: string[];
  categories?: string[];
  sensitivity_levels?: string[];
  min_size?: number;
  max_size?: number;
  date_from?: string;
  date_to?: string;
  owner?: string;
  is_hidden?: boolean;
  is_duplicate?: boolean;
  has_passwords?: boolean;
  has_api_keys?: boolean;
  has_sql?: boolean;
  sort_by?: string;
  sort_order?: string;
  page?: number;
  page_size?: number;
}

export interface SearchResponse {
  items: FileRecord[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface ScanInsight {
  type: string;
  content: Record<string, unknown>;
  created_at: string | null;
}

export interface ScanInsightsResponse {
  insights: ScanInsight[];
  has_ai_data: boolean;
}

export interface DashboardSummary {
  total_files: number;
  total_storage: number;
  sensitive_files: number;
  duplicate_files: number;
  executable_files: number;
  document_files: number;
  archive_files: number;
  source_code_files: number;
  image_files: number;
  media_files: number;
  recently_modified: number;
  scan_count: number;
  latest_scan_id: number | null;
  latest_scan_path: string | null;
}
