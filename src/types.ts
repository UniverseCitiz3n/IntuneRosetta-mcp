export interface PolicyMetadata {
  name: string;
  description: string;
  value: string;
  csp_path: string;
  category: string;
  docs_url: string;
}

export interface PolicyRecord {
  id?: number;
  normalized_key: string;
  name: string;
  description: string;
  csp_path: string;
  category: string;
  docs_url: string;
  value_map: string; // JSON string: Record<string, string>
}

export type ValueMap = Record<string, string>;
