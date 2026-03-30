export interface PolicyOption {
  itemId: string;
  displayName: string;
}

export interface PolicyMetadata {
  name: string;
  description: string;
  value: string;
  csp_path: string;
  category: string;
  docs_url: string;
  options?: PolicyOption[];
  deprecation_warning?: string;
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
  is_deprecated?: boolean;      // true when the policy has been superseded
  replaced_by_csp?: string;     // normalized_key of the replacement record
  deprecation_notice?: string;  // free-text: why deprecated, context, date if known
}

export type ValueMap = Record<string, string>;
