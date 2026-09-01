export interface DomainAssessment {
  domain: string;
  summary: Summary;
  evidence_assessment: EvidenceAssessment;
  threat_categorization: string[];
  blocklist_recommendations: BlocklistRecommendations;
}

export interface Summary {
  tri_state_result: "YES" | "NO" | "MAYBE";
  dangerousness_score: DangerousnessScore;
  verdict_reasoning: string;
}

export interface DangerousnessScore {
  value: number; // integer (0-100)
  severity_label: "none" | "low" | "low-to-moderate" | "moderate" | "high" | "critical";
}

export interface EvidenceAssessment {
  adtech: VectorAssessment;
  personal_data_mining: VectorAssessment;
  malware_distribution: VectorAssessment;
}

export interface VectorAssessment {
  tri_state_subresult: "YES" | "NO" | "MAYBE";
  details: string;
}

export interface BlocklistRecommendations {
  malware_security_lists: RecommendationDetail;
  privacy_adblock_dns_sinkholes: RecommendationDetail;
}

export interface RecommendationDetail {
  should_block: boolean;
  priority: "low" | "medium" | "high" | "critical";
  supported_platforms?: string[];
  notes: string;
}
