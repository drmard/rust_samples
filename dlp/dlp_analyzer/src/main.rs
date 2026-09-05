use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;
use std::thread;

/// Types of critical data supported by DLP
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LeakType {
    Passport,
    CreditCard,
    ConfidentialKeyword,
    SourceCode,
}

/// Incident criticality levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Structure of the incident (detected match)
#[derive(Debug, Clone)]
pub struct Detection {
    pub leak_type: LeakType,
    pub matched_text: String,
    pub score_impact: u32,
}

/// Final result of the document analysis
#[derive(Debug, Clone)]
pub struct AnalysisResult {
    pub is_violation: bool,
    pub total_score: u32,
    pub severity: Severity,
    pub detections: Vec<Detection>,
}

/// Types of content analysis rules
pub enum Rule {
    /// Signature analysis (Regular expression, Leak type, Weight)
    Signature(Regex, LeakType, u32),
    /// Keyword analysis (Keyword -> Weight)
    Dictionary(HashMap<String, u32>, LeakType),
}

/// DLP analysis engine
pub struct DlpEngine {
    rules: Vec<Rule>,
    threshold: u32,
}

impl DlpEngine {
    pub fn new(threshold: u32) -> Self {
        DlpEngine {
            rules: Vec::new(),
            threshold,
        }
    }

    pub fn add_rule(&mut self, rule: Rule) {
        self.rules.push(rule);
    }

    /// Comprehensive content analysis of the text
    pub fn analyze(&self, text: &str) -> AnalysisResult {
        let mut detections = Vec::new();
        let mut total_score = 0;

        for rule in &self.rules {
            match rule {
                Rule::Signature(regex, leak_type, score) => {
                    for mat in regex.find_iter(text) {
                        let matched_str = mat.as_str().to_string();
                        
                        // Additional validation if it is a bank card
                        if *leak_type == LeakType::CreditCard && !validate_luhn(&matched_str) {
                            // False positive; skipping it
                            continue;
                        }

                        detections.push(Detection {
                            leak_type: leak_type.clone(),
                            matched_text: matched_str,
                            score_impact: *score,
                        });
                        total_score += score;
                    }
                }
                Rule::Dictionary(dict, leak_type) => {
                    let lower_text = text.to_lowercase();
                    for (word, score) in dict {
                        let mut pos = 0;
                        while let Some(index) = lower_text[pos..].find(&word.to_lowercase()) {
                            let exact_match = &text[pos + index..pos + index + word.len()];
                            detections.push(Detection {
                                leak_type: leak_type.clone(),
                                matched_text: exact_match.to_string(),
                                score_impact: *score,
                            });
                            total_score += score;
                            pos += index + word.len();
                        }
                    }
                }
            }
        }

        let is_violation = total_score >= self.threshold;
        let severity = match total_score {
            0 => Severity::Low,
            1..=10 => Severity::Medium,
            11..=30 => Severity::High,
            _ => Severity::Critical,
        };

        AnalysisResult {
            is_violation,
            total_score,
            severity,
            detections,
        }
    }

    /// Multithreaded analysis of a document array
    pub fn analyze_parallel(self: Arc<Self>, documents: Vec<String>) -> Vec<AnalysisResult> {
        let mut handles = vec![];

        for doc in documents {
            let engine_clone = Arc::clone(&self);
            let handle = thread::spawn(move || engine_clone.analyze(&doc));
            handles.push(handle);
        }

        handles.into_iter().map(|h| h.join().unwrap()).collect()
    }
}

/// Luhn algorithm validator for card number verification
fn validate_luhn(card_number: &str) -> bool {
    let digits: Vec<u32> = card_number
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }

    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(idx, &digit)| {
            if idx % 2 == 1 {
                let d = digit * 2;
                if d > 9 { d - 9 } else { d }
            } else {
                digit
            }
        })
        .sum();

    sum % 10 == 0
}

fn main() {

    // Engine initialization. Blocking threshold: 20 points
    let mut engine = DlpEngine::new(20);

    // Adding signature rules (Regular expressions)
    let cc_regex = Regex::new(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b").unwrap();
    engine.add_rule(Rule::Signature(cc_regex, LeakType::CreditCard, 15));

    let passport_regex = Regex::new(r"\b\d{4}\s?\d{6}\b").unwrap();
    engine.add_rule(Rule::Signature(passport_regex, LeakType::Passport, 25));

    // Adding a dictionary rule
    let mut keywords = HashMap::new();
    keywords.insert("trade secret".to_string(), 10);
    keywords.insert("NDA".to_string(), 5);
    keywords.insert("private key".to_string(), 15);
    engine.add_rule(Rule::Dictionary(keywords, LeakType::ConfidentialKeyword));

    // wrapping to Arc for safe use across threads
    let engine = Arc::new(engine);

    // preparation of test documents
    let documents = vec![
        "Hi! My card number is 4000 1234 5678 9010. Don't show it to anyone".to_string(),     // Valid card by Luhn algorithm
        "This is a test document containing an NDA and trade secrets".to_string(),            // Keywords (15 points)
        "Passport of a citizen of the Russian Federation: 4508 123456. Urgent".to_string(),   // Passport (25 points -> Blocked)
        "The fake card number 1111-1111-1111-1111 will not pass Luhn validation".to_string(), // Luhn Error
    ];

    // starting parallel analysis
    println!("=== Launching content-based DLP analysis ===");

    let results = engine.analyze_parallel(documents);

    for (idx, result) in results.iter().enumerate() {
        println!("\nDocument №{}:", idx + 1);
        println!("  Blocking status: {}", if result.is_violation { "BLOCKED" } else { "PERMITTED" });
        println!("  Total weight of threats:  {}", result.total_score);
        println!("  Risk level:    {:?}", result.severity);
        if !result.detections.is_empty() {
            println!("  Matches found:");
            for det in &result.detections {
                println!("    - [{:?}] '{}' (Weight: {})", det.leak_type, det.matched_text, det.score_impact);
            }
        }
    }
}
