use std::sync::Arc;
use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::debug;
use ipnet::IpNet;

use crate::config::CustomRule;
use crate::error::Result as WafResult;
use super::{RequestContext, WafInspectionResult};

/// WAF action to take
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WafAction {
    Allow,
    Block,
    Challenge,
    Log,
}

/// Result from rule evaluation
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RuleResult {
    pub action: WafAction,
    pub reason: String,
    pub rule_name: Option<String>,
    pub confidence: f32,
    pub metadata: serde_json::Value,
}

/// Compiled rule for efficient evaluation
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct CompiledRule {
    name: String,
    action: WafAction,
    conditions: Vec<CompiledCondition>,
    rate_limit: Option<crate::config::RateLimit>,
}

/// Compiled condition for efficient evaluation
#[derive(Debug, Clone)]
#[allow(dead_code)]
enum CompiledCondition {
    PathRegex(Regex),
    PathPrefix(String),
    PathExact(String),
    HeaderExists(String),
    HeaderEquals { name: String, value: String },
    HeaderRegex { name: String, regex: Regex },
    IpInWhitelist(Vec<IpNet>),
    IpNotInWhitelist(Vec<IpNet>),
    IpInBlacklist(Vec<IpNet>),
    MethodEquals(String),
    UserAgentRegex(Regex),
    QueryParamExists(String),
    QueryParamEquals { name: String, value: String },
    BodyContains(String),
    BodyRegex(Regex),
    ContentTypeEquals(String),
}

/// Rules engine for custom WAF rules
#[allow(dead_code)]
pub struct RuleEngine {
    rules: Arc<RwLock<Vec<CompiledRule>>>,
    statistics: Arc<RwLock<RuleStatistics>>,
}

#[derive(Debug, Default)]
#[allow(dead_code)]
struct RuleStatistics {
    total_evaluations: u64,
    rules_matched: u64,
    actions_taken: std::collections::HashMap<String, u64>,
}

impl RuleEngine {
    pub fn new(rules: &[CustomRule]) -> Result<Self> {
        let compiled_rules = Self::compile_rules(rules)?;
        
        Ok(Self {
            rules: Arc::new(RwLock::new(compiled_rules)),
            statistics: Arc::new(RwLock::new(RuleStatistics::default())),
        })
    }
    
    fn compile_rules(rules: &[CustomRule]) -> Result<Vec<CompiledRule>> {
        let mut compiled = Vec::new();
        
        for rule in rules {
            let action = match rule.action.as_str() {
                "allow" => WafAction::Allow,
                "block" => WafAction::Block,
                "challenge" => WafAction::Challenge,
                "log" => WafAction::Log,
                _ => return Err(anyhow::anyhow!("Invalid action: {}", rule.action)),
            };
            
            let mut conditions = Vec::new();
            for condition in &rule.conditions {
                let compiled_condition = Self::compile_condition(condition)?;
                conditions.push(compiled_condition);
            }
            
            compiled.push(CompiledRule {
                name: rule.name.clone(),
                action,
                conditions,
                rate_limit: rule.rate_limit.clone(),
            });
        }
        
        Ok(compiled)
    }
    
    fn compile_condition(condition: &crate::config::RuleCondition) -> Result<CompiledCondition> {
        match condition.condition_type.as_str() {
            "path_regex" => {
                let pattern = condition.value.as_str().unwrap_or("");
                let regex = Regex::new(pattern)?;
                Ok(CompiledCondition::PathRegex(regex))
            }
            "path_prefix" => {
                let prefix = condition.value.as_str().unwrap_or("").to_string();
                Ok(CompiledCondition::PathPrefix(prefix))
            }
            "path_exact" => {
                let path = condition.value.as_str().unwrap_or("").to_string();
                Ok(CompiledCondition::PathExact(path))
            }
            "header_exists" => {
                let name = condition.value.as_str().unwrap_or("").to_string();
                Ok(CompiledCondition::HeaderExists(name))
            }
            "header_equals" => {
                let obj = condition.value.as_object().unwrap();
                let name = obj.get("name").unwrap().as_str().unwrap().to_string();
                let value = obj.get("value").unwrap().as_str().unwrap().to_string();
                Ok(CompiledCondition::HeaderEquals { name, value })
            }
            "header_regex" => {
                let obj = condition.value.as_object().unwrap();
                let name = obj.get("name").unwrap().as_str().unwrap().to_string();
                let pattern = obj.get("pattern").unwrap().as_str().unwrap();
                let regex = Regex::new(pattern)?;
                Ok(CompiledCondition::HeaderRegex { name, regex })
            }
            "ip_in_whitelist" => {
                let ips = Self::parse_ip_list(&condition.value)?;
                Ok(CompiledCondition::IpInWhitelist(ips))
            }
            "ip_not_in_whitelist" => {
                let ips = Self::parse_ip_list(&condition.value)?;
                Ok(CompiledCondition::IpNotInWhitelist(ips))
            }
            "ip_in_blacklist" => {
                let ips = Self::parse_ip_list(&condition.value)?;
                Ok(CompiledCondition::IpInBlacklist(ips))
            }
            "method_equals" => {
                let method = condition.value.as_str().unwrap_or("").to_string();
                Ok(CompiledCondition::MethodEquals(method))
            }
            "user_agent_regex" => {
                let pattern = condition.value.as_str().unwrap_or("");
                let regex = Regex::new(pattern)?;
                Ok(CompiledCondition::UserAgentRegex(regex))
            }
            "query_param_exists" => {
                let name = condition.value.as_str().unwrap_or("").to_string();
                Ok(CompiledCondition::QueryParamExists(name))
            }
            "query_param_equals" => {
                let obj = condition.value.as_object().unwrap();
                let name = obj.get("name").unwrap().as_str().unwrap().to_string();
                let value = obj.get("value").unwrap().as_str().unwrap().to_string();
                Ok(CompiledCondition::QueryParamEquals { name, value })
            }
            "body_contains" => {
                let text = condition.value.as_str().unwrap_or("").to_string();
                Ok(CompiledCondition::BodyContains(text))
            }
            "body_regex" => {
                let pattern = condition.value.as_str().unwrap_or("");
                let regex = Regex::new(pattern)?;
                Ok(CompiledCondition::BodyRegex(regex))
            }
            "content_type_equals" => {
                let content_type = condition.value.as_str().unwrap_or("").to_string();
                Ok(CompiledCondition::ContentTypeEquals(content_type))
            }
            _ => Err(anyhow::anyhow!("Unknown condition type: {}", condition.condition_type)),
        }
    }
    
    fn parse_ip_list(value: &serde_json::Value) -> Result<Vec<IpNet>> {
        let mut ips = Vec::new();
        
        if let Some(arr) = value.as_array() {
            for item in arr {
                if let Some(ip_str) = item.as_str() {
                    let ip_net: IpNet = ip_str.parse()?;
                    ips.push(ip_net);
                }
            }
        }
        
        Ok(ips)
    }
    
    /// Evaluate all rules against a request context
    pub async fn evaluate(&self, context: &RequestContext) -> WafResult<Option<WafInspectionResult>> {
        let rules = self.rules.read().await;
        let mut stats = self.statistics.write().await;
        
        stats.total_evaluations += 1;
        
        for rule in rules.iter() {
            debug!("Evaluating rule: {}", rule.name);
            
            if self.evaluate_rule(rule, context).await? {
                debug!("Rule matched: {}", rule.name);
                stats.rules_matched += 1;
                *stats.actions_taken.entry(format!("{:?}", rule.action)).or_insert(0) += 1;
                
                return Ok(Some(WafInspectionResult {
                    action: rule.action.clone(),
                    reason: format!("Matched rule: {}", rule.name),
                    rule_name: Some(rule.name.clone()),
                    confidence: 1.0,
                    metadata: serde_json::json!({
                        "rule_name": rule.name,
                        "action": format!("{:?}", rule.action),
                    }),
                }));
            }
        }
        
        Ok(None)
    }
    
    async fn evaluate_rule(&self, rule: &CompiledRule, context: &RequestContext) -> WafResult<bool> {
        // All conditions must match for the rule to match
        for condition in &rule.conditions {
            if !self.evaluate_condition(condition, context).await? {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    async fn evaluate_condition(&self, condition: &CompiledCondition, context: &RequestContext) -> WafResult<bool> {
        match condition {
            CompiledCondition::PathRegex(regex) => {
                Ok(regex.is_match(&context.uri))
            }
            CompiledCondition::PathPrefix(prefix) => {
                Ok(context.uri.starts_with(prefix))
            }
            CompiledCondition::PathExact(path) => {
                Ok(context.uri == *path)
            }
            CompiledCondition::HeaderExists(name) => {
                Ok(context.headers.contains_key(name))
            }
            CompiledCondition::HeaderEquals { name, value } => {
                if let Some(header_value) = context.headers.get(name) {
                    if let Ok(header_str) = header_value.to_str() {
                        return Ok(header_str == value);
                    }
                }
                Ok(false)
            }
            CompiledCondition::HeaderRegex { name, regex } => {
                if let Some(header_value) = context.headers.get(name) {
                    if let Ok(header_str) = header_value.to_str() {
                        return Ok(regex.is_match(header_str));
                    }
                }
                Ok(false)
            }
            CompiledCondition::IpInWhitelist(ips) => {
                Ok(ips.iter().any(|net| net.contains(&context.client_ip)))
            }
            CompiledCondition::IpNotInWhitelist(ips) => {
                Ok(!ips.iter().any(|net| net.contains(&context.client_ip)))
            }
            CompiledCondition::IpInBlacklist(ips) => {
                Ok(ips.iter().any(|net| net.contains(&context.client_ip)))
            }
            CompiledCondition::MethodEquals(method) => {
                Ok(context.method == *method)
            }
            CompiledCondition::UserAgentRegex(regex) => {
                if let Some(user_agent) = &context.user_agent {
                    Ok(regex.is_match(user_agent))
                } else {
                    Ok(false)
                }
            }
            CompiledCondition::QueryParamExists(name) => {
                Ok(context.query_string.contains(&format!("{}=", name)))
            }
            CompiledCondition::QueryParamEquals { name, value } => {
                let param_pattern = format!("{}={}", name, value);
                Ok(context.query_string.contains(&param_pattern))
            }
            CompiledCondition::BodyContains(text) => {
                if let Some(body) = &context.body {
                    if let Ok(body_str) = std::str::from_utf8(body) {
                        return Ok(body_str.contains(text));
                    }
                }
                Ok(false)
            }
            CompiledCondition::BodyRegex(regex) => {
                if let Some(body) = &context.body {
                    if let Ok(body_str) = std::str::from_utf8(body) {
                        return Ok(regex.is_match(body_str));
                    }
                }
                Ok(false)
            }
            CompiledCondition::ContentTypeEquals(content_type) => {
                if let Some(ct) = &context.content_type {
                    Ok(ct == content_type)
                } else {
                    Ok(false)
                }
            }
        }
    }
    
    /// Update rules at runtime
    pub async fn update_rules(&self, new_rules: &[CustomRule]) -> Result<()> {
        let compiled_rules = Self::compile_rules(new_rules)?;
        let mut rules = self.rules.write().await;
        *rules = compiled_rules;
        Ok(())
    }
    
    /// Get rule engine statistics
    pub async fn get_statistics(&self) -> serde_json::Value {
        let stats = self.statistics.read().await;
        serde_json::json!({
            "total_evaluations": stats.total_evaluations,
            "rules_matched": stats.rules_matched,
            "actions_taken": stats.actions_taken,
        })
    }
}
