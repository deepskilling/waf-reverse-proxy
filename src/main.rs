use anyhow::Result;
use clap::Parser;
use std::sync::Arc;
use tracing::{info, error};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod waf;
mod proxy;
mod observability;
mod admin;
mod security;
mod health;
mod ssl;
mod error;

use config::Config;
use waf::WafEngine;
use proxy::ReverseProxy;
use observability::{MetricsCollector, Logger};
use admin::AdminServer;
use health::HealthChecker;
use ssl::SslManager;

#[derive(Parser, Debug)]
#[command(name = "waf-reverse-proxy")]
#[command(about = "A high-performance WAF and Reverse Proxy")]
struct Args {
    #[arg(short, long, default_value = "config.yaml")]
    config: String,
    
    #[arg(short, long)]
    validate_config: bool,
    
    #[arg(short, long)]
    daemon: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
    
    info!("Starting WAF + Reverse Proxy");
    
    // Load configuration
    let config = Config::load(&args.config).await?;
    
    if args.validate_config {
        info!("Configuration is valid");
        return Ok(());
    }
    
    // Initialize components
    let metrics_collector = Arc::new(MetricsCollector::new(&config.metrics)?);
    let logger = Arc::new(Logger::new(&config.logging)?);
    let health_checker = Arc::new(HealthChecker::new());
    
    // Initialize SSL manager if SSL is enabled
    let ssl_manager = if config.ssl.enabled {
        Some(Arc::new(SslManager::new(config.ssl.clone()).await?))
    } else {
        None
    };
    
    // Initialize WAF engine
    let waf_engine = Arc::new(WafEngine::new(&config.waf, metrics_collector.clone()).await?);
    
    // Initialize reverse proxy
    let reverse_proxy = Arc::new(
        ReverseProxy::new(
            &config.proxy,
            waf_engine.clone(),
            metrics_collector.clone(),
            logger.clone(),
            health_checker.clone(),
        ).await?
    );
    
    // Start health checker
    let health_task = {
        let health_checker = health_checker.clone();
        let config = config.clone();
        tokio::spawn(async move {
            health_checker.start_monitoring(&config.proxy).await;
        })
    };
    
    // Start admin server if enabled
    let admin_task = if config.admin.enabled {
        let admin_server = AdminServer::new(
            &config.admin,
            config.clone(),
            metrics_collector.clone(),
        )?;
        Some(tokio::spawn(async move {
            if let Err(e) = admin_server.start().await {
                error!("Admin server error: {}", e);
            }
        }))
    } else {
        None
    };
    
    // Start metrics server if enabled
    let metrics_task = if config.metrics.enabled {
        let metrics_collector = metrics_collector.clone();
        let config = config.clone();
        Some(tokio::spawn(async move {
            if let Err(e) = metrics_collector.start_server(&config.metrics).await {
                error!("Metrics server error: {}", e);
            }
        }))
    } else {
        None
    };
    
    // Start the main server
    let host = config.server.host.clone();
    let port = config.server.port;
    
    let server_task = tokio::spawn(async move {
        if let Err(e) = reverse_proxy.start(&config.server).await {
            error!("Server error: {}", e);
        }
    });
    
    info!("WAF + Reverse Proxy started successfully");
    info!("Server listening on {}:{}", host, port);
    
    // Handle shutdown gracefully
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Received shutdown signal");
        }
        _ = server_task => {
            error!("Main server task exited unexpectedly");
        }
        _ = health_task => {
            error!("Health checker task exited unexpectedly");
        }
    }
    
    // Wait for optional tasks to complete
    if let Some(admin_task) = admin_task {
        admin_task.abort();
    }
    
    if let Some(metrics_task) = metrics_task {
        metrics_task.abort();
    }
    
    info!("WAF + Reverse Proxy shutdown complete");
    Ok(())
}
