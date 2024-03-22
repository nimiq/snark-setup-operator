use reqwest::Client;
use serde_json::json;
use tracing::{error, info, warn};

pub enum NotificationPriority {
    Info,
    Warning,
    Error,
}

pub struct Logger {
    webhook_url: String,
    client: Client,
}

impl Logger {
    pub fn new(webhook_url: String) -> Self {
        Self {
            webhook_url,
            client: Client::new(),
        }
    }

    pub async fn log_and_notify_slack(
        &self,
        message: &String,
        priority_type: NotificationPriority,
    ) {
        // Format the message payload as per Slack's requirements
        let payload = json!({
            "text": message,
        });

        // Send the payload to the Slack webhook URL using a POST request
        let res = self
            .client
            .post(&self.webhook_url)
            .json(&payload)
            .send()
            .await;

        match res {
            core::result::Result::Ok(res) => {
                // Check if the request was successful
                if !res.status().is_success() {
                    error!(
                        "Failed to send trace log to Slack. Status code: {}",
                        res.status()
                    );
                }
            }
            Err(e) => {
                error!("Failed to send trace log to Slack. Error: {:?}", e);
            }
        }

        // Log error.
        match priority_type {
            NotificationPriority::Info => info!(message),
            NotificationPriority::Warning => warn!(message),
            NotificationPriority::Error => error!(message),
        }
    }
}
