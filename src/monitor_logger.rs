use reqwest::Client;
use serde_json::json;
use tracing::{error, info, warn};

pub enum NotificationPriority {
    Resolved,
    Info,
    Warning,
    Error,
}

impl NotificationPriority {
    // Function to format the message based on its type
    fn format_message(&self, log_message: &String) -> String {
        match self {
            Self::Resolved => format!(":white_check_mark: {}", log_message),
            Self::Info => format!(":information_source: {}", log_message),
            Self::Warning => format!(":warning: *[WARNING]* {}", log_message),
            Self::Error => format!(":x: *[ERROR]* {}", log_message),
        }
    }
}

pub struct Logger {
    webhook_url: String,
    client: Client,
    first_run_logging_opt: bool,
    is_first_run: bool,
}

impl Logger {
    pub fn new(webhook_url: String, first_run_logging_opt: bool) -> Self {
        Self {
            webhook_url,
            client: Client::new(),
            first_run_logging_opt,
            is_first_run: true,
        }
    }

    pub fn finish_first_run(&mut self) {
        self.is_first_run = false;
    }

    pub async fn log_and_notify_slack(&self, message: String, priority_type: NotificationPriority) {
        // Log error.
        match priority_type {
            NotificationPriority::Info | NotificationPriority::Resolved => info!(message),
            NotificationPriority::Warning => warn!(message),
            NotificationPriority::Error => error!(message),
        }
        if self.is_first_run && !self.first_run_logging_opt {
            return;
        }
        // Format the message payload as per Slack's requirements
        let payload = json!({
            "text": priority_type.format_message(&message),
        });

        // Send the payload to the Slack webhook URL using a POST request
        let res = self
            .client
            .post(&self.webhook_url)
            .json(&payload)
            .send()
            .await;

        match res {
            Ok(res) => {
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
    }
}
