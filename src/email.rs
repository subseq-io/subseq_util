use std::future::Future;
use std::path::PathBuf;

use anyhow::Result;
use diesel_async::AsyncPgConnection;
use email_address::EmailAddress;
use handlebars::{DirectorySourceOptions, Handlebars};
use serde::Serialize;
use tokio::sync::broadcast;

use crate::{
    rate_limit::{rate_limited_channel, RateLimitProfile, RateLimitedReceiver},
    tables::UserTable,
};

/// Intended to be used with an HTML-based template.
/// I use Maizzle for this.
pub fn setup_handlebars(templates_dir: &PathBuf) -> Result<Handlebars> {
    let mut handlebars = Handlebars::new();
    let opts = DirectorySourceOptions {
        tpl_extension: ".html".to_string(),
        hidden: false,
        temporary: false,
    };
    handlebars.register_templates_directory(templates_dir, opts)?;

    Ok(handlebars)
}

#[derive(Clone, Debug)]
pub struct FilledTemplate(pub String);

impl AsRef<str> for FilledTemplate {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

impl FilledTemplate {
    pub fn new<S: Serialize>(
        handlebars: &Handlebars,
        template: &str,
        template_data: &S,
    ) -> anyhow::Result<FilledTemplate> {
        let rendered = handlebars.render(template, template_data)?;
        Ok(FilledTemplate(rendered))
    }
}

pub trait EmailTemplate: Clone + std::fmt::Debug + Send {
    /// The subject of the email.
    fn subject(&self) -> String;

    /// Fill the template with the handlebars instance.
    fn fill(self, handlebars: &Handlebars) -> FilledTemplate;
}

pub trait EmailTemplateBuilder<Template, User>: Sized
where
    Template: EmailTemplate,
    User: UserTable,
{
    fn new(
        conn: &mut AsyncPgConnection,
        user: &User,
    ) -> impl std::future::Future<Output = anyhow::Result<Self>> + Send;
    fn unique_link(self, link: &str) -> Self;
    fn subject(self, subject: &str) -> Self;
    fn build(self) -> anyhow::Result<Template>;
}

#[derive(Clone, Debug)]
pub struct ScheduledEmail<T: EmailTemplate + 'static> {
    pub to: EmailAddress,
    pub template: T,
}

#[derive(Clone)]
pub struct Email {
    pub to: EmailAddress,
    pub from: EmailAddress,
    pub subject: String,
    pub message: FilledTemplate,
}

impl Email {
    pub fn new(
        to: &EmailAddress,
        from: &EmailAddress,
        subject: &str,
        message: FilledTemplate,
    ) -> Self {
        Self {
            to: to.clone(),
            from: from.clone(),
            subject: subject.to_string(),
            message,
        }
    }
}

pub fn schedule_emails<T, F, Fut>(
    from: EmailAddress,
    templates_dir: PathBuf,
    mut schedule_rx: broadcast::Receiver<ScheduledEmail<T>>,
    send_email: F,
    profile: RateLimitProfile,
) where
    T: EmailTemplate,
    F: FnOnce(RateLimitedReceiver<Email>) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let (tx, rx) = rate_limited_channel(profile);

    tokio::spawn(async move {
        let handlebars = setup_handlebars(&templates_dir).expect("Failed to setup handlebars");

        while let Ok(scheduled_email) = schedule_rx.recv().await {
            let ScheduledEmail { to, template } = scheduled_email;
            let subject = template.subject();
            let filled_template = template.fill(&handlebars);
            let email = Email::new(&to, &from, &subject, filled_template);
            if tx.send(email).await.is_err() {
                break;
            }
        }
        tracing::info!("Email scheduler shutting down");
    });

    tokio::spawn(send_email(rx));
}
