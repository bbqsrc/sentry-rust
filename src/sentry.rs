use url::{Url, ParseError};
use std::time::{SystemTime, UNIX_EPOCH};
use reqwest::Error as ReqwestError;
// use reqwest::unstable::async as reqwest;
use reqwest;
use serde_json;
use ::models::*;
use futures::Future;
use tokio_core::reactor::Core;
use std::cell::RefCell;

pub struct Sentry {
    http_client: reqwest::Client,
    builder: EventBuilder,
    url: Url,
    store_url: Url,
    // core: RefCell<Core>
}

impl Sentry {
    pub fn new(dsn: &str) -> Result<Sentry, ParseError> {
        // If an empty DSN is passed, you should treat it as valid option which signifies disabling the SDK.
        if dsn == "" {
            unimplemented!("Support for disabling Sentry not yet implemented")
        }

        let url = Url::parse(dsn)?;
        let store_url = Sentry::store_url(&url)?;
        let core = Core::new().unwrap();

        Ok(Sentry {
            http_client: reqwest::Client::new(), //(&core.handle()),
            builder: EventBuilder::new(),
            url: url,
            store_url: store_url,
            // core: RefCell::new(core)
        })

        // TODO: add context.os 
    }

    fn store_url(dsn: &Url) -> Result<Url, ParseError> {
        // TODO another error type
        let id = dsn.path_segments().and_then(|paths| paths.last()).unwrap();

        let url_str = format!("{}://{}/api/{}/store/",
            dsn.scheme(),
            dsn.host_str().unwrap(),
            id
        );

        Url::parse(&url_str)
    }

    fn auth_header(&self) -> XSentryAuth {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let key = self.url.username();
        let secret = self.url.password().unwrap();

        XSentryAuth {
            version: "7".to_owned(),
            timestamp: now.as_secs() as u64,
            key: key.to_owned(),
            secret: secret.to_owned(),
            client: "sentry-rust/0.1.0-dev".to_owned()
        }
    }

    pub fn dsn(&self) -> Url {
        self.url.clone()
    }

    pub fn capture_event(&self, event: &Event) -> Result<reqwest::Response, ReqwestError> {
        let request = self.http_client.post(&self.store_url.to_string())
            .header(self.auth_header())
            .body(serde_json::to_string(event).unwrap())
            .send();

        request

        // let mut core = self.core.borrow_mut();
        // core.run(request)
    }    

    pub fn capture_message(&self, message: &str) -> () {
        let event = self.builder.clone().message(message.to_owned()).build().unwrap();
        let result = self.capture_event(&event).unwrap();
        println!("{:?}", result);
    }

    pub fn event(&self) -> EventBuilder {
        self.builder.clone()
    }
}

#[cfg(test)]
mod tests {
    use sentry::*;
    use std::collections::BTreeMap;
    use backtrace::*;
    
    #[test]
    fn create_client() {
        let sentry = Sentry::new("https://public:secret@sentry.example.com/1").unwrap();
        assert_eq!(sentry.dsn(), Url::parse("https://public:secret@sentry.example.com/1").unwrap());
        assert_eq!(sentry.store_url, Url::parse("https://sentry.example.com/api/1/store/").unwrap());
    }

    #[test]
    fn get_auth_header() {
        let sentry = Sentry::new("https://public:secret@sentry.example.com/1").unwrap();
        let header = sentry.auth_header();
        assert_eq!(header.key, "public");
    }
    
    #[test]
    fn event_builder() {
        let mut tags: BTreeMap<String, String> = BTreeMap::new();
        tags.insert("test".to_owned(), "true".to_owned());
        
        let builder = EventBuilder::new()
            .tags(tags);

        println!("{:?}", builder.build());
        println!("{:?}", builder.build());
    }

    // #[test]
    // fn send_real_event() {
    //     let dsn_str = "https://423c6fcc62dc40c39df7b6e5f29f3df6:2182ec652bb8404ba7a13578c406e572@sentry.io/301539";
    //     let sentry = Sentry::new(dsn_str).unwrap();
    //     let event = sentry.event()
    //         .message("This is another test".to_owned())
    //         .level(SeverityLevel::Debug).build().unwrap();
    //     // sentry.capture_message("This is a test again");
    //     sentry.capture_event(&event);
    // }

    #[test]
    fn stacktrace() {
        let st = Stacktrace::from(Backtrace::new(), env!("CARGO_PKG_NAME"));
        println!("{:?}", st);

        let ex = Exception::new(vec![
            ExceptionValue::new("BacktraceError", "A test backtrace", Some(module_path!()), st)
        ]);

        let dsn_str = "https://423c6fcc62dc40c39df7b6e5f29f3df6:2182ec652bb8404ba7a13578c406e572@sentry.io/301539";
        let sentry = Sentry::new(dsn_str).unwrap();
        let event = sentry.event()
            .message("Exception test".to_owned())
            .exception(ex)
            .level(SeverityLevel::Fatal)
            .build()
            .unwrap();

        println!("{:?}", sentry.capture_event(&event));
    }
}