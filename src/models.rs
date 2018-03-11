use std::fmt;
use hyper;
use hyper::header::{self, Header, Raw};
use uuid::Uuid;
use chrono::prelude::*;
use std::collections::BTreeMap;
use backtrace::{Backtrace, BacktraceFrame};
use std::ptr;
use rustc_demangle::demangle;

#[cfg(target_os = "macos")]
use sysctl;

#[cfg(unix)]
use uname::uname;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sdk {
    name: String,
    version: String,
    integrations: Vec<String>
}

#[derive(Debug, Clone)]
pub enum SeverityLevel {
    Fatal,
    Error,
    Warning,
    Info,
    Debug
}

impl SeverityLevel {
    fn to_str(&self) -> &'static str {
        match *self {
            SeverityLevel::Fatal => "fatal",
            SeverityLevel::Error => "error",
            SeverityLevel::Warning => "warning",
            SeverityLevel::Info => "info",
            SeverityLevel::Debug => "debug"
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    event_id: String,
    timestamp: DateTime<Utc>,
    logger: String,
    platform: String,
    sdk: Sdk,
    level: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    culprit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    server_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    release: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    modules: Option<BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    extra: Option<BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fingerprint: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    contexts: Option<Contexts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exception: Option<Exception>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackFrame {
    filename: String,
    function: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    package: Option<String>,
    lineno: u32,
    instruction_addr: String, // 0x...
    symbol_addr: String, // 0x...
    in_app: bool
}

impl StackFrame {
    fn from(frame: &BacktraceFrame, app_name: &str) -> Vec<StackFrame> {
        let frames: Vec<StackFrame> = frame.symbols().iter().filter_map(|symbol| {
            let symbol_name: String = match symbol.name() {
                Some(v) => demangle(v.as_str().unwrap_or("<invalid>")).to_string(),
                None => "<unknown>".to_owned()
            };

            if symbol_name.starts_with("backtrace::") {
                return None;
            }

            let function: String = match symbol_name.starts_with("<") {
                true => symbol_name.to_owned(),
                false => {
                    let fparts: Vec<&str> = symbol_name.split("::").collect();
                    
                    if let Some(last) = fparts.last() {
                        if last.starts_with("h") {
                            fparts[fparts.len() - 2].to_owned()
                        } else {
                            String::from(*last)
                        }
                    } else {
                        symbol_name.to_owned()
                    }
                }
            };

            let package = if function == symbol_name { None } else { Some(symbol_name.to_owned()) };

            let filename: String = match symbol.filename() {
                Some(v) => String::from(v.to_string_lossy()),
                None => "<unknown>".to_owned()
            };

            let in_app = match &package {
                &Some(ref v) => v.starts_with(app_name),
                &None => false
            };

            Some(StackFrame {
                filename: filename,
                function: function,
                package: package,
                lineno: symbol.lineno().unwrap_or(0),
                instruction_addr: format!("0x{:x}", frame.ip() as usize),
                symbol_addr: format!("0x{:x}", symbol.addr().unwrap_or(ptr::null_mut()) as usize),
                in_app: in_app
            })
        }).collect();

        frames
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Exception {
    values: Vec<ExceptionValue>
}

impl Exception {
    pub fn new(values: Vec<ExceptionValue>) -> Exception {
        Exception { 
            values: values
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExceptionValue {
    #[serde(rename = "type")]
    type_: String,
    value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    module: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    thread_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stacktrace: Option<Stacktrace>
}

impl ExceptionValue {
    pub fn new(type_: &str, value: &str, module: Option<&str>, stacktrace: Stacktrace) -> ExceptionValue {
        ExceptionValue {
            type_: type_.to_owned(),
            value: value.to_owned(),
            module: module.map(|x| x.to_owned()),
            thread_id: None,
            stacktrace: Some(stacktrace)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stacktrace {
    #[serde(skip_serializing_if = "Option::is_none")]
    frames: Option<Vec<StackFrame>>
}

impl Stacktrace {
    pub fn from(backtrace: Backtrace, app_name: &str) -> Stacktrace {
        let frames: Vec<StackFrame> = backtrace.frames().iter().flat_map(|frame| {
            return StackFrame::from(&frame, &app_name)
        }).collect();

        Stacktrace {
            frames: Some(frames)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contexts {
    os: OsContext,
    device: DeviceContext
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceContext {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    family: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    model_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    arch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    battery_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    orientation: Option<String>,
}

impl DeviceContext {
    #[cfg(target_os = "macos")]
    pub fn new() -> DeviceContext {
        let info = uname().unwrap();

        let model = match sysctl::value("hw.model").unwrap() {
            sysctl::CtlValue::String(v) => Some(v),
            _ => None
        };

        DeviceContext {
            name: info.nodename,
            family: None,
            model: model,
            model_id: None,
            arch: Some(info.machine),
            battery_level: None,
            orientation: None
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsContext {
    name: String,
    version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    build: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kernel_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rooted: Option<bool>
}

impl OsContext {
    #[cfg(unix)]
    pub fn new() -> OsContext {
        let info = uname().unwrap();

        let build = match sysctl::value("kern.osversion").unwrap() {
            sysctl::CtlValue::String(v) => Some(v),
            _ => None
        };

        OsContext {
            name: info.sysname,
            version: info.release,
            build: build,
            kernel_version: Some(info.version),
            rooted: None
        }
    }
}

#[derive(Debug)]
pub enum EventBuilderError {
    MissingField(&'static str)
}

#[derive(Debug, Clone)]
pub struct EventBuilder {
    logger: Option<String>,
    platform: Option<String>,
    sdk: Option<Sdk>,
    level: Option<SeverityLevel>,
    culprit: Option<String>,
    server_name: Option<String>,
    release: Option<String>,
    tags: Option<BTreeMap<String, String>>,
    modules: Option<BTreeMap<String, String>>,
    extra: Option<BTreeMap<String, String>>,
    fingerprint: Option<Vec<String>>,
    contexts: Option<Contexts>,
    message: Option<String>,
    exception: Option<Exception>
}

impl EventBuilder {
    pub fn new() -> EventBuilder {
        let sdk = Sdk {
            name: "sentry-rust".to_owned(),
            version: "0.1.0".to_owned(),
            integrations: vec![]
        };

        let os_context = OsContext::new();
        let device_context = DeviceContext::new();

        EventBuilder {
            logger: Some("root".to_owned()),
            platform: Some("other".to_owned()),
            sdk: Some(sdk),
            level: None,
            culprit: None,
            server_name: None,
            release: None,
            tags: None,
            modules: None,
            extra: None,
            fingerprint: None,
            contexts: Some(Contexts { os: os_context, device: device_context }),
            message: None,
            exception: None
        }
    }

    pub fn logger(mut self, logger: String) -> EventBuilder {
        self.logger = Some(logger);
        self
    }

    pub fn platform(mut self, platform: String) -> EventBuilder {
        self.platform = Some(platform);
        self
    }

    pub fn sdk(mut self, sdk: Sdk) -> EventBuilder {
        self.sdk = Some(sdk);
        self
    }

    pub fn tags(mut self, tags: BTreeMap<String, String>) -> EventBuilder {
        self.tags = Some(tags);
        self
    }

    pub fn level(mut self, level: SeverityLevel) -> EventBuilder {
        self.level = Some(level);
        self
    }

    pub fn message(mut self, message: String) -> EventBuilder {
        self.message = Some(message);
        self
    }

    pub fn exception(mut self, exception: Exception) -> EventBuilder {
        self.exception = Some(exception);
        self
    }

    pub fn extra(mut self, extra: BTreeMap<String, String>) -> EventBuilder {
        self.extra = Some(extra);
        self
    }

    pub fn build(&self) -> Result<Event, EventBuilderError> {
        if self.logger.is_none() {
            return Err(EventBuilderError::MissingField("logger"));
        }

        if self.platform.is_none() {
            return Err(EventBuilderError::MissingField("platform"));
        }

        if self.sdk.is_none() {
            return Err(EventBuilderError::MissingField("sdk"));
        }

        Ok(Event {
            event_id: Uuid::new_v4().simple().to_string(),
            timestamp: Utc::now(),
            logger: self.logger.clone().unwrap(),
            platform: self.platform.clone().unwrap(),
            sdk: self.sdk.clone().unwrap(),
            level: self.level.clone().unwrap_or(SeverityLevel::Error).to_str().to_owned(),
            culprit: self.culprit.clone(),
            server_name: self.server_name.clone(),
            release: self.release.clone(),
            tags: self.tags.clone(),
            modules: self.modules.clone(),
            extra: self.extra.clone(),
            fingerprint: self.fingerprint.clone(),
            contexts: self.contexts.clone(),
            message: self.message.clone(),
            exception: self.exception.clone()
        })
    }
}

#[derive(Debug, Clone)]
pub struct XSentryAuth {
    pub version: String,
    pub timestamp: u64,
    pub key: String,
    pub secret: String,
    pub client: String
}

impl Header for XSentryAuth {
    fn header_name() -> &'static str {
        "X-Sentry-Auth"
    }

    fn parse_header(_raw: &Raw) -> hyper::Result<XSentryAuth> {
        unimplemented!()
    }

    fn fmt_header(&self, f: &mut header::Formatter) -> fmt::Result {
        f.fmt_line(&format!("Sentry sentry_version={}, sentry_timestamp={}, sentry_key={}, sentry_secret={}, sentry_client={}",
            self.version,
            self.timestamp,
            self.key,
            self.secret,
            self.client))
    }
}
