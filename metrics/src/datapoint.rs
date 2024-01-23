//! This file defines a set of macros for reporting metrics.
//!
//! To report a metric, simply calling one of the following datapoint macros
//! with a suitable message level:
//!
//! - datapoint_error!
//! - datapoint_warn!
//! - datapoint_trace!
//! - datapoint_info!
//! - datapoint_debug!
//!
//! The matric macro consists of the following three main parts:
//!  - name: the name of the metric.
//!
//!  - tags (optional): when a metric sample is reported with tags, you can use
//!    group-by when querying the reported samples.  Each metric sample can be
//!    attached with zero to many tags.  Each tag is of the format:
//!
//!    - "tag-name" => "tag-value"
//!
//!  - fields (optional): fields are the main content of a metric sample. The
//!    macro supports four different types of fields: bool, i64, f64, and String.
//!    Here're their syntax:
//!
//!    - ("field-name", "field-value", bool)
//!    - ("field-name", "field-value", i64)
//!    - ("field-name", "field-value", f64)
//!    - ("field-name", "field-value", String)
//!
//! Example:
//!
//! datapoint_debug!(
//!     "name-of-the-metric",
//!     "tag" => "tag-value",
//!     "tag2" => "tag-value2",
//!     ("some-bool", false, bool),
//!     ("some-int", 100, i64),
//!     ("some-float", 1.05, f64),
//!     ("some-string", "field-value", String),
//! );
//!
use std::{fmt, time::SystemTime};

#[derive(Clone, Debug)]
pub struct DataPoint {
    pub name: &'static str,
    pub timestamp: SystemTime,
    /// tags are eligible for group-by operations.
    pub tags: Vec<(&'static str, String)>,
    pub fields: Vec<(&'static str, String)>,
}

impl DataPoint {
    pub fn new(name: &'static str) -> Self {
        DataPoint {
            name,
            timestamp: SystemTime::now(),
            tags: vec![],
            fields: vec![],
        }
    }

    pub fn add_tag(&mut self, name: &'static str, value: &str) -> &mut Self {
        self.tags.push((name, value.to_string()));
        self
    }

    pub fn add_field_str(&mut self, name: &'static str, value: &str) -> &mut Self {
        self.fields
            .push((name, format!("\"{}\"", value.replace('\"', "\\\""))));
        self
    }

    pub fn add_field_bool(&mut self, name: &'static str, value: bool) -> &mut Self {
        self.fields.push((name, value.to_string()));
        self
    }

    pub fn add_field_i64(&mut self, name: &'static str, value: i64) -> &mut Self {
        self.fields.push((name, value.to_string() + "i"));
        self
    }

    pub fn add_field_f64(&mut self, name: &'static str, value: f64) -> &mut Self {
        self.fields.push((name, value.to_string()));
        self
    }
}

impl fmt::Display for DataPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "datapoint: {}", self.name)?;
        for tag in &self.tags {
            write!(f, ",{}={}", tag.0, tag.1)?;
        }
        for field in &self.fields {
            write!(f, " {}={}", field.0, field.1)?;
        }
        Ok(())
    }
}

#[macro_export]
macro_rules! create_datapoint {
    (@field $point:ident $name:expr, $string:expr, String) => {
        $point.add_field_str($name, &$string);
    };
    (@field $point:ident $name:expr, $value:expr, i64) => {
        $point.add_field_i64($name, $value as i64);
    };
    (@field $point:ident $name:expr, $value:expr, f64) => {
        $point.add_field_f64($name, $value as f64);
    };
    (@field $point:ident $name:expr, $value:expr, bool) => {
        $point.add_field_bool($name, $value as bool);
    };
    (@tag $point:ident $tag_name:expr, $tag_value:expr) => {
        $point.add_tag($tag_name, &$tag_value);
    };

    (@fields $point:ident) => {};

    // process optional fields
    (@fields $point:ident ($name:expr, $value:expr, Option<$type:ident>) , $($rest:tt)*) => {
        if let Some(value) = $value {
            $crate::create_datapoint!(@field $point $name, value, $type);
        }
        $crate::create_datapoint!(@fields $point $($rest)*);
    };
    (@fields $point:ident ($name:expr, $value:expr, Option<$type:ident>) $(,)?) => {
        if let Some(value) = $value {
            $crate::create_datapoint!(@field $point $name, value, $type);
        }
    };

    // process tags
    (@fields $point:ident $tag_name:expr => $tag_value:expr, $($rest:tt)*) => {
        $crate::create_datapoint!(@tag $point $tag_name, $tag_value);
        $crate::create_datapoint!(@fields $point $($rest)*);
    };
    (@fields $point:ident $tag_name:expr => $tag_value:expr $(,)?) => {
        $crate::create_datapoint!(@tag $point $tag_name, $tag_value);
    };

    // process fields
    (@fields $point:ident ($name:expr, $value:expr, $type:ident) , $($rest:tt)*) => {
        $crate::create_datapoint!(@field $point $name, $value, $type);
        $crate::create_datapoint!(@fields $point $($rest)*);
    };
    (@fields $point:ident ($name:expr, $value:expr, $type:ident) $(,)?) => {
        $crate::create_datapoint!(@field $point $name, $value, $type);
    };

    (@point $name:expr, $($fields:tt)+) => {
        {
            let mut point = $crate::datapoint::DataPoint::new(&$name);
            $crate::create_datapoint!(@fields point $($fields)+);
            point
        }
    };
    (@point $name:expr $(,)?) => {
        $crate::datapoint::DataPoint::new(&$name)
    };
}

#[macro_export]
macro_rules! datapoint {
    ($level:expr, $name:expr $(,)?) => {
        if log::log_enabled!($level) {
            $crate::submit($crate::create_datapoint!(@point $name), $level);
        }
    };
    ($level:expr, $name:expr, $($fields:tt)+) => {
        if log::log_enabled!($level) {
            $crate::submit($crate::create_datapoint!(@point $name, $($fields)+), $level);
        }
    };
}
#[macro_export]
macro_rules! datapoint_error {
    ($name:expr $(,)?) => {
        $crate::datapoint!(log::Level::Error, $name);
    };
    ($name:expr, $($fields:tt)+) => {
        $crate::datapoint!(log::Level::Error, $name, $($fields)+);
    };
}

#[macro_export]
macro_rules! datapoint_warn {
    ($name:expr $(,)?) => {
        $crate::datapoint!(log::Level::Warn, $name);
    };
    ($name:expr, $($fields:tt)+) => {
        $crate::datapoint!(log::Level::Warn, $name, $($fields)+);
    };
}

#[macro_export]
macro_rules! datapoint_info {
    ($name:expr) => {
        $crate::datapoint!(log::Level::Info, $name);
    };
    ($name:expr, $($fields:tt)+) => {
        $crate::datapoint!(log::Level::Info, $name, $($fields)+);
    };
}

#[macro_export]
macro_rules! datapoint_debug {
    ($name:expr) => {
        $crate::datapoint!(log::Level::Debug, $name);
    };
    ($name:expr, $($fields:tt)+) => {
        $crate::datapoint!(log::Level::Debug, $name, $($fields)+);
    };
}

#[macro_export]
macro_rules! datapoint_trace {
    ($name:expr) => {
        $crate::datapoint!(log::Level::Trace, $name);
    };
    ($name:expr, $($fields:tt)+) => {
        $crate::datapoint!(log::Level::Trace, $name, $($fields)+);
    };
}
