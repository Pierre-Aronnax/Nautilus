// protocols/mdns/src/behaviour/service/mod.rs

pub mod core_service;
pub mod advertiser;
pub mod listener;
pub mod query;
pub mod socket;
pub mod event_handler;
pub mod service_api;
// Re-export the main struct so user code can do:
// use crate::behaviour::service::MdnsService;
pub use core_service::MdnsService;
pub use service_api::MdnsRuntime;