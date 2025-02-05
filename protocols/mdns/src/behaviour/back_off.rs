// protocols\mdns\src\behaviour\back_off.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackoffState {
    Normal,
    #[allow(dead_code)]
    Backoff,
    #[allow(dead_code)]
    Recovery,
    #[allow(dead_code)]
    Stable,
}