/// Polling until a TXT record is visible.
pub mod propagation;
/// Finding the zone that owns a name.
pub mod zone;

pub use propagation::{wait_for_propagation, DEFAULT_RESOLVERS};
pub use zone::find_zone;
