/// Polling until a TXT record is visible.
pub mod propagation;
/// Finding the zone that owns a name.
pub mod zone;

pub use propagation::{DEFAULT_RESOLVERS, wait_for_propagation};
pub use zone::find_zone;
