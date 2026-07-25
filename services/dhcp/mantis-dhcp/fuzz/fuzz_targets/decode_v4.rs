#![no_main]

use dhcproto::v4::Message;
use dhcproto::{Decodable, Decoder};
use libfuzzer_sys::fuzz_target;

// Exactly what main.rs::socket_loop does with a raw, untrusted UDP payload
// before any other code runs — this is the actual trust boundary (design.md
// §26 R8). A malformed/adversarial byte sequence must produce an `Err`, not
// a panic.
fuzz_target!(|data: &[u8]| {
    let _ = Message::decode(&mut Decoder::new(data));
});
