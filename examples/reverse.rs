//! Check what reverse DNS says about a few addresses.
//!
//! A diagnostic, not part of the product: it answers "is the PTR path working
//! on this machine, and what does it actually return for the companies this
//! tool is supposed to identify".

fn main() {
    let addresses = [
        "8.8.8.8",
        "1.1.1.1",
        "142.250.75.238",
        "140.82.114.25",
        "162.159.135.234",
        "203.0.113.9", // documentation range: should have no name
    ];

    for address in addresses {
        match tattletale::dns::reverse::lookup(address) {
            Some(name) => {
                let owner = tattletale::dns::reverse::owner_of(&name).unwrap_or("-");
                println!("{address:<18} {name:<44} owner: {owner}");
            }
            None => println!("{address:<18} (no name)"),
        }
    }
}
