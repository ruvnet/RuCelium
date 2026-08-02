#[test]
fn dbg_float() {
    let s = "23.470000000000002";
    let a: f64 = s.parse().unwrap();
    let b: f64 = serde_json::from_str(s).unwrap();
    println!("std   = {:?} bits={:x}", a, a.to_bits());
    println!("serde = {:?} bits={:x}", b, b.to_bits());
    assert_eq!(a.to_bits(), b.to_bits());
}
