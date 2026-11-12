use std::{env, fs};
fn main() {
    let path = env::args().nth(1).expect("partition plan required");
    let plan = fs::read_to_string(path).expect("read plan");
    assert!(
        plan.lines().any(|line| line.starts_with("left="))
            && plan.lines().any(|line| line.starts_with("right=")),
        "plan requires left and right sets"
    );
    println!("partition plan validated; no host firewall was modified");
}
