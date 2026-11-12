#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fault {
    Drop {
        from: String,
        to: String,
    },
    Delay {
        from: String,
        to: String,
        millis: u64,
    },
    Crash {
        node: String,
    },
    DiskFull {
        node: String,
    },
    Byzantine {
        node: String,
    },
}
