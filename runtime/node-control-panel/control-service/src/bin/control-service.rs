use synergy_node_control_panel::app_context::AppContext;
use synergy_node_control_panel::control_service;

const CONTROL_SERVICE_WORKER_STACK_BYTES: usize = 64 * 1024 * 1024;

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(CONTROL_SERVICE_WORKER_STACK_BYTES)
        .build()
        .unwrap_or_else(|error| {
            eprintln!("failed to start control-service runtime: {error}");
            std::process::exit(1);
        });

    runtime.block_on(async_main());
}

async fn async_main() {
    let mut port: u16 = 47_891;
    let mut token = String::new();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--port" => {
                if let Some(value) = args.next() {
                    if let Ok(parsed) = value.parse::<u16>() {
                        port = parsed;
                    }
                }
            }
            "--token" => {
                if let Some(value) = args.next() {
                    token = value;
                }
            }
            _ => {}
        }
    }

    if token.trim().is_empty() {
        eprintln!("control-service requires --token");
        std::process::exit(1);
    }

    let app_context = AppContext::from_env();
    if let Err(error) = control_service::serve(port, token, app_context).await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
