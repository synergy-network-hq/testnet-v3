//! Node.js specific initialization for WASM modules
//!
//! This module provides Node.js-compatible initialization that avoids
//! browser-specific dependencies and getrandom conflicts.

use js_sys::{Object, Reflect};
use wasm_bindgen::prelude::*;

/// Initialize the WASM module for Node.js environment
#[wasm_bindgen]
pub async fn init_nodejs() -> Result<(), JsValue> {
    // Set up Node.js-specific global variables
    let global = js_sys::global().dyn_into::<Object>()?;

    // Ensure __dirname is available (Node.js specific)
    if !Reflect::has(&global, &"__dirname".into())? {
        let dirname = std::env::current_dir()
            .map_err(|e| JsValue::from_str(&format!("Failed to get current dir: {}", e)))?
            .to_string_lossy()
            .to_string();
        Reflect::set(&global, &"__dirname".into(), &dirname.into())?;
    }

    // Ensure __filename is available
    if !Reflect::has(&global, &"__filename".into())? {
        let filename = std::env::current_exe()
            .map_err(|e| JsValue::from_str(&format!("Failed to get exe path: {}", e)))?
            .to_string_lossy()
            .to_string();
        Reflect::set(&global, &"__filename".into(), &filename.into())?;
    }

    // Set up process global if not available
    if !Reflect::has(&global, &"process".into())? {
        let process = Object::new();

        // Add versions
        let versions = Object::new();
        Reflect::set(&versions, &"node".into(), &"18.0.0".into())?;
        Reflect::set(&process, &"versions".into(), &versions)?;

        // Add platform
        Reflect::set(&process, &"platform".into(), &"nodejs".into())?;

        Reflect::set(&global, &"process".into(), &process)?;
    }

    Ok(())
}

/// Check if we're running in Node.js
#[wasm_bindgen]
pub fn is_nodejs() -> bool {
    js_sys::global()
        .dyn_into::<Object>()
        .ok()
        .and_then(|global| Reflect::get(&global, &"process".into()).ok())
        .and_then(|process| Reflect::get(&process, &"versions".into()).ok())
        .and_then(|versions| Reflect::get(&versions, &"node".into()).ok())
        .is_some()
}

/// Get Node.js version if available
#[wasm_bindgen]
pub fn nodejs_version() -> Option<String> {
    js_sys::global()
        .dyn_into::<Object>()
        .ok()
        .and_then(|global| Reflect::get(&global, &"process".into()).ok())
        .and_then(|process| Reflect::get(&process, &"versions".into()).ok())
        .and_then(|versions| Reflect::get(&versions, &"node".into()).ok())
        .and_then(|node_version| node_version.as_string())
}

/// Initialize WASM for Node.js with custom configuration
#[wasm_bindgen]
pub async fn init_wasm_nodejs(base_path: Option<String>) -> Result<(), JsValue> {
    // Initialize Node.js environment
    init_nodejs().await?;

    // Set up WASM loader with Node.js-compatible paths
    let loader_base_path = base_path.unwrap_or_else(|| "./pqwasm/refimp/".to_string());

    // Store the base path in global scope for the loader to use
    let global = js_sys::global().dyn_into::<Object>()?;
    Reflect::set(
        &global,
        &"__wasm_base_path".into(),
        &loader_base_path.into(),
    )?;

    Ok(())
}
