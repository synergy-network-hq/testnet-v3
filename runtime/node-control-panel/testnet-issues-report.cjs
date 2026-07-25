const fs = require("fs");
const { Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
        Header, Footer, AlignmentType, LevelFormat,
        HeadingLevel, BorderStyle, WidthType, ShadingType,
        PageNumber, PageBreak } = require("docx");

const border = { style: BorderStyle.SINGLE, size: 1, color: "CCCCCC" };
const borders = { top: border, bottom: border, left: border, right: border };
const cellMargins = { top: 80, bottom: 80, left: 120, right: 120 };

function headerCell(text, width) {
  return new TableCell({
    borders, width: { size: width, type: WidthType.DXA },
    shading: { fill: "1B2A4A", type: ShadingType.CLEAR },
    margins: cellMargins,
    verticalAlign: "center",
    children: [new Paragraph({ children: [new TextRun({ text, bold: true, color: "FFFFFF", font: "Arial", size: 20 })] })]
  });
}

function cell(text, width, opts = {}) {
  return new TableCell({
    borders, width: { size: width, type: WidthType.DXA },
    shading: opts.fill ? { fill: opts.fill, type: ShadingType.CLEAR } : undefined,
    margins: cellMargins,
    children: [new Paragraph({ children: [new TextRun({ text, font: "Arial", size: 20, bold: opts.bold, color: opts.color })] })]
  });
}

function severityCell(severity, width) {
  const colors = { "CRITICAL": { fill: "FADBD8", color: "922B21" }, "HIGH": { fill: "FDEBD0", color: "B9770E" }, "MEDIUM": { fill: "FEF9E7", color: "7D6608" } };
  const c = colors[severity] || { fill: "FFFFFF", color: "000000" };
  return cell(severity, width, { fill: c.fill, color: c.color, bold: true });
}

function heading(text, level) {
  return new Paragraph({ heading: level, spacing: { before: 300, after: 150 }, children: [new TextRun({ text, font: "Arial" })] });
}

function para(text, opts = {}) {
  return new Paragraph({ spacing: { after: 120 }, children: [new TextRun({ text, font: "Arial", size: 22, ...opts })] });
}

function bulletList(items, ref) {
  return items.map(item => new Paragraph({
    numbering: { reference: ref, level: 0 },
    spacing: { after: 60 },
    children: [new TextRun({ text: item, font: "Arial", size: 22 })]
  }));
}

const doc = new Document({
  styles: {
    default: { document: { run: { font: "Arial", size: 22 } } },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 36, bold: true, font: "Arial", color: "1B2A4A" },
        paragraph: { spacing: { before: 360, after: 200 }, outlineLevel: 0 } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 30, bold: true, font: "Arial", color: "2E75B6" },
        paragraph: { spacing: { before: 280, after: 160 }, outlineLevel: 1 } },
      { id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 26, bold: true, font: "Arial", color: "1B2A4A" },
        paragraph: { spacing: { before: 200, after: 120 }, outlineLevel: 2 } },
    ]
  },
  numbering: {
    config: [
      { reference: "bullets", levels: [{ level: 0, format: LevelFormat.BULLET, text: "\u2022", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
      { reference: "numbers", levels: [{ level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
      { reference: "bullets2", levels: [{ level: 0, format: LevelFormat.BULLET, text: "\u2022", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
      { reference: "bullets3", levels: [{ level: 0, format: LevelFormat.BULLET, text: "\u2022", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
      { reference: "bullets4", levels: [{ level: 0, format: LevelFormat.BULLET, text: "\u2022", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
      { reference: "bullets5", levels: [{ level: 0, format: LevelFormat.BULLET, text: "\u2022", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
      { reference: "bullets6", levels: [{ level: 0, format: LevelFormat.BULLET, text: "\u2022", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
      { reference: "bullets7", levels: [{ level: 0, format: LevelFormat.BULLET, text: "\u2022", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
      { reference: "bullets8", levels: [{ level: 0, format: LevelFormat.BULLET, text: "\u2022", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
      { reference: "bullets9", levels: [{ level: 0, format: LevelFormat.BULLET, text: "\u2022", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
      { reference: "bullets10", levels: [{ level: 0, format: LevelFormat.BULLET, text: "\u2022", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
    ]
  },
  sections: [{
    properties: {
      page: {
        size: { width: 12240, height: 15840 },
        margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 }
      }
    },
    headers: {
      default: new Header({ children: [new Paragraph({
        alignment: AlignmentType.RIGHT,
        children: [new TextRun({ text: "Synergy Testnet Control Panel \u2014 Issue Analysis Report", font: "Arial", size: 18, color: "888888", italics: true })]
      })] })
    },
    footers: {
      default: new Footer({ children: [new Paragraph({
        alignment: AlignmentType.CENTER,
        children: [new TextRun({ text: "Page ", font: "Arial", size: 18, color: "888888" }), new TextRun({ children: [PageNumber.CURRENT], font: "Arial", size: 18, color: "888888" })]
      })] })
    },
    children: [
      // TITLE PAGE
      new Paragraph({ spacing: { before: 2400 } }),
      new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 200 }, children: [new TextRun({ text: "SYNERGY TESTNET CONTROL PANEL", font: "Arial", size: 44, bold: true, color: "1B2A4A" })] }),
      new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 400 }, children: [new TextRun({ text: "Setup Issue Analysis & Root Cause Report", font: "Arial", size: 32, color: "2E75B6" })] }),
      new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 100 }, children: [new TextRun({ text: "March 8, 2026", font: "Arial", size: 24, color: "666666" })] }),
      new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 600 }, children: [new TextRun({ text: "Based on full codebase analysis of Electron app, Rust backend, shell scripts, and React frontend", font: "Arial", size: 20, color: "888888", italics: true })] }),
      
      // SEVERITY SUMMARY TABLE
      new Paragraph({ spacing: { before: 600, after: 200 }, children: [new TextRun({ text: "Issue Severity Summary", font: "Arial", size: 28, bold: true, color: "1B2A4A" })] }),
      new Table({
        width: { size: 9360, type: WidthType.DXA },
        columnWidths: [4000, 1200, 4160],
        rows: [
          new TableRow({ children: [headerCell("Issue", 4000), headerCell("Severity", 1200), headerCell("Root Cause Location", 4160)] }),
          new TableRow({ children: [cell("Chain reset doesn't fully erase data", 4000), severityCell("CRITICAL", 1200), cell("remote-node-orchestrator.sh: reset_chain()", 4160)] }),
          new TableRow({ children: [cell("Nodes report 'not running' while producing blocks", 4000), severityCell("CRITICAL", 1200), cell("testnet_agent_service.rs: PID file desynch", 4160)] }),
          new TableRow({ children: [cell("Explorer shows stale data after reset", 4000), severityCell("CRITICAL", 1200), cell("No explorer/indexer reset integration", 4160)] }),
          new TableRow({ children: [cell("Nodes auto-restart after chain reset", 4000), severityCell("CRITICAL", 1200), cell("remote-node-orchestrator.sh line 380", 4160)] }),
          new TableRow({ children: [cell("Nodes can't fully sync with bootnodes", 4000), severityCell("CRITICAL", 1200), cell("No bootnode readiness check before start", 4160)] }),
          new TableRow({ children: [cell("Global actions fail for some nodes", 4000), severityCell("HIGH", 1200), cell("monitor.rs: agent port 47990 not in firewall", 4160)] }),
          new TableRow({ children: [cell("Random peer counts across nodes", 4000), severityCell("HIGH", 1200), cell("network_discovery.rs: single-endpoint sampling", 4160)] }),
          new TableRow({ children: [cell("Port/firewall errors on Windows", 4000), severityCell("HIGH", 1200), cell("install_and_start.ps1: silent firewall failures", 4160)] }),
          new TableRow({ children: [cell("Pre-start sync silently fails", 4000), severityCell("MEDIUM", 1200), cell("install_and_start.sh: 12 retries then continues", 4160)] }),
          new TableRow({ children: [cell("Block height divergence (explorer vs indexer)", 4000), severityCell("MEDIUM", 1200), cell("Separate services, no sync guarantee", 4160)] }),
        ]
      }),

      new Paragraph({ children: [new PageBreak()] }),

      // ===== ISSUE 1: RESET CHAIN =====
      heading("Issue 1: Chain Reset Does Not Fully Erase Data", HeadingLevel.HEADING_1),
      para("When the \"Reset Chain\" action is triggered, chain data is not reliably erased across all nodes. Some nodes retain old blockchain state, and the reset appears to succeed even when files persist on disk."),

      heading("What Should Happen", HeadingLevel.HEADING_2),
      para("All nodes stop completely. All chain data (chain directory, chain.json, token_state.json, validator_registry.json) is fully erased. Explorer and indexer databases are cleared. Nodes display a \"ready\" status once stopped and wiped. Nodes do NOT auto-restart."),

      heading("What Actually Happens", HeadingLevel.HEADING_2),
      ...bulletList([
        "The rm -rf commands in remote-node-orchestrator.sh run without any verification that deletion actually succeeded.",
        "The shell command exit code (0) is the only success check \u2014 rm -rf can return 0 even when files persist due to permission errors or filesystem locks.",
        "Nodes auto-restart immediately after deletion (line 380: run_nodectl \"start\"), regardless of whether data was actually cleared.",
        "The explorer service has its own internal database that is never cleared \u2014 no integration exists to signal a reindex from genesis.",
        "Partial failures during bulk reset don't stop the operation \u2014 if node 5 fails to reset, node 6 still proceeds.",
      ], "bullets"),

      heading("Root Cause: No Deletion Verification", HeadingLevel.HEADING_3),
      para("In remote-node-orchestrator.sh, the reset_chain() function runs rm -rf on the data directories, then immediately restarts the node without checking whether files were actually removed. The Rust backend in monitor.rs only checks the shell exit code (exit_code == 0) to determine success."),

      heading("Root Cause: Unconditional Auto-Restart", HeadingLevel.HEADING_3),
      para("Line 380 of remote-node-orchestrator.sh calls run_nodectl \"start\" unconditionally after the reset. This means nodes always restart, even if the deletion failed. The user explicitly noted that nodes should NOT auto-restart after a chain reset \u2014 they should display a \"ready\" status."),

      heading("Root Cause: Explorer Not Integrated", HeadingLevel.HEADING_3),
      para("The explorer (testnet-explorer.synergy-network.io) and indexer are external services with their own databases. The reset_chain flow has zero integration with these services. There is no API call to trigger an explorer reindex, no cache clear, and no signal that the chain has been reset to genesis."),

      heading("Recommended Fixes", HeadingLevel.HEADING_2),
      ...bulletList([
        "Add post-deletion verification: after rm -rf, check that data/chain directory no longer exists. If it does, fail loudly with a non-zero exit code.",
        "Add filesystem sync (sync command) before proceeding to ensure deletions are flushed to disk.",
        "Remove the auto-restart from reset_chain(). The function should stop nodes, delete data, verify deletion, and report status as \"ready\" without restarting.",
        "Add an explorer/indexer reset API endpoint, or at minimum send a POST to the explorer service signaling a reindex from block 0.",
        "In monitor.rs, after a bulk reset, verify each node's block height is 0 before reporting success.",
      ], "bullets2"),

      new Paragraph({ children: [new PageBreak()] }),

      // ===== ISSUE 2: STATUS MISMATCH =====
      heading("Issue 2: Nodes Report \"Not Running\" While Producing Blocks", HeadingLevel.HEADING_1),
      para("The control panel shows certain nodes (specifically validator nodes like node-02, node-04, node-06) as \"not running\" or \"offline\" while those nodes are actively producing blocks on the network."),

      heading("Root Cause: PID File Desynchronization", HeadingLevel.HEADING_2),
      para("This bug is explicitly documented in the codebase at testnet_agent_service.rs lines 254-257. The comment reads: \"Always follow with force-kill to handle the case where the node was started outside nodectl (no PID file), leaving nodectl returning 'not running' while the process is still alive. This is the root cause of validator nodes (node-02, node-04, node-06) ignoring stop commands.\""),

      para("The nodectl status check relies entirely on PID files (data/node.pid or data/synergy-testnet.pid). If a node was started outside of nodectl, or if the PID file was deleted while the node was running, nodectl reports \"not running\" even though the process is alive and producing blocks."),

      heading("Root Cause: Status Detection Uses RPC Only", HeadingLevel.HEADING_2),
      para("The dashboard determines online/offline status by making RPC calls to each node (synergy_nodeInfo, synergy_getBlockNumber, etc.) with a 2-second timeout. If the RPC port is unreachable due to firewall rules, network latency, or port conflicts, the node shows as \"offline\" regardless of whether the process is actually running."),

      heading("Recommended Fixes", HeadingLevel.HEADING_2),
      ...bulletList([
        "Replace PID-file-based status detection with process enumeration. Use OS-level process queries (pgrep/Get-Process) that search for the synergy-testnet binary instead of checking PID files.",
        "Add a dual-status model in the UI: \"process_running\" (is the binary executing) vs \"online\" (is RPC responding). These are different states and should be displayed separately.",
        "Ensure all node startup paths create PID files consistently, whether started via nodectl, the installer, or manual commands.",
        "Increase the RPC probe timeout from 2 seconds to at least 5 seconds for nodes that may be under heavy load.",
      ], "bullets3"),

      new Paragraph({ children: [new PageBreak()] }),

      // ===== ISSUE 3: NODE SYNC =====
      heading("Issue 3: Nodes Cannot Fully Sync With Bootnodes", HeadingLevel.HEADING_1),
      para("Nodes trail behind bootnodes by several blocks and cannot catch up. Block heights are inconsistent across the network (e.g., explorer showing 3955 while indexer shows 178). Peer counts are random and unstable across nodes."),

      heading("Root Cause: No Bootnode Readiness Check", HeadingLevel.HEADING_2),
      para("The startup sequence in remote-node-orchestrator.sh starts dependent nodes immediately after issuing the bootnode start command. There is no health check or readiness gate to confirm that bootnodes (node-01, node-02) are fully running and accepting connections before starting the remaining 13 nodes. The pre-start sync attempts 12 retries with 5-second sleeps, but if bootnodes aren't ready within that 60-second window, the sync fails silently and the node starts anyway."),

      heading("Root Cause: Overlay Timing Race", HeadingLevel.HEADING_2),
      para("In the bootstrap_node operation, the legacy overlay-connect step is followed immediately by node start. Route propagation may not be complete, meaning the node binary tries to connect to bootnode addresses before the network path is fully established. This causes initial peer discovery to fail."),

      heading("Root Cause: Peer Count Inconsistency", HeadingLevel.HEADING_2),
      para("The network_discovery.rs module queries RPC endpoints sequentially and uses the first successful response to determine peer counts. Different RPC nodes have different connected peer sets, and the HashMap used for deduplication has non-deterministic iteration. This means each status refresh can show different peer counts depending on which endpoint responds first."),

      heading("Root Cause: Block Height Divergence", HeadingLevel.HEADING_2),
      para("The explorer and indexer are separate services pointing to different RPC endpoints. If the explorer RPC node is ahead at block 3955 while the indexer's RPC node is lagging at 178, the two services show wildly different numbers. There is no mechanism to ensure both services query the same canonical chain tip."),

      heading("Recommended Fixes", HeadingLevel.HEADING_2),
      ...bulletList([
        "Add an explicit bootnode readiness gate: after starting node-01 and node-02, poll their RPC endpoints until they return a valid block height and peer count before starting any other nodes.",
        "Add a network reachability check between bootstrap connectivity setup and node start: probe the bootnode addresses and verify they respond before proceeding.",
        "Implement peer count aggregation across all RPC endpoints with consensus (e.g., take the median peer count across all reachable nodes) instead of using the first response.",
        "Ensure both explorer and indexer point to the same authoritative RPC endpoint, or implement a fanout query that takes the highest confirmed block height across all nodes.",
        "Increase pre-start sync timeout from 60 seconds (12 x 5s) to at least 120 seconds, and fail hard for validator nodes if sync cannot be established.",
        "Add block-height convergence monitoring: after all nodes start, continuously check that all block heights are within 2-3 blocks of each other. Alert if any node falls more than 5 blocks behind.",
      ], "bullets4"),

      new Paragraph({ children: [new PageBreak()] }),

      // ===== ISSUE 4: GLOBAL ACTIONS =====
      heading("Issue 4: Global Actions Fail For Some Nodes", HeadingLevel.HEADING_1),
      para("The \"Start All\", \"Stop All\", and \"Reset Chain\" global actions in the dashboard do not work reliably across all 15 nodes. Some nodes don't respond to the commands while others execute successfully."),

      heading("Root Cause: Agent Port Not In Firewall Rules", HeadingLevel.HEADING_2),
      para("The testnet agent service listens on port 47990, but this port is NOT included in the firewall rules created by install_and_start.ps1. The installer only opens ports 9944-9948 (RPC, WS, gRPC, etc.). On Windows machines, the agent port is blocked by default, causing the agent HTTP request to fail. The system then falls back to SSH, which may also fail if SSH keys or credentials are misconfigured."),

      heading("Root Cause: Sequential Execution With No Parallelism", HeadingLevel.HEADING_2),
      para("In monitor.rs, bulk actions are executed sequentially in a for loop. Each node gets a 300-second (5-minute) timeout for operations like reset_chain. If one node hangs, the entire queue is blocked. With 15 nodes and a worst-case 5-minute timeout each, a full bulk operation could take over an hour if multiple nodes are unresponsive."),

      heading("Root Cause: Silent Failure Continuation", HeadingLevel.HEADING_2),
      para("When a node fails during a bulk operation, the error is captured but the loop continues without any rollback. The UI shows an aggregate success/failure count after completion, but there is no mechanism to retry failed nodes or alert the user to partial completion during the operation."),

      heading("Recommended Fixes", HeadingLevel.HEADING_2),
      ...bulletList([
        "Add port 47990 to the firewall rules in install_and_start.ps1 alongside the existing RPC/WS/gRPC ports.",
        "Implement parallel execution for bulk actions using tokio::join_all() instead of a sequential for loop. Group nodes by phase (bootnodes first, then validators, then others) but execute nodes within each phase in parallel.",
        "Add a per-node status callback during bulk operations so the UI can show real-time progress (e.g., \"Stopped 7/15 nodes, 2 failed\") instead of waiting for the entire operation to complete.",
        "Implement a retry mechanism: if a node fails, queue it for one automatic retry before marking it as failed.",
        "Add a pre-flight connectivity check before bulk operations: verify agent reachability on all nodes before starting the action, and warn the user about unreachable nodes.",
      ], "bullets5"),

      new Paragraph({ children: [new PageBreak()] }),

      // ===== ISSUE 5: PORT/FIREWALL =====
      heading("Issue 5: Port and Firewall Configuration Errors", HeadingLevel.HEADING_1),
      para("Windows nodes show firewall warnings about TCP ports 38649, 48649, 58649, 50062, 39649 not being opened automatically. The PowerShell installer requires Administrator privileges to create firewall rules, and fails silently when not run as Admin."),

      heading("Root Cause", HeadingLevel.HEADING_2),
      para("The Open-Ports function in install_and_start.ps1 checks for admin privileges with Test-Admin. If the user is not an administrator, it prints a warning message listing the ports but does not actually open them. The New-NetFirewallRule calls also have no error handling \u2014 if a rule creation fails (duplicate name, policy restriction, etc.), execution continues silently. Additionally, port 47990 for the agent service is entirely missing from the port list."),

      heading("Recommended Fixes", HeadingLevel.HEADING_2),
      ...bulletList([
        "Add port 47990 to the ports array in Open-Ports function.",
        "Add error handling around New-NetFirewallRule with try/catch blocks that log failures.",
        "On non-admin runs, provide a copy-pasteable PowerShell command that opens all required ports, so the user can run it in an elevated prompt.",
        "Consider using netsh advfirewall as a fallback method that works in some non-admin contexts.",
      ], "bullets6"),

      new Paragraph({ children: [new PageBreak()] }),

      // ===== PRIORITY ACTION PLAN =====
      heading("Priority Action Plan", HeadingLevel.HEADING_1),
      para("Based on the analysis, these are the recommended fix priorities ordered by impact on the immediate goal of getting nodes synced and the testnet operational."),

      heading("Phase 1: Immediate (Unblock Testnet)", HeadingLevel.HEADING_2),
      new Table({
        width: { size: 9360, type: WidthType.DXA },
        columnWidths: [500, 4860, 4000],
        rows: [
          new TableRow({ children: [headerCell("#", 500), headerCell("Action", 4860), headerCell("Files to Change", 4000)] }),
          new TableRow({ children: [cell("1", 500), cell("Remove auto-restart from reset_chain() \u2014 stop + erase + report ready only", 4860), cell("remote-node-orchestrator.sh", 4000)] }),
          new TableRow({ children: [cell("2", 500), cell("Add deletion verification (test -d after rm -rf) with hard failure on data persistence", 4860), cell("remote-node-orchestrator.sh", 4000)] }),
          new TableRow({ children: [cell("3", 500), cell("Replace PID-file status checks with process enumeration (pgrep synergy-testnet)", 4860), cell("testnet_agent_service.rs, nodectl.sh, install_and_start.ps1", 4000)] }),
          new TableRow({ children: [cell("4", 500), cell("Add bootnode readiness gate before starting dependent nodes", 4860), cell("remote-node-orchestrator.sh, reset-testnet.sh", 4000)] }),
          new TableRow({ children: [cell("5", 500), cell("Add port 47990 to firewall rules", 4860), cell("install_and_start.ps1", 4000)] }),
        ]
      }),

      heading("Phase 2: Stabilization (Reliable Sync)", HeadingLevel.HEADING_2),
      new Table({
        width: { size: 9360, type: WidthType.DXA },
        columnWidths: [500, 4860, 4000],
        rows: [
          new TableRow({ children: [headerCell("#", 500), headerCell("Action", 4860), headerCell("Files to Change", 4000)] }),
          new TableRow({ children: [cell("6", 500), cell("Add a network reachability check before node start (probe bootnode addresses)", 4860), cell("remote-node-orchestrator.sh", 4000)] }),
          new TableRow({ children: [cell("7", 500), cell("Implement peer count consensus (aggregate across all RPC endpoints, take median)", 4860), cell("network_discovery.rs", 4000)] }),
          new TableRow({ children: [cell("8", 500), cell("Add block-height convergence monitoring with alert if any node falls >5 blocks behind", 4860), cell("monitor.rs, monitoring.rs", 4000)] }),
          new TableRow({ children: [cell("9", 500), cell("Increase pre-start sync timeout to 120s+ and fail hard for validators", 4860), cell("install_and_start.sh", 4000)] }),
          new TableRow({ children: [cell("10", 500), cell("Add explorer/indexer reset integration (reindex-from-genesis API call)", 4860), cell("monitor.rs, new endpoint needed", 4000)] }),
        ]
      }),

      heading("Phase 3: Reliability (Production-Ready)", HeadingLevel.HEADING_2),
      new Table({
        width: { size: 9360, type: WidthType.DXA },
        columnWidths: [500, 4860, 4000],
        rows: [
          new TableRow({ children: [headerCell("#", 500), headerCell("Action", 4860), headerCell("Files to Change", 4000)] }),
          new TableRow({ children: [cell("11", 500), cell("Parallelize bulk actions with tokio::join_all() (grouped by phase)", 4860), cell("monitor.rs", 4000)] }),
          new TableRow({ children: [cell("12", 500), cell("Add real-time progress callbacks during bulk operations", 4860), cell("monitor.rs, NetworkMonitorDashboard.jsx", 4000)] }),
          new TableRow({ children: [cell("13", 500), cell("Implement pre-flight connectivity check before any global action", 4860), cell("monitor.rs", 4000)] }),
          new TableRow({ children: [cell("14", 500), cell("Add dual-status model in UI (process_running vs rpc_online)", 4860), cell("NetworkMonitorDashboard.jsx, monitor.rs", 4000)] }),
          new TableRow({ children: [cell("15", 500), cell("Add error handling to Windows firewall rule creation", 4860), cell("install_and_start.ps1", 4000)] }),
        ]
      }),

      new Paragraph({ spacing: { before: 400 }, children: [] }),
      new Paragraph({
        border: { top: { style: BorderStyle.SINGLE, size: 6, color: "2E75B6", space: 8 } },
        spacing: { before: 200 },
        children: [new TextRun({ text: "This report was generated from a full analysis of the Synergy Testnet Control Panel codebase including: control-service/src/monitor.rs (7400+ lines), testnet_agent_service.rs, remote-node-orchestrator.sh, reset-testnet.sh, render-configs.sh, network_discovery.rs, multi_node_process.rs, NetworkMonitorDashboard.jsx, and install_and_start.ps1.", font: "Arial", size: 18, color: "888888", italics: true })]
      }),
    ]
  }]
});

Packer.toBuffer(doc).then(buffer => {
  fs.writeFileSync("/sessions/great-elegant-volta/mnt/testnet-control-panel/Testnet-Control-Panel-Issue-Report.docx", buffer);
  console.log("Document created successfully");
});
