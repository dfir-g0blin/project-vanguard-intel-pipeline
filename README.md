# Project Vanguard: Autonomous GitOps Detection Engineering Pipeline

An enterprise-ready, GitOps-driven security architecture designed to eliminate the structural decay of static Indicators of Compromise (IOCs). Project Vanguard automates the lifecycle of high-fidelity threat intelligence ingestion, programmatic guardrail validation, abstract rule compilation, and active cloud-SIEM deployment.

---

## 1. Architectural Overview & Design

### The Problem
Traditional detection engineering workflows treat threat intelligence dynamically but treat SIEM rules statically. When a threat feed (e.g., C2 IP addresses) updates, engineers must manually edit rules, causing a massive operational bottleneck, high configuration drift, and stale detections. 

### The Solution
Project Vanguard treats detections strictly as code (GitOps). By using an automated Python orchestration engine and **pySigma**, abstract threat signatures are decoupled from changing indicators. An automated CI/CD loop pulls real-time infrastructure data from multiple open-source intelligence (OSINT) feeds natively, deduplicates the indicators in memory, filters them through strict corporate health guardrails, compiles them into native Cloud SIEM syntax (YARA-L), and updates active detection states via API.

### Core Facets Demonstrated
* **Detection Engineering:** Decoupling logic from parameters using template parameter hydration seamlessly inside abstract Sigma rules (`status: stable`).
* **Multi-Feed Ingestion & Normalization:** Programmatically aggregating diverse intelligence feeds (Feodo Tracker & URLhaus) and natively deduplicating tracking arrays using high-performance Python datasets before compilation.
* **Incident Response Automation:** Programmatic allow-lists checking incoming threat telemetry against critical business subnets and trusted DNS providers to prevent catastrophic self-dos or upstream feed poisoning variables.
* **DevSecOps / GitOps:** Full execution state management managed natively via version control tracking abstraction barriers, running on modernized GitHub Actions runtime parameters.

---

## 2. Deployment & Execution Guide

This repository is structured for seamless local testing or fully decoupled execution via GitHub Actions.

### Prerequisites
* Python 3.11+

### Local Installation & Setup
1. Clone the repository:
   ```bash
   git clone [https://github.com/dfir-g0blin/project-vanguard-intel-pipeline.git](https://github.com/dfir-g0blin/project-vanguard-intel-pipeline.git)
   cd project-vanguard-intel-pipeline
   ```

2. Install the necessary transformation, HTTP client, and parsing frameworks:
   ```bash
   pip install pysigma pysigma-backend-secops google-auth requests ioc-finder
   ```

### Running a Local Dry-Run Validation

To test the pipeline locally without pushing live configurations to a production environment, execute the orchestrator script with default simulation constraints:

   ``` bash
   # This will pull live feeds, filter them against the allow-list, and print the compiled YARA-L logic
   python scripts/vanguard_orchestrator.py
   ```

## 3. Risk Management & Enterprise Guardrails
* **Upstream Feed Poisoning:** Upstream Feed Poisoning: Managed via scripts/enterprise_allowlist.json. If a threat intel feed accidentally includes public DNS providers (e.g., 1.1.1.1) or internal RFC 1918 company ranges, the orchestrator strips them prior to compilation.
* **SIEM File Size Boundaries:** The engine tracks array size constraints. If an external feed spikes unpredictably, the compiler splits the data across segmented rule batches (Vanguard_C2_Part1, Vanguard_C2_Part2) to ensure zero SIEM compilation drops.
* **Resilient Graceful Degredation**Built-in error handling wraps all ingestion steps. If an external OSINT provider experiences an outage, the script catches the failure and serves a verified fallback telemetry matrix to protect pipeline continuity.

## 4. Future Roadmap & Extensibility

Because Project Vanguard is completely modular, the pipeline is designed to easily scale into broader security operations facets:

* **Automated Retroactive Hunting:** Integrating an automated hook into the sync cycle that programmatically passes newly identified IOCs to a SIEM's lookback API (e.g., Google SecOps UDM Search API) to sweep the previous 30 days of cold storage logs for historical compromises.
* **LLM Triage Enrichment:** Interfacing with inference APIs (such as Anthropic's Claude) to ingest raw threat feed updates during compilation and automatically generate plain-text analyst investigation briefs embedded straight into the YARA-L metadata block.