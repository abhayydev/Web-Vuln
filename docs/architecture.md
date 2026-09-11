# WebVuln Scanner — Architecture & System Design

```mermaid
graph TD
    A[Target Input] --> B[Target Validation & Scope Engine]
    B --> C[Asynchronous HTTP Engine]
    C --> D[Passive Reconnaissance]
    C --> E[BFS Web Crawler]
    
    D --> D1[Server & Framework Fingerprinting]
    D --> D2[Robots.txt & Sitemap Parsers]
    
    E --> E1[HTML Link & Script Extractor]
    E --> E2[Form & Parameter Parser]
    
    E1 --> F[Discovered Attack Surface]
    E2 --> F
    
    F --> G[Modular Vulnerability Scanners]
    
    G --> H1[Security Headers Scanner]
    G --> H2[Cookie & Session Scanner]
    G --> H3[CORS Policy Scanner]
    G --> H4[TLS/SSL Configuration Scanner]
    G --> H5[Contextual Reflection Scanner]
    G --> H6[SQL Syntax Error Scanner]
    G --> H7[Path Traversal Parameter Scanner]
    G --> H8[Open Redirect Scanner]
    G --> H9[API & OpenAPI Scanner]
    G --> H10[Auth & Object Identifier Scanner]
    
    H1 --> I[Risk & Correlation Engine]
    H2 --> I
    H3 --> I
    H4 --> I
    H5 --> I
    H6 --> I
    H7 --> I
    H8 --> I
    H9 --> I
    H10 --> I
    
    I --> J1[Terminal Rich Dashboard]
    I --> J2[Executive HTML Report]
    I --> J3[Machine-Readable JSON]
```

## Modular Layers

1. **Target Validation Layer (`webvuln.core.target`)**: Strict URL normalization, protocol verification (`http`/`https`), and domain boundary enforcement.
2. **Asynchronous Transport Layer (`webvuln.core.context`)**: Connection pooling, concurrency semaphores, rate limiting, and memory-safe 2MB body buffering.
3. **Discovery Layer (`webvuln.discovery`)**: BFS crawling, deduplication hashing, parameter extraction, and passive robots/sitemap parsing.
4. **Vulnerability Assessment Layer (`webvuln.scanners`)**: 10 independent active/passive security audit modules adhering to [`BaseScanner`](file:///C:/Users/ACER/.gemini/antigravity/scratch/webvuln-scanner/webvuln/core/scanner.py).
5. **Risk Engine Layer (`webvuln.core.risk`)**: Multi-factor scoring combining severity weights and confidence multipliers, with finding deduplication.
6. **Reporting Layer (`webvuln.reporting`)**: Rich terminal summary UI, structured JSON data, and Jinja2-rendered HTML executive reports.
