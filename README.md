# ThreatIntel-Dashboard

    A public GitHub Pages threat intelligence dashboard that collects and publishes:
    - Global security news
    - Indian national advisories
    - Exploits and vulnerability intelligence
    - OSINT sources
    - Red-team / offensive security research
    - A static cybersecurity advisory for awareness

    The pipeline runs every 3 hours through GitHub Actions, writes normalized JSON into `docs/data/latest.json`, and the public dashboard reads that file directly from GitHub Pages.

    ## What it does

    - Pulls feeds from multiple RSS/Atom sources
    - Filters items into:
      - last 3 hours
      - last 24 hours
    - Adds simple classification tags and risk scores
    - Generates a markdown digest
    - Optionally sends email alerts if SMTP secrets are configured
    - Publishes a public dashboard through GitHub Pages

    ## Repo structure

    ```text
    ThreatIntel-Dashboard/
    ├── .github/
    │   └── workflows/
    │       └── threatintel.yml
    ├── docs/
    │   ├── assets/
    │   │   └── styles.css
    │   ├── data/
    │   │   └── latest.json
    │   ├── advisory.html
    │   └── index.html
    ├── advisory.md
    ├── config.example.json
    ├── requirements.txt
    ├── threatintel_fetcher.py
    └── README.md
    ```

    ## Quick start

    1. Clone the repository.
    2. Install dependencies:
       ```bash
       pip install -r requirements.txt
       ```
    3. Run the fetcher:
       ```bash
       python threatintel_fetcher.py
       ```
    4. Open `docs/index.html` locally or enable GitHub Pages.

    ## GitHub Pages setup

    In the repository settings:
    - Go to **Pages**
    - Select **Deploy from a branch**
    - Branch: `main`
    - Folder: `/docs`

    ## GitHub Actions setup

    The workflow runs every 3 hours:
    - Fetches feeds
    - Updates `docs/data/latest.json`
    - Optionally sends email
    - Commits the refreshed data back to the repository

    ## Optional email alerting

    Configure these GitHub Secrets if you want email delivery:
    - `SMTP_HOST`
    - `SMTP_PORT`
    - `SMTP_USERNAME`
    - `SMTP_PASSWORD`
    - `SMTP_FROM`
    - `ALERT_EMAIL_TO`

    The script will send the digest only when these values are available.

    ## Customizing feeds

    Edit `config.example.json`, copy it to `config.json`, and add or remove sources as needed.

    ## Advisory

    The dashboard includes a static advisory section covering:
    - critical infrastructure risks
    - phishing and spear-phishing
    - ransomware and malware delivery
    - defacement and DDoS
    - unpatched vulnerabilities
    - disinformation and social engineering

    ## Notes

    This repository is designed for defensive monitoring, OSINT awareness, and SOC workflow support.
