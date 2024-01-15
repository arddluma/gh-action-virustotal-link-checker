# gh-action-virustotal-link-checker
## GitHub action to check for Malicious URLs using VirusTotal API 


Get VirusTotal API KEY [here](https://support.virustotal.com/hc/en-us/articles/115002100149-API)

**Due to VirusTotal API personal limits, GH Action checks each url every 30 seconds**

*Idea: Thanks to [Eric Siu](https://github.com/randomishwalk) a.k.a randomishwalk [issue link](https://github.com/4337Mafia/awesome-account-abstraction/issues/187)*

Example:
```bash
name: Check Malicious Links

on:
  push:
    branches:
      - 'main'
  pull_request:
    branches:
      - 'main'

jobs:
  check-links:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Repo
        uses: actions/checkout@v4

      - name: Run VirusTotal Link Checker
        uses: arddluma/gh-action-virustotal-link-checker@v1.0.0
        with:
            virustotal-api-key: ${{ secrets.VIRUS_TOTAL_API_KEY }}
            filename: 'README.md'
            malicious_threshold: 1
            suspicious_threshold: 1