# UDS-Test-Copilot-demo-and-proposal  https://uds-test-copilot-demo-and-proposal.streamlit.app/
# UDS Test Copilot

A local, citation-grounded assistant that turns diagnostic requirements into validated, executable UDS test cases.

This repository contains a **working prototype** and the **project proposal** for *Case Study 5: UDS Diagnostics and Automated Test Generation* from the Automotive Engineering AI case study document.

## The idea

UDS test design is slow and inconsistent. Engineers read ISO 14229 together with OEM and ECU specifications, build request messages by hand, work out session and security prerequisites, and then write automation scripts.

UDS Test Copilot splits the work in two:

- **The language model drafts and explains.** It retrieves evidence from approved specifications and proposes test cases.
- **A deterministic rule engine decides what is protocol-correct.** Every request and expected response is validated in plain Python, with no LLM involved.

An engineer reviews every test before anything is exported.

## Features

- **Knowledge base and Q&A:** upload a PDF or TXT specification, index it in ChromaDB, and ask questions. Answers cite the source file and page.
- **Requirement to tests:** paste a requirement and get positive and negative test cases with preconditions, request bytes and expected responses.
- **Rule engine:** checks positive-response SIDs (request SID + 0x40), negative-response format (`7F SID NRC`), message length, subfunction validity, NRCs allowed per service, and session and security state. Covers services 0x10, 0x22, 0x27, 0x2E and 0x31.
- **Human review:** each test has a Decision column (PENDING, APPROVED, REJECTED). Only approved tests can be exported.
- **Export:** Python script and CAPL template.
- **Switchable LLM backend:** offline templates, a local model through Ollama, or the Anthropic API.

## How it works

```
Spec (PDF/TXT) -> chunks -> ChromaDB
                                |
Requirement ----> retrieve evidence ----> LLM drafts tests (JSON)
                                              |
                              Rule engine validates every test
                                              |
                      Engineer approves -> export Python / CAPL
```

## Quick start

Requires Python 3.10 or newer.

```bash
pip install -r requirements.txt
streamlit run app.py
```

The first run downloads a small embedding model for ChromaDB, so an internet connection is needed once.

### Choosing a backend (sidebar)

| Backend | Setup |
|---|---|
| None (offline) | Nothing to set up. Uses built-in test templates and shows the top evidence chunks instead of a written answer. |
| Ollama (local) | Install [Ollama](https://ollama.com), run `ollama pull llama3.1`, keep it running, and set the model name in the sidebar. Data stays on your machine. |
| Anthropic API | Set your key as an environment variable, or paste it in the sidebar. PowerShell: `$env:ANTHROPIC_API_KEY="your-key"` |

Never commit an API key to the repository.

## Suggested demo walkthrough

1. Click **Load sample spec** and ask: *What are the prerequisites for writing DID 0xF190?*
2. Open **Requirement to tests** and generate tests.
3. Approve a few in the Decision column and export the Python or CAPL file.
4. Open **Validate a message** and try request `2E F1 90 00` with response `6E F1 90` in session 0x01. The rule engine flags it.

## Repository contents

| File | Purpose |
|---|---|
| `app.py` | Streamlit application: RAG, LLM backends, rule engine, review and export |
| `requirements.txt` | Python dependencies |
| `docs/UDS_Test_Copilot_Proposal.docx` | Project proposal (problem, solution, architecture, risks, roadmap) |

## Limitations

This is a prototype, not a production tool.

- The sample knowledge base is **made up** for demonstration. Use only specifications you are authorized to use.
- The rule engine's DID and service tables are **hard-coded** in `app.py`. They are not yet extracted from uploaded specifications.
- Small local models may return invalid JSON. The app reports an error and you can retry.
- The CAPL output is a template. Adapt the send and receive calls to your CANoe diagnostic description.
- There is no user login, project isolation, audit log or saved history.
- Generated tests must never be run on a production vehicle without controls. Use approved bench or HIL environments.

## Roadmap

1. Extract services, DIDs, RIDs and NRCs from uploaded specifications to drive the rule engine.
2. Add coverage reporting (service x session x security x NRC).
3. Add an audit log of approvals.
4. Add project isolation, role-based access and a PostgreSQL backend.
5. Integrate with test toolchains.

## Governance

AI-generated content must be traceable to approved source material and reviewed by authorized engineering specialists before it is used for validation or release.

## License

Add a license of your choice before sharing publicly.
