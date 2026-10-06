"""UDS Test Copilot v2.  Run:  pip install -r requirements.txt  &&  streamlit run app.py
RAG: PDF/TXT -> chunks -> ChromaDB (first run downloads a small embedding model).
LLM backend (sidebar): None = offline templates, Ollama = local model, Anthropic API = hosted model.
The deterministic rule engine validates every test whichever backend is used."""
import json, os, uuid
import chromadb, pandas as pd, requests, streamlit as st
from pypdf import PdfReader

# ---------- Demo knowledge (replace by uploading real, authorized specs) ----------
SAMPLE = [(48, "DID 0xF190 (VIN) is 17 bytes. It can be read in sessions 0x01, 0x02 and 0x03."),
          (52, "Writing DID 0xF190 requires extended session 0x03 and an unlocked security level. Otherwise NRC 0x7F (wrong session) or NRC 0x33 (security denied)."),
          (50, "DID 0xF186 returns the active diagnostic session as 1 byte. It is read-only; writes return NRC 0x31."),
          (12, "Positive response SID = request SID + 0x40. Negative response format is 7F SID NRC. A wrong request length returns NRC 0x13.")]
DIDS = {0xF190: dict(name="VIN", length=17, write=[3], sec=True), 0xF186: dict(name="ActiveSession", length=1, write=[], sec=False)}
SVC = {0x10: dict(n="DiagnosticSessionControl", nrc=[0x12, 0x13, 0x22], sub=[1, 2, 3]),
       0x22: dict(n="ReadDataByIdentifier", nrc=[0x13, 0x31, 0x33]),
       0x27: dict(n="SecurityAccess", nrc=[0x12, 0x13, 0x24, 0x35, 0x36, 0x37]),
       0x2E: dict(n="WriteDataByIdentifier", nrc=[0x13, 0x31, 0x33, 0x7F]),
       0x31: dict(n="RoutineControl", nrc=[0x12, 0x13, 0x31, 0x33, 0x7F], sub=[1, 2, 3])}
def hx(s): return bytes.fromhex(s.replace(" ", ""))
def fmt(b): return " ".join(f"{x:02X}" for x in b)

# ---------- Deterministic rule engine (state-aware) ----------
def validate(req_s, resp_s, session=None, unlocked=None):
    try: req, resp = hx(req_s), hx(resp_s)
    except ValueError: return ["Not valid hex"]
    if not req or not resp: return ["Empty message"]
    sid, out = req[0], []
    if sid not in SVC: return [f"Service 0x{sid:02X} not in rule set"]
    nrc = resp[2] if resp[0] == 0x7F and len(resp) == 3 else None
    bad_len = (sid == 0x22 and (len(req) < 3 or (len(req) - 1) % 2)) or (sid in (0x10, 0x27, 0x31) and len(req) < 2)
    bad_sub = "sub" in SVC[sid] and len(req) > 1 and (req[1] & 0x7F) not in SVC[sid]["sub"]
    did = (req[1] << 8 | req[2]) if sid in (0x22, 0x2E) and len(req) >= 3 else None
    if sid == 0x2E and did in DIDS and len(req) - 3 != DIDS[did]["length"]: bad_len = True
    if bad_len and nrc != 0x13: out.append("Length is invalid; expected NRC 0x13")
    if bad_sub and not bad_len and nrc != 0x12: out.append("Unsupported subfunction; expected NRC 0x12")
    if resp[0] == 0x7F:
        if len(resp) != 3: out.append("Negative response must be 3 bytes")
        elif resp[1] != sid: out.append("Negative response echoes wrong SID")
        elif nrc not in SVC[sid]["nrc"]: out.append(f"NRC 0x{nrc:02X} not allowed for 0x{sid:02X}")
    elif resp[0] != sid + 0x40: out.append(f"Positive SID should be 0x{sid + 0x40:02X}")
    elif sid == 0x2E and did in DIDS and not bad_len and session is not None:
        if session not in DIDS[did]["write"]: out.append("Positive response, but spec says NRC 0x7F/0x31 here")
        elif DIDS[did]["sec"] and not unlocked: out.append("Positive response, but security is locked: expected NRC 0x33")
    return out

def offline_tests(did):
    d, hi, lo, data = DIDS[did], did >> 8, did & 255, list(range(DIDS[did]["length"]))
    t = [("Read OK", 1, False, [0x22, hi, lo], [0x62, hi, lo, *data]), ("Read, wrong length", 1, False, [0x22, hi], [0x7F, 0x22, 0x13]),
         ("Read, unknown DID", 1, False, [0x22, 0xF1, 0xFF], [0x7F, 0x22, 0x31])]
    if d["write"]:
        t += [("Write OK", 3, True, [0x2E, hi, lo, *data], [0x6E, hi, lo]), ("Write, wrong session", 1, False, [0x2E, hi, lo, *data], [0x7F, 0x2E, 0x7F]),
              ("Write, security locked", 3, False, [0x2E, hi, lo, *data], [0x7F, 0x2E, 0x33]), ("Write, wrong length", 3, True, [0x2E, hi, lo, 0], [0x7F, 0x2E, 0x13])]
    else: t.append(("Write to read-only DID", 3, True, [0x2E, hi, lo, *data], [0x7F, 0x2E, 0x31]))
    return [dict(title=a, session=b, unlocked=c, send=fmt(bytes(d1)), expect=fmt(bytes(e))) for a, b, c, d1, e in t]

# ---------- RAG ----------
def col():
    if "col" not in st.session_state:
        st.session_state.col = chromadb.EphemeralClient().get_or_create_collection("spec" + uuid.uuid4().hex[:8])
    return st.session_state.col

def ingest(pages, src):
    docs, metas, ids = [], [], []
    for p, text in pages:
        for i in range(0, max(len(text), 1), 800):
            if text[i:i + 800].strip():
                docs.append(text[i:i + 800]); metas.append({"src": src, "page": p}); ids.append(f"{src}-{p}-{i}")
    if docs: col().upsert(documents=docs, metadatas=metas, ids=ids)
    return len(docs)

def retrieve(q, k=4):
    c = col()
    if c.count() == 0: return []
    r = c.query(query_texts=[q], n_results=min(k, c.count()))
    return list(zip(r["documents"][0], r["metadatas"][0]))

# ---------- Pluggable LLM ----------
def llm(prompt, system):
    be, model = st.session_state.be, st.session_state.model
    try:
        if be == "Ollama (local)":
            r = requests.post(st.session_state.url + "/api/chat", timeout=300, json={"model": model, "stream": False,
                              "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}]})
            return r.json()["message"]["content"]
        if be == "Anthropic API":
            r = requests.post("https://api.anthropic.com/v1/messages", timeout=120, headers={"x-api-key": st.session_state.key,
                              "anthropic-version": "2023-06-01"}, json={"model": model, "max_tokens": 2000, "system": system,
                              "messages": [{"role": "user", "content": prompt}]})
            return r.json()["content"][0]["text"]
    except Exception as e:
        st.error(f"LLM call failed: {e}")
    return None

def ctx(hits): return "\n".join(f"[{m['src']} p.{m['page']}] {d}" for d, m in hits)

# ---------- Exports ----------
def to_py(df):
    o = ["# UDS Test Copilot export (approved tests only)", "def run(send):  # send(bytes)->bytes"]
    for r in df.itertuples():
        o += [f"    # {r.ID}: {r.Title} [session 0x{r.Session:02X}, unlocked={r.Unlocked}]",
              f"    assert send(bytes.fromhex('{r.Send}')) == bytes.fromhex('{r.Expect}'), '{r.ID}'"]
    return "\n".join(o)

def to_capl(df):
    o = ["/* UDS Test Copilot CAPL template: adapt send/receive calls to your CANoe diagnostic description */"]
    for r in df.itertuples():
        b = ", ".join("0x" + x for x in r.Send.split())
        o += [f"testcase {r.ID}()  // {r.Title}", "{", f"  byte req[] = {{ {b} }};",
              f"  // precondition: session 0x{r.Session:02X}, security unlocked = {r.Unlocked}",
              f"  // TODO: send req, then expect: {r.Expect}", "}", ""]
    return "\n".join(o)

# ---------- UI ----------
st.set_page_config(page_title="UDS Test Copilot v2", layout="wide")
with st.sidebar:
    st.header("Settings")
    st.session_state.be = st.selectbox("LLM backend", ["None (offline)", "Ollama (local)", "Anthropic API"])
    st.session_state.model = st.text_input("Model", {"Ollama (local)": "llama3.1", "Anthropic API": "claude-sonnet-5-5"}.get(st.session_state.be, ""))
    st.session_state.url = st.text_input("Ollama URL", "http://localhost:11434")
    st.session_state.key = st.text_input("Anthropic API key", os.getenv("ANTHROPIC_API_KEY", ""), type="password")
    st.metric("Indexed chunks", col().count())
st.title("UDS Test Copilot v2")
st.caption("Every answer is cited and every test is rule-checked. Nothing runs on a vehicle; engineers approve before export.")
t1, t2, t3 = st.tabs(["1. Knowledge base and Q&A", "2. Requirement to tests", "3. Validate a message"])

with t1:
    up = st.file_uploader("Upload an authorized spec (PDF or TXT)", type=["pdf", "txt"])
    c1, c2 = st.columns(2)
    if up and c1.button("Index file"):
        pages = [(i + 1, p.extract_text() or "") for i, p in enumerate(PdfReader(up).pages)] if up.name.endswith(".pdf") else [(1, up.read().decode("utf-8", "ignore"))]
        st.success(f"Indexed {ingest(pages, up.name)} chunks")
    if c2.button("Load sample spec"):
        st.success(f"Indexed {ingest(SAMPLE, 'Demo_OEM_Spec')} chunks")
    q = st.text_input("Ask a question", "What are the prerequisites for writing DID 0xF190?")
    if st.button("Ask"):
        hits = retrieve(q)
        if not hits: st.warning("Index a document first.")
        else:
            ans = llm(f"Question: {q}\n\nEvidence:\n{ctx(hits)}", "Answer only from the evidence and cite sources like [file p.N]. If the answer is not in the evidence, say 'not found in spec'.")
            st.markdown(ans or "**Offline mode: top evidence chunks**")
            with st.expander("Evidence used", expanded=ans is None):
                for d, m in hits: st.markdown(f"**{m['src']} p.{m['page']}**: {d}")

with t2:
    req = st.text_area("Diagnostic requirement", "The ECU shall only allow writing the VIN (DID 0xF190) in the extended session after security unlock.")
    did = st.selectbox("DID (offline mode)", list(DIDS), format_func=lambda x: f"0x{x:04X} {DIDS[x]['name']}") if st.session_state.be.startswith("None") else None
    if st.button("Generate tests"):
        hits, items = retrieve(req), None
        if did is not None: items = offline_tests(did)
        else:
            out = llm(f"Requirement: {req}\n\nEvidence:\n{ctx(hits)}\n\nReturn ONLY a JSON list of positive and negative UDS tests, each with keys title, session (int), unlocked (bool), send (hex string), expect (hex string).",
                      "You are a UDS test engineer. Use only the evidence. Output JSON only.")
            try: items = json.loads(out[out.index("["): out.rindex("]") + 1]) if out else None
            except ValueError: st.error("Model did not return valid JSON; try again.")
        if items:
            ev = ", ".join(sorted({f"{m['src']} p.{m['page']}" for _, m in hits})) or "offline template"
            st.session_state.tests = pd.DataFrame([{"ID": f"TC_{i:02d}", "Title": t["title"], "Session": int(t["session"]), "Unlocked": bool(t["unlocked"]),
                "Send": t["send"], "Expect": t["expect"], "Rules": "PASS" if not validate(t["send"], t["expect"], int(t["session"]), bool(t["unlocked"])) else "FAIL",
                "Evidence": ev, "Decision": "PENDING"} for i, t in enumerate(items, 1)])
    if "tests" in st.session_state:
        ed = st.data_editor(st.session_state.tests, hide_index=True, use_container_width=True, key="ed",
                            disabled=[c for c in st.session_state.tests.columns if c != "Decision"],
                            column_config={"Decision": st.column_config.SelectboxColumn(options=["PENDING", "APPROVED", "REJECTED"])})
        ok = ed[ed["Decision"] == "APPROVED"]
        st.write(f"{len(ok)} approved, rule failures: {(ed['Rules'] == 'FAIL').sum()}")
        if len(ok):
            st.download_button("Export Python", to_py(ok), "uds_tests.py")
            st.download_button("Export CAPL template", to_capl(ok), "uds_tests.can")
        else: st.info("Approve tests in the Decision column to enable export.")

with t3:
    a, b = st.columns(2)
    rq, rs = a.text_input("Request (hex)", "2E F1 90 00"), b.text_input("Response (hex)", "6E F1 90")
    s = a.selectbox("Session", [1, 2, 3], index=0, format_func=lambda x: f"0x{x:02X}")
    u = b.checkbox("Security unlocked")
    if st.button("Validate"):
        res = validate(rq, rs, s, u)
        for r in res: st.error(r)
        if not res: st.success("Valid against the rule set and the given state")