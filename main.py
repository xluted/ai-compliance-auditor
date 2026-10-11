from fastapi import FastAPI, UploadFile, File, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from langchain_community.document_loaders import PyMuPDFLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import FAISS
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_community.llms import Ollama
import os
import subprocess
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from concurrent.futures import ThreadPoolExecutor
import winrm

from database import get_db, User, AuditLog
from auth import verify_password, get_password_hash, create_access_token, get_current_user

app = FastAPI(title="AI Compliance Auditor API")

vector_store = None

class QueryRequest(BaseModel):
    query: str

class MultiHostScanRequest(BaseModel):
    hosts: list[str]
    username: str
    password: str

def get_windows_config_state():
    ps_script = """
    $config = @{}
    $netAccounts = net accounts
    $config['MinPasswordLength'] = ($netAccounts | Select-String "Length of password") -replace '.*:\\s*', ''
    $config['LockoutThreshold'] = ($netAccounts | Select-String "Lockout threshold") -replace '.*:\\s*', ''
    $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
    $config['AntivirusEnabled'] = $defender.AntivirusEnabled
    $config['RealTimeProtectionEnabled'] = $defender.RealTimeProtectionEnabled
    $smb = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
    $config['EnableSMB1Protocol'] = $smb.EnableSMB1Protocol
    $config | ConvertTo-Json
    """
    process = subprocess.run(["powershell", "-Command", ps_script], capture_output=True, text=True)
    return process.stdout.strip()

def run_remote_winrm_audit(host: str, user: str, pass_word: str) -> dict:
    ps_script = """
    $config = @{}
    $netAccounts = net accounts
    $config['MinPasswordLength'] = ($netAccounts | Select-String "Length of password") -replace '.*:\\s*', ''
    $config['LockoutThreshold'] = ($netAccounts | Select-String "Lockout threshold") -replace '.*:\\s*', ''
    $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
    $config['AntivirusEnabled'] = $defender.AntivirusEnabled
    $config['RealTimeProtectionEnabled'] = $defender.RealTimeProtectionEnabled
    $smb = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
    $config['EnableSMB1Protocol'] = $smb.EnableSMB1Protocol
    $config | ConvertTo-Json
    """
    try:
        session = winrm.Session(f"http://{host}:5985/wsman", auth=(user, pass_word), transport='ntlm')
        result = session.run_ps(ps_script)
        if result.status_code == 0:
            return {"host": host, "status": "Success", "config": result.std_out.decode('utf-8').strip()}
        else:
            return {"host": host, "status": "Failed", "error": result.std_err.decode('utf-8').strip()}
    except Exception as e:
        return {"host": host, "status": "Error", "error": str(e)}

@app.post("/register")
def register_user(username: str, password: str, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = get_password_hash(password)
    new_user = User(username=username, hashed_password=hashed_password, role="admin")
    db.add(new_user)
    db.commit()
    return {"message": "User registered successfully"}

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/ingest")
async def ingest_document(file: UploadFile = File(...)):
    global vector_store
    file_path = f"temp_{file.filename}"
    with open(file_path, "wb") as buffer:
        buffer.write(await file.read())
    loader = PyMuPDFLoader(file_path)
    docs = loader.load()
    text_splitter = RecursiveCharacterTextSplitter(chunk_size=2000, chunk_overlap=250)
    chunks = text_splitter.split_documents(docs)
    embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2") 
    if vector_store is None:
        vector_store = FAISS.from_documents(chunks, embeddings)
    else:
        vector_store.add_documents(chunks)
    os.remove(file_path)
    return {"status": "success", "message": f"Ingested {len(chunks)} chunks from {file.filename}."}

@app.post("/evaluate")
async def evaluate_compliance(request: QueryRequest):
    if vector_store is None:
        return {"error": "No framework loaded. Please upload a PDF first."}
    retriever = vector_store.as_retriever(search_kwargs={"k": 3})
    relevant_docs = retriever.invoke(request.query)
    context = "\n\n".join([doc.page_content for doc in relevant_docs])
    llm = Ollama(model="llama3")
    prompt = f"Using ONLY the following compliance guidelines:\n{context}\n\nEvaluate this scenario: {request.query}"
    response = llm.invoke(prompt)
    return {"assessment": response, "rules_referenced": len(relevant_docs)}

@app.get("/analyze-system-audit")
async def analyze_system_audit():
    try:
        ps_cmd = 'Get-WinEvent -LogName Security -MaxEvents 50 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, Message | ConvertTo-Json'
        process = subprocess.run(["powershell", "-Command", ps_cmd], capture_output=True, text=True)
        raw_logs = process.stdout.strip()
        if not raw_logs:
            ps_cmd_fallback = 'Get-EventLog -LogName Security -Newest 50 -ErrorAction SilentlyContinue | Select-Object TimeGenerated, EventID, Message | ConvertTo-Json'
            process_fallback = subprocess.run(["powershell", "-Command", ps_cmd_fallback], capture_output=True, text=True)
            raw_logs = process_fallback.stdout.strip()
        if not raw_logs:
            return {"raw_logs": "No security log entries retrieved from PowerShell.", "plain_english_summary": "Unable to pull live system logs."}
        llm = Ollama(model="llama3")
        translation_prompt = f"Translate these raw event logs into a clean, simple, bulleted summary for non-technical stakeholders:\n\n{raw_logs[:4000]}"
        try:
            plain_english_summary = llm.invoke(translation_prompt)
        except Exception as e:
            plain_english_summary = f"Llama 3 failed: {str(e)}"
        return {"raw_logs": raw_logs, "plain_english_summary": plain_english_summary}
    except Exception as general_error:
        return {"raw_logs": f"System error executing audit: {str(general_error)}", "plain_english_summary": "An error occurred."}

@app.get("/audit-host-configuration")
async def audit_host_configuration(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if vector_store is None:
        return {"error": "No baseline framework loaded. Please upload a STIG or policy PDF first."}
    host_config = get_windows_config_state()
    retriever = vector_store.as_retriever(search_kwargs={"k": 5})
    relevant_docs = retriever.invoke("Password length, account lockout threshold, antivirus status, SMB protocol requirements")
    compliance_rules = "\n\n".join([doc.page_content for doc in relevant_docs])
    llm = Ollama(model="llama3")
    audit_prompt = f"Compare ACTUAL HOST CONFIGURATION VALUES against DOCUMENTED COMPLIANCE RULES.\nRULES:\n{compliance_rules}\nHOST CONFIG:\n{host_config}\nOutput status label [COMPLIANT] or [NON-COMPLIANT] with a 1-sentence remediation."
    assessment = llm.invoke(audit_prompt)
    new_log = AuditLog(user_id=current_user.id, target_system="localhost", assessment_type="Active Host Configuration Scan", report_data=assessment)
    db.add(new_log)
    db.commit()
    return {"host_configuration": host_config, "compliance_audit_report": assessment}

@app.post("/audit-multi-host")
async def audit_multi_host(scan_request: MultiHostScanRequest, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if vector_store is None:
        return {"error": "No baseline framework loaded. Please upload a STIG or policy PDF first."}
    retriever = vector_store.as_retriever(search_kwargs={"k": 5})
    relevant_docs = retriever.invoke("Password length, account lockout threshold, antivirus status, SMB protocol requirements")
    compliance_rules = "\n\n".join([doc.page_content for doc in relevant_docs])
    llm = Ollama(model="llama3")
    scan_results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(run_remote_winrm_audit, host, scan_request.username, scan_request.password) for host in scan_request.hosts]
        for future in futures:
            scan_results.append(future.result())
    final_reports = []
    for res in scan_results:
        host_ip = res["host"]
        if res["status"] == "Success":
            host_config = res["config"]
            audit_prompt = f"Compare ACTUAL HOST CONFIGURATION VALUES against DOCUMENTED COMPLIANCE RULES.\nRULES:\n{compliance_rules}\nHOST CONFIG:\n{host_config}\nOutput status label [COMPLIANT] or [NON-COMPLIANT] with 1-sentence remediations."
            assessment = llm.invoke(audit_prompt)
            log_entry = AuditLog(user_id=current_user.id, target_system=host_ip, assessment_type="Multi-Host WinRM Scan", report_data=assessment)
            db.add(log_entry)
            final_reports.append({"host": host_ip, "status": "COMPLETED", "report": assessment})
        else:
            final_reports.append({"host": host_ip, "status": "FAILED", "error": res.get("error", "Unknown error")})
    db.commit()
    return {"results": final_reports}

@app.post("/parse-ckl")
async def parse_ckl_file(file: UploadFile = File(...)):
    try:
        content = await file.read()
        filename = file.filename.lower()
        open_findings = []
        if filename.endswith(".cklb"):
            data = json.loads(content.decode("utf-8"))
            for stig in data.get("stigs", []):
                for rule in stig.get("rules", []):
                    if rule.get("status") == "Open":
                        vuln_id = rule.get("vuln_id") or rule.get("id")
                        if vuln_id:
                            open_findings.append(vuln_id)
        else:
            root = ET.fromstring(content)
            for vuln in root.findall('.//VULN'):
                status = vuln.find('STATUS')
                if status is not None and status.text == "Open":
                    for stig_data in vuln.findall('.//STIG_DATA'):
                        attr = stig_data.find('VULN_ATTRIBUTE')
                        if attr is not None and attr.text == "Vuln_Num":
                            data_elem = stig_data.find('ATTRIBUTE_DATA')
                            if data_elem is not None:
                                open_findings.append(data_elem.text)
        if not open_findings:
            return {"status": "success", "message": "No open findings detected.", "open_vulnerabilities": []}
        return {"status": "success", "message": f"Found {len(open_findings)} open vulnerabilities.", "open_vulnerabilities": open_findings}
    except Exception as e:
        return {"error": f"Failed to parse checklist file: {str(e)}"}

@app.post("/parse-nessus")
async def parse_nessus_file(file: UploadFile = File(...)):
    try:
        content = await file.read()
        root = ET.fromstring(content)
        high_critical_findings = []
        for report_host in root.findall('.//ReportHost'):
            host_name = report_host.get('name', 'Unknown Host')
            for item in report_host.findall('.//ReportItem'):
                severity = item.get('severity', '0')
                if severity in ['3', '4']:
                    vuln = {
                        "Host": host_name,
                        "Plugin ID": item.get('pluginID', 'N/A'),
                        "Vulnerability": item.get('pluginName', 'Unknown'),
                        "Severity": "Critical" if severity == '4' else "High"
                    }
                    cve_node = item.find('cve')
                    vuln["CVE"] = cve_node.text if cve_node is not None else "N/A"
                    high_critical_findings.append(vuln)
        if not high_critical_findings:
            return {"status": "success", "message": "No High or Critical vulnerabilities found.", "findings": []}
        return {"status": "success", "message": f"Extracted {len(high_critical_findings)} High/Critical vulnerabilities.", "findings": high_critical_findings}
    except Exception as e:
        return {"error": f"Failed to parse Nessus file: {str(e)}"}

@app.post("/generate-poam")
async def generate_poam_entry(data: dict):
    vids = data.get("open_vids", [])
    assessment = data.get("assessment", "")
    nessus_findings = data.get("nessus_findings", [])
    today = datetime.now()
    cat_ii_completion = (today + timedelta(days=90)).strftime("%Y-%m-%d")
    cat_i_completion = (today + timedelta(days=30)).strftime("%Y-%m-%d")
    
    poam_items = []
    if vids:
        for vid in vids:
            poam_items.append({
                "POAM ID": f"POAM-{vid}",
                "Weakness Name": f"Open STIG Finding {vid}",
                "Scheduled Completion Date": cat_ii_completion,
                "Raw V-ID / CVE": vid,
                "Source": "STIG Checklist"
            })
    if "NON-COMPLIANT" in assessment.upper():
        poam_items.append({
            "POAM ID": f"POAM-HOST-{today.strftime('%Y%m%d%H%M')}",
            "Weakness Name": "Host Configuration Baseline Gap",
            "Scheduled Completion Date": cat_ii_completion,
            "Raw V-ID / CVE": "N/A",
            "Source": "Active Host Scan"
        })
    for finding in nessus_findings:
        poam_items.append({
            "POAM ID": f"POAM-NESSUS-{finding.get('Plugin ID', 'UNKNOWN')}",
            "Weakness Name": finding.get("Vulnerability", "Network Vulnerability"),
            "Scheduled Completion Date": cat_i_completion if finding.get("Severity") == "Critical" else cat_ii_completion,
            "Raw V-ID / CVE": finding.get("CVE", "N/A"),
            "Source": f"Nessus ({finding.get('Host', 'Unknown')})"
        })
    return {"poam_entries": poam_items}