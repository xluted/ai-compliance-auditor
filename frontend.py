import streamlit as st
import requests
import pandas as pd

st.set_page_config(page_title="AI Compliance Auditor & eMASS Exporter", layout="wide")

if "access_token" not in st.session_state:
    st.session_state["access_token"] = None
if "username" not in st.session_state:
    st.session_state["username"] = None

st.title("🛡️ AI-Driven Federal Compliance Auditor")
st.markdown("Upload baseline security PDFs, evaluate controls locally using Llama 3, and export structured data for eMASS bulk compliance uploads.")

with st.sidebar:
    st.header("🔐 User Authentication")
    if st.session_state["access_token"] is None:
        auth_mode = st.radio("Select Action", ["Login", "Register"], horizontal=True)
        auth_user = st.text_input("Username")
        auth_pass = st.text_input("Password", type="password")
        if st.button(auth_mode):
            if not auth_user or not auth_pass:
                st.warning("Please enter both username and password.")
            elif auth_mode == "Register":
                res = requests.post("http://127.0.0.1:8000/register", params={"username": auth_user, "password": auth_pass})
                if res.status_code == 200:
                    st.success("Registered successfully! You can now log in.")
                else:
                    try:
                        error_msg = res.json().get("detail", "Registration failed.")
                    except:
                        error_msg = f"Server Error {res.status_code}: Please check backend."
                    st.error(error_msg)
            else:
                res = requests.post("http://127.0.0.1:8000/token", data={"username": auth_user, "password": auth_pass})
                if res.status_code == 200:
                    st.session_state["access_token"] = res.json().get("access_token")
                    st.session_state["username"] = auth_user
                    st.rerun()
                else:
                    st.error("Invalid username or password.")
    else:
        st.success(f"Logged in as: **{st.session_state['username']}**")
        if st.button("Logout"):
            st.session_state["access_token"] = None
            st.session_state["username"] = None
            st.rerun()

    st.markdown("---")
    st.header("1. Framework Ingestion")
    uploaded_file = st.file_uploader("Upload Policy/STIG PDF", type=["pdf"])
    if uploaded_file is not None:
        if st.button("Process & Ingest PDF"):
            with st.spinner("Processing document chunks..."):
                files = {"file": (uploaded_file.name, uploaded_file.getvalue(), "application/pdf")}
                response = requests.post("http://127.0.0.1:8000/ingest", files=files)
                if response.status_code == 200:
                    st.success(response.json().get("message", "Ingested successfully!"))
                else:
                    st.error("Failed to ingest document.")

    st.markdown("---")
    st.header("STIG Checklist Ingestion")
    ckl_file = st.file_uploader("Upload STIG Checklist", type=["ckl", "cklb"])
    if ckl_file is not None:
        if st.button("Parse Checklist Vulnerabilities"):
            with st.spinner("Extracting STIG findings..."):
                mime_type = "application/json" if ckl_file.name.endswith(".cklb") else "application/xml"
                files = {"file": (ckl_file.name, ckl_file.getvalue(), mime_type)}
                response = requests.post("http://127.0.0.1:8000/parse-ckl", files=files)
                if response.status_code == 200:
                    data = response.json()
                    if "error" in data:
                        st.error(data["error"])
                    else:
                        st.success(data["message"])
                        if data.get("open_vulnerabilities"):
                            st.warning(f"Open V-IDs: {', '.join(data['open_vulnerabilities'])}")
                            st.session_state["open_vids"] = data["open_vulnerabilities"]
                else:
                    st.error("Failed to communicate with parser backend.")

    st.markdown("---")
    st.header("ACAS / Nessus Ingestion")
    nessus_file = st.file_uploader("Upload Nessus Scan", type=["nessus"])
    if nessus_file is not None:
        if st.button("Parse Nessus Vulnerabilities"):
            with st.spinner("Extracting High & Critical findings..."):
                files = {"file": (nessus_file.name, nessus_file.getvalue(), "application/xml")}
                response = requests.post("http://127.0.0.1:8000/parse-nessus", files=files)
                if response.status_code == 200:
                    data = response.json()
                    if "error" in data:
                        st.error(data["error"])
                    else:
                        st.success(data["message"])
                        if data.get("findings"):
                            st.session_state["nessus_findings"] = data["findings"]
                            st.dataframe(pd.DataFrame(data["findings"]), use_container_width=True)
                else:
                    st.error("Failed to communicate with Nessus backend.")

st.header("2. Compliance Assessment & Analysis")
query = st.text_area("Enter your compliance query or control evaluation scenario:")
if st.button("Run AI Evaluation"):
    if query:
        with st.spinner("Querying local vector database..."):
            response = requests.post("http://127.0.0.1:8000/evaluate", json={"query": query})
            if response.status_code == 200:
                data = response.json()
                assessment = data.get("assessment", "")
                rules_count = data.get("rules_referenced", 0)
                st.session_state["last_query"] = query
                st.session_state["last_assessment"] = assessment
                st.subheader("Assessment Results")
                st.write(assessment)
                st.info(f"Rules Referenced / Chunks Analyzed: {rules_count}")
            else:
                st.error("Error communicating with backend API.")

if "last_assessment" in st.session_state:
    st.markdown("---")
    st.header("3. eMASS POA&M Generator")
    is_compliant = "NON-COMPLIANT" not in st.session_state["last_assessment"].upper()
    open_vids = st.session_state.get("open_vids", [])
    nessus_vulns = st.session_state.get("nessus_findings", [])
    
    if is_compliant and not open_vids and not nessus_vulns:
        st.success("🎉 System is fully compliant! No POA&M items required.")
    else:
        if st.button("Generate eMASS POA&M Table"):
            with st.spinner("Building master POA&M..."):
                payload = {
                    "open_vids": open_vids,
                    "assessment": st.session_state["last_assessment"],
                    "nessus_findings": nessus_vulns
                }
                res = requests.post("http://127.0.0.1:8000/generate-poam", json=payload)
                if res.status_code == 200:
                    poam_data = res.json().get("poam_entries", [])
                    st.session_state["poam_df"] = pd.DataFrame(poam_data)
                else:
                    st.error("Failed to generate POA&M table.")

    if "poam_df" in st.session_state:
        st.subheader("Generated POA&M Items")
        st.dataframe(st.session_state["poam_df"], use_container_width=True)
        csv_data = st.session_state["poam_df"].to_csv(index=False).encode('utf-8')
        st.download_button(label="📥 Download eMASS POA&M CSV Report", data=csv_data, file_name=f"eMASS_POAM_Report_{pd.Timestamp.now().strftime('%Y%m%d')}.csv", mime="text/csv")

st.markdown("---")
st.header("Live System Audit")
if st.button("Scan Local Security Logs"):
    with st.spinner("Pulling live audit files..."):
        try:
            response = requests.get("http://127.0.0.1:8000/analyze-system-audit")
            if response.status_code == 200:
                data = response.json()
                st.subheader("Executive Log Summary")
                st.info(data.get("plain_english_summary", ""))
                with st.expander("View Raw Audit Data"):
                    st.code(data.get("raw_logs", ""))
            else:
                st.error("Failed to read system logs. Run as Administrator.")
        except Exception as e:
            st.error(f"Error connecting: {str(e)}")

st.markdown("---")
st.header("4. Active Host Configuration Compliance Check (RBAC Secured)")
if st.button("Run Active Host Compliance Audit"):
    if not st.session_state["access_token"]:
        st.error("🚨 Authentication Required!")
    else:
        with st.spinner("Auditing OS configuration..."):
            try:
                headers = {"Authorization": f"Bearer {st.session_state['access_token']}"}
                res = requests.get("http://127.0.0.1:8000/audit-host-configuration", headers=headers)
                if res.status_code == 401:
                    st.error("Session expired.")
                    st.session_state["access_token"] = None
                    st.rerun()
                elif res.status_code == 200:
                    data = res.json()
                    st.subheader("System Compliance Audit Report")
                    st.markdown(data.get("compliance_audit_report", ""))
                    st.success("✅ Audit log successfully written to enterprise database.")
            except Exception as e:
                st.error(f"Failed to execute audit: {str(e)}")

st.markdown("---")
st.header("5. Multi-Host Enterprise Network Scan (WinRM)")
if not st.session_state["access_token"]:
    st.info("🔒 Log in via sidebar to access Multi-Host Network Scanning.")
else:
    target_hosts_input = st.text_area("Target IP Addresses (Comma Separated)", placeholder="192.168.1.10, 192.168.1.11")
    winrm_user = st.text_input("Domain / Admin Username", value="Administrator")
    winrm_pass = st.text_input("Admin Password", type="password")
    if st.button("Execute Multi-Host Scan"):
        if not target_hosts_input or not winrm_pass:
            st.warning("Please provide target IPs and admin password.")
        else:
            host_list = [h.strip() for h in target_hosts_input.split(",") if h.strip()]
            payload = {"hosts": host_list, "username": winrm_user, "password": winrm_pass}
            headers = {"Authorization": f"Bearer {st.session_state['access_token']}"}
            with st.spinner(f"Scanning {len(host_list)} hosts..."):
                res = requests.post("http://127.0.0.1:8000/audit-multi-host", json=payload, headers=headers)
                if res.status_code == 200:
                    for item in res.json().get("results", []):
                        if item["status"] == "COMPLETED":
                            st.success(f" Host: {item['host']} - Scan Complete")
                            st.markdown(item["report"])
                        else:
                            st.error(f"❌ Host: {item['host']} - Failed: {item.get('error')}")
                else:
                    st.error(f"Scan request failed.")