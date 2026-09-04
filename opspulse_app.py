import streamlit as st
from google import genai

# Page Config
st.set_page_config(page_title="OpsPulse - AI Log Analyzer", layout="wide", page_icon="🛡️")

st.title("🛡️ OpsPulse: Real-Time AI Log & Incident Analyzer")
st.write("Upload raw system logs to parse critical errors, pinpoint root causes, and get immediate code fixes.")

# Sidebar setup
st.sidebar.header("Configuration")
api_key = st.sidebar.text_input("Enter Gemini API Key", type="password")

# File Upload Section
uploaded_file = st.file_uploader("Upload Server Log File (.txt, .log)", type=["txt", "log"])

if uploaded_file and api_key:
    log_content = uploaded_file.read().decode("utf-8")
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.subheader("Raw Log File Stream")
        st.code(log_content[:2000] + ("\n... [Truncated]" if len(log_content) > 2000 else ""), language="text")
    
    with col2:
        st.subheader("Incident Diagnosis")
        if st.button("Run AI Log Analysis", type="primary"):
            with st.spinner("Analyzing log events and stack traces..."):
                try:
                    client = genai.Client(api_key=api_key)
                    prompt = f"""
                    You are an expert DevOps and Cybersecurity engineer. Analyze the following server log text:
                    
                    {log_content}
                    
                    Output a structured report in valid Markdown with these exact sections:
                    ### 🚨 Executive Incident Summary
                    ### 🔍 Error Details & Timestamps
                    ### 🛠️ Root Cause Analysis
                    ### 💡 Recommended Fix Instructions (Include Code/Terminal Commands)
                    """
                    
                    response = client.models.generate_content(
                        model='gemini-2.5-flash',
                        contents=prompt
                    )
                    
                    st.success("Analysis Complete!")
                    st.markdown(response.text)
                except Exception as e:
                    st.error(f"Error processing logs: {str(e)}")

elif uploaded_file and not api_key:
    st.warning("Please enter your Gemini API Key in the sidebar to generate the report.")