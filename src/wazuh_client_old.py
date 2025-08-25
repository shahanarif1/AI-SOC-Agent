import streamlit as st
import asyncio
import json
import os
from dotenv import load_dotenv
from contextlib import AsyncExitStack
from typing import Optional
import nest_asyncio
from openai import AzureOpenAI
from langchain.memory import ConversationBufferMemory
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from pathlib import Path

nest_asyncio.apply()
load_dotenv()
project_root = Path(__file__).resolve().parent.parent
MCP_SERVER_PATH = os.getenv("MCP_SERVER_PATH")
SUBSCRIPTION_KEY = os.getenv("OPENAI_API_KEY")
END_POINT = os.getenv("END_POINT")
ENV_PATH = project_root / '.env'
SERVER_PATH = project_root /'src'/'wazuh_mcp_server'/'main.py'
PYTHON_PATH = project_root / 'venv' / 'Scripts' / 'python.exe'
css_path = project_root /'src' /'Style'/'Styles.css'

with open(css_path) as f:
    css_content = f.read()

# --- MCP Client Class ---
class MCPClient:
    def __init__(self, model_name='gpt-4o' , api_version = '2024-12-01-preview'):
        self.chat_client = AzureOpenAI(
            api_version = api_version,
            azure_endpoint = END_POINT,
            api_key = SUBSCRIPTION_KEY,

            )
        self.model_name = model_name
        self.session: Optional[ClientSession] = None
        self.exit_stack = AsyncExitStack()
        # self.llm = ChatOllama(model=model_name, temperature=0.6, streaming=False)
        self.resource_map = {}

    # --- Server Connection  ---
    async def connect(self, server_path: str):
        server_params = StdioServerParameters(
            command= str(PYTHON_PATH),
            args= [str(server_path)],
            env=None
        )
        stdio_transport = await self.exit_stack.enter_async_context(stdio_client(server_params))
        self.stdio, self.write = stdio_transport
        self.session = await self.exit_stack.enter_async_context(ClientSession(self.stdio, self.write))
        await self.session.initialize()

        resources = await self.session.list_resources()
        for res in resources.resources:
            content = await self.session.read_resource(res.uri)
            self.resource_map[res.description.lower()] = {
                "description": res.description,
                "data": content.contents[0] if content.contents else {}
            }
    
    # --- Helper: Decide if query is follow-up ---
    async def is_follow_up(self, query: str, previous_answer: str = None, resource_list: str = None) -> bool:
        """
        Uses LLM to decide if the query is a follow-up to the previous answer, considering the resource list and previous context.
        Returns True if follow-up, False if new query.
        """
        if not previous_answer:
            return False
        system_prompt = (
            "You are an intelligent SOC assistant. Given the user's query, the previous answer/context, and the list of all available resources, "
            "decide if the query is a follow-up question that depends on the previous answer/context, or does it require more resources to read data from to fully answer the user's query (perform a new query)."
            # "If you think you dont have context to fully answer users query , perform a new query."
            "Reply with only 'follow-up' or 'new'."
        )
        resource_info = f"\nAvailable resources:\n{resource_list}" if resource_list else ""
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Previous answer/context: {previous_answer}\nUser query: {query}{resource_info}"}
        ]
        completion = self.chat_client.chat.completions.create(
            messages=messages,
            max_completion_tokens=10,
            temperature=0.0,
            model=self.model_name
        )
        reply = completion.choices[0].message.content.strip().lower()
        return reply.startswith("follow-up")
    
    # --- Building Query Understanding  ---
    async def built_understanding(self, query:str , resource_list) ->str:
        assistant_prompt = f"""
            #You are a cybersecurity Analyst for a SOC team.
            #Your role is to interpret queries written in natural language by User and i want you to build an understanding of what inforamtion does user want in his query.
            #Your job is to point out resource(s) that you think would best describe or can fulfill users need and best match the user's query.
            # I want you to Think step by step and build an understanding as an SOC analyst of available resources and what inforamtion would be available in them.
            #Here is the list of available resources:
            {resource_list}
            #Here is the query: {query}
            #Instructions:
            #You can expand on users Query to answer it more in detail but you should not expand on the query in any way that is not necessary to answer the query.
            #point out one or more resources with solid reason why you narrowed this resource / resources that best match user's query.
            #Mention resources one by one and reason to use them as resource to answer the user's query.
            #Create a final understanding and mention resource names and reason to use them.
            # """
        try:
            completion = self.chat_client.chat.completions.create(messages = [{'role': 'system' , 'content':assistant_prompt}],
                                                                               max_completion_tokens = 1000,
                                                                               temperature = 1.0,
                                                                               top_p=1.0,
                                                                               frequency_penalty=0.0,
                                                                               presence_penalty=0.0,
                                                                               model = self.model_name )
        
            print(completion.choices[0].message.content.strip().splitlines())
            return completion.choices[0].message.content.strip().splitlines()
        except Exception as e :
            print(f'Error an Occured !! {e}')
            return ''

    # --- Selecting Resources ---
    async def select_resource(self , query: str) -> str:
        resource_list = "\n".join([f"- {desc}" for desc in self.resource_map.keys()])
        understanding  = await self.built_understanding(query , resource_list)
        if understanding == '':
            return "" 
        assistant_prompt = f"""
            #You are a cybersecurity SOC assistant for a SOC team.
            #Your role is to take into account what SOC analyst has understood from query and built a list of resources that best match the user's intent.
            #Your job is to choose the resource(s) according to that understanding.
            #Here is the understanding from SOC analyst:
            {understanding}
            #Here is the list of available resources
            {resource_list}
            #Instructions:
            - Choose one or more resources best match the SOC Analyst's final understanding.
            - Finalise the relevant resource(s) based on the understanding.
            - If only one resource matches, return just that resource name.
            - If more than one resource matches, return a list (one per line).
            - If **none** of the resources match the query, reply with: NONE
            - Do NOT explain anything. Just output the exact matching resource name(s).
            """
        user_prompt = f'''
            #{query}

            '''
        try:
            completion = self.chat_client.chat.completions.create(messages = [{'role': 'system' , 'content':assistant_prompt}
                                                                               ,{'role':'user' , 'content':user_prompt}],
                                                                               max_completion_tokens = 800,
                                                                               temperature = 0.7,
                                                                               top_p=1.0,
                                                                               frequency_penalty=0.0,
                                                                               presence_penalty=0.0,
                                                                               model = self.model_name )
        
            return completion.choices[0].message.content.strip().splitlines()
        except Exception as e :
            print(f'Error an Occured !! {e}')
            return ''

    # --- Multicontext Querying  ---
    async def process_query_Multi_resource(self, query: str, selected_resources: list) -> str:
        import re 
        import json
        pattern = r'[^A-Za-z ]+'
        parsed_resources = [re.sub(pattern, '', s).strip().lower() for s in selected_resources]

        matched_data = {}

        for resource in parsed_resources:
            match = next((key for key in self.resource_map if resource in key.lower()), None)
            if not match:
                continue

            resource_entry = self.resource_map.get(match)
            raw_data = resource_entry.get("data") if isinstance(resource_entry, dict) else None

            if not raw_data:
                return f"⚠️ No data found for resource: {match}"
            try:
                if hasattr(raw_data, "text"):
                    json_text = raw_data.text
                elif isinstance(raw_data, str):
                    json_text = raw_data
                else:
                    return f"⚠️ Unsupported data format for resource: {match}"

                # Parse JSON data
                parsed_json = json.loads(json_text)
                matched_data[match] = parsed_json

            except json.JSONDecodeError:
                return f"⚠️ Couldn't parse JSON data for resource: {match}"
            except Exception as e:
                return f"⚠️ Unexpected error while processing resource {match}: {e}"

        if not matched_data:
            return "⚠️ No matching resources with valid data were found."

        print(f"[INFO] Matched and parsed resources: {list(matched_data.keys())}")

        context = "\n\n".join([f"{k}:\n{json.dumps(v, indent=2)}" for k, v in matched_data.items()])

        system_prompt = f"""
                    #You are a SOC analyst. Read the data and Format the data as clean report or summary for the user based on their query.
                    #so the user is able to understnad the response by just reading it. 
                    #Here is the Data:
                    #{context}

                    #Reply clearly, needed detail not more, and professionally.
                    #Replace Wazuh with Threathawk whenever you find it.
                    """
        user_prompt = f'''
        #{query}

         '''

        try:
            result = self.chat_client.chat.completions.create(messages = [{'role': 'assistant' , 'content':system_prompt}
                                                                               ,{'role':'user' , 'content':user_prompt}],
                                                                               max_completion_tokens = 1000,
                                                                               temperature = 1.0,
                                                                               top_p=1.0,
                                                                               frequency_penalty=0.0,
                                                                               presence_penalty=0.0,
                                                                               model = self.model_name )
        except Exception as e :
            print(f'Error an Occured !! {e}')
            return '⚠️ Couldn\'t perform query !!! Something went wrong while processing your request !!!'
            
        return {"response": result.choices[0].message.content, "context": context}

    # --- Processing Query ---
    async def process_query(self, query: str) -> str:
        selected = []
        lines = await self.select_resource(query)
        if lines == '':
            return "⚠️ I couldn't find the Threat-Hawk alerts data."
        print(f'lines : {lines}')
        selected = lines
        print(f'selected : {selected} and length: {len(selected)}')
        if len(selected) == 1:                                      # if user wants to handle only and read from one resource...
            Resource = next(iter(selected), None)              
            Resource = Resource.strip().lower()
            import re
            pattern = r'[^A-Za-z ]+'
            Resource = re.sub(pattern, '', Resource).strip().lower()
            print(f'[INFO] Matched and parsed resources: {Resource}')
            if Resource == "none":
                return 'Given input doesnot reflect data in threathawk , Or did i not understand your question , kindly Ask again ?'
            
            
            matched_key = next((k for k in self.resource_map.keys() if Resource in k.lower()), None)
            if not matched_key:
                return "I'm sorry, I couldn't find relevant data for your request."

            try:
                key = matched_key
                if key not in self.resource_map:
                    return "⚠️ I couldn't find the Threat-Hawk alerts data."
                json_data = self.resource_map[key]["data"]
                
                if not hasattr(json_data, "text"):
                    return "⚠️ The resource data isn't in readable format."
            
                try:
                    parsed_json = json.loads(json_data.text)
                except json.JSONDecodeError:
                    return "⚠️ Couldn't parse the Threat-Hawk alert data."

                context_str = json.dumps(parsed_json, indent=2)
                system_prompt = f"""
                    #You are a SOC analyst. Read the data and Format the data as clean report or summary for the user based on their query.
                    #so the user is able to understnad the response just reading it.
                    #Here is the Data:
                    #{context_str}

                    #Reply clearly, and professionally.
                    #Replace Wazuh with Threathawk whenever you find it.
                    """
                user_prompt = f'''
                    #{query}

                    '''
                try:
                    result = self.chat_client.chat.completions.create(messages = [{'role': 'assistant' , 'content':system_prompt}
                                                                               ,{'role':'user' , 'content':user_prompt}],
                                                                               max_completion_tokens = 1000,
                                                                               temperature = 1.0,
                                                                               top_p=1.0,
                                                                               frequency_penalty=0.0,
                                                                               presence_penalty=0.0,
                                                                               model = self.model_name )
                except Exception as e :
                    print(f'Error an Occured !! {e}')
                    return '⚠️ Couldn''t perform query !!! Something went wrong while processing your request !!!'
            
                return {"response": result.choices[0].message.content, "context": context_str}

            except Exception:
                return "⚠️ Something went wrong while processing your request."
        else:
            result = await self.process_query_Multi_resource(query , selected) 
            if isinstance(result, dict) and "context" in result:
                st.session_state["last_data"] = result["context"]
                response = result.get("response", "")
            else:
                st.session_state["last_data"] = result
                response = result
            return response

    async def close(self):
        await self.exit_stack.aclose()

def main_page_setup():
    st.header("🛡️ Threat-Hawk Smart Monitoring")
    st.markdown(
        """
        <div style='text-align:center; margin-bottom:12px;'>
            <p style='font-size:17px; color:var(--th-text); margin-bottom:6px;'>
                <span style='color:var(--th-accent); font-weight:bold;'>How to use:</span>
            </p>
        </div>
        <div style='background:var(--th-user-bg); border-radius:14px; padding:14px 18px; color:var(--th-text); margin-bottom:10px; box-shadow:0 1px 4px rgba(0,0,0,0.18);'>
            <ul style='font-size:15px; margin:0;'>
                <li>Type your question in the input box below and press <b style='color:var(--th-accent);'>Enter</b>.</li>
                <li>You can ask about <b style='color:var(--th-accent);'>agents, alerts, vulnerabilities, compliance, threats, system health</b> and more.</li>
                <li>For follow-up questions, just continue the conversation naturally.</li>
                <li>If your query is unclear, the assistant will ask for clarification.</li>
                <li>For CVE details, simply mention the CVE ID (e.g., <span style='color:var(--th-accent);'>CVE-2023-12345</span>).</li>
            </ul>
        </div>
        <div style='margin-bottom:8px;'>
            <h4 style='color:var(--th-accent); margin-bottom:4px;'>Sample Questions:</h4>
            <ul style='font-size:14px; margin:0;'>
                <li>🕵️ Show me active and non-active agents</li>
                <li>🕵️ Show me critical alerts in last 24 hours</li>
                <li>🕵️ Show overall system health</li>
                <li>🕵️ What vulnerabilities are present on agent 5?</li>
                <li>🕵️ Is my system compliant with CIS benchmarks?</li>
                <li>🕵️ Show recent threat indicators</li>
            </ul>
        </div>
        <div style='margin-top:10px;'>
            <h4 style='color:var(--th-accent); margin-bottom:4px;'>What can I ask?</h4>
            <ul style='font-size:14px; margin:0;'>
                <li>Recent Security Alerts</li>
                <li>Statistical Summary of Alerts</li>
                <li>Status Across Agents</li>
                <li>Vulnerabilities Across Agents</li>
                <li>Current Compliance Posture</li>
                <li>Current Active Threat Indicators</li>
                <li>Over-All System Health Metrics</li>
            </ul>
        </div>
        """,
        unsafe_allow_html=True
    )
    
# --- Streamlit Setup ---
st.set_page_config(page_title="Threat-Hawk Smart", layout="centered")

# Initialize session state for conversation management
if "messages" not in st.session_state:
    st.session_state.messages = []
if "memory" not in st.session_state:
    st.session_state.memory = ConversationBufferMemory(return_messages=True)
if "mcp_client" not in st.session_state:
    st.session_state.mcp_client = None
    st.session_state.connected = False
if "conversation_started" not in st.session_state:
    st.session_state.conversation_started = False
if "conversation_history" not in st.session_state:
    st.session_state.conversation_history = []

# Header
st.header("🛡️ Threat-Hawk Smart Monitoring")

# Welcome message (always show but becomes scrollable when chat starts)
with st.container():
    if not st.session_state.conversation_started and len(st.session_state.messages) == 0:
        main_page_setup()
    else:
        # Show compact welcome when chat is active
        with st.expander("📋 Welcome Guide (Click to expand)", expanded=True):
            main_page_setup()

# MCP Connection Setup
async def setup_mcp():
    client = MCPClient()
    await client.connect(SERVER_PATH)
    st.session_state.mcp_client = client
    st.session_state.connected = True

if not st.session_state.connected:
    with st.spinner("Connecting to Threat Hawk server..."):
        asyncio.run(setup_mcp())
        loop = asyncio.new_event_loop()

if st.session_state.connected:
    st.success("✅ Connected to Threat Hawk.")

# Helper: convert simple Markdown tables to HTML for proper rendering in bubbles
import re as _re
def _convert_markdown_tables_to_html(text: str) -> str:
    pattern = _re.compile(r"(?ms)^\s*\|(.+?)\|\s*\n\s*\|(?:\s*:?-+:?\s*\|)+\s*\n((?:\s*\|.*\|\s*\n)+)")

    def repl(match: _re.Match) -> str:
        header_cells = [h.strip() for h in match.group(1).split('|')]
        body_lines = [ln.strip().strip('|') for ln in match.group(2).strip().splitlines()]
        st.markdown(
            """
            <div style='text-align:center; margin-bottom:18px;'>
                <h2 style='color:#ffb300; margin-bottom:8px; font-size:2.2rem; letter-spacing:1px;'>🛡️ Threat Hawk Smart Monitoring System</h2>
                <p style='font-size:18px; color:var(--th-text); margin-bottom:10px;'>
                    <span style='color:#ffb300; font-weight:bold;'>Monitor your network</span> by chatting with our smart SOC assistant and get real-time results.<br>
                </p>
            </div>
            <div style='background:var(--th-user-bg); border-radius:16px; padding:18px 22px; color:var(--th-text); margin-bottom:14px; box-shadow:0 2px 8px rgba(0,0,0,0.18);'>
                <h3 style='color:#e53935; margin-bottom:8px;'>How to Use</h3>
                <ul style='font-size:16px; margin:0;'>
                    <li>Type your question in the input box below and press <b style='color:#ffb300;'>Enter</b>.</li>
                    <li>Ask about <b style='color:#ffb300;'>agents, alerts, vulnerabilities, compliance, threats, system health</b> and more.</li>
                    <li>Continue the conversation for follow-up questions.</li>
                    <li>If your query is unclear, the assistant will ask for clarification.</li>
                    <li>For CVE details, mention the CVE ID (e.g., <span style='color:#ffb300;'>CVE-2023-12345</span>).</li>
                </ul>
            </div>
            <div style='margin-bottom:10px;'>
                <h4 style='color:#e53935; margin-bottom:4px;'>Sample Questions</h4>
                <ul style='font-size:15px; margin:0;'>
                    <li>🕵️ Show me active and non-active agents</li>
                    <li>🕵️ Show me critical alerts in last 24 hours</li>
                    <li>🕵️ Show overall system health</li>
                    <li>🕵️ What vulnerabilities are present on agent 5?</li>
                    <li>🕵️ Is my system compliant with CIS benchmarks?</li>
                    <li>🕵️ Show recent threat indicators</li>
                </ul>
            </div>
            <div style='margin-top:12px;'>
                <h4 style='color:#e53935; margin-bottom:4px;'>What can I ask?</h4>
                <ul style='font-size:15px; margin:0;'>
                    <li>Recent Security Alerts</li>
                    <li>Statistical Summary of Alerts</li>
                    <li>Status Across Agents</li>
                    <li>Vulnerabilities Across Agents</li>
                    <li>Current Compliance Posture</li>
                    <li>Current Active Threat Indicators</li>
                    <li>Over-All System Health Metrics</li>
                </ul>
            </div>
            <div style='margin-top:18px; background:var(--th-assistant-bg); border-radius:12px; padding:14px 18px; color:var(--th-text); box-shadow:0 1px 4px rgba(0,0,0,0.12);'>
                <h4 style='color:#e53935; margin-bottom:6px;'>Visual Insights & Charts</h4>
                <p style='font-size:15px;'>
                    <b>Results in chat may include interactive charts and graphs for:</b>
                    <ul style='margin-top:4px;'>
                        <li>Agent status breakdown</li>
                        <li>Alert trends over time</li>
                        <li>Vulnerability distribution</li>
                        <li>Compliance scores</li>
                        <li>Threat indicator frequency</li>
                    </ul>
                    <span style='color:#ffb300;'>Look for charts and data visualizations in your chat results!</span>
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )
    content = _convert_markdown_tables_to_html(content)
    # Tighten whitespace before tables
    content = re.sub(r'^\s+(?=<table)', '', content, flags=re.MULTILINE)
    # Unwrap code fences around HTML so tags render instead of showing as text
    content = re.sub(r'```(?:html|HTML)\s*([\s\S]*?)```', r'\1', content)
    content = re.sub(r'```\s*([\s\S]*?<table[\s\S]*?>[\s\S]*?)```', r'\1', content)
    # Trim outer whitespace
    content = content.strip()
    
    if message["role"] == "user":
        # User message on the left with icon beside bubble
        st.markdown(f"""
        <div class=\"th-row user\" style='margin:2px 0;'>
            <div class=\"th-avatar\">👤</div>
            <div class=\"th-bubble user\" style='margin-bottom:2px;'>
                <div class=\"th-chat\">{content}</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        # Assistant message on the right with icon beside bubble, with chart area
        st.markdown(f"""
        <div class=\"th-row assistant\" style='margin:2px 0;'>
            <div class=\"th-bubble assistant\" style='margin-bottom:2px; background:var(--th-assistant-bg); border:1px solid #ffb300;'>
                <div class=\"th-chat\">{content}</div>
                <div class=\"th-chart-area\" style='margin-top:8px;'></div>
            </div>
            <div class=\"th-avatar\">🤖</div>
        </div>
        """, unsafe_allow_html=True)

# Auto-scroll to bottom (focus on latest messages)
if st.session_state.messages:
    st.markdown("""
    <script>
        window.scrollTo(0, document.body.scrollHeight);
    </script>
    """, unsafe_allow_html=True)

# Chat input
if prompt := st.chat_input("Ask me something..."):
    # Add user message to chat history
    st.session_state.messages.append({"role": "user", "content": prompt})
    st.session_state.conversation_started = True
    
    # Set conversation start time if this is the first message
    if len(st.session_state.messages) == 1:
        from datetime import datetime
        st.session_state.conversation_start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Generate response
    async def handle_response():
        previous_answer = st.session_state.get("last_data")
        mcp_client = st.session_state.mcp_client
        resource_list = "\n".join([f"- {desc}" for desc in mcp_client.resource_map.keys()])
        is_followup = await mcp_client.is_follow_up(prompt, previous_answer, resource_list)
        response = ""
        if is_followup and ("cve" in prompt.lower() and "remediation" in prompt.lower()):
            # CVE web search stub
            system_prompt = (f"""
            You are a cybersecurity assistant specializing in vulnerability research and remediation.
            I will provide a single CVE ID and its related package name if package name is available.
            Here is CVE id in this prompt {prompt}  
            Your task:
                Search authoritative sources (NVD, MITRE, vendor advisories, security blogs, exploit databases, GitHub if applicable) for the latest technical details — verify accuracy and freshness.
                Summarize the vulnerability in one short line (affected products, versions, severity, exploitability, public PoCs).
                Output only a short, expert-facing Actions Taken checklist — no background, no explanations, no references.
                Checklist rules:
                Group into Immediate (Today), Fix (Within 48h), and Afterwards (Post-Remediation).
                Each bullet must be a clear, concise past-tense action (e.g., “Applied patch”, “Rotated credentials”, “Isolated server”).
                Avoid generic language — be specific to the CVE's context.
                Instructions:

                Input:
                CVE: 
                Package: if available
                Output:

                One-line CVE summary

                """)
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"User query: {prompt}"}
            ]
            completion = mcp_client.chat_client.chat.completions.create(
                messages=messages,
                max_completion_tokens=800,
                temperature=0.7,
                model=mcp_client.model_name
            )
            response = completion.choices[0].message.content.strip().lower()
        elif is_followup and previous_answer:
            # Use previous context for follow-up
            context_data = previous_answer
            system_prompt = f"""
                You are a SOC analyst continuing a conversation with the user.
                You have the following previously retrieved Threat-Hawk data:
                {context_data}
                Answer the user's follow-up question based on this data and the conversation context.
                If the data does not contain an answer, tell the user that.
                Be conversational and reference previous parts of the conversation when relevant.
                Replace Wazuh with Threathawk whenever you find it.
            """
            conversation_messages = [
                {"role": "system", "content": system_prompt}
            ]
            recent_messages = st.session_state.memory.chat_memory.messages[-10:]
            for msg in recent_messages:
                role_mapping = {
                    'human': 'user',
                    'ai': 'assistant',
                    'system': 'system'
                }
                mapped_role = role_mapping.get(msg.type, 'user')
                conversation_messages.append({
                    "role": mapped_role,
                    "content": msg.content
                })
            conversation_messages.append({"role": "user", "content": prompt})
            completion = mcp_client.chat_client.chat.completions.create(
                messages=conversation_messages,
                max_completion_tokens=800,
                temperature=0.7,
                model=mcp_client.model_name
            )
            response = completion.choices[0].message.content.strip()
        else:
            # New query
            result = await mcp_client.process_query(prompt)
            if isinstance(result, dict) and "context" in result:
                st.session_state["last_data"] = result["context"]
                response = result.get("response", "")
            else:
                st.session_state["last_data"] = result
                response = result
        # Save assistant response to memory
        st.session_state.memory.chat_memory.add_ai_message(response)
        return response

    # Display assistant response
    with st.spinner("Thinking..."):
        try:
            result = asyncio.run(handle_response())
            st.session_state.messages.append({"role": "assistant", "content": result})
            st.rerun()  # Rerun to show the new message
        except Exception as e:
            error_msg = f"❌ Error: {e}"
            st.error(error_msg)
            st.session_state.messages.append({"role": "assistant", "content": error_msg})
            st.rerun()  # Rerun to show the error message
            if st.button("Shut Down Application"):
                import signal
                os.kill(os.getpid(), signal.SIGKILL)

# Display conversation info
if st.session_state.conversation_started:
    with st.sidebar.expander("💬 Conversation Info", expanded=False):
        st.write(f"**Messages:** {len(st.session_state.messages)}")
        st.write("**Total Messages Allowed: 10**")
        
        # New Chat button (only show when there are messages)
        if len(st.session_state.messages) > 0:
            if st.button("💬 New Chat"):
                # Save current conversation to history before clearing
                if st.session_state.messages:
                    conversation_summary = {
                        "timestamp": st.session_state.get("conversation_start_time", "Unknown"),
                        "message_count": len(st.session_state.messages),
                        "first_message": st.session_state.messages[0]["content"][:50] + "..." if st.session_state.messages else "",
                        "messages": st.session_state.messages.copy()
                    }
                    st.session_state.conversation_history.append(conversation_summary)
                
                # Reset conversation
                st.session_state.messages = []
                st.session_state.memory = ConversationBufferMemory(return_messages=True)
                st.session_state.conversation_started = False
                st.session_state.last_data = None
                st.rerun()
        
        # Clear Chat History button (only show when there are messages)
        if len(st.session_state.messages) > 0:
            if st.button("🗑️ Clear Chat History"):
                st.session_state.messages = []
                st.session_state.memory = ConversationBufferMemory(return_messages=True)
                st.session_state.conversation_started = False
                st.session_state.last_data = None
                st.rerun()
        
        # Show conversation history if available
        if st.session_state.conversation_history:
            st.markdown("---")
            st.write("**📚 Previous Conversations:**")
            for i, conv in enumerate(reversed(st.session_state.conversation_history)):
                with st.expander(f"💬 {conv['first_message']} ({conv['message_count']} messages)", expanded=False):
                    st.write(f"**Started:** {conv['timestamp']}")
                    st.write(f"**Messages:** {conv['message_count']}")
                    if st.button(f"View Details", key=f"view_{i}"):
                        st.write("**Full Conversation:**")
                        for msg in conv['messages']:
                            if msg["role"] == "user":
                                st.write(f"**You:** {msg['content']}")
                            else:
                                st.write(f"**Assistant:** {msg['content']}")
                            st.write("---")
