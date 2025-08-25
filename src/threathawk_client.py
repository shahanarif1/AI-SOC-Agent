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
            
        # Enhanced system prompt for better follow-up detection
        system_prompt = """You are a cybersecurity assistant analyzing if a user's query is a follow-up question.

         CRITERIA FOR FOLLOW-UP QUESTIONS:
        - References previous data/context (e.g., "What about the other agents?", "Show me more details")
        - Asks for clarification or expansion of previous information
        - Uses pronouns like "it", "they", "those", "this" referring to previous context
        - Asks "why", "how", "when", "where" about previously mentioned items
        - Requests additional analysis of the same data
        - Asks for comparisons or relationships between previously mentioned items

        CRITERIA FOR NEW QUERIES:
        - Asks for completely different information not in previous context
        - Requests data from different resources
        - Asks about unrelated topics or systems
        - Uses specific names/IDs not mentioned before

        Previous context: {previous_answer}

        User query: {query}

        # Analyze if this is a follow-up question based on the criteria above.
        # Respond with ONLY: "follow-up" or "new"
        """
        
        messages = [
            {"role": "system", "content": system_prompt.format(previous_answer=previous_answer[:500], query=query)},
            {"role": "user", "content": f"Previous context: {previous_answer[:500]}\nUser query: {query}"}
        ]
        
        try:
            completion = self.chat_client.chat.completions.create(
                messages=messages,
                max_completion_tokens=5,
                temperature=0.0,
                model=self.model_name
            )
            reply = completion.choices[0].message.content.strip().lower()
            print(f"[DEBUG] Follow-up detection - Query: '{query}' | Reply: '{reply}' | Is follow-up: {reply.startswith('follow-up')}")
            return reply.startswith("follow-up")
        except Exception as e:
            print(f"[ERROR] Follow-up detection failed: {e}")
            # Fallback: simple keyword-based detection
            follow_up_indicators = [
                "what about", "how about", "tell me more", "show me more", "give me more",
                "explain", "why", "when", "where", "how", "which", "what else",
                "it", "this", "that", "these", "those", "they", "them",
                "the other", "others", "remaining", "rest", "additional",
                "compare", "difference", "similar", "related", "connection"
            ]
            query_lower = query.lower()
            return any(indicator in query_lower for indicator in follow_up_indicators)
    
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

        #IMPORTANT: Format the response using bullet points, paragraphs, or numbered lists. Avoid tables unless comparing 3+ agents side-by-side.
        #Keep the response concise (max 300-400 words) and well-formatted for chat display.
        #If there's extensive data, provide a summary with key points only.
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
                    #You are a SOC analyst. Read the data and provide a clear, informative response based on the user's query.
                    
                    #CRITICAL FORMATTING RULES:
                    #- DO NOT use tables for agent information unless explicitly comparing 3+ agents side-by-side
                    #- For agent data, use bullet points, paragraphs, or numbered lists instead
                    #- Tables should be used ONLY for comparing multiple items with identical properties
                    #- Prefer natural language descriptions over structured tables
                    
                    #CONTENT LENGTH MANAGEMENT:
                    #- Keep responses concise and focused (max 300-400 words)
                    #- If data is extensive, provide a summary with key points
                    #- Use "..." to indicate when there's more data available
                    #- Break long lists into smaller, manageable chunks
                    #- Focus on the most relevant information for the user's query
                    
                    #AGENT DATA FORMATTING:
                    #- Single agent info: Use paragraphs and bullet points
                    #- Multiple agents: Use bullet points with agent names as headers
                    #- Agent status: Use descriptive text, not tables
                    #- Agent details: Use organized bullet points or numbered lists
                    
                    #Examples of GOOD formatting for agents:
                    #- "Agent-001 is currently active and running on Windows 10. It has 2 active alerts and 1 vulnerability."
                    #- "Found 3 agents: • Agent-001 (Active) • Agent-002 (Inactive) • Agent-003 (Active)"
                    #- "Agent Status Summary: 1. Agent-001: Active, 2 alerts 2. Agent-002: Inactive, 0 alerts"
                    
                    #Here is the Data:
                    #{context}

                    #Reply clearly, professionally, and in a way that's easy to read and understand.
                    #Replace Wazuh with Threathawk whenever you find it.
                    #AVOID TABLES for agent information unless absolutely necessary for comparison.
                    """
        user_prompt = f'''
        #{query}

        #IMPORTANT: Format the response using bullet points, paragraphs, or numbered lists. Avoid tables unless comparing 3+ agents side-by-side.
        #Keep the response concise (max 300-400 words) and well-formatted for chat display.
        #If there's extensive data, provide a summary with key points only.
         '''

        try:
            result = self.chat_client.chat.completions.create(messages = [{'role': 'assistant' , 'content':system_prompt}
                                                                               ,{'role':'user' , 'content':user_prompt}],
                                                                               max_completion_tokens = 600,
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
                    #You are a SOC analyst. Read the data and provide a clear, informative response based on the user's query.
                    
                    #CRITICAL FORMATTING RULES:
                    #- DO NOT use tables for agent information unless explicitly comparing 3+ agents side-by-side
                    #- For agent data, use bullet points, paragraphs, or numbered lists instead
                    #- Tables should be used ONLY for comparing multiple items with identical properties
                    #- Prefer natural language descriptions over structured tables
                    
                    #CONTENT LENGTH MANAGEMENT:
                    #- Keep responses concise and focused (max 300-400 words)
                    #- If data is extensive, provide a summary with key points
                    #- Use "..." to indicate when there's more data available
                    #- Break long lists into smaller, manageable chunks
                    #- Focus on the most relevant information for the user's query
                    
                    #AGENT DATA FORMATTING:
                    #- Single agent info: Use paragraphs and bullet points
                    #- Multiple agents: Use bullet points with agent names as headers
                    #- Agent status: Use descriptive text, not tables
                    #- Agent details: Use organized bullet points or numbered lists
                    
                    #Examples of GOOD formatting for agents:
                    #- "Agent-001 is currently active and running on Windows 10. It has 2 active alerts and 1 vulnerability."
                    #- "Found 3 agents: • Agent-001 (Active) • Agent-002 (Inactive) • Agent-003 (Active)"
                    #- "Agent Status Summary: 1. Agent-001: Active, 2 alerts 2. Agent-002: Inactive, 0 alerts"
                    
                    #Here is the Data:
                    #{context_str}

                    #Reply clearly, professionally, and in a way that's easy to read and understand.
                    #Replace Wazuh with Threathawk whenever you find it.
                    #AVOID TABLES for agent information unless absolutely necessary for comparison.
                    """
                user_prompt = f'''
        #{query}

        #IMPORTANT: Format the response using bullet points, paragraphs, or numbered lists. Avoid tables unless comparing 3+ agents side-by-side.
        #Keep the response concise (max 300-400 words) and well-formatted for chat display.
        #If there's extensive data, provide a summary with key points only.
         '''
                try:
                    result = self.chat_client.chat.completions.create(messages = [{'role': 'assistant' , 'content':system_prompt}
                                                                               ,{'role':'user' , 'content':user_prompt}],
                                                                               max_completion_tokens = 600,
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
    
    # --- Test follow-up detection ---
    async def test_followup_detection(self):
        """
        Test function to verify follow-up detection is working
        """
        test_cases = [
            {
                "previous": "Found 5 active agents: Agent-001, Agent-002, Agent-003, Agent-004, Agent-005",
                "query": "What about the other agents?",
                "expected": True
            },
            {
                "previous": "Critical alerts: 3 high severity alerts detected",
                "query": "Show me system health",
                "expected": False
            },
            {
                "previous": "Agent-001 has 2 vulnerabilities",
                "query": "Tell me more about it",
                "expected": True
            }
        ]
        
        print("\n=== Testing Follow-up Detection ===")
        for i, test in enumerate(test_cases):
            result = await self.is_follow_up(test["query"], test["previous"])
            status = "✅ PASS" if result == test["expected"] else "❌ FAIL"
            print(f"Test {i+1}: {status} | Query: '{test['query']}' | Expected: {test['expected']} | Got: {result}")
        print("=== End Test ===\n")


def main_page_setup():
    # Main header with gradient text
    st.markdown("""
    <div style="text-align: center; margin-bottom: 2rem; padding: 2rem; background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); border-radius: 16px; border: 1px solid #334155; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1);">
        <h1 style="font-size: 2.5rem; font-weight: 700; background: linear-gradient(135deg, #6366f1, #10b981); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; margin-bottom: 0.5rem;">
            Threat Hawk 🧠 Smart Monitoring System
        </h1>
        <p style="font-size: 1.2rem; color: #cbd5e1; font-weight: 400; margin: 0;">
            Your intelligent cybersecurity companion for real-time threat monitoring and analysis
        </p>
    </div>
    """, unsafe_allow_html=True)
    

    
    # How to use section
    st.markdown("### 💡 How to use Threat Hawk")
    st.markdown("""
    <div style="background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 1.5rem; margin: 1rem 0; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);">
        <ul style="color: #cbd5e1; font-size: 1rem; line-height: 1.8; margin: 0; padding-left: 1.5rem;">
            <li style="margin-bottom: 0.5rem;">Type your question in the input box below and press <strong style="color: #10b981;">Enter</strong></li>
            <li style="margin-bottom: 0.5rem;">Ask about <strong style="color: #10b981;">agents, alerts, vulnerabilities, compliance, threats, system health</strong> and more</li>
            <li style="margin-bottom: 0.5rem;">For follow-up questions, continue the conversation naturally</li>
            <li style="margin-bottom: 0.5rem;">For CVE details, mention the CVE ID (e.g., <code style="background: #334155; padding: 2px 6px; border-radius: 4px; color: #10b981;">CVE-2023-12345</code>)</li>
            <li style="margin-bottom: 0.5rem;">Use natural language - Threat Hawk understands context and intent</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
    
    # Sample questions
    st.markdown("### 🔍 Sample Questions")
    sample_questions = [
        ("🕵️", "Show me active and non-active agents"),
        ("🚨", "Show me critical alerts in last 24 hours"),
        ("💚", "Show overall system health"),
        ("🔓", "What vulnerabilities are present on agent 5?"),
        ("✅", "Is my system compliant with CIS benchmarks?"),
        ("🎯", "Show recent threat indicators")
    ]
    
    cols = st.columns(2)
    for i, (icon, question) in enumerate(sample_questions):
        with cols[i % 2]:
            st.markdown(f"""
            <div style="background: #334155; border: 1px solid #475569; border-radius: 8px; padding: 1rem; margin: 0.5rem 0; cursor: pointer; transition: all 0.2s ease; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);">
                <span style="color: #10b981; margin-right: 0.5rem; font-size: 1.2rem;">{icon}</span>
                <span style="color: #cbd5e1; font-size: 0.95rem;">{question}</span>
            </div>
            """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # What can I ask about
    st.markdown("### 📋 What can I ask about?")
    capabilities = [
        ("🚨", "Security Alerts", "Recent alerts, critical events, and threat indicators"),
        ("📊", "Statistics", "Statistical summaries and trend analysis"),
        ("🖥️", "Agent Status", "Status across all monitored agents"),
        ("🔓", "Vulnerabilities", "Vulnerability assessment and CVE details"),
        ("✅", "Compliance", "Compliance posture and benchmark checks"),
        ("💚", "System Health", "Overall system health metrics and performance")
    ]
    
    cap_cols = st.columns(3)
    for i, (icon, title, desc) in enumerate(capabilities):
        with cap_cols[i % 3]:
            st.markdown(f"""
            <div style="background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 1.5rem; text-align: center; margin: 0.5rem 0; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);">
                <div style="font-size: 1.5rem; margin-bottom: 0.5rem;">{icon}</div>
                <h4 style="color: #f8fafc; margin-bottom: 0.5rem; font-size: 1.1rem;">{title}</h4>
                <p style="color: #cbd5e1; font-size: 0.85rem; line-height: 1.4; margin: 0;">{desc}</p>
            </div>
            """, unsafe_allow_html=True)
    
# --- Streamlit Setup ---
st.set_page_config(
    page_title="Threat Hawk Smart Monitoring System",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed",
    menu_items={
        'Get Help': 'https://github.comshahanarif1/AI-SOC-Agent/threat-hawk',
        'Report a bug': 'https://github.comshahanarif1/AI-SOC-Agent/issues',
        'About': 'Threat Hawk is an intelligent cybersecurity monitoring system powered by AI.'
    }
)

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
        
        # Test follow-up detection after connection
        try:
            asyncio.run(st.session_state.mcp_client.test_followup_detection())
        except Exception as e:
            print(f"[WARNING] Follow-up detection test failed: {e}")

if st.session_state.connected:
    st.success("✅ Connected to Threat Hawk.")

# Helper: convert simple Markdown tables to HTML for proper rendering in bubbles
import re as _re
def _convert_markdown_tables_to_html(text: str) -> str:
    pattern = _re.compile(r"(?ms)^\s*\|(.+?)\|\s*\n\s*\|(?:\s*:?-+:?\s*\|)+\s*\n((?:\s*\|.*\|\s*\n)+)")

    def repl(match: _re.Match) -> str:
        header_cells = [h.strip() for h in match.group(1).split('|')]
        body_lines = [ln.strip().strip('|') for ln in match.group(2).strip().splitlines()]
        rows_html = []
        
        # Clean up header cells - remove any markdown formatting
        clean_headers = []
        for h in header_cells:
            # Remove markdown formatting
            h = re.sub(r'\*\*(.*?)\*\*', r'\1', h)  # Remove bold
            h = re.sub(r'\*(.*?)\*', r'\1', h)      # Remove italic
            h = re.sub(r'`(.*?)`', r'\1', h)        # Remove code
            clean_headers.append(h)
        
        for ln in body_lines:
            if not ln:
                continue
            cells = [c.strip() for c in ln.split('|')]
            
            # Clean up cell content and add status classes
            clean_cells = []
            for cell in cells:
                # Remove markdown formatting but preserve content
                cell = re.sub(r'\*\*(.*?)\*\*', r'\1', cell)  # Remove bold
                cell = re.sub(r'\*(.*?)\*', r'\1', cell)      # Remove italic
                
                # Add status classes for common status indicators
                cell_lower = cell.lower()
                if 'active' in cell_lower:
                    cell = f'<span class="status-active">{cell}</span>'
                elif 'inactive' in cell_lower or 'offline' in cell_lower:
                    cell = f'<span class="status-inactive">{cell}</span>'
                elif 'warning' in cell_lower or 'critical' in cell_lower:
                    cell = f'<span class="status-warning">{cell}</span>'
                
                clean_cells.append(cell)
            
            rows_html.append('<tr>' + ''.join(f'<td>{c}</td>' for c in clean_cells) + '</tr>')
        
        thead = '<thead><tr>' + ''.join(f'<th>{c}</th>' for c in clean_headers) + '</tr></thead>'
        tbody = '<tbody>' + ''.join(rows_html) + '</tbody>'
        return f'<div class="table-container"><table class="chat-table">{thead}{tbody}</table></div>'

    return pattern.sub(repl, text)

# Inject compact CSS for content spacing
st.markdown(
    f"""
    <style>
    {css_content}
    </style>
    """,
    unsafe_allow_html=True,
)

# Display chat messages with improved styling
for i, message in enumerate(st.session_state.messages):
    # Lightly sanitize but allow basic HTML (divs, tables, etc.) to render inside the bubble
    import re

    content = message["content"]
    # Strip script tags and inline JS event handlers
    content = re.sub(r'(?is)<script.*?>.*?</script>', '', content)
    content = re.sub(r'(?i)\son\\w+\s*=\s*"[^"]*"', '', content)
    content = re.sub(r"(?i)\son\\w+\s*=\s*'[^']*'", '', content)
    content = re.sub(r'(?i)\son\\w+\s*=\s*[^\s>]+', '', content)

    # Basic markdown emphasis to HTML for nicer rendering
    content = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', content)
    content = re.sub(r'\*(.*?)\*', r'<em>\1</em>', content)
    # Make lines starting with #... bold and strip the leading # symbols
    content = re.sub(r'(?m)^\s*#{1,6}\s*(.+)$', r'<strong>\1</strong>', content)
    
    # Fix ordered and unordered lists - remove excessive spacing
    # Convert markdown lists to proper HTML lists
    content = re.sub(r'(?m)^(\s*)(\d+\.)\s+(.+)$', r'\1<li>\3</li>', content)
    content = re.sub(r'(?m)^(\s*)([-*+]\s+)(.+)$', r'\1<li>\3</li>', content)
    
    # Wrap consecutive list items in <ol> or <ul> tags
    def wrap_lists(text):
        lines = text.split('\n')
        result = []
        in_list = False
        list_type = None
        list_items = []
        
        for line in lines:
            # Check if line is a list item
            ol_match = re.match(r'^\s*<li>(.+?)</li>\s*$', line)
            ul_match = re.match(r'^\s*<li>(.+?)</li>\s*$', line)
            
            if ol_match or ul_match:
                if not in_list:
                    in_list = True
                    list_type = 'ol' if ol_match else 'ul'
                list_items.append(line)
            else:
                # End of list
                if in_list and list_items:
                    result.append(f'<{list_type}>')
                    result.extend(list_items)
                    result.append(f'</{list_type}>')
                    list_items = []
                    in_list = False
                result.append(line)
        
        # Handle list at end of content
        if in_list and list_items:
            result.append(f'<{list_type}>')
            result.extend(list_items)
            result.append(f'</{list_type}>')
        
        return '\n'.join(result)
    
    content = wrap_lists(content)
    
    # Collapse excessive blank lines
    content = re.sub(r'\n{3,}', '\n\n', content)
    # Unwrap any HTML code fences so tags render
    content = re.sub(r'```(?:[a-zA-Z]+)?\s*([\s\S]*?)```', r'\1', content)
    # Convert markdown pipe tables to HTML tables
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
        <div class=\"th-row user\">
            <div class=\"th-avatar\">👤</div>
            <div class=\"th-bubble user\">
                <div class=\"th-chat\">{content}</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        # Assistant message on the right with icon beside bubble
        st.markdown(f"""
        <div class=\"th-row assistant\">
            <div class=\"th-bubble assistant\">
                <div class=\"th-chat\">{content}</div>
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

# Add JavaScript for interactive features
st.markdown("""
<script>
// Make sample questions clickable
document.addEventListener('DOMContentLoaded', function() {
    const sampleItems = document.querySelectorAll('.sample-item');
    sampleItems.forEach(item => {
        item.addEventListener('click', function() {
            const text = this.textContent.trim();
            const chatInput = document.querySelector('.stChatInput textarea');
            if (chatInput) {
                chatInput.value = text;
                chatInput.dispatchEvent(new Event('input', { bubbles: true }));
                chatInput.focus();
            }
        });
    });
    
    // Add hover effects to feature cards
    const featureCards = document.querySelectorAll('.feature-card');
    featureCards.forEach(card => {
        card.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-4px) scale(1.02)';
        });
        card.addEventListener('mouseleave', function() {
            this.style.transform = 'translateY(0) scale(1)';
        });
    });
    
    // Smooth scrolling for better UX
    const smoothScroll = (target) => {
        target.scrollIntoView({
            behavior: 'smooth',
            block: 'start'
        });
    };
    
    // Add smooth scrolling to all internal links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                smoothScroll(target);
            }
        });
    });
});

// Add typing indicator animation
function addTypingIndicator() {
    const typingDiv = document.createElement('div');
    typingDiv.className = 'th-row assistant';
    typingDiv.innerHTML = `
        <div class="th-bubble assistant">
            <div class="th-chat">
                <div class="loading-dots">Thinking</div>
            </div>
        </div>
        <div class="th-avatar">🤖</div>
    `;
    document.body.appendChild(typingDiv);
    return typingDiv;
}

// Remove typing indicator
function removeTypingIndicator(typingDiv) {
    if (typingDiv && typingDiv.parentNode) {
        typingDiv.parentNode.removeChild(typingDiv);
    }
}
</script>
""", unsafe_allow_html=True)

# Chat input with improved styling
st.markdown("""
<style>
/* Chat input styling */
.stChatInput {
    background: #1e293b !important;
    border: 2px solid #334155 !important;
    border-radius: 12px !important;
    color: #f8fafc !important;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
    font-size: 1rem !important;
    padding: 1rem 1.25rem !important;
    transition: all 0.2s ease !important;
    position: relative !important;
    z-index: 1000 !important;
    margin-bottom: 2rem !important;
}

/* Ensure chat input container has proper spacing */
.stChatInputContainer {
    margin-bottom: 1rem !important;
}

.stChatInput:focus {
    border-color: #6366f1 !important;
    box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.1) !important;
    outline: none !important;
}

.stChatInput::placeholder {
    color: #94a3b8 !important;
}

/* Chat container styling */
.main .block-container {
    padding-top: 2rem !important;
    padding-bottom: 2rem !important;
    max-width: 1200px !important;
}

/* Sidebar styling */
.sidebar .sidebar-content {
    background: #1e293b !important;
    border-right: 1px solid #334155 !important;
}

/* Success message styling */
.stSuccess {
    background: rgba(34, 197, 94, 0.1) !important;
    border: 1px solid rgba(34, 197, 94, 0.3) !important;
    color: #22c55e !important;
    border-radius: 8px !important;
    padding: 0.75rem 1rem !important;
}

/* Error message styling */
.stError {
    background: rgba(239, 68, 68, 0.1) !important;
    border: 1px solid rgba(239, 68, 68, 0.3) !important;
    color: #ef4444 !important;
    border-radius: 8px !important;
    padding: 0.75rem 1rem !important;
}

/* Warning message styling */
.stWarning {
    background: rgba(245, 158, 11, 0.1) !important;
    border: 1px solid rgba(245, 158, 11, 0.3) !important;
    color: #f59e0b !important;
    border-radius: 8px !important;
    padding: 0.75rem 1rem !important;
}

/* Info message styling */
.stInfo {
    background: rgba(99, 102, 241, 0.1) !important;
    border: 1px solid rgba(99, 102, 241, 0.3) !important;
    color: #6366f1 !important;
    border-radius: 8px !important;
    padding: 0.75rem 1rem !important;
}

/* Button styling */
.stButton > button {
    background: linear-gradient(135deg, #6366f1, #4f46e5) !important;
    color: white !important;
    border: none !important;
    border-radius: 8px !important;
    padding: 0.5rem 1rem !important;
    font-weight: 600 !important;
    transition: all 0.2s ease !important;
    box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05) !important;
}

.stButton > button:hover {
    transform: translateY(-1px) !important;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1) !important;
    background: linear-gradient(135deg, #4f46e5, #6366f1) !important;
}

/* Expander styling */
.streamlit-expanderHeader {
    background: #1e293b !important;
    border: 1px solid #334155 !important;
    border-radius: 8px !important;
    color: #f8fafc !important;
    font-weight: 600 !important;
    padding: 0.75rem 1rem !important;
}

.streamlit-expanderContent {
    background: #334155 !important;
    border: 1px solid #334155 !important;
    border-top: none !important;
    border-radius: 0 0 8px 8px !important;
    padding: 1rem !important;
}

 /* Spinner styling */
 .stSpinner > div {
     border-color: #6366f1 !important;
     border-top-color: transparent !important;
 }
 
 /* List styling to reduce spacing */
 .th-chat ol, .th-chat ul {
     margin: 0.5rem 0 !important;
     padding-left: 1.5rem !important;
 }
 
 .th-chat li {
     margin: 0.25rem 0 !important;
     line-height: 1.4 !important;
 }
 
 .th-chat ol ol, .th-chat ul ul, .th-chat ol ul, .th-chat ul ol {
     margin: 0.25rem 0 !important;
 }
 
 /* Table styling for chat bubbles */
 .table-container {
     margin: 0.75rem 0 !important;
     overflow-x: auto !important;
     border-radius: 8px !important;
     background: rgba(30, 41, 59, 0.5) !important;
     border: 1px solid #334155 !important;
 }
 
 .chat-table {
     width: 100% !important;
     border-collapse: collapse !important;
     font-size: 0.85rem !important;
     line-height: 1.3 !important;
     margin: 0 !important;
     background: transparent !important;
 }
 
 .chat-table thead {
     background: rgba(51, 65, 85, 0.8) !important;
 }
 
 .chat-table th {
     padding: 0.5rem 0.75rem !important;
     text-align: left !important;
     font-weight: 600 !important;
     color: #f8fafc !important;
     border-bottom: 2px solid #475569 !important;
     font-size: 0.8rem !important;
     text-transform: uppercase !important;
     letter-spacing: 0.5px !important;
 }
 
 .chat-table td {
     padding: 0.5rem 0.75rem !important;
     border-bottom: 1px solid #334155 !important;
     color: #cbd5e1 !important;
     vertical-align: top !important;
     word-wrap: break-word !important;
     max-width: 200px !important;
 }
 
 .chat-table tbody tr:hover {
     background: rgba(51, 65, 85, 0.3) !important;
 }
 
 .chat-table tbody tr:last-child td {
     border-bottom: none !important;
 }
 
 /* Responsive table handling */
 @media (max-width: 768px) {
     .chat-table {
         font-size: 0.75rem !important;
     }
     
     .chat-table th,
     .chat-table td {
         padding: 0.4rem 0.5rem !important;
         max-width: 150px !important;
     }
 }
 
 /* Ensure tables don't overflow chat bubbles */
 .th-bubble .table-container {
     max-width: 100% !important;
     margin-left: 0 !important;
     margin-right: 0 !important;
 }
 
 /* Code block styling within tables */
 .chat-table code {
     background: rgba(51, 65, 85, 0.8) !important;
     padding: 0.1rem 0.3rem !important;
     border-radius: 3px !important;
     font-family: 'Courier New', monospace !important;
     font-size: 0.8rem !important;
     color: #10b981 !important;
 }
 
 /* Status indicators in tables */
 .chat-table .status-active {
     color: #10b981 !important;
     font-weight: 600 !important;
 }
 
 .chat-table .status-inactive {
     color: #ef4444 !important;
     font-weight: 600 !important;
 }
 
 .chat-table .status-warning {
     color: #f59e0b !important;
     font-weight: 600 !important;
 }
 
 /* Ensure chat bubbles can accommodate tables */
.th-bubble {
    max-width: 100% !important;
    overflow: hidden !important;
}

/* Add proper spacing between chat messages and input */
.th-row {
    margin-bottom: 1.5rem !important;
}

/* Ensure last message has proper spacing from input */
.th-row:last-child {
    margin-bottom: 2rem !important;
}


 
 .th-bubble .th-chat {
     overflow-x: auto !important;
     word-wrap: break-word !important;
 }
 
 /* Improve table readability in chat */
 .th-chat .table-container {
     box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2) !important;
 }
 
 /* Compact table for mobile */
 @media (max-width: 480px) {
     .chat-table {
         font-size: 0.7rem !important;
     }
     
     .chat-table th,
     .chat-table td {
         padding: 0.3rem 0.4rem !important;
         max-width: 120px !important;
     }
     
     .table-container {
         margin: 0.5rem 0 !important;
     }
 }
</style>
""", unsafe_allow_html=True)

if prompt := st.chat_input("Ask me something about your security infrastructure..."):
    # Add user message to chat history
    st.session_state.messages.append({"role": "user", "content": prompt})
    st.session_state.conversation_started = True
    
    # Set conversation start time if this is the first message
    if len(st.session_state.messages) == 1:
        from datetime import datetime
        st.session_state.conversation_start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Display user message (will be shown in the loop above)
    pass
    
    # Add to memory
    st.session_state.memory.chat_memory.add_user_message(prompt)

    # Generate response
    async def handle_response():
        previous_answer = st.session_state.get("last_data")
        mcp_client = st.session_state.mcp_client
        resource_list = "\n".join([f"- {desc}" for desc in mcp_client.resource_map.keys()])
        is_followup = await mcp_client.is_follow_up(prompt, previous_answer, resource_list)
        print(f"[DEBUG] Follow-up detection result: {is_followup}")
        print(f"[DEBUG] Previous answer exists: {previous_answer is not None}")
        print(f"[DEBUG] Previous answer length: {len(previous_answer) if previous_answer else 0}")
        if not previous_answer:
            print(f"[INFO] Is follow-up: {is_followup}, Previous answer: {previous_answer}")
        else:
            print(f"[INFO] Is follow-up: {is_followup}")
            print(f"[DEBUG] Previous answer preview: {previous_answer[:200]}...")
        # Check for CVE-related queries (both follow-up and new queries)
        cve_keywords = ["cve", "vulnerability", "exploit", "patch", "advisory", "security advisory"]
        is_cve_query = any(keyword in prompt.lower() for keyword in cve_keywords)
        
        # Trigger web search for CVE queries (both follow-up and new)
        if is_cve_query:
            # conversation_messages.append({"role": "user", "content": prompt})
            print("[INFO] Triggering web search for vulnerability query...")
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

                Also return External URL for vulnerabilities if available. for example: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-50166 for CVE-2025-50166
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
            response = completion.choices[0].message.content.strip()

            st.session_state.memory.chat_memory.add_ai_message(response)
            return response

        if is_followup and previous_answer:
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
            if 'loop' in locals() and loop.is_running():
                loop = asyncio.get_running_loop()
                asyncio.set_event_loop(loop)
                result = loop.run(handle_response())
            else:
                result = asyncio.run(handle_response())
            
            # Add assistant message to chat history
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

# Sidebar with improved styling
with st.sidebar:
    st.markdown("""
    <div style="text-align: center; padding: 1rem 0; border-bottom: 1px solid #334155; margin-bottom: 1rem;">
        <h3 style="color: #6366f1; margin: 0; font-size: 1.3rem;">🛡️ Threat Hawk</h3>
        <p style="color: #cbd5e1; margin: 0.5rem 0 0 0; font-size: 0.9rem;">Smart Monitoring System</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Connection status
    if st.session_state.connected:
        st.success("✅ Connected to Threat Hawk")
    else:
        st.error("❌ Connection Failed")
    
    # Conversation management
    if st.session_state.conversation_started:
        st.markdown("### 💬 Conversation")
        
        # Stats
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Messages", len(st.session_state.messages))
        with col2:
            st.metric("Context limit", "10", delta="" + str(10 - len(st.session_state.messages)))
        
        # Action buttons
        if len(st.session_state.messages) > 0:
            col1, col2 = st.columns(2)
            with col1:
                if st.button("🆕 Chat", use_container_width=True):
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
            
            with col2:
                if st.button("🗑️ Clear", use_container_width=True):
                    st.session_state.messages = []
                    st.session_state.memory = ConversationBufferMemory(return_messages=True)
                    st.session_state.conversation_started = False
                    st.session_state.last_data = None
                    st.rerun()
        
        # Conversation history
        if st.session_state.conversation_history:
            st.markdown("---")
            st.markdown("### 📚 History")
            for i, conv in enumerate(reversed(st.session_state.conversation_history)):
                with st.expander(f"💬 {conv['first_message']} ({conv['message_count']} msgs)", expanded=False):
                    st.caption(f"Started: {conv['timestamp']}")
                    st.caption(f"Messages: {conv['message_count']}")
                    
                    if st.button(f"📖 View", key=f"view_{i}", use_container_width=True):
                        st.markdown("**Full Conversation:**")
                        for msg in conv['messages']:
                            if msg["role"] == "user":
                                st.markdown(f"**👤 You:** {msg['content']}")
                            else:
                                st.markdown(f"**🤖 Assistant:** {msg['content']}")
                            st.markdown("---")
    
    # Quick actions
    st.markdown("---")
    st.markdown("### ⚡ Quick Actions")
    
    # Quick question buttons
    quick_questions = [
        "Show me active agents",
        "Critical alerts last 24h",
        "System health status",
        "Recent vulnerabilities"
    ]
    
    for question in quick_questions:
        if st.button(f"🔍 {question}", key=f"quick_{question}", use_container_width=True):
            # Add the question directly to chat history and trigger processing
            st.session_state.messages.append({"role": "user", "content": question})
            st.session_state.conversation_started = True
            
            # Set conversation start time if this is the first message
            if len(st.session_state.messages) == 1:
                from datetime import datetime
                st.session_state.conversation_start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Add to memory
            st.session_state.memory.chat_memory.add_user_message(question)
            
                         # Generate response
            async def handle_quick_response():
                previous_answer = st.session_state.get("last_data")
                mcp_client = st.session_state.mcp_client
                resource_list = "\n".join([f"- {desc}" for desc in mcp_client.resource_map.keys()])
                is_followup = await mcp_client.is_follow_up(question, previous_answer, resource_list)
                 
                 # Check for CVE-related queries in quick actions too
                cve_keywords = ["cve", "vulnerability", "exploit", "patch", "advisory", "security advisory"]
                is_cve_query = any(keyword in question.lower() for keyword in cve_keywords)
                 
                 # Trigger web search for CVE queries (both follow-up and new)
                if is_cve_query:
                    print("[INFO] Triggering web search for vulnerability query from quick action...")
                    system_prompt = (f"""
                     You are a cybersecurity assistant specializing in vulnerability research and remediation.
                     
                     User Query: {question}
                     
                     Your task:
                         1. If the query contains a specific CVE ID (e.g., CVE-2023-12345), search for that specific vulnerability
                         2. If the query is about general vulnerabilities, security advisories, or exploits, search for relevant recent information
                         3. Search authoritative sources (NVD, MITRE, vendor advisories, security blogs, exploit databases, GitHub if applicable) for the latest technical details
                         4. Provide accurate, up-to-date information about the vulnerability or security topic
                         
                     Output Format:
                         - Brief summary of the vulnerability/security issue
                         - Key technical details (affected products, versions, severity, exploitability)
                         - Recommended actions or remediation steps
                         - External URLs for official advisories if available
                         
                     For External Source vulnerabilities, include the URL for the vulnerability.
                     """)
                     
                    messages = [
                         {"role": "system", "content": system_prompt},
                         {"role": "user", "content": f"User query: {question}"}
                     ]
                    completion = mcp_client.chat_client.chat.completions.create(
                         messages=messages,
                         max_completion_tokens=1500,
                         temperature=0.7,
                         model=mcp_client.model_name
                     )
                    response = completion.choices[0].message.content.strip()
                     
                    st.session_state.memory.chat_memory.add_ai_message(response)
                    return response
                 
                if is_followup and previous_answer:
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
                    conversation_messages.append({"role": "user", "content": question})
                    completion = mcp_client.chat_client.chat.completions.create(
                        messages=conversation_messages,
                        max_completion_tokens=800,
                        temperature=0.7,
                        model=mcp_client.model_name
                    )
                    response = completion.choices[0].message.content.strip()
                else:
                    # New query
                    result = await mcp_client.process_query(question)
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
                    if 'loop' in locals() and loop.is_running():
                        loop = asyncio.get_running_loop()
                        asyncio.set_event_loop(loop)
                        result = loop.run(handle_quick_response())
                    else:
                        result = asyncio.run(handle_quick_response())
                    
                    # Add assistant message to chat history
                    st.session_state.messages.append({"role": "assistant", "content": result})
                    st.rerun()  # Rerun to show the new message
                
                except Exception as e:
                    error_msg = f"❌ Error: {e}"
                    st.error(error_msg)
                    st.session_state.messages.append({"role": "assistant", "content": error_msg})
                    st.rerun()  # Rerun to show the error message
    
    # System info
    st.markdown("---")
    st.markdown("### ℹ️ System Info")
    st.caption("Version: 1.0.0")
    st.caption("Status: Active")
    st.caption("Last Updated: " + st.session_state.get("conversation_start_time", "N/A"))
