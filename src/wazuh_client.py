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

MCP_SERVER_PATH = os.getenv("MCP_SERVER_PATH")
SUBSCRIPTION_KEY = os.getenv("OPENAI_API_KEY")
END_POINT = os.getenv("END_POINT")
ENV_PATH = Path(__file__).resolve().parents[1] / '.env'
SERVER_PATH = Path(__file__).resolve().parents[1] /'src'/'wazuh_mcp_server'/'main.py'
project_root = Path(__file__).resolve().parent.parent.parent

# print(f'These are the paths {ENV_PATH} and Server path:{SERVER_PATH}')
# import sys
# sys.exit(0)




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

    async def connect(self, server_path: str):
        server_params = StdioServerParameters(
            command="python",
            args=[str(server_path)],
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

    async def process_query(self, query: str) -> str:

         # Step 1: Ask LLM if a resource is needed
        resource_list = "\n".join([f"- {desc}" for desc in self.resource_map.keys()])

        assistant_prompt = f"""
        # You are an helpful assistant."
        # Choose one resource realted to asked about in the query. 
        # Here are available data sources:
        # {resource_list}
        # reply with ONLY one exact matching resource description. if you think more than one corrosponds still select one and return only one resource. 
        # reply ONLY with the exact matching resource description.
        # If not, reply with: NONE
        # """

        user_prompt = f'''
        
        #{query}

         '''
        
        completion = self.chat_client.chat.completions.create(messages = [{'role': 'assistant' , 'content':assistant_prompt}
                                                                               ,{'role':'user' , 'content':user_prompt}],
                                                                               max_completion_tokens = 1000,
                                                                               temperature = 1.0,
                                                                               top_p=1.0,
                                                                               frequency_penalty=0.0,
                                                                               presence_penalty=0.0,
                                                                               model = self.model_name )
        # selected = detect_response.content.strip().lower()
        print(f'this is the response from the chatgpt :  { completion.choices[0].message.content}')
        lines = completion.choices[0].message.content.strip().splitlines()
        for line in reversed(lines):
            if line.strip():
                selected = line.strip().lower()
                import re
                selected = re.sub(r'[^A-Za-z ]+', '', selected)
        print(f'selected:{selected}')
        
        if selected == "none":
            # response = self.chat_client.response()
            return 'You have Not Selected Resource that is Available !!'
        
        selected = selected.lower().strip()
        # print(f'selected key:{selected}')
        # print(f'{self.resource_map.keys()}') 
        matched_key = next((k for k in self.resource_map.keys() if selected in k.lower()), None)
        # print(f'matched_key:{matched_key}selected:{selected}')
        if not matched_key:
            return "I'm sorry, I couldn't find relevant data for your request."

        try:
            key = matched_key
            print(f'Here:  type of matched key is : {type(matched_key)} and Matched key is: {key} ')
            if key not in self.resource_map:
                return "⚠️ I couldn't find the Wazuh alerts data."
            json_data = self.resource_map[key]["data"]
            # print(f'SO this is json data : {json_data}')
            if not hasattr(json_data, "text"):
                return "⚠️ The resource data isn't in readable format."
            
            try:

                parsed_json = json.loads(json_data.text)
                # print(f'This is the parsed JSON : {parsed_json}')
            except json.JSONDecodeError:
                return "⚠️ Couldn't parse the Wazuh alert data."

            system_prompt = f"""
                #You are a SOC analyst. Read the data and Format the data as clean report or summary for the user based on their query.
                #so the user is able to understnad the response just reading it. 
                #Here is the Data:
                #{json.dumps(parsed_json, indent=2)}

                #Reply clearly, concisely, and professionally.
                #Replace : Replace Whereever Wazuh is with Threat-Hawk 
                """
            try:
                result = self.chat_client.chat.completions.create(messages = [{'role': 'system' , 'content':system_prompt}
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
            
            print(f'This is response from Chat GPT : {result.choices[0].message.content}')
            return result.choices[0].message.content

        except Exception:
            return "⚠️ Something went wrong while processing your request."

    async def close(self):
        await self.exit_stack.aclose()

# --- Streamlit Setup ---


st.set_page_config(page_title="Threat-Hawk Smart", layout="centered")
st.header("   🛡️ Threat-Hawk Smart Monitoring ")


if "messages" not in st.session_state:
# --- Session State Init ---
    # st.markdown("# Welcome to My Threat Hawk Smart Monitoring!")
    st.subheader('''
            Welcome to Threat Hawk 🧠 Smart Monitoring System!
            ''')
    st.markdown('''
        Where you can Monitor your Network. By talking to our smart monitoring sytem and getting real time results.
        Please follow the instructions below to get started:
                ''')
    st.subheader("Sample FAQ's ")
    st.markdown("🕵️ : -Show me Active and non-Active Agents")
    st.markdown("🕵️ : -Show me Critical Alerts in last 24 Hours")
    st.markdown("🕵️ : -Show Over-all system Health ")
      
    # st.write(''' <h3>  ⚠️ Functinalities Available </h3>\n\n''')
    col1, col2 = st.columns(2)
    with col1:
        st.write("-***Recent Alerts***")
        st.write("-***Alert Summary***")
        st.write("-***Agent Status***")
        st.write("-***Critical Vulnerabilities***")
        st.write("-***Compliance Status***")
        st.write("-***Active Threats***")
        st.write("-***System Health***")
        
    with col2:
        st.write("(Recent Security Alerts)")
        st.write("(Statistical Summary of Alerts)")
        st.write("(Status Across Agents)")
        st.write("(Vulnerabilities Across Agents)")
        st.write("(Current Compliance Posture)")
        st.write("(Current Active Threat Indicators)")
        st.write("(Over-All System Health Metrics)")

    st.session_state.chat_history = []
if "memory" not in st.session_state:
    st.session_state.memory = ConversationBufferMemory(return_messages=True)
if "mcp_client" not in st.session_state:
    st.session_state.mcp_client = None
    st.session_state.connected = False

# --- MCP Connect Once ---
async def setup_mcp():
    client = MCPClient()
    await client.connect(SERVER_PATH)
    st.session_state.mcp_client = client
    st.session_state.connected = True

if not st.session_state.connected:
    with st.spinner("Connecting to Threat Hawk server..."):
        asyncio.run(setup_mcp())
    st.success("✅ Connected to Threat Hawk.")
# if "chat_history" not in st.session_state:
            
# --- Chat Input Handling ---

user_input = st.chat_input("Ask me something...")

if user_input:
    st.chat_message("user").markdown(user_input)
    # st.session_state.chat_history.append(("User", user_input))

    async def handle_response():
        return await st.session_state.mcp_client.process_query(user_input)

    # with st.chat_message("assistant"):
    with st.spinner("Thinking..."):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try: 
            result =  loop.run_until_complete(handle_response())
            # st.markdown(result)
            st.chat_message("assistant").markdown(result)
            # st.session_state.chat_history.append(("Bot", result))
        except:
            loop.close()
            result = 'This server is done for !!!!'
            if st.button("Shut Down Application"):
                import signal
                os.kill(os.getpid(), signal.SIGKILL)


            # st.markdown(result)
            # st.session_state.chat_history.append(("Bot", result))

# --- Display Chat History ---
for role, msg in st.session_state.chat_history:
    with st.chat_message("user" if role == "User" else "assistant"):
        st.markdown(msg)
