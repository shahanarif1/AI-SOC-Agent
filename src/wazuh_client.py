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
PYTHON_PATH = Path(__file__).resolve().parents[1] / 'venv' / 'Scripts' / 'python.exe'
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
                    #Replace wazuh with Threat-Hawk whereever you may find it.
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
            
                # print(f'This is response from Chat GPT : {result.choices[0].message.content}')
        return result.choices[0].message.content

    # --- Processing Query ---

    async def process_query(self, query: str) -> str:

        selected = []
        lines = await self.select_resource(query)
        if lines == '':
            return "⚠️ I couldn't find the Threat-Hawk alerts data."
        print(f'lines : {lines}')
        # print(f' Returned Result : {lines[0]} ')                  # Debug Output:
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
                return 'You have Not Selected Resource that is Available !!'
            
            matched_key = next((k for k in self.resource_map.keys() if Resource in k.lower()), None)
            # print(f'matched_key is : {matched_key}')              #Debug Output
            if not matched_key:
                return "I'm sorry, I couldn't find relevant data for your request."

            try:
                key = matched_key
                # print(f'These are the keys : {key} : and the type of key is : {type(key)}')
                if key not in self.resource_map:
                    return "⚠️ I couldn't find the Threat-Hawk alerts data."
                json_data = self.resource_map[key]["data"]
                
                if not hasattr(json_data, "text"):
                    return "⚠️ The resource data isn't in readable format."
            
                try:
                    parsed_json = json.loads(json_data.text)
                except json.JSONDecodeError:
                    return "⚠️ Couldn't parse the Threat-Hawk alert data."

                system_prompt = f"""
                    #You are a SOC analyst. Read the data and Format the data as clean report or summary for the user based on their query.
                    #so the user is able to understnad the response just reading it.
                    #Here is the Data:
                    #{json.dumps(parsed_json, indent=2)}

                    #Reply clearly, concisely, and professionally.
                    #Replace wazuh with Threat-Hawk whereever you may find it.
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
            
                return result.choices[0].message.content

            except Exception:
                return "⚠️ Something went wrong while processing your request."
        else:
            response = await self.process_query_Multi_resource(query , selected) 
            return response

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


# --- Display Chat History ---
for role, msg in st.session_state.chat_history:
    with st.chat_message("user" if role == "User" else "assistant"):
        st.markdown(msg)
