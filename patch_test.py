from crewai import Agent, Task, Crew, LLM
from dotenv import load_dotenv
import litellm

# Litellm should drop unsupported params
litellm.drop_params = True

load_dotenv()

llm = LLM(model="groq/llama-3.3-70b-versatile", temperature=0.1)
agent = Agent(role="test", goal="test", backstory="test", llm=llm)
task = Task(description="say hi", expected_output="a greeting", agent=agent)
crew = Crew(agents=[agent], tasks=[task])

try:
    print(crew.kickoff())
except Exception as e:
    print("ERROR:", e)
