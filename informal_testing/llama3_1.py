import ollama
import time

# Initialize the Ollama client
start = time.time()
client = ollama.Client()
end = time.time()
period = end - start
print(f"Setup client: {period} seconds")

# Define model and the input prompt
model = "llama3.1"
prompt = "Explain me whats a CVE in cybersecurity therms"

# Send the query to the model
start = time.time()
response = client.generate(model=model, prompt=prompt)
end = time.time()
period = end - start
# Print Response
print("Response from Ollama: ")
print(response.response)
print(f"Processing the prompt takes: {period} seconds")

# send another query
start = time.time()
response = client.generate(model=model, prompt="whats metasploit?")
end = time.time()
period = end - start

# Print Response
print("Response from Ollama: ")
print(response.response)
print(f"Processing the prompt takes: {period} seconds")
