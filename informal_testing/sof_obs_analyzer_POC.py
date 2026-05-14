import ollama
import time

# Initialize the Ollama client
start = time.time()
client = ollama.Client()
end = time.time()
period = end - start
print(f"Setup client: {period} seconds")

# Define model and the input prompt
model = "soft_obs_analyzer"
prompt = [
    "service: telnet   other_info: ",
    "service: rexec   other_info: ",
    "service: ssh    other_info: ",
]

# Send the query to the model
start = time.time()
response = client.generate(model=model, prompt=prompt[1])
end = time.time()
period = end - start
# Print Response
print("Response from Ollama: ")
print(response.response)
print(f"Processing the prompt takes: {period} seconds")

# send another query
start = time.time()
response = client.generate(model=model, prompt=prompt[0])
end = time.time()
period = end - start

# Print Response
print("Response from Ollama: ")
print(response.response)
print(f"Processing the prompt takes: {period} seconds")

# send another query
start = time.time()
response = client.generate(model=model, prompt=prompt[2])
end = time.time()
period = end - start

# Print Response
print("Response from Ollama: ")
print(response.response)
print(f"Processing the prompt takes: {period} seconds")

print("============================================")
print("Expected: 1, 1, 0")
