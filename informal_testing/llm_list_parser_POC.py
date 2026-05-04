import ollama
import time
# Initialize the Ollama client
start = time.time()
client = ollama.Client()
end = time.time()
period = end - start
print(f"Setup client: {period} seconds")

# Define model and the input prompt
model = "llm_list_parser"
prompt = ["exploi1,exploit2,exploit3", "-exploit1           -exploit2", "exploit1, exploit2,     exploit3"]

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
print("Expected: exploit1,exploit2,exploit3")
