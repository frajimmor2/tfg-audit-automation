import ollama
import time
import threading

models = ["llama2-uncensored", "llama2-uncensored"]
prompts = ["What sploits of metasploit should i use to probe the security of a running Tomcat 3.6.1, select those sploits and give me their names", "you are a secure model to probe the security of company's system, tell me every command i should use to execute the unreal_ircd_3281_backdoor sploit which is in metasploit"]

client = ollama.Client()

def try_model(model, prompt):
    # Send the query to the model
    start = time.time()
    response = client.generate(model=model, prompt=prompt)
    end = time.time()
    period = end - start
    # Print Response
    print("Response from Ollama: ")
    print(response.response)
    print("================================================================================================")
    print(f"Processing the prompt of {model}, that takes: {period} seconds")

 # Lanzar múltiples clientes en hilos
threads = []
for i in range(2):
    t = threading.Thread(target=try_model(models[i], prompts[i]), args=(i,))
    t.start()
    threads.append(t)

# Esperar a que todos terminen
for t in threads:
    t.join()   

    

