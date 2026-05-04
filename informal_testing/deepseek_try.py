from transformers import AutoModel, AutoTokenizer
import argparse

model_name = "DeepSeek-R1-Distill-Llama-8B"  # Reemplaza con el nombre exacto del modelo
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModel.from_pretrained(model_name)



def main():
    parser = argparse.ArgumentParser(description="CLI para usar el modelo DeepSeek V3")
    parser.add_argument("input", type=str, help="Texto de entrada para el modelo")
    args = parser.parse_args()

    # Procesar la entrada con el modelo
    inputs = tokenizer(args.input, return_tensors="pt")
    outputs = model(**inputs)

    print(outputs)

if __name__ == "__main__":
    main()
