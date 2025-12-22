import typer
# from typing_extensions import Annotated


app = typer.Typer()


@app.command()
def test(name: str):
    print(f"This is working {name}")


@app.command()
def run(target: str):
    print("Running")


@app.command("setModels")
def setModels():
    print("Installing all the ollama models")


if __name__ == "__main__":
    app()
