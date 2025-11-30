import frida

data = open("dist/bundle.js", "r", encoding="utf-8").read()

open(f"dist/libgene.script.so", "wb").write(frida.attach(0).compile_script(data))