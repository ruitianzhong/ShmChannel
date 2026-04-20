#!/bin/env python3
import time

time.sleep(1)

print("Ok")
print("Doing initialization")
print("Init")

while True:
    try:
        first = input("[HUAWEI] ")
        print(f"Doing {first}")
        time.sleep(0.5)

    except EOFError as e:
        break
    first = first.strip()

    if first == "exit":
        break
