out = open(r"C:\Users\Cameron\Desktop\Cameron new.txt", "w")
with open(r"C:\Users\Cameron\Desktop\Camerons log.txt", "r") as file:
    for line in file:
        if line[:6] == "[DATA]":
            out.write(line)
            print(line)

out.flush()
out.close()

