with open(r"C:\Users\Cameron\Documents\GitHub\openGame\Log tools\Cameron new.txt", "r") as testFile:
    with open(r"C:\Users\Cameron\Documents\GitHub\openGame\Log tools\Logan new.txt", "r") as ctrlFile:
        f = open(r"C:\Users\Cameron\Documents\GitHub\openGame\Log tools\Log Result.txt", "w")
        testFileList = [a for a in testFile]
        for i, line in enumerate(ctrlFile):
            try:
                print(str(i) + ": " + str(testFileList.index(line)), file=f)
            except ValueError:
                print(str(i) + ": NO MATCH", file=f)
                
        f.flush()
        f.close()