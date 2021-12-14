## Python Script to Compare H1 and H2 values ##
def main():
	h1 = "b96b86946a972e63fd0df5471a1e2d3999e3541cb706fbb038e6e7f2a59bf94e"
	h2 = "f0c4c1c0a7766794f74ff7da1018cdb3f130daf8d2b1851148c9c6ee4785db5b"
	
	equal = 0
	for i in range(len(h1) - 1, -1, -1):
		if h1[i] == h2[i]:
			equal += 1
	print("There are ", equal, " similar bits between H1 and H2.")

if __name__ == "__main__":
	main()

