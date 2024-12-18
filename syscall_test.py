import os
import time

def main():
    # Create a test file
    filename = "test_syscalls.txt"

    # Open file for writing
    print(f"Opening {filename} for writing...")
    with open(filename, "w") as f:
        # Write some data
        print("Writing data...")
        f.write("Hello, World!\n")
        f.write("This is a test file.\n")
        # Force flush to ensure write happens
        f.flush()
        # Sleep to make it easier to observe
        time.sleep(1)

    # Open file for reading
    print(f"Opening {filename} for reading...")
    with open(filename, "r") as f:
        # Read the file content
        print("Reading data...")
        content = f.read()
        print(f"Read content: {content}")
        time.sleep(1)

    # Explicit close happens automatically with 'with' statement

    # Clean up
    print("Removing test file...")
    os.remove(filename)

if __name__ == "__main__":
    print(f"Process ID: {os.getpid()}")
    time.sleep(10)
    main()