# rust-memtester
Reconstructed using Rust for memtester

## Project Overview

This project is a multi-threaded memory tester written in Rust. It's designed to test RAM for faults by running various test patterns on allocated memory. The tool is highly configurable, allowing the user to specify the amount of memory to test, the number of CPU cores to use, the duration of the test, and the specific test patterns to run.

The project is structured into several modules:

*   `main.rs`: The main application logic, including thread creation and management.
*   `utils.rs`: Handles command-line argument parsing, memory allocation, and other utilities.
*   `tests.rs`: Defines and implements the various memory test patterns.
*   `logger.rs`: Provides logging functionality.
*   `cpu_utils.rs`: Contains functions for CPU core management, such as binding threads to specific cores.
*   `ecc.rs`: Appears to be related to ECC memory error checking, although its full implementation is not clear from the initial analysis.

## Building and Running

This is a Rust project, so it uses `cargo` to build and run.

**To build the project:**

```bash
cargo build
```

**To run the project:**

The program accepts several command-line arguments to control its behavior. Here are some examples based on the `src/utils.rs` file:

* **Test with default memory (total memory - 4GB) for 30 minutes:**

  ```bash
  cargo run -- --time 30
  ```

* **Test 1GB of memory for 10 loops:**

  ```bash
  cargo run -- --memory 1G --loops 10
  ```

* **Test 512MB of memory using 8 cores for 15 minutes:**

  ```bash
  cargo run -- --memory 512M --cores 8 --time 15
  ```

* **Test with a specific test pattern (hex mask):**

  ```bash
  cargo run -- --pattern 0x1
  ```

**Available Arguments:**

*   `-m`, `--memory`: The amount of memory to test (e.g., `1G`, `512M`). Defaults to the total memory minus 4GB.
*   `-l`, `--loops`: The number of test loops to run.
*   `-t`, `--time`: The maximum time to run the tests in minutes.
*   `-c`, `--cores`: The number of CPU cores to use.
*   `-p`, `--pattern`: A hex mask to select specific test patterns to run.
*   `-L`, `--log-path`: The path to the directory where the log file should be saved.

## Development Conventions

*   **Language:** The project is written in Rust and follows standard Rust conventions.
*   **Error Handling:** The project uses Rust's `Result` type for error handling, which is idiomatic and ensures that errors are handled explicitly.
*   **Concurrency:** The project is multi-threaded and uses `std::thread` for thread management. It uses atomic types and barriers for synchronization between threads.
*   **Dependencies:** The project uses several external crates, which are managed in the `Cargo.toml` file. These include:
    *   `clap`: For command-line argument parsing.
    *   `libc`: For interacting with the underlying C library, specifically for `mlock` and `munlock`.
    *   `sysinfo`: For getting system information, such as total memory.
    *   `rand`: For generating random numbers for some of the tests.

