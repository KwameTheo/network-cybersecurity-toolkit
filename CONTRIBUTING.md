# Contributing Guidelines

Thank you for your interest in contributing to the **Network & Cybersecurity IT Support Toolkit**! This project is designed as both a practical diagnostic workstation for Windows IT support technicians and a portfolio showcase demonstrating clean software engineering and defensive cybersecurity practices.

---

## Code of Conduct

* Be respectful, constructive, and helpful to learners of all skill levels.
* Keep all contributions focused on **defensive diagnostics, IT administration, and defensive security auditing**. (Do not submit offensive exploits or unauthorized scanning features).

---

## Development Workflow

1. **Fork the Repository** on GitHub.
2. **Clone your fork locally**:
   ```bash
   git clone https://github.com/your-username/network-cybersecurity-toolkit.git
   cd network-cybersecurity-toolkit
   ```
3. **Set up the virtual environment**:
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\pip install -r requirements.txt
   ```
4. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

---

## Coding & Architectural Standards

* **Separation of Concerns**: Keep GUI code strictly in `ui/` and business/diagnostic logic in `core/`. Core modules must have zero GUI dependencies so they remain fully testable via automated scripts.
* **Safe Execution**:
  * Never use `shell=True` in subprocess calls.
  * Always validate user input with `utils/validators.py`.
* **Thread Safety**: Never run long-running network or CLI commands on the Tkinter main thread. Use `threading.Thread(target=..., daemon=True)` and dispatch UI updates using `self.after(0, ...)`.
* **Error Handling**: Gracefully handle missing privileges, offline network adapters, and command timeouts.

---

## Testing Requirements

Before opening a Pull Request, ensure that all automated unit tests pass:

```powershell
.\.venv\Scripts\python.exe -m unittest discover tests
```

Add new unit test cases in `tests/` for any new diagnostic functions or parser routines you introduce.
