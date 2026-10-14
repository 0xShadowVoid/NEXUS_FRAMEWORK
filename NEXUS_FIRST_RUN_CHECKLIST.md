# NEXUS First-Run Checklist

Follow this checklist to verify correct installation, configuration, and operation of NEXUS RC1.

- [ ] **1. Environment Verification**
  - Python 3.11+ installed (`python --version`).
  - Isolated virtual environment created and activated.

- [ ] **2. Wheel Installation**
  - Install frozen RC1 wheel: `pip install dist/nexus_framework-2.0.0-py3-none-any.whl`
  - Verify CLI executable: `python -m nexus --help`

- [ ] **3. Environment & Configuration Check**
  - Verify configuration templates exist under `config/`.
  - Run environment doctor / tool check: `python -m nexus check-tools`

- [ ] **4. Scope & Safety Policy Verification**
  - Confirm target domain is defined within `config/nexus.yaml` under `in_scope`.
  - Verify out-of-scope targets are rejected prior to execution.

- [ ] **5. Test Suite Validation**
  - Run regression test suite (requires `dev` dependencies):
    ```powershell
    python -m pytest tests -q -p no:cacheprovider
    ```
    *(Expected outcome: 481 passed, 11 skipped, 0 failed).*
