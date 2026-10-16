# NEXUS First-Run Checklist

Follow this checklist to verify correct installation, configuration, and operation of NEXUS 2.0.1.

- [ ] **1. Environment Verification**
  - Python 3.11+ installed (`python --version`).
  - Isolated virtual environment created and activated.

- [ ] **2. Installation**
  - Install NEXUS from the checkout: `pip install .`
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
    *(Expected outcome: 483 passed, 11 skipped, 0 failed).*
