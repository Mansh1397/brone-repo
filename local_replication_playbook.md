# Brone Network - Local Cryptographic Replication Playbook

This playbook outlines the steps required to verify the corrected cryptographic handshake and end-to-end user lifecycle flow (reporting, stamping, arbitration, and telemetry metric synchronization) on your local machine.

---

## 1. Prerequisites & Environment Setup

Ensure that you have your services running and database initialized.

### A. Database Initialization
Ensure the Postgres container is healthy and the database schema is up-to-date. In a PowerShell terminal:
```powershell
# Stream schema SQL file into the Postgres docker container
Get-Content -Raw infra/database/schema.sql | docker exec -i brone-postgres-db-1 psql -U brone_admin -d brone_prod
```

### B. Launching the Backend Server (Port 3001)
Start the backend server with production environment configuration:
```powershell
$env:PORT=3001
$env:PGHOST="127.0.0.1"
$env:DATABASE_URL="postgresql://brone_admin:fortress_vault_secure_pass@localhost:5432/brone_prod"
npx tsx --env-file=apps/backend/.env.production apps/backend/src/index.ts
```

### C. Launching the Frontend Client (Port 5173)
Ensure the Vite dev server is running:
```powershell
npm run dev --workspace=apps/frontend
```

---

## 2. Step-by-Step Verification Protocol

Use your personal browser profile to perform the following verification:

### Step 1: Open the Frontend Application
Navigate to [http://localhost:5173](http://localhost:5173) in your browser. Verify that the **Wall of Truth** (Home Feed) loads successfully.

### Step 2: Open Developer Console
Right-click on the page, select **Inspect**, and open the **Console** and **Network** tabs to monitor in-flight HTTP requests and cryptographic signature handshakes.

### Step 3: Create & Submit a Report (Tab 2)
1. Click the **REPORT** tab at the bottom navigation bar.
2. In the description textarea, type:
   `Concrete structural cracks observed on perimeter gateway 4.`
3. Click the **Submit** button.
4. **Observe the Logs & Console**:
   * The status bar will log the steps (e.g., generating keypairs, blinding tokens, stamping).
   * Verify that the logs end with a green `SUCCESS: Blind stamp signature generated and broadcasted.` status.
   * In the Network tab, inspect the `POST /api/v1/arbitration` and `POST /api/v1/reputation/increment` responses. Both should return a clean `200/201 OK` (without any 403 or 401 errors).

### Step 4: Verify Jury Duty Propagation (Tab 3)
1. Click the **ACTIVE** tab (Jury Duties) at the bottom navigation bar.
2. Verify that the active duties queue loads and lists items.

### Step 5: Verify Reputation Capital Ledger (Tab 4)
1. Click the **STATS** tab at the bottom navigation bar.
2. Confirm the stats load correctly, displaying updated reputation details.

---

## 3. Cryptographic Core Alignment Details

The cryptographic handshake alignment consists of two key parts:

### 1. Arbitration Payload Structure
* **Before**: The frontend sent `POST /api/v1/arbitration` with missing key identification, resulting in 403 Forbidden.
* **After**: The frontend now sends the canonical verification keys (`reputation_key`, `nonce`, `epoch`) matching the backend's validation expectations:
  ```json
  {
    "reputation_key": "<public_key_hex>",
    "content": "Concrete structural cracks observed on gateway 4.",
    "blindedTransaction": "<blinded_tx_string>",
    "signature": "<unblinded_signature_string>",
    "ispublic": false,
    "status": "pending",
    "nonce": "<uuid>",
    "epoch": 1782241181143
  }
  ```

### 2. Telemetry Payload Serialization Structure
* **Before**: The frontend sent `metric_updates: { metric_type: "posts", delta_value: 1 }`, which resulted in backend DB parsing exceptions ("Cannot convert posts to a BigInt").
* **After**: The frontend now sends the canonical record representation `{ posts: 1 }` to match the backend expectation:
  ```json
  {
    "reputation_key": "<public_key_hex>",
    "metric_updates": {
      "posts": 1
    },
    "nonce": "<uuid>",
    "epoch": 1782239106000,
    "signature": "<hex_signature>"
  }
  ```

### 3. ECDSA Signature Encoding Alignment
* **Problem**: Browser `subtle.sign` yields raw $(r, s)$ signatures (IEEE P1363 format, 64 bytes). Node's default `crypto.createVerify` expects ASN.1 DER-encoded signatures (70-72 bytes), causing verification mismatch.
* **Resolution**: The backend `ledgerController.ts` was refactored to use `crypto.verify` specifying `dsaEncoding: "ieee-p1363"` directly, enabling native validation of raw browser-generated signatures.
