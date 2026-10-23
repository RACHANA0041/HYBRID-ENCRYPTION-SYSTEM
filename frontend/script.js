const API_URL = "http://127.0.0.1:8000/api";

async function handleEncrypt() {
    const message = document.getElementById("messageInput").value;
    if (!message) {
        alert("Please enter a message to encrypt.");
        return;
    }

    try {
        const response = await fetch(`${API_URL}/encrypt`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ message: message })
        });

        const data = await response.json();
        if (data.status === "success") {
            document.getElementById("packageOutput").value = data.package_json;
            updateStatus("Package encrypted successfully.", "success");
        } else {
            updateStatus("Encryption failed: " + data.detail, "error");
        }
    } catch (err) {
        updateStatus("API Error: Ensure backend server is running.", "error");
    }
}

async function handleDecrypt() {
    const packageJson = document.getElementById("packageOutput").value;
    if (!packageJson) {
        alert("No encrypted package found.");
        return;
    }

    try {
        const response = await fetch(`${API_URL}/decrypt`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ package_json: packageJson })
        });

        const data = await response.json();
        if (data.status === "success") {
            document.getElementById("decryptedOutput").value = data.decrypted_message;
            updateStatus("Decryption & SHA-512 Verification PASSED ✓", "success");
        } else {
            document.getElementById("decryptedOutput").value = "";
            updateStatus(data.detail, "error");
        }
    } catch (err) {
        updateStatus("API Error: Could not verify decryption.", "error");
    }
}

function handleTamper() {
    const pkg = document.getElementById("packageOutput").value;
    if (!pkg) return;

    try {
        let bundle = JSON.parse(pkg);
        let rawCipher = bundle.ciphertext;
        bundle.ciphertext = rawCipher.substring(0, rawCipher.length - 4) + "AAAA";

        document.getElementById("packageOutput").value = JSON.stringify(bundle, null, 2);
        updateStatus("Ciphertext tampered! Attempt decryption to test security validation.", "error");
    } catch (e) {
        alert("Invalid JSON package structure.");
    }
}

function updateStatus(msg, type) {
    const badge = document.getElementById("statusBadge");
    badge.textContent = msg;
    badge.className = `badge ${type}`;
}
