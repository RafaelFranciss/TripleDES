// Generate a proper 192-bit (24-byte) TripleDES key in hex
function generateHexKey(length) {
    return CryptoJS.lib.WordArray.random(length).toString(CryptoJS.enc.Hex);
}

function saveLetter() {
    const to = document.getElementById("to").value.trim();
    const letter = document.getElementById("letter").value.trim();
    const unlockDate = document.getElementById("unlockDate").value;
    const password = document.getElementById("password").value.trim();

    if (!to || !letter || !unlockDate || !password) {
      alert("Please fill out all fields.");
      return;
    }

    // Derive a 24-byte (192-bit) Triple DES key from SHA-256 hash
    const fullHash = CryptoJS.SHA256(password).toString(CryptoJS.enc.Hex);
    const key192 = fullHash.slice(0, 48); // 24 bytes = 48 hex characters
    const keyHex = CryptoJS.enc.Hex.parse(key192);

    // Encrypt using official Triple DES (EDE mode)
    const encrypted = CryptoJS.TripleDES.encrypt(letter, keyHex, {
      mode: CryptoJS.mode.ECB,
      padding: CryptoJS.pad.Pkcs7
    }).toString();

    // Store the encrypted letter and metadata
    const stored = JSON.parse(localStorage.getItem("letters") || "[]");
    stored.push({
      to,
      encrypted,
      key: key192,
      unlockDate
    });
    localStorage.setItem("letters", JSON.stringify(stored));

    // Clear inputs
    document.getElementById("to").value = "";
    document.getElementById("letter").value = "";
    document.getElementById("unlockDate").value = "";
    document.getElementById("password").value = "";

    alert("💌 Letter saved and encrypted with official 3DES!");
    loadLetters();
}

function loadLetters() {
    const list = document.getElementById("letterList");
    list.innerHTML = "";

    const letters = JSON.parse(localStorage.getItem("letters") || "[]");
    const today = new Date().toISOString().slice(0, 10);

    letters.forEach((item, index) => {
        const li = document.createElement("li");
        const locked = item.unlockDate > today;

        li.innerHTML = `
          <strong>${item.to}</strong><br>
          <p><i><strong>Encrypted Message:</strong></i> ${item.encrypted}</p>
          <p style="color: ${locked ? "#c00" : "#090"};"><strong>${locked ? "Locked until" : "Unlocked"} ${item.unlockDate}</strong></p>
          <p><strong>Key (Hex):</strong> ${locked ? "<em>Hidden until unlock date</em>" : item.key}</p>
          <button onclick="deleteLetter(${index})">Delete</button>
        `;
        list.appendChild(li);
    });
}

function decryptManual() {
    const encryptedText = document.getElementById("decryptionInput").value.trim();
    const keyHex = document.getElementById("keyInput").value.trim();
    const password = document.getElementById("decryptionPassword").value.trim();
    const outputDiv = document.getElementById("decryptedOutput");

    if (!encryptedText || !keyHex || !password) {
        alert("❗ Please provide the encrypted message, key (Hex), and password.");
        return;
    }

    try {
        const derivedKey = CryptoJS.SHA256(password).toString(CryptoJS.enc.Hex).slice(0, 48);
        if (derivedKey !== keyHex) throw "Key mismatch or wrong password";

        const keyHexParsed = CryptoJS.enc.Hex.parse(derivedKey);
        const decrypted = CryptoJS.TripleDES.decrypt(encryptedText, keyHexParsed, {
            mode: CryptoJS.mode.ECB,
            padding: CryptoJS.pad.Pkcs7
        });


        const plaintext = decrypted.toString(CryptoJS.enc.Utf8);
        if (!plaintext) throw "Invalid decryption";

        outputDiv.innerHTML = `
            <div style="padding: 10px; border: 1px solid #ccc; background-color: #f9f9f9; border-radius: 8px;">
                <h4>💌 Decrypted Message:</h4>
                <p>${plaintext}</p>
            </div>`;
    } catch (e) {
        alert("❌ Decryption failed. Check your password and key.");
        outputDiv.innerHTML = ""; // Clear the output container if error occurs
    }
}

function clearDecryption() {
    document.getElementById("decryptionInput").value = "";
    document.getElementById("keyInput").value = "";
    document.getElementById("decryptionPassword").value = "";
    document.getElementById("decryptedOutput").innerHTML = "";
}

function deleteLetter(index) {
    if (confirm("Delete this letter forever?")) {
        const letters = JSON.parse(localStorage.getItem("letters") || "[]");
        letters.splice(index, 1);
        localStorage.setItem("letters", JSON.stringify(letters));
        alert("🗑️ Letter deleted.");
        loadLetters();
    }
}

window.onload = loadLetters;