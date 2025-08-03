// api/decrypt-whatsapp-media.js
import crypto from "crypto";

class WhatsAppMediaDecryptor {
  /**
   * Decode base64 media key dari WhatsApp message
   */
  decodeMediaKey(mediaKeyBase64) {
    return Buffer.from(mediaKeyBase64, "base64");
  }

  /**
   * HKDF Expand function
   */
  hkdfExpand(prk, info, length) {
    const hashLength = 32; // SHA-256 output length
    const n = Math.ceil(length / hashLength);
    let t = Buffer.alloc(0);
    let okm = Buffer.alloc(0);

    for (let i = 1; i <= n; i++) {
      const hmac = crypto.createHmac("sha256", prk);
      hmac.update(t);
      hmac.update(info);
      hmac.update(Buffer.from([i]));
      t = hmac.digest();
      okm = Buffer.concat([okm, t]);
    }

    return okm.slice(0, length);
  }

  /**
   * Generate key dan IV untuk dekripsi
   */
  generateDecryptionKeys(mediaKey) {
    const salt = Buffer.alloc(32, 0);
    const info = Buffer.from("WhatsApp Image Keys", "utf8");

    const prk = crypto.createHmac("sha256", salt).update(mediaKey).digest();
    const expandedKey = this.hkdfExpand(prk, info, 112);

    return {
      key: expandedKey.slice(0, 32), // AES-256 key (32 bytes)
      iv: expandedKey.slice(32, 48), // IV (16 bytes)
      macKey: expandedKey.slice(48, 80), // MAC key (32 bytes)
    };
  }

  /**
   * Download encrypted media dari URL
   */
  async downloadEncryptedMedia(url) {
    try {
      const response = await fetch(url, {
        method: "GET",
        headers: {
          "User-Agent": "WhatsApp/2.21.0",
        },
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const arrayBuffer = await response.arrayBuffer();
      return Buffer.from(arrayBuffer);
    } catch (error) {
      throw new Error(`Failed to download media: ${error.message}`);
    }
  }

  /**
   * Verify MAC untuk memastikan integritas data
   */
  verifyMac(encryptedData, macKey) {
    if (encryptedData.length < 10) return false;

    const dataToVerify = encryptedData.slice(0, -10);
    const receivedMac = encryptedData.slice(-10);

    const calculatedMac = crypto
      .createHmac("sha256", macKey)
      .update(dataToVerify)
      .digest()
      .slice(0, 10);

    return receivedMac.equals(calculatedMac);
  }

  /**
   * Decrypt media menggunakan AES-256-CBC
   */
  decryptMedia(encryptedData, key, iv) {
    const dataToDecrypt = encryptedData.slice(0, -10);

    const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
    decipher.setAutoPadding(true);

    const decrypted = Buffer.concat([
      decipher.update(dataToDecrypt),
      decipher.final(),
    ]);

    return decrypted;
  }

  /**
   * Main function untuk mendekripsi media WhatsApp
   */
  async decryptWhatsAppMedia(messageData) {
    try {
      // Extract data dari message
      const mediaMessage =
        messageData.payload?._data?.message?.imageMessage ||
        messageData.payload?._data?.message?.videoMessage ||
        messageData.payload?._data?.message?.audioMessage ||
        messageData.payload?._data?.message?.documentMessage;

      if (!mediaMessage) {
        throw new Error("No media message found in the provided data");
      }

      const mediaKeyBase64 = mediaMessage.mediaKey;
      const mediaUrl = mediaMessage.url;

      if (!mediaKeyBase64 || !mediaUrl) {
        throw new Error("Missing mediaKey or URL in message data");
      }

      // Decode media key
      const mediaKey = this.decodeMediaKey(mediaKeyBase64);

      // Generate decryption keys
      const keys = this.generateDecryptionKeys(mediaKey);

      // Download encrypted media
      const encryptedData = await this.downloadEncryptedMedia(mediaUrl);

      // Verify MAC
      if (!this.verifyMac(encryptedData, keys.macKey)) {
        throw new Error("MAC verification failed - data might be corrupted");
      }

      // Decrypt media
      const decryptedData = this.decryptMedia(encryptedData, keys.key, keys.iv);

      return {
        success: true,
        data: decryptedData,
        mimeType: mediaMessage.mimetype,
        fileSize: decryptedData.length,
        originalFileSize: mediaMessage.fileLength,
      };
    } catch (error) {
      throw new Error(`Decryption failed: ${error.message}`);
    }
  }
}

export default async function handler(req, res) {
  // Set CORS headers
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  // Handle preflight requests
  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  // Only allow POST requests
  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      error: "Method not allowed. Use POST request.",
    });
  }

  try {
    const { messageData, returnFormat = "base64" } = req.body;

    if (!messageData) {
      return res.status(400).json({
        success: false,
        error: "Missing messageData in request body",
      });
    }

    const decryptor = new WhatsAppMediaDecryptor();
    const result = await decryptor.decryptWhatsAppMedia(messageData);

    let responseData;

    switch (returnFormat.toLowerCase()) {
      case "base64":
        responseData = {
          success: true,
          data: result.data.toString("base64"),
          mimeType: result.mimeType,
          fileSize: result.fileSize,
          originalFileSize: result.originalFileSize,
          format: "base64",
        };
        break;

      case "buffer":
        responseData = {
          success: true,
          data: Array.from(result.data),
          mimeType: result.mimeType,
          fileSize: result.fileSize,
          originalFileSize: result.originalFileSize,
          format: "buffer",
        };
        break;

      case "dataurl":
        const dataUrl = `data:${result.mimeType};base64,${result.data.toString(
          "base64"
        )}`;
        responseData = {
          success: true,
          data: dataUrl,
          mimeType: result.mimeType,
          fileSize: result.fileSize,
          originalFileSize: result.originalFileSize,
          format: "dataurl",
        };
        break;

      default:
        return res.status(400).json({
          success: false,
          error: "Invalid returnFormat. Use: base64, buffer, or dataurl",
        });
    }

    return res.status(200).json(responseData);
  } catch (error) {
    console.error("API Error:", error);
    return res.status(500).json({
      success: false,
      error: error.message,
      timestamp: new Date().toISOString(),
    });
  }
}

// Export config untuk Vercel
export const config = {
  api: {
    bodyParser: {
      sizeLimit: "10mb",
    },
    responseLimit: "50mb",
  },
};
