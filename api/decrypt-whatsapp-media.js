// api/decrypt-whatsapp-media-debug.js
// Version dengan debugging detail untuk troubleshoot masalah MAC verification

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
   * Generate key dan IV untuk dekripsi - dengan berbagai variasi algoritma WhatsApp
   */
  generateDecryptionKeysVariation1(mediaKey, mediaType = "image") {
    // Variasi 1: Standard WhatsApp HKDF
    const infoMap = {
      image: "WhatsApp Image Keys",
      video: "WhatsApp Video Keys",
      audio: "WhatsApp Audio Keys",
      document: "WhatsApp Document Keys",
    };

    const info = Buffer.from(infoMap[mediaType] || infoMap["image"], "utf8");
    const salt = Buffer.alloc(32, 0);

    const prk = crypto.createHmac("sha256", salt).update(mediaKey).digest();
    const expandedKey = this.hkdfExpand(prk, info, 112);

    return {
      iv: expandedKey.slice(0, 16),
      cipherKey: expandedKey.slice(16, 48),
      macKey: expandedKey.slice(48, 80),
      type: "variation1",
    };
  }

  generateDecryptionKeysVariation2(mediaKey, mediaType = "image") {
    // Variasi 2: Urutan berbeda (iv di tengah)
    const infoMap = {
      image: "WhatsApp Image Keys",
      video: "WhatsApp Video Keys",
      audio: "WhatsApp Audio Keys",
      document: "WhatsApp Document Keys",
    };

    const info = Buffer.from(infoMap[mediaType] || infoMap["image"], "utf8");
    const salt = Buffer.alloc(32, 0);

    const prk = crypto.createHmac("sha256", salt).update(mediaKey).digest();
    const expandedKey = this.hkdfExpand(prk, info, 112);

    return {
      cipherKey: expandedKey.slice(0, 32),
      iv: expandedKey.slice(32, 48),
      macKey: expandedKey.slice(48, 80),
      type: "variation2",
    };
  }

  generateDecryptionKeysVariation3(mediaKey, mediaType = "image") {
    // Variasi 3: Tanpa salt (direct HMAC)
    const infoMap = {
      image: "WhatsApp Image Keys",
      video: "WhatsApp Video Keys",
      audio: "WhatsApp Audio Keys",
      document: "WhatsApp Document Keys",
    };

    const info = Buffer.from(infoMap[mediaType] || infoMap["image"], "utf8");
    const expandedKey = this.hkdfExpand(mediaKey, info, 112);

    return {
      iv: expandedKey.slice(0, 16),
      cipherKey: expandedKey.slice(16, 48),
      macKey: expandedKey.slice(48, 80),
      type: "variation3",
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
   * Verify MAC dengan debugging
   */
  verifyMacWithDebug(encryptedData, macKey, keyVariation = "unknown") {
    if (encryptedData.length < 10) {
      console.log(
        `MAC verification failed: Data too short (${encryptedData.length} bytes)`
      );
      return { success: false, reason: "data_too_short" };
    }

    const mediaData = encryptedData.slice(0, -10);
    const receivedMac = encryptedData.slice(-10);

    console.log(`[${keyVariation}] Data length: ${mediaData.length}`);
    console.log(
      `[${keyVariation}] Received MAC: ${receivedMac.toString("hex")}`
    );
    console.log(
      `[${keyVariation}] MAC Key: ${macKey.toString("hex").substring(0, 16)}...`
    );

    const calculatedMac = crypto
      .createHmac("sha256", macKey)
      .update(mediaData)
      .digest()
      .slice(0, 10);

    console.log(
      `[${keyVariation}] Calculated MAC: ${calculatedMac.toString("hex")}`
    );

    const isValid = crypto.timingSafeEqual(receivedMac, calculatedMac);
    console.log(`[${keyVariation}] MAC Valid: ${isValid}`);

    return {
      success: isValid,
      receivedMac: receivedMac.toString("hex"),
      calculatedMac: calculatedMac.toString("hex"),
      variation: keyVariation,
    };
  }

  /**
   * Decrypt media menggunakan AES-256-CBC
   */
  decryptMedia(encryptedData, cipherKey, iv) {
    const cipherData = encryptedData.slice(0, -10);

    try {
      const decipher = crypto.createDecipheriv("aes-256-cbc", cipherKey, iv);
      decipher.setAutoPadding(true);

      let decrypted = decipher.update(cipherData);
      const final = decipher.final();

      return Buffer.concat([decrypted, final]);
    } catch (error) {
      throw new Error(`AES decryption failed: ${error.message}`);
    }
  }

  /**
   * Main function dengan extensive debugging
   */
  async decryptWhatsAppMedia(messageData, debugMode = true) {
    const debugLog = [];

    try {
      // Extract data dari message
      let mediaMessage = null;
      let mediaType = "image";

      const payload = messageData.payload || messageData;
      const messageObj = payload._data?.message || payload.message || payload;

      if (messageObj.imageMessage) {
        mediaMessage = messageObj.imageMessage;
        mediaType = "image";
      } else if (messageObj.videoMessage) {
        mediaMessage = messageObj.videoMessage;
        mediaType = "video";
      } else if (messageObj.audioMessage) {
        mediaMessage = messageObj.audioMessage;
        mediaType = "audio";
      } else if (messageObj.documentMessage) {
        mediaMessage = messageObj.documentMessage;
        mediaType = "document";
      }

      debugLog.push(`Detected media type: ${mediaType}`);

      if (!mediaMessage) {
        throw new Error("No media message found in the provided data");
      }

      const mediaKeyBase64 = mediaMessage.mediaKey;
      const mediaUrl = mediaMessage.url;

      if (!mediaKeyBase64 || !mediaUrl) {
        throw new Error("Missing mediaKey or URL in message data");
      }

      debugLog.push(
        `Media Key (base64): ${mediaKeyBase64.substring(0, 20)}...`
      );
      debugLog.push(`Media URL: ${mediaUrl.substring(0, 50)}...`);

      // Decode media key
      const mediaKey = this.decodeMediaKey(mediaKeyBase64);
      debugLog.push(`Media Key (hex): ${mediaKey.toString("hex")}`);

      // Download encrypted media
      const encryptedData = await this.downloadEncryptedMedia(mediaUrl);
      debugLog.push(`Downloaded encrypted data: ${encryptedData.length} bytes`);

      // Coba semua variasi key generation
      const keyVariations = [
        this.generateDecryptionKeysVariation1(mediaKey, mediaType),
        this.generateDecryptionKeysVariation2(mediaKey, mediaType),
        this.generateDecryptionKeysVariation3(mediaKey, mediaType),
      ];

      // Coba juga dengan semua media types
      const mediaTypes = ["image", "video", "audio", "document"];

      let workingKeys = null;
      let macResult = null;

      for (const type of mediaTypes) {
        for (let i = 0; i < 3; i++) {
          const keys =
            i === 0
              ? this.generateDecryptionKeysVariation1(mediaKey, type)
              : i === 1
              ? this.generateDecryptionKeysVariation2(mediaKey, type)
              : this.generateDecryptionKeysVariation3(mediaKey, type);

          const macCheck = this.verifyMacWithDebug(
            encryptedData,
            keys.macKey,
            `${type}_${keys.type}`
          );

          if (macCheck.success) {
            workingKeys = keys;
            macResult = macCheck;
            debugLog.push(
              `✅ MAC verified with ${type} keys using ${keys.type}`
            );
            break;
          } else {
            debugLog.push(
              `❌ MAC failed with ${type} keys using ${keys.type}: ${
                macCheck.reason || "mismatch"
              }`
            );
          }
        }

        if (workingKeys) break;
      }

      if (!workingKeys) {
        return {
          success: false,
          error: "MAC verification failed for all combinations",
          debugLog: debugLog,
          encryptedDataLength: encryptedData.length,
          mediaKeyHex: mediaKey.toString("hex"),
          lastMacAttempt: macResult,
        };
      }

      // Decrypt media
      const decryptedData = this.decryptMedia(
        encryptedData,
        workingKeys.cipherKey,
        workingKeys.iv
      );
      debugLog.push(`✅ Decryption successful: ${decryptedData.length} bytes`);

      return {
        success: true,
        data: decryptedData,
        mimeType: mediaMessage.mimetype,
        fileSize: decryptedData.length,
        originalFileSize: mediaMessage.fileLength,
        mediaType: mediaType,
        keyVariation: workingKeys.type,
        macResult: macResult,
        debugLog: debugMode ? debugLog : undefined,
      };
    } catch (error) {
      debugLog.push(`❌ Error: ${error.message}`);
      console.error("Decryption error:", error);

      return {
        success: false,
        error: error.message,
        debugLog: debugLog,
      };
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
    const { messageData, returnFormat = "base64", debugMode = true } = req.body;

    if (!messageData) {
      return res.status(400).json({
        success: false,
        error: "Missing messageData in request body",
      });
    }

    const decryptor = new WhatsAppMediaDecryptor();
    const result = await decryptor.decryptWhatsAppMedia(messageData, debugMode);

    if (!result.success) {
      return res.status(500).json(result);
    }

    let responseData;

    switch (returnFormat.toLowerCase()) {
      case "base64":
        responseData = {
          success: true,
          data: result.data.toString("base64"),
          mimeType: result.mimeType,
          fileSize: result.fileSize,
          originalFileSize: result.originalFileSize,
          mediaType: result.mediaType,
          keyVariation: result.keyVariation,
          format: "base64",
          debugLog: result.debugLog,
        };
        break;

      case "buffer":
        responseData = {
          success: true,
          data: Array.from(result.data),
          mimeType: result.mimeType,
          fileSize: result.fileSize,
          originalFileSize: result.originalFileSize,
          mediaType: result.mediaType,
          keyVariation: result.keyVariation,
          format: "buffer",
          debugLog: result.debugLog,
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
          mediaType: result.mediaType,
          keyVariation: result.keyVariation,
          format: "dataurl",
          debugLog: result.debugLog,
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

export const config = {
  api: {
    bodyParser: {
      sizeLimit: "10mb",
    },
    responseLimit: "50mb",
  },
};
