// api/decrypt-whatsapp-media-fixed.js
// Versi yang diperbaiki dengan implementasi HKDF yang benar dan debugging

import crypto from "crypto";

class WhatsAppMediaDecryptor {
  /**
   * Decode base64 media key dari WhatsApp message
   */
  decodeMediaKey(mediaKeyBase64) {
    return Buffer.from(mediaKeyBase64, "base64");
  }

  /**
   * HKDF Extract - RFC 5869 compliant
   */
  hkdfExtract(salt, ikm) {
    if (!salt || salt.length === 0) {
      salt = Buffer.alloc(32, 0); // Zero salt jika null
    }
    return crypto.createHmac("sha256", salt).update(ikm).digest();
  }

  /**
   * HKDF Expand - RFC 5869 compliant
   */
  hkdfExpand(prk, info, length) {
    const hashLength = 32; // SHA-256 output length
    const n = Math.ceil(length / hashLength);
    let okm = Buffer.alloc(0);
    let t = Buffer.alloc(0);

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
   * HKDF - RFC 5869 compliant implementation
   */
  hkdf(ikm, salt, info, length) {
    const prk = this.hkdfExtract(salt, ikm);
    return this.hkdfExpand(prk, info, length);
  }

  /**
   * Generate keys sesuai spesifikasi WhatsApp yang benar
   */
  generateWhatsAppKeys(mediaKey, mediaType = "image") {
    const infoStrings = {
      image: "WhatsApp Image Keys",
      video: "WhatsApp Video Keys",
      audio: "WhatsApp Audio Keys",
      document: "WhatsApp Document Keys",
    };

    const info = Buffer.from(
      infoStrings[mediaType] || infoStrings.image,
      "utf8"
    );
    const salt = Buffer.alloc(32, 0); // 32 bytes zero salt

    // Generate 112 bytes total: 16 (IV) + 32 (cipher key) + 32 (MAC key) + 32 (refKey)
    const derivedKey = this.hkdf(mediaKey, salt, info, 112);

    return {
      iv: derivedKey.slice(0, 16), // bytes 0-15
      cipherKey: derivedKey.slice(16, 48), // bytes 16-47
      macKey: derivedKey.slice(48, 80), // bytes 48-79
      refKey: derivedKey.slice(80, 112), // bytes 80-111 (reference key)
      type: "standard",
    };
  }

  /**
   * Variasi alternatif tanpa salt
   */
  generateAlternativeKeys(mediaKey, mediaType = "image") {
    const infoStrings = {
      image: "WhatsApp Image Keys",
      video: "WhatsApp Video Keys",
      audio: "WhatsApp Audio Keys",
      document: "WhatsApp Document Keys",
    };

    const info = Buffer.from(
      infoStrings[mediaType] || infoStrings.image,
      "utf8"
    );

    // Direct expand tanpa extract
    const derivedKey = this.hkdfExpand(mediaKey, info, 112);

    return {
      iv: derivedKey.slice(0, 16),
      cipherKey: derivedKey.slice(16, 48),
      macKey: derivedKey.slice(48, 80),
      refKey: derivedKey.slice(80, 112),
      type: "no_salt",
    };
  }

  /**
   * Variasi dengan salt berbeda
   */
  generateVariantKeys(mediaKey, mediaType = "image") {
    const infoStrings = {
      image: "WhatsApp Image Keys",
      video: "WhatsApp Video Keys",
      audio: "WhatsApp Audio Keys",
      document: "WhatsApp Document Keys",
    };

    const info = Buffer.from(
      infoStrings[mediaType] || infoStrings.image,
      "utf8"
    );
    const salt = Buffer.from("WhatsApp", "utf8"); // Different salt

    const derivedKey = this.hkdf(mediaKey, salt, info, 112);

    return {
      iv: derivedKey.slice(0, 16),
      cipherKey: derivedKey.slice(16, 48),
      macKey: derivedKey.slice(48, 80),
      refKey: derivedKey.slice(80, 112),
      type: "variant_salt",
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
          Accept: "*/*",
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
   * Verify MAC dengan debugging yang lebih detail
   */
  verifyMacDetailed(encryptedData, macKey, keyInfo = "unknown") {
    if (encryptedData.length < 10) {
      return {
        success: false,
        reason: "data_too_short",
        dataLength: encryptedData.length,
      };
    }

    // WhatsApp menggunakan 10 bytes terakhir sebagai MAC
    const mediaData = encryptedData.slice(0, -10);
    const receivedMac = encryptedData.slice(-10);

    console.log(`\n=== MAC Verification [${keyInfo}] ===`);
    console.log(`Data length: ${mediaData.length} bytes`);
    console.log(`MAC key: ${macKey.toString("hex")}`);
    console.log(`Received MAC: ${receivedMac.toString("hex")}`);

    // Hitung MAC menggunakan HMAC-SHA256, ambil 10 bytes pertama
    const hmac = crypto.createHmac("sha256", macKey);
    hmac.update(mediaData);
    const fullMac = hmac.digest();
    const calculatedMac = fullMac.slice(0, 10);

    console.log(`Calculated MAC: ${calculatedMac.toString("hex")}`);
    console.log(`Full HMAC: ${fullMac.toString("hex")}`);

    const isValid = crypto.timingSafeEqual(receivedMac, calculatedMac);
    console.log(`MAC Valid: ${isValid}`);

    return {
      success: isValid,
      receivedMac: receivedMac.toString("hex"),
      calculatedMac: calculatedMac.toString("hex"),
      fullHmac: fullMac.toString("hex"),
      keyInfo: keyInfo,
      dataLength: mediaData.length,
    };
  }

  /**
   * Decrypt media menggunakan AES-256-CBC
   */
  decryptMedia(encryptedData, cipherKey, iv) {
    // Remove MAC dari akhir data
    const cipherData = encryptedData.slice(0, -10);

    console.log(`\n=== Decryption ===`);
    console.log(`Cipher data length: ${cipherData.length}`);
    console.log(`Cipher key: ${cipherKey.toString("hex")}`);
    console.log(`IV: ${iv.toString("hex")}`);

    try {
      const decipher = crypto.createDecipheriv("aes-256-cbc", cipherKey, iv);
      decipher.setAutoPadding(true);

      let decrypted = decipher.update(cipherData);
      const final = decipher.final();

      const result = Buffer.concat([decrypted, final]);
      console.log(`Decrypted length: ${result.length}`);

      return result;
    } catch (error) {
      console.log(`Decryption error: ${error.message}`);
      throw new Error(`AES decryption failed: ${error.message}`);
    }
  }

  /**
   * Coba dekripsi dengan mode ECB (fallback)
   */
  decryptMediaECB(encryptedData, cipherKey) {
    const cipherData = encryptedData.slice(0, -10);

    console.log(`\n=== Trying ECB Decryption ===`);

    try {
      const decipher = crypto.createDecipheriv("aes-256-ecb", cipherKey, null);
      decipher.setAutoPadding(true);

      let decrypted = decipher.update(cipherData);
      const final = decipher.final();

      return Buffer.concat([decrypted, final]);
    } catch (error) {
      throw new Error(`AES-ECB decryption failed: ${error.message}`);
    }
  }

  /**
   * Main function dengan debugging komprehensif
   */
  async decryptWhatsAppMedia(messageData, debugMode = true) {
    const debugLog = [];

    try {
      // Extract data dari message dengan berbagai struktur
      let mediaMessage = null;
      let mediaType = "image";

      // Coba berbagai jalur untuk mengakses message data
      const possiblePaths = [
        messageData,
        messageData.payload,
        messageData.payload?._data?.message,
        messageData.payload?.message,
        messageData.message,
        messageData._data?.message,
      ];

      for (const path of possiblePaths) {
        if (!path) continue;

        if (path.imageMessage) {
          mediaMessage = path.imageMessage;
          mediaType = "image";
          break;
        } else if (path.videoMessage) {
          mediaMessage = path.videoMessage;
          mediaType = "video";
          break;
        } else if (path.audioMessage) {
          mediaMessage = path.audioMessage;
          mediaType = "audio";
          break;
        } else if (path.documentMessage) {
          mediaMessage = path.documentMessage;
          mediaType = "document";
          break;
        }
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
      debugLog.push(`Media URL: ${mediaUrl.substring(0, 60)}...`);

      // Decode media key
      const mediaKey = this.decodeMediaKey(mediaKeyBase64);
      debugLog.push(`Media Key (hex): ${mediaKey.toString("hex")}`);
      debugLog.push(`Media Key length: ${mediaKey.length} bytes`);

      // Download encrypted media
      console.log("Downloading encrypted media...");
      const encryptedData = await this.downloadEncryptedMedia(mediaUrl);
      debugLog.push(`Downloaded encrypted data: ${encryptedData.length} bytes`);

      // Show first and last few bytes untuk debugging
      const firstBytes = encryptedData.slice(0, 16).toString("hex");
      const lastBytes = encryptedData.slice(-16).toString("hex");
      debugLog.push(`First 16 bytes: ${firstBytes}`);
      debugLog.push(`Last 16 bytes: ${lastBytes}`);

      // Coba semua kombinasi key generation dan media types
      const mediaTypes = [mediaType, "image", "video", "audio", "document"];
      const keyGenerators = [
        { name: "standard", func: this.generateWhatsAppKeys },
        { name: "no_salt", func: this.generateAlternativeKeys },
        { name: "variant_salt", func: this.generateVariantKeys },
      ];

      let workingKeys = null;
      let macResult = null;

      for (const type of mediaTypes) {
        for (const generator of keyGenerators) {
          const keys = generator.func.call(this, mediaKey, type);
          const keyInfo = `${type}_${generator.name}`;

          debugLog.push(`\nTrying ${keyInfo}:`);
          debugLog.push(`  IV: ${keys.iv.toString("hex")}`);
          debugLog.push(`  Cipher Key: ${keys.cipherKey.toString("hex")}`);
          debugLog.push(`  MAC Key: ${keys.macKey.toString("hex")}`);

          const macCheck = this.verifyMacDetailed(
            encryptedData,
            keys.macKey,
            keyInfo
          );

          if (macCheck.success) {
            workingKeys = keys;
            macResult = macCheck;
            debugLog.push(`✅ MAC verified with ${keyInfo}`);
            break;
          } else {
            debugLog.push(`❌ MAC failed with ${keyInfo}`);
            debugLog.push(`   Expected: ${macCheck.calculatedMac}`);
            debugLog.push(`   Received: ${macCheck.receivedMac}`);
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
          firstBytes: encryptedData.slice(0, 32).toString("hex"),
          lastBytes: encryptedData.slice(-32).toString("hex"),
        };
      }

      // Coba dekripsi dengan CBC mode
      let decryptedData;
      try {
        decryptedData = this.decryptMedia(
          encryptedData,
          workingKeys.cipherKey,
          workingKeys.iv
        );
        debugLog.push(
          `✅ CBC Decryption successful: ${decryptedData.length} bytes`
        );
      } catch (cbcError) {
        debugLog.push(`❌ CBC Decryption failed: ${cbcError.message}`);

        // Fallback ke ECB mode
        try {
          decryptedData = this.decryptMediaECB(
            encryptedData,
            workingKeys.cipherKey
          );
          debugLog.push(
            `✅ ECB Decryption successful: ${decryptedData.length} bytes`
          );
        } catch (ecbError) {
          debugLog.push(`❌ ECB Decryption failed: ${ecbError.message}`);
          throw new Error(`Both CBC and ECB decryption failed`);
        }
      }

      // Validate decrypted data
      const fileSignature = decryptedData.slice(0, 4).toString("hex");
      debugLog.push(`File signature: ${fileSignature}`);

      return {
        success: true,
        data: decryptedData,
        mimeType: mediaMessage.mimetype,
        fileSize: decryptedData.length,
        originalFileSize: mediaMessage.fileLength,
        mediaType: mediaType,
        keyVariation: workingKeys.type,
        macResult: macResult,
        fileSignature: fileSignature,
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

    console.log("Processing WhatsApp media decryption request...");

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
          fileSignature: result.fileSignature,
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
          fileSignature: result.fileSignature,
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
          fileSignature: result.fileSignature,
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
