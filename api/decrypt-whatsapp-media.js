// api/decrypt-whatsapp-media-v2.js
// Versi dengan implementasi yang lebih akurat berdasarkan spesifikasi WhatsApp

import crypto from "crypto";

class WhatsAppMediaDecryptor {
  /**
   * Decode base64 media key dari WhatsApp message
   */
  decodeMediaKey(mediaKeyBase64) {
    return Buffer.from(mediaKeyBase64, "base64");
  }

  /**
   * HKDF Extract - RFC 5869
   */
  hkdfExtract(salt, ikm) {
    if (!salt || salt.length === 0) {
      salt = Buffer.alloc(32, 0);
    }
    return crypto.createHmac("sha256", salt).update(ikm).digest();
  }

  /**
   * HKDF Expand - RFC 5869
   */
  hkdfExpand(prk, info, length) {
    const hashLength = 32;
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
   * Generate keys dengan format yang tepat sesuai WhatsApp protocol
   */
  generateWhatsAppKeysV1(mediaKey, mediaType = "image") {
    // Format info string yang benar
    const infoMap = {
      image: Buffer.from("WhatsApp Image Keys", "utf8"),
      video: Buffer.from("WhatsApp Video Keys", "utf8"),
      audio: Buffer.from("WhatsApp Audio Keys", "utf8"),
      document: Buffer.from("WhatsApp Document Keys", "utf8"),
    };

    const info = infoMap[mediaType] || infoMap.image;
    const salt = Buffer.alloc(32, 0);

    const prk = this.hkdfExtract(salt, mediaKey);
    const derivedKey = this.hkdfExpand(prk, info, 112);

    return {
      iv: derivedKey.slice(0, 16),
      cipherKey: derivedKey.slice(16, 48),
      macKey: derivedKey.slice(48, 80),
      type: "v1_standard",
    };
  }

  /**
   * Variasi dengan format info berbeda
   */
  generateWhatsAppKeysV2(mediaKey, mediaType = "image") {
    // Coba dengan format yang lebih pendek
    const infoMap = {
      image: Buffer.from("WhatsApp Image", "utf8"),
      video: Buffer.from("WhatsApp Video", "utf8"),
      audio: Buffer.from("WhatsApp Audio", "utf8"),
      document: Buffer.from("WhatsApp Document", "utf8"),
    };

    const info = infoMap[mediaType] || infoMap.image;
    const salt = Buffer.alloc(32, 0);

    const prk = this.hkdfExtract(salt, mediaKey);
    const derivedKey = this.hkdfExpand(prk, info, 112);

    return {
      iv: derivedKey.slice(0, 16),
      cipherKey: derivedKey.slice(16, 48),
      macKey: derivedKey.slice(48, 80),
      type: "v2_short",
    };
  }

  /**
   * Variasi dengan case sensitive
   */
  generateWhatsAppKeysV3(mediaKey, mediaType = "image") {
    const infoMap = {
      image: Buffer.from("whatsapp image keys", "utf8"),
      video: Buffer.from("whatsapp video keys", "utf8"),
      audio: Buffer.from("whatsapp audio keys", "utf8"),
      document: Buffer.from("whatsapp document keys", "utf8"),
    };

    const info = infoMap[mediaType] || infoMap.image;
    const salt = Buffer.alloc(32, 0);

    const prk = this.hkdfExtract(salt, mediaKey);
    const derivedKey = this.hkdfExpand(prk, info, 112);

    return {
      iv: derivedKey.slice(0, 16),
      cipherKey: derivedKey.slice(16, 48),
      macKey: derivedKey.slice(48, 80),
      type: "v3_lowercase",
    };
  }

  /**
   * Variasi dengan media key sebagai salt
   */
  generateWhatsAppKeysV4(mediaKey, mediaType = "image") {
    const infoMap = {
      image: Buffer.from("WhatsApp Image Keys", "utf8"),
      video: Buffer.from("WhatsApp Video Keys", "utf8"),
      audio: Buffer.from("WhatsApp Audio Keys", "utf8"),
      document: Buffer.from("WhatsApp Document Keys", "utf8"),
    };

    const info = infoMap[mediaType] || infoMap.image;
    const salt = mediaKey; // Gunakan media key sebagai salt

    const prk = this.hkdfExtract(salt, mediaKey);
    const derivedKey = this.hkdfExpand(prk, info, 112);

    return {
      iv: derivedKey.slice(0, 16),
      cipherKey: derivedKey.slice(16, 48),
      macKey: derivedKey.slice(48, 80),
      type: "v4_mediakey_salt",
    };
  }

  /**
   * Variasi langsung tanpa HKDF extract
   */
  generateWhatsAppKeysV5(mediaKey, mediaType = "image") {
    const infoMap = {
      image: Buffer.from("WhatsApp Image Keys", "utf8"),
      video: Buffer.from("WhatsApp Video Keys", "utf8"),
      audio: Buffer.from("WhatsApp Audio Keys", "utf8"),
      document: Buffer.from("WhatsApp Document Keys", "utf8"),
    };

    const info = infoMap[mediaType] || infoMap.image;

    // Langsung expand tanpa extract
    const derivedKey = this.hkdfExpand(mediaKey, info, 112);

    return {
      iv: derivedKey.slice(0, 16),
      cipherKey: derivedKey.slice(16, 48),
      macKey: derivedKey.slice(48, 80),
      type: "v5_direct_expand",
    };
  }

  /**
   * Download encrypted media
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
   * Verify MAC dengan berbagai metode
   */
  verifyMacVariations(encryptedData, macKey, keyInfo = "unknown") {
    if (encryptedData.length < 10) {
      return { success: false, reason: "data_too_short" };
    }

    const results = [];

    // Method 1: Standard - 10 bytes terakhir
    const mediaData1 = encryptedData.slice(0, -10);
    const receivedMac1 = encryptedData.slice(-10);
    const calculatedMac1 = crypto
      .createHmac("sha256", macKey)
      .update(mediaData1)
      .digest()
      .slice(0, 10);

    const valid1 = crypto.timingSafeEqual(receivedMac1, calculatedMac1);
    results.push({
      method: "last_10_bytes",
      success: valid1,
      received: receivedMac1.toString("hex"),
      calculated: calculatedMac1.toString("hex"),
    });

    // Method 2: Coba dengan 32 bytes terakhir sebagai MAC
    if (encryptedData.length >= 32) {
      const mediaData2 = encryptedData.slice(0, -32);
      const receivedMac2 = encryptedData.slice(-32);
      const calculatedMac2 = crypto
        .createHmac("sha256", macKey)
        .update(mediaData2)
        .digest();

      const valid2 = crypto.timingSafeEqual(receivedMac2, calculatedMac2);
      results.push({
        method: "last_32_bytes",
        success: valid2,
        received: receivedMac2.toString("hex"),
        calculated: calculatedMac2.toString("hex"),
      });
    }

    // Method 3: Coba dengan media key + data
    const combinedData = Buffer.concat([mediaKey, mediaData1]);
    const calculatedMac3 = crypto
      .createHmac("sha256", macKey)
      .update(combinedData)
      .digest()
      .slice(0, 10);

    const valid3 = crypto.timingSafeEqual(receivedMac1, calculatedMac3);
    results.push({
      method: "with_mediakey",
      success: valid3,
      received: receivedMac1.toString("hex"),
      calculated: calculatedMac3.toString("hex"),
    });

    // Method 4: Coba dengan IV + data
    // Kita perlu generate keys dulu untuk mendapatkan IV
    const tempKeys = this.generateWhatsAppKeysV1(macKey, "image");
    const combinedDataIV = Buffer.concat([tempKeys.iv, mediaData1]);
    const calculatedMac4 = crypto
      .createHmac("sha256", macKey)
      .update(combinedDataIV)
      .digest()
      .slice(0, 10);

    const valid4 = crypto.timingSafeEqual(receivedMac1, calculatedMac4);
    results.push({
      method: "with_iv",
      success: valid4,
      received: receivedMac1.toString("hex"),
      calculated: calculatedMac4.toString("hex"),
    });

    // Return hasil yang berhasil atau semua hasil untuk debugging
    const successful = results.find((r) => r.success);
    return successful || { success: false, attempts: results, keyInfo };
  }

  /**
   * Main decryption function dengan testing lebih komprehensif
   */
  async decryptWhatsAppMedia(messageData, debugMode = true) {
    const debugLog = [];

    try {
      // Extract media message
      let mediaMessage = null;
      let mediaType = "image";

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

      if (!mediaMessage) {
        throw new Error("No media message found");
      }

      const mediaKeyBase64 = mediaMessage.mediaKey;
      const mediaUrl = mediaMessage.url;

      if (!mediaKeyBase64 || !mediaUrl) {
        throw new Error("Missing mediaKey or URL");
      }

      debugLog.push(`Media type: ${mediaType}`);
      debugLog.push(`Media key: ${mediaKeyBase64.substring(0, 20)}...`);

      const mediaKey = this.decodeMediaKey(mediaKeyBase64);
      const encryptedData = await this.downloadEncryptedMedia(mediaUrl);

      debugLog.push(`Media key hex: ${mediaKey.toString("hex")}`);
      debugLog.push(`Encrypted data length: ${encryptedData.length}`);
      debugLog.push(
        `Last 16 bytes: ${encryptedData.slice(-16).toString("hex")}`
      );

      // Test semua variasi key generation
      const keyGenerators = [
        { name: "v1", func: this.generateWhatsAppKeysV1 },
        { name: "v2", func: this.generateWhatsAppKeysV2 },
        { name: "v3", func: this.generateWhatsAppKeysV3 },
        { name: "v4", func: this.generateWhatsAppKeysV4 },
        { name: "v5", func: this.generateWhatsAppKeysV5 },
      ];

      const mediaTypes = [mediaType, "image", "video", "audio", "document"];

      let workingKeys = null;
      let macResult = null;

      // Global variable untuk menyimpan mediaKey agar bisa diakses di verifyMacVariations
      this.currentMediaKey = mediaKey;

      for (const type of mediaTypes) {
        for (const generator of keyGenerators) {
          const keys = generator.func.call(this, mediaKey, type);
          const keyInfo = `${type}_${generator.name}`;

          debugLog.push(`\n=== Testing ${keyInfo} ===`);
          debugLog.push(`MAC Key: ${keys.macKey.toString("hex")}`);

          const macCheck = this.verifyMacVariations(
            encryptedData,
            keys.macKey,
            keyInfo
          );

          if (macCheck.success) {
            workingKeys = keys;
            macResult = macCheck;
            debugLog.push(
              `✅ MAC verified with ${keyInfo} using method: ${macCheck.method}`
            );
            debugLog.push(`   Received: ${macCheck.received}`);
            debugLog.push(`   Calculated: ${macCheck.calculated}`);
            break;
          } else {
            debugLog.push(`❌ MAC failed with ${keyInfo}`);
            if (macCheck.attempts) {
              macCheck.attempts.forEach((attempt) => {
                debugLog.push(
                  `   ${attempt.method}: ${attempt.success ? "✅" : "❌"}`
                );
                debugLog.push(`     Expected: ${attempt.calculated}`);
                debugLog.push(`     Received: ${attempt.received}`);
              });
            }
          }
        }

        if (workingKeys) break;
      }

      if (!workingKeys) {
        return {
          success: false,
          error: "MAC verification failed for all combinations",
          debugLog: debugLog,
          suggestion:
            "The WhatsApp media format might have changed or the mediaKey/URL might be invalid",
          encryptedDataLength: encryptedData.length,
          mediaKeyHex: mediaKey.toString("hex"),
        };
      }

      // Decrypt dengan kunci yang berhasil
      const cipherData = encryptedData.slice(0, -10); // Remove MAC

      let decryptedData;
      try {
        const decipher = crypto.createDecipheriv(
          "aes-256-cbc",
          workingKeys.cipherKey,
          workingKeys.iv
        );
        decipher.setAutoPadding(true);
        decryptedData = Buffer.concat([
          decipher.update(cipherData),
          decipher.final(),
        ]);
        debugLog.push(
          `✅ Decryption successful: ${decryptedData.length} bytes`
        );
      } catch (error) {
        // Try ECB mode as fallback
        try {
          const decipher = crypto.createDecipheriv(
            "aes-256-ecb",
            workingKeys.cipherKey,
            null
          );
          decipher.setAutoPadding(true);
          decryptedData = Buffer.concat([
            decipher.update(cipherData),
            decipher.final(),
          ]);
          debugLog.push(
            `✅ ECB Decryption successful: ${decryptedData.length} bytes`
          );
        } catch (ecbError) {
          throw new Error(
            `Both CBC and ECB decryption failed: ${error.message}`
          );
        }
      }

      // Validate file signature
      const fileSignature = decryptedData.slice(0, 8).toString("hex");
      debugLog.push(`File signature: ${fileSignature}`);

      return {
        success: true,
        data: decryptedData,
        mimeType: mediaMessage.mimetype,
        fileSize: decryptedData.length,
        originalFileSize: mediaMessage.fileLength,
        mediaType: mediaType,
        keyVariation: workingKeys.type,
        macMethod: macResult.method,
        macResult: macResult,
        fileSignature: fileSignature,
        debugLog: debugMode ? debugLog : undefined,
      };
    } catch (error) {
      debugLog.push(`❌ Error: ${error.message}`);
      return {
        success: false,
        error: error.message,
        debugLog: debugLog,
      };
    }
  }
}

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

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
    const baseResponse = {
      success: true,
      mimeType: result.mimeType,
      fileSize: result.fileSize,
      originalFileSize: result.originalFileSize,
      mediaType: result.mediaType,
      keyVariation: result.keyVariation,
      macMethod: result.macMethod,
      fileSignature: result.fileSignature,
      debugLog: result.debugLog,
    };

    switch (returnFormat.toLowerCase()) {
      case "base64":
        responseData = {
          ...baseResponse,
          data: result.data.toString("base64"),
          format: "base64",
        };
        break;

      case "buffer":
        responseData = {
          ...baseResponse,
          data: Array.from(result.data),
          format: "buffer",
        };
        break;

      case "dataurl":
        responseData = {
          ...baseResponse,
          data: `data:${result.mimeType};base64,${result.data.toString(
            "base64"
          )}`,
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

export const config = {
  api: {
    bodyParser: {
      sizeLimit: "10mb",
    },
    responseLimit: "50mb",
  },
};
