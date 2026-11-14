
const express = require("express");
const crypto = require("crypto");
const admin = require("firebase-admin");

const app = express();
const PORT = process.env.PORT || 3000;

const SECRET = process.env.OFFERWALL_SECRET;
const SERVICE_ACCOUNT_JSON = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;

if (!SECRET || !SERVICE_ACCOUNT_JSON) {
  throw new Error("Missing required environment variables");
}

// Firebase Admin initialization
const serviceAccount = JSON.parse(SERVICE_ACCOUNT_JSON);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();

app.get("/", (req, res) => {
  res.status(200).send("MyContest Offerwall.GG Backend Running");
});

// Offerwall.GG Postback
app.get("/offerwall", async (req, res) => {
  try {
    const {
      user,
      tx,
      amount,
      status,
      test = "0",
      sig,
      currencyName,
      offerId,
      offerName,
      goalId,
      payoutUsd,
    } = req.query;

    if (!user || !tx || amount === undefined || !status || !sig) {
      return res.status(400).send("Missing parameters");
    }

    if (!["credited", "reversed"].includes(status)) {
      return res.status(400).send("Invalid status");
    }

    // Verify HMAC-SHA256 signature
    const signatureData = `${user}:${tx}:${amount}`;

    const expected = crypto
      .createHmac("sha256", SECRET)
      .update(signatureData)
      .digest("hex");

    const receivedBuffer = Buffer.from(String(sig), "hex");
    const expectedBuffer = Buffer.from(expected, "hex");

    if (
      receivedBuffer.length !== expectedBuffer.length ||
      !crypto.timingSafeEqual(receivedBuffer, expectedBuffer)
    ) {
      return res.status(403).send("Invalid signature");
    }

    // Test postbacks must never credit Points
    if (test === "1") {
      return res.status(200).send("ok");
    }

    const points = Number(amount);

    if (!Number.isFinite(points) || points === 0) {
      return res.status(400).send("Invalid amount");
    }

    if (
      (status === "credited" && points <= 0) ||
      (status === "reversed" && points >= 0)
    ) {
      return res.status(400).send("Invalid amount for status");
    }

    if (!/^[a-zA-Z0-9_-]{1,128}$/.test(String(user))) {
      return res.status(400).send("Invalid user ID");
    }

    const transactionId = String(tx);

    if (transactionId.length > 200) {
      return res.status(400).send("Invalid transaction ID");
    }

    const walletRef = db.collection("offerwall_gg_wallets").doc(String(user));

    // Hash transaction ID to create a safe Firestore document ID
    const transactionDocId = crypto
      .createHash("sha256")
      .update(transactionId)
      .digest("hex");

    const transactionRef = db
      .collection("offerwall_gg_transactions")
      .doc(transactionDocId);

    await db.runTransaction(async (t) => {
      const transactionSnap = await t.get(transactionRef);
      const walletSnap = await t.get(walletRef);

      const currentBalance = walletSnap.exists
        ? Number(walletSnap.data().points || 0)
        : 0;

      if (!Number.isFinite(currentBalance)) {
        throw new Error("Invalid wallet balance");
      }

      if (status === "credited") {
        // Never credit the same transaction twice
        if (transactionSnap.exists) {
          const oldStatus = transactionSnap.data().status;

          if (oldStatus === "credited" || oldStatus === "reversed") {
            return;
          }
        }

        t.set(walletRef, {
          userId: String(user),
          points: currentBalance + points,
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        }, { merge: true });

        t.set(transactionRef, {
          userId: String(user),
          transactionId,
          points,
          status: "credited",
          currencyName: currencyName || "Point",
          offerId: offerId || "",
          offerName: offerName || "",
          goalId: goalId || "",
          payoutUsd: payoutUsd || "",
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
        }, { merge: true });

      } else {
        // Reverse only a previously credited transaction
        if (
          !transactionSnap.exists ||
          transactionSnap.data().status !== "credited"
        ) {
          return;
        }

        const old = transactionSnap.data();

        if (old.userId !== String(user)) {
          throw new Error("Transaction user mismatch");
        }

        const reversalPoints = Math.abs(Number(old.points));

        if (currentBalance < reversalPoints) {
          throw new Error("Insufficient wallet balance for reversal");
        }

        t.set(walletRef, {
          userId: String(user),
          points: currentBalance - reversalPoints,
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        }, { merge: true });

        t.update(transactionRef, {
          status: "reversed",
          reversedAt: admin.firestore.FieldValue.serverTimestamp(),
        });
      }
    });

    return res.status(200).send("ok");

  } catch (error) {
    console.error("Offerwall postback error:", error);
    return res.status(500).send("Server error");
  }
});

app.listen(PORT, () => {
  console.log(`Offerwall.GG backend running on port ${PORT}`);
});
